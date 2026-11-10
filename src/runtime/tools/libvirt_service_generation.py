"""Observe the original pinned daemon and the peer on its dedicated socket."""

from copy import deepcopy
import os
from pathlib import PurePosixPath
import socket
import stat

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_service_observer import qualify_service
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_bundle import metadata
from tools.libvirt_bus_connection import peer_credentials
from tools.libvirt_systemd_bus import require
from tools.vm_host_inventory import entry


def directory_identity(info):
    require(stat.S_ISDIR(info.st_mode), 'original runtime directory required')
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode), kind='directory')


class ServiceSocketReader:
    def __init__(self, root, installation, *, socket_factory=socket.socket):
        self.root, self.socket_factory = root, socket_factory
        self.session = deepcopy(installation['profile']['session'])
        runtime = self.session['runtime_root']
        self.directories = {}
        for path in (runtime, runtime + '/libvirt'):
            matches = [item for item in installation['items']
                       if item['spec']['kind'] == 'directory' and item['spec']['path'] == path]
            require(len(matches) == 1 and matches[0]['phase'] == 'created',
                    'original dedicated socket directory proof required')
            self.directories[path] = deepcopy(matches[0]['proof']['identity'])

    def _verify_directories(self):
        for path, expected in self.directories.items():
            with entry(self.root, path.lstrip('/')) as (_, _, info):
                require(directory_identity(info) == expected, 'original dedicated socket directory differs')

    def __call__(self, spec, pid):
        role = spec['role']
        require((role, spec['unit']) in {
            ('libvirtd', 'dnlab-libvirtd.service'), ('virtlogd', 'dnlab-virtlogd.service'),
            ('virtlockd', 'dnlab-virtlockd.service'),
        }, 'original dedicated service socket required')
        runtime = self.session['runtime_root'] + '/libvirt'
        path = self.session['socket'] if role == 'libvirtd' else runtime + '/' + role + '-sock'
        require(PurePosixPath(path).parent == PurePosixPath(runtime),
                'service socket must be a direct child of its original runtime directory')
        self._verify_directories()
        with entry(self.root, path.lstrip('/')) as (parent, name, info):
            require(directory_identity(os.fstat(parent)) == self.directories[runtime],
                    'dedicated socket parent replaced before connection')
            require(stat.S_ISSOCK(info.st_mode) and not info.st_mode & 0o077
                    and (info.st_uid, info.st_gid) == (spec['uid'], spec['gid']),
                    'original private service socket metadata differs')
            with self.socket_factory(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(5)
                # Resolve only the socket name below the already opened parent.
                stream.connect(f'/proc/self/fd/{parent}/{name}')
                peer = peer_credentials(stream)
            require(peer == dict(pid=pid, uid=info.st_uid, gid=info.st_gid),
                    'private socket peer differs from original service process')
            observed = dict(path=path, device=info.st_dev, inode=info.st_ino, mode=info.st_mode,
                            uid=info.st_uid, gid=info.st_gid,
                            peer_pid=peer['pid'], peer_uid=peer['uid'], peer_gid=peer['gid'])
        with entry(self.root, path.lstrip('/')) as (_, _, current):
            require(metadata(current) == metadata(info), 'original private service socket replaced')
        self._verify_directories()
        return observed


class NativeServiceObserver:
    """Bind fresh unit/file proof and socket peer to the original event pin."""

    def __init__(self, installation, *, unit_reader, processes, socket_reader):
        self.installation = deepcopy(installation)
        self.unit_reader, self.processes, self.socket_reader = unit_reader, processes, socket_reader

    def __call__(self, request, invocation):
        source = self.installation
        spec = request['spec']
        require(request['installation_sha256'] == fingerprint(source) and request['context'] == source['context']
                and spec['kind'] == 'start' and spec in steps(source['profile']),
                'original dedicated service observation request required')
        row = self.unit_reader()[spec['unit']]
        unit = row['unit']
        reference = invocation['process_reference']
        require(row['load_state'] == 'loaded' and unit['active'] == 'active' and unit['job'] == 0
                and unit['pid'] == invocation['pid'] == reference['pid']
                and unit['invocation_id'] == invocation['invocation_id'] == reference['invocation_id'],
                'systemd unit differs from the original service invocation')
        with self.processes.observe(reference, request) as process:
            endpoint = self.socket_reader(spec, process['pid'])
            return qualify_service(source, spec['unit'], endpoint['path'],
                                   dict(unit=unit, process=process, socket=endpoint, files=row['files']))
