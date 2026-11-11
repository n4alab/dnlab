"""Reject pre-existing driver and recovery state before the first daemon start."""

from copy import deepcopy
import os
import stat

from dnlab_runtime.libvirt_service_profile import require_activatable
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vm_bundle import metadata
from tools.libvirt_service_generation import directory_identity
from tools.vm_host_inventory import entry


class InitialSessionState:
    def __init__(self, root, installation):
        profile = installation['profile']
        require_activatable(profile)
        self.root = root
        self.session = deepcopy(profile['session'])
        environment = profile['client_environment']
        state = self.session['state_root']
        runtime = self.session['runtime_root']
        self.runtime = runtime + '/libvirt'
        self.contents = {
            environment['XDG_CONFIG_HOME']: {'libvirt'},
            profile['driver_layout']['config_base']: {'qemu.conf', 'qemu'},
            profile['driver_layout']['mutable_root']: set(),
            state: {'cache', 'data'},
            environment['XDG_CACHE_HOME']: set(),
            environment['XDG_DATA_HOME']: set(),
            runtime: {'libvirt'},
            self.runtime: set(),
        }
        self.identities = {item['spec']['path']: deepcopy(item['proof']['identity'])
                           for item in installation['items'] if item['spec']['kind'] == 'directory'
                           and item['phase'] == 'created' and item['spec']['path'] in self.contents}
        if set(self.identities) != set(self.contents):
            raise Conflict('original installed session directories required before activation')

    def _inspect(self, path, required, optional):
        with entry(self.root, path.lstrip('/')) as (parent, name, info):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                current = os.fstat(fd)
                if metadata(info) != metadata(current) or directory_identity(current) != self.identities[path]:
                    raise Conflict('original initial libvirt directory differs: ' + path)
                seen = set()
                with os.scandir(fd) as children:
                    for child in children:
                        seen.add(child.name)
                        if child.name in required:
                            continue
                        expected_type = optional.get(child.name)
                        if expected_type is None:
                            raise Conflict('pre-existing libvirt state at ' + path + '/' + child.name)
                        observed = child.stat(follow_symlinks=False)
                        if (stat.S_IFMT(observed.st_mode) != expected_type
                                or (observed.st_uid, observed.st_gid) != (self.session['uid'], self.session['gid'])
                                or observed.st_mode & 0o077):
                            raise Conflict('unqualified helper runtime entry at ' + path + '/' + child.name)
                if not required <= seen or metadata(os.fstat(fd)) != metadata(current):
                    raise Conflict('initial libvirt directory changed or incomplete: ' + path)
                return metadata(current)
            finally:
                os.close(fd)

    def __call__(self, receipts):
        if receipts['dnlab-libvirtd.service'] is not None:
            # Confirmed generations are checked by the live service and domain observers.
            return
        helpers = {}
        for role in ('virtlogd', 'virtlockd'):
            if receipts['dnlab-' + role + '.service'] is not None:
                helpers.update({role + '.pid': stat.S_IFREG, role + '-sock': stat.S_IFSOCK,
                                role + '-admin-sock': stat.S_IFSOCK})

        def read():
            return {path: self._inspect(path, required, helpers if path == self.runtime else {})
                    for path, required in self.contents.items()}

        if read() != read():
            raise Conflict('initial libvirt state changed during preflight')
