"""Read-only provenance for the two pinned cleanup containers.

This is one component of the current-state observer, not gate admission.
Native provenance, the agreed window and image-build hold remain separate.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import select
import stat

from cleanup_execution import absolute, canonical_digest, require, sha, source_map


def config_digest(value):
    return canonical_digest({key: value[key] for key in ('Config', 'HostConfig', 'Mounts', 'Path', 'Args')})


def import_environment_digest(raw):
    require(type(raw) is bytes and len(raw) <= 65536, 'bounded process environment required')
    selected = {}
    for item in raw.split(b'\0'):
        if not item:
            continue
        key, separator, value = item.partition(b'=')
        require(bool(separator), 'malformed process environment')
        if key.startswith((b'PYTHON', b'LD_')) or key in (b'PATH', b'HOME', b'VIRTUAL_ENV', b'__PYVENV_LAUNCHER__'):
            name = key.decode('ascii')
            require(name not in selected, 'duplicate import environment key')
            selected[name] = value.decode('utf-8')
    return canonical_digest(selected)


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def file_proof(fd, *, limit):
    first = os.fstat(fd)
    require(stat.S_ISREG(first.st_mode) and first.st_uid == 0 and not first.st_mode & 0o022,
            'unsafe executable/source metadata')
    require(0 <= first.st_size <= limit, 'execution asset size exceeds bound')
    digest, total = hashlib.sha256(), 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, min(65536, limit + 1 - total))
        if not block:
            break
        total += len(block)
        require(total <= limit, 'execution asset read exceeds bound')
        digest.update(block)
    require(metadata(first) == metadata(os.fstat(fd)), 'execution asset changed during read')
    return {'sha256': digest.hexdigest(), 'metadata': metadata(first)}


def source_at(root, path):
    require(absolute(path), 'absolute execution asset path required')
    directory = os.dup(root)
    try:
        parts = path.split('/')[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            return file_proof(fd, limit=1024 * 1024)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


class LinuxProcess:
    """Pinned readonly pidfd and namespace/root observations; never signals."""

    def _view(self, pid):
        root = Path('/proc') / str(pid)
        def bounded(name):
            with (root / name).open('rb') as stream:
                data = stream.read(65537)
            require(len(data) <= 65536, 'process evidence exceeds bound')
            return data
        def namespace(name):
            path = root / 'ns' / name
            info = os.stat(path)
            link = os.readlink(path)
            require(link == name + ':[' + str(info.st_ino) + ']', 'process namespace changed during read')
            return {'device': info.st_dev, 'inode': info.st_ino, 'link': link}
        fields = bounded('stat').decode().rsplit(')', 1)[1].split()
        return {'pid': pid, 'start_ticks': fields[19],
                'cmdline_sha256': hashlib.sha256(bounded('cmdline')).hexdigest(),
                'exe': os.readlink(root / 'exe'), 'cwd': os.readlink(root / 'cwd'),
                'import_env_sha256': import_environment_digest(bounded('environ')),
                'cgroup': bounded('cgroup').decode(),
                'namespaces': {name: namespace(name) for name in ('pid', 'mnt', 'net')}}

    @contextmanager
    def capture(self, pid, container_id, copies):
        require(type(pid) is int and pid > 0, 'running container PID required')
        pidfd = os.pidfd_open(pid, 0)
        root = binary = None
        try:
            poll = select.poll()
            poll.register(pidfd, select.POLLIN)
            def alive():
                # POLLERR/POLLNVAL/ambiguous events are never proof of liveness.
                require(not poll.poll(0), 'process exited or pidfd observation failed')
            alive()
            first = self._view(pid)
            require(re.search(r'(?<![0-9a-f])' + re.escape(container_id) + r'(?![0-9a-f])', first['cgroup']),
                    'process does not belong to original container')
            # proc magic links are intentional; all paths below root reject symlinks.
            root = os.open('/proc/' + str(pid) + '/root', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            binary = os.open('/proc/' + str(pid) + '/exe', os.O_RDONLY | os.O_CLOEXEC)
            sources = {path: source_at(root, path) for path in copies}
            executable = file_proof(binary, limit=32 * 1024 * 1024)
            failure = None
            try:
                yield {'process': first, 'sources': sources, 'executable': executable}
            except BaseException as error:
                failure = error
            try:
                require({path: source_at(root, path) for path in copies} == sources,
                        'container execution sources changed')
                require(file_proof(binary, limit=32 * 1024 * 1024) == executable,
                        'container executable changed')
                require(self._view(pid) == first, 'process generation or namespace changed')
                alive()
            except BaseException as error:
                if failure is None:
                    failure = error
                else:
                    failure.add_note('process post-observation failed: ' + str(error))
            if failure is not None:
                raise failure
        finally:
            for fd in (binary, root, pidfd):
                if fd is not None:
                    os.close(fd)


def observe_container(api, role, profile, descriptor, *, process=None):
    """Return qualified artifact/generation evidence for an explicit original ID."""
    require(role in ('daemon', 'multinode'), 'container cleanup role required')
    require(type(profile) is dict and set(profile) == {
        'container_id', 'config_sha256', 'exe', 'exe_sha256', 'cmdline_sha256', 'cwd', 'import_env_sha256', 'copies'},
        'complete pinned container provenance required')
    require(sha(profile['container_id']) and all(sha(profile[key]) for key in (
        'config_sha256', 'exe_sha256', 'cmdline_sha256', 'import_env_sha256'))
            and absolute(profile['exe']) and absolute(profile['cwd']),
        'pinned container process required')
    require(descriptor.get('kind') == 'container' and type(descriptor.get('image')) is str
            and descriptor['image'].startswith('sha256:') and sha(descriptor['image'][7:]),
            'executed container artifact descriptor required')
    sources = source_map(descriptor.get('sources'), role)
    copies = profile['copies']
    require(type(copies) is dict and all(absolute(path) and sha(value) for path, value in copies.items()),
            'pinned source copies required')
    for source in sources.values():
        match = re.fullmatch(r'/usr/local/lib/python[0-9]+\.[0-9]+/site-packages/dnlab_multinode/(.+\.py)', source['path'])
        require(match is not None, 'qualified container import location required')
        for path in (source['path'], '/opt/dnlab-multinode/dnlab_multinode/' + match[1]):
            require(copies.get(path) == source['sha256'], 'both execution source copies required')
    scripts = {'/usr/local/bin/dnlab-lab-cleanup'}
    if role == 'multinode':
        scripts |= {'/usr/local/bin/dnlab-multinode', '/usr/local/bin/dnlab-multinode-api'}
    require(scripts <= set(copies), 'qualified console bootstraps required')
    identity = profile['container_id']
    before = api.inspect(identity)
    require(type(before) is dict and before.get('Id') == identity
            and before.get('Image') == descriptor['image'], 'original container identity differs')
    require(before['State']['Running'] is True and before['State']['Status'] == 'running'
            and config_digest(before) == profile['config_sha256'], 'original container config or lifecycle differs')
    process = LinuxProcess() if process is None else process
    with process.capture(before['State']['Pid'], identity, copies) as observed:
        view = observed['process']
        require(view['exe'] == profile['exe'] and view['cmdline_sha256'] == profile['cmdline_sha256']
                and view['cwd'] == profile['cwd'] and view['import_env_sha256'] == profile['import_env_sha256']
                and observed['executable']['sha256'] == profile['exe_sha256'],
                'container interpreter or invocation differs')
        require(set(observed['sources']) == set(copies)
                and all(observed['sources'][path]['sha256'] == value for path, value in copies.items()),
                'container execution asset differs')
        after = api.inspect(identity)
        require(type(after) is dict and after.get('Id') == identity
                and after.get('Image') == descriptor['image'] and config_digest(after) == profile['config_sha256'],
                'container config changed during observation')
        for key in ('Pid', 'StartedAt', 'Running', 'Status'):
            require(after['State'][key] == before['State'][key], 'container lifecycle changed during observation')
        require(after.get('RestartCount') == before.get('RestartCount'), 'container restart count changed')
        generation = {'container_id': identity, 'started_at': before['State']['StartedAt'],
                      'restart_count': before.get('RestartCount'), 'config_sha256': profile['config_sha256'],
                      **observed}
    return {'container_id': identity, 'artifact_sha256': canonical_digest(descriptor),
            'generation_sha256': canonical_digest(generation), 'evidence': generation}
