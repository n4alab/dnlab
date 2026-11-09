"""Opt-in bootstrap barrier for qualification; no production NOS capability."""

from .manifest import Conflict
from .image_commands import python_command

# File content identifies this PID namespace's init process start. A container
# restart retains its writable layer, so mere existence of a marker is unsafe.
RELEASE = r'''import os, stat
with open('/proc/1/stat') as stream:
    boot = stream.read().rsplit(')', 1)[1].split()[19]
root = '/run/dnlab-runtime'
try:
    os.mkdir(root, 0o700)
except FileExistsError:
    pass
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    info = os.fstat(fd)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('unexpected bootstrap directory ownership or mode')
    name = 'ready-' + str(os.getpid())
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(out, 'w') as stream:
            stream.write(boot + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, 'management-ready', src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass
finally:
    os.close(fd)
'''


class Bootstrap:
    def __init__(self, backend, request, spec, port):
        self.backend, self.request, self.spec, self.port = backend, request, spec, port

    def release(self, identity, connection):
        container = self.port.container()
        if container['Id'] != identity['container_id']:
            raise Conflict('bootstrap container changed')
        image = self.backend.docker.request('GET', '/images/' + container['Image'] + '/json')
        labels = image.get('Config', {}).get('Labels') or {}
        if 'runtime-management-v1' not in labels.get('org.dnlab.capabilities', '').split(',') or labels.get('org.dnlab.runtime-management.status') != 'experimental-unqualified':
            raise Conflict('bootstrap requires an explicitly labelled candidate image')
        env = dict(item.split('=', 1) for item in container['Config'].get('Env', []) if '=' in item)
        if env.get('DNLAB_RUNTIME_BOOT_WAIT', '').lower() != 'true' or env.get('DNLAB_RUNTIME_MGMT_INTF') != 'mgmt0':
            raise Conflict('bootstrap candidate must wait for stable mgmt0')
        command = python_command(image, RELEASE)
        # Do not signal readiness until stable identity and addresses are valid.
        self.port.verify(identity, connection)
        helper = self.backend.docker.exec_checked(container['Id'], command)
        self.port.verify(identity, connection)
        return {'container_id': container['Id'], 'exec_id': helper, 'bootstrap_released': True, 'guest_readiness': 'unknown'}
