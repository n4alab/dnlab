"""Read-only verification of an already recorded host QEMU incarnation.

The record must be acquired and persisted by the original creation operation.
This provider never discovers a PID, trusts a pidfile, or derives one from a
libvirt domain ID. The caller must qualify the host procfs mount/namespace.
No signals or subprocesses are used; a pidfd is held across both observations.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import select
import stat

from .manifest import Conflict
from .vm_events import validate_birth, validate_observation
from .vm_template import digest, fields, require


def stat_start(raw, pid):
    """Parse field 22 after comm, which may itself contain spaces and ')'."""
    try:
        prefix, tail = raw.rsplit(b')', 1)
        observed_pid = int(prefix.split(b'(', 1)[0])
        columns = tail.split()
        ticks = int(columns[19])
    except (ValueError, IndexError) as error:
        raise Conflict('QEMU stat is malformed') from error
    if observed_pid != pid or columns[0] not in (b'R', b'S', b'D', b'T', b't', b'W', b'I') or ticks <= 0:
        raise Conflict('original live QEMU stat differs')
    return ticks


def validate_process_record(record):
    """Validate an original receipt as data, without observing or learning it."""
    fields(record, ('birth', 'process', 'uid', 'gid', 'cmdline_sha256', 'namespaces'), 'original QEMU record')
    validate_birth(record['birth'])
    validate_observation({'birth': record['birth'], 'config_sha256': '0'*64,
                          'process': record['process']}, record['birth'])
    require(record['process'] is not None and type(record['uid']) is int and record['uid'] > 0
            and type(record['gid']) is int and record['gid'] > 0 and digest(record['cmdline_sha256']),
            'original non-root QEMU process record required')
    fields(record['namespaces'], ('pid', 'mnt', 'net', 'user'), 'original QEMU namespaces')
    for value in record['namespaces'].values():
        fields(value, ('device', 'inode'), 'namespace identity')
        require(all(type(v) is int and v > 0 for v in value.values()), 'invalid original namespace identity')
    return deepcopy(record)


class PinnedQEMUProcess:
    def __init__(self, record, *, proc_root='/proc', pidfd_open=None, poll_factory=None, pid_namespace=None):
        self.record, self.proc_root = validate_process_record(record), Path(proc_root)
        self.pidfd_open = pidfd_open or os.pidfd_open
        self.poll_factory = poll_factory or select.poll
        self.pid_namespace = pid_namespace or self._local_pid_namespace

    @staticmethod
    def _local_pid_namespace():
        info = os.stat('/proc/self/ns/pid')
        return {'device': info.st_dev, 'inode': info.st_ino}

    def _pid_namespace(self):
        if self.pid_namespace() != self.record['namespaces']['pid']:
            raise Conflict('pidfd caller and original QEMU PID namespace differ')

    def _open(self, name, parent, stack, *, directory=False, follow=False):
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:flags |= os.O_DIRECTORY
        if not follow:flags |= os.O_NOFOLLOW
        fd = os.open(name, flags, dir_fd=parent)
        stack.callback(os.close, fd)
        if not directory and not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Conflict('regular QEMU observation file required')
        return fd

    def _read(self, name, parent, limit):
        with ExitStack() as stack:
            fd = self._open(name, parent, stack)
            data = bytearray()
            while len(data) <= limit:
                block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block:break
                data.extend(block)
            if len(data) > limit:raise Conflict('QEMU observation exceeds bound')
            return bytes(data)

    def _executable(self, root):
        with ExitStack() as stack:
            # exe is a procfs magic link; the enclosing original PID directory
            # and pidfd are pinned by capture, never a user-supplied target path.
            fd = self._open('exe', root, stack, follow=True)
            first = os.fstat(fd)
            if not 0 < first.st_size <= 512 * 1024 * 1024:
                raise Conflict('bounded QEMU executable required')
            hashed = hashlib.sha256(); remaining = first.st_size
            while remaining:
                block = os.read(fd, min(remaining, 1024 * 1024))
                if not block:raise Conflict('QEMU executable truncated during read')
                hashed.update(block); remaining -= len(block)
            last = os.fstat(fd)
            keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if os.read(fd, 1) or any(getattr(first, k) != getattr(last, k) for k in keys):
                raise Conflict('QEMU executable changed during read')
            return hashed.hexdigest()

    def _observe(self, root, proc):
        expected = self.record; process = expected['process']; pid = process['pid']
        boot = self._read('sys/kernel/random/boot_id', proc, 128).decode('ascii').strip()
        ticks = stat_start(self._read('stat', root, 16384), pid)
        credentials = {}
        for line in self._read('status', root, 65536).splitlines():
            key, sep, value = line.partition(b':')
            if sep and key in (b'Uid', b'Gid'):
                if key in credentials:raise Conflict('duplicate QEMU credentials')
                try:credentials[key] = [int(v) for v in value.split()]
                except ValueError as error:raise Conflict('malformed QEMU credentials') from error
        if credentials != {b'Uid': [expected['uid']]*4, b'Gid': [expected['gid']]*4}:
            raise Conflict('original dedicated QEMU credentials differ')
        command = self._read('cmdline', root, 1024 * 1024)
        argv = command.split(b'\0')
        uuid_arg = expected['birth']['uuid'].encode('ascii')
        if (not command.endswith(b'\0') or not argv[0] or argv.count(b'-uuid') != 1
                or argv.index(b'-uuid') + 1 >= len(argv) or argv[argv.index(b'-uuid') + 1] != uuid_arg
                or hashlib.sha256(command).hexdigest() != expected['cmdline_sha256']):
            raise Conflict('original QEMU command or UUID differs')
        for name, identity in expected['namespaces'].items():
            info = os.stat('ns/' + name, dir_fd=root)
            if {'device': info.st_dev, 'inode': info.st_ino} != identity:
                raise Conflict('original QEMU namespace differs: ' + name)
        observed = {'boot_id': boot, 'pid': pid, 'start_ticks': ticks, 'executable_sha256': self._executable(root)}
        if observed != process:raise Conflict('original QEMU process incarnation differs')
        return observed

    @contextmanager
    def capture(self, birth):
        if birth != self.record['birth']:raise Conflict('original QEMU birth differs')
        with ExitStack() as stack:
            self._pid_namespace()
            pid = self.record['process']['pid']
            fd = self.pidfd_open(pid, 0); stack.callback(os.close, fd)
            poll = self.poll_factory(); poll.register(fd, select.POLLIN)
            proc = self._open(str(self.proc_root), None, stack, directory=True)
            root = self._open(str(pid), proc, stack, directory=True)
            def verify():
                self._pid_namespace()
                if poll.poll(0):raise Conflict('QEMU exited or pidfd status is not qualified')
                current = os.stat(str(pid), dir_fd=proc, follow_symlinks=False)
                pinned = os.fstat(root)
                if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                    raise Conflict('original QEMU proc directory replaced')
                result = self._observe(root, proc)
                if poll.poll(0):raise Conflict('QEMU exited during observation')
                return result
            proof = verify()
            yield deepcopy(proof)
            verify()
