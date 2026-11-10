"""Retain the original systemd service process in the activation supervisor."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import os
import re
import select
import stat
import uuid

from dnlab_runtime.libvirt_activation_bus import UNITS
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.qemu_process import stat_start
from dnlab_runtime.vm_bundle import metadata
from tools.libvirt_systemd_bus import require
from tools.vm_host_inventory import regular

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
NAMESPACES = ('pid', 'mnt', 'net', 'user')
EXECUTABLE_LIMIT = 128 * 1024 * 1024


def identity(info):
    return info.st_dev, info.st_ino


def executable_digest(root):
    # The proc directory and pidfd pin the original process that owns this link.
    fd = os.open('exe', os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=root)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                and 0 < before.st_size <= EXECUTABLE_LIMIT, 'bounded root-controlled service executable required')
        remaining = before.st_size
        hashed = hashlib.sha256()
        while remaining:
            data = os.read(fd, min(remaining, 65536))
            require(data, 'service executable truncated during observation')
            hashed.update(data)
            remaining -= len(data)
        require(not os.read(fd, 1) and metadata(before) == metadata(os.fstat(fd))
                and metadata(before) == metadata(os.stat('exe', dir_fd=root)),
                'original service executable changed during observation')
        return hashed.hexdigest()
    finally:
        os.close(fd)


def process_details(root, status, environment, spec):
    groups = [line[7:].split() for line in status.splitlines() if line.startswith(b'Groups:')]
    require(len(groups) == 1 and all(group.isdigit() for group in groups[0]),
            'original service supplementary groups malformed')
    raw_command = regular(root, 'cmdline', 1024 * 1024)
    require(raw_command.endswith(b'\0') and raw_command[0] != 0, 'original service command malformed')
    variables = {}
    for entry in environment[:-1].split(b'\0'):
        key, separator, value = entry.partition(b'=')
        name = os.fsdecode(key)
        require(separator and name and name not in variables, 'original service environment malformed')
        variables[name] = os.fsdecode(value)
    digest = executable_digest(root)
    require(digest == spec['binary']['sha256'], 'original service executable digest differs')
    return dict(uids=[spec['uid']] * 4, gids=[spec['gid']] * 4, groups=[int(group) for group in groups[0]],
                executable_sha256=digest, argv=[os.fsdecode(arg) for arg in raw_command[:-1].split(b'\0')],
                environment=variables)


class ServiceProcessPins:
    def __init__(self, proc, owner, context, read_context, pidfd_open, poll_factory):
        self.proc, self.owner = proc, owner
        self.context, self.read_context = deepcopy(context), read_context
        self.pidfd_open, self.poll_factory = pidfd_open, poll_factory
        self.live = {}
        self.units = set()
        self.active = True

    def _check_context(self):
        require(self.active and self.read_context() == self.context,
                'original service process observation context differs')
        require(os.readlink('self', dir_fd=self.proc) == str(os.getpid()),
                'procfs PID namespace differs from pidfd caller')
        device, inode = identity(os.stat('self/ns/pid', dir_fd=self.proc))
        require(dict(device=device, inode=inode) == self.context['namespaces']['pid'],
                'original service procfs namespace differs')
        boot = regular(self.proc, 'sys/kernel/random/boot_id', 128).decode('ascii').strip()
        require(boot == self.context['boot_id'], 'original service boot identity differs')

    def _snapshot(self, root, pid, invocation, spec, poll, *, details=False):
        self._check_context()
        require(not poll.poll(0), 'original service process exited or pidfd status differs')
        original = identity(os.fstat(root))
        ticks = stat_start(regular(root, 'stat', 16384), pid)
        status = regular(root, 'status', 65536)
        for field, key in ((b'Uid:', 'uid'), (b'Gid:', 'gid')):
            entries = [line[len(field):].split() for line in status.splitlines() if line.startswith(field)]
            require(entries == [[str(spec[key]).encode('ascii')] * 4],
                    'original dedicated service credentials differ')
        environment = regular(root, 'environ', 1024 * 1024)
        prefix = b'INVOCATION_ID='
        observed = [entry[len(prefix):] for entry in environment.split(b'\0') if entry.startswith(prefix)]
        require(environment.endswith(b'\0') and observed == [invocation.encode('ascii')],
                'original systemd invocation ID differs in process environment')
        for name in NAMESPACES:
            device, inode = identity(os.stat('ns/' + name, dir_fd=root))
            require(dict(device=device, inode=inode) == self.context['namespaces'][name],
                    'original service process namespace differs: ' + name)
        result = dict(pid=pid, start_ticks=ticks, boot_id=self.context['boot_id'],
                      namespaces=deepcopy(self.context['namespaces']), pidfd_alive=True)
        if details:
            result.update(process_details(root, status, environment, spec))
        current = os.stat(str(pid), dir_fd=self.proc, follow_symlinks=False)
        require(identity(current) == original and stat_start(regular(root, 'stat', 16384), pid) == ticks
                and not poll.poll(0), 'original service process changed during observation')
        self._check_context()
        return result

    def pin(self, request, subscription, pid, invocation):
        spec = request['spec']
        require(spec['unit'] in UNITS and spec['unit'] not in self.units
                and all(type(spec[key]) is int and spec[key] > 0 for key in ('uid', 'gid'))
                and request['context'] == self.context
                and subscription['request_sha256'] == fingerprint(request)
                and subscription['context_sha256'] == fingerprint(self.context)
                and type(pid) is int and pid > 0 and isinstance(invocation, str)
                and re.fullmatch('[0-9a-f]{32}', invocation) is not None and invocation != '0' * 32,
                'original dedicated service invocation and subscription required')
        self._check_context()
        with ExitStack() as resources:
            descriptor = self.pidfd_open(pid, 0)
            resources.callback(os.close, descriptor)
            poll = self.poll_factory()
            poll.register(descriptor, select.POLLIN)
            root = os.open(str(pid), DIRECTORY_FLAGS, dir_fd=self.proc)
            resources.callback(os.close, root)
            observation = self._snapshot(root, pid, invocation, spec, poll)
            reference = dict(
                kind='original-service-process-v1', token=uuid.uuid4().hex,
                request_sha256=fingerprint(request), subscription_sha256=fingerprint(subscription),
                invocation_id=invocation, pid=pid, start_ticks=observation['start_ticks'], boot_id=self.context['boot_id'],
                namespaces_sha256=fingerprint(self.context['namespaces']),
            )
            self.owner.enter_context(resources.pop_all())
        self.live[reference['token']] = (deepcopy(reference), root, poll)
        self.units.add(spec['unit'])
        return reference

    def verify(self, reference, request, subscription):
        if reference['subscription_sha256'] != fingerprint(subscription):
            return False
        try:
            self._observe(reference, request)
        except (OSError, Conflict):
            return False
        return True

    def _observe(self, reference, request, *, details=False):
        live = self.live.get(reference['token'])
        require(self.active and live is not None and live[0] == reference
                and reference['request_sha256'] == fingerprint(request), 'original live service pin required')
        result = self._snapshot(live[1], reference['pid'], reference['invocation_id'],
                                request['spec'], live[2], details=details)
        require(result['start_ticks'] == reference['start_ticks'], 'original service start time differs')
        return result

    @contextmanager
    def observe(self, reference, request):
        yield self._observe(reference, request, details=True)
        self._observe(reference, request)


@contextmanager
def open_service_process_pins(context, *, read_context, proc_root='/proc',
                              pidfd_open=os.pidfd_open, poll_factory=select.poll):
    with ExitStack() as owner:
        proc = os.open(proc_root, DIRECTORY_FLAGS)
        owner.callback(os.close, proc)
        keeper = ServiceProcessPins(proc, owner, context, read_context, pidfd_open, poll_factory)
        keeper._check_context()
        try:
            yield keeper
        finally:
            keeper.active = False
            keeper.live.clear()
