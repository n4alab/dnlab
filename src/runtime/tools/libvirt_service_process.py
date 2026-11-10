"""Retain the original systemd service process in the activation supervisor."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
import re
import select
import uuid

from dnlab_runtime.libvirt_activation_bus import UNITS
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.qemu_process import stat_start
from tools.libvirt_systemd_bus import require
from tools.vm_host_inventory import regular

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
NAMESPACES = ('pid', 'mnt', 'net', 'user')


def identity(info):
    return info.st_dev, info.st_ino


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

    def _snapshot(self, root, pid, invocation, spec, poll):
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
        current = os.stat(str(pid), dir_fd=self.proc, follow_symlinks=False)
        require(identity(current) == original and stat_start(regular(root, 'stat', 16384), pid) == ticks
                and not poll.poll(0), 'original service process changed during observation')
        self._check_context()
        return ticks

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
            ticks = self._snapshot(root, pid, invocation, spec, poll)
            reference = dict(
                kind='original-service-process-v1', token=uuid.uuid4().hex,
                request_sha256=fingerprint(request), subscription_sha256=fingerprint(subscription),
                invocation_id=invocation, pid=pid, start_ticks=ticks, boot_id=self.context['boot_id'],
                namespaces_sha256=fingerprint(self.context['namespaces']),
            )
            self.owner.enter_context(resources.pop_all())
        self.live[reference['token']] = (deepcopy(reference), root, poll)
        self.units.add(spec['unit'])
        return reference

    def verify(self, reference, request, subscription):
        live = self.live.get(reference['token'])
        if (not self.active or live is None or live[0] != reference
                or reference['request_sha256'] != fingerprint(request)
                or reference['subscription_sha256'] != fingerprint(subscription)):
            return False
        try:
            ticks = self._snapshot(live[1], reference['pid'], reference['invocation_id'], request['spec'], live[2])
        except (OSError, Conflict):
            return False
        return ticks == reference['start_ticks']


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
