"""RTNL continuity using synthetic datagrams; no socket is opened."""
from copy import deepcopy
import errno
import os
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_tap_link_events import TapLinkEvents, decode, HEADER, LINK


def packet(kind=16, name='dtp-one', index=110):
    raw = name.encode() + b'\0'
    attr = struct.pack('=HH', len(raw) + 4, 3) + raw
    attr += b'\0' * (-len(attr) % 4)
    body = LINK.pack(0, 0, 1, index, 0, 0) + attr
    return HEADER.pack(HEADER.size + len(body), kind, 0, 0, 0) + body


@pytest.fixture
def case():
    state = dict(epoch={'original': 1}, queue=[], records=[], identity=10, failure=None)
    class Feed:
        def setblocking(self, value):
            assert value is False
        def bind(self, value):
            assert value == (0, 1)
        def fileno(self):
            return 50
        def getsockopt(self, level, option):
            assert (level, option) == (270, 5)
            return 0
        def recvmsg(self, size):
            if not state['queue']:
                raise BlockingIOError(errno.EAGAIN, 'empty')
            value = state['queue'].pop(0)
            if isinstance(value, BaseException):
                raise value
            return value, [], 0, (0, 1)
        def close(self):
            state['closed'] = True
    def record(value):
        if value['phase'] == state['failure']:
            raise OSError('synthetic record failure')
        state['records'].append(deepcopy(value))
    current = os.stat('/proc/thread-self/ns/net')
    scope = dict(boot_id='12345678-1234-4234-8234-123456789abc',
                 device=current.st_dev, inode=current.st_ino)
    runtime = SimpleNamespace(check=lambda: deepcopy(state['epoch']))
    monitor = TapLinkEvents(scope, runtime=runtime, read_context=lambda: deepcopy(scope), record=record,
        socket_factory=lambda *args: Feed(), descriptor=lambda fd:
            SimpleNamespace(st_dev=7, st_ino=state['identity'], st_mode=stat.S_IFSOCK | 0o600))
    monitor.open()
    return monitor, state


def test_original_birth_and_updates_are_recorded_before_acceptance(case):
    monitor, state = case
    state['queue'] = [packet()]
    birth = monitor.birth('dtp-one', 110)
    assert state['records'][-1] == dict(phase='birth_bound', birth=birth)
    state['queue'] = [packet(name='other', index=111) + packet()]
    proof = monitor.verify(birth)
    assert proof['continuity_verified'] and proof['cursor'] == 3
    assert state['records'][-1]['raw'] == (packet(name='other', index=111) + packet()).hex()
    assert monitor.birth('dtp-one', 110) == birth


@pytest.mark.parametrize('event', [packet(kind=17), packet(name='renamed'), packet(index=111),
                                  packet(kind=17) + packet()])
def test_delete_rename_or_recreated_identity_is_rejected(case, event):
    monitor, state = case
    state['queue'] = [packet()]
    birth = monitor.birth('dtp-one', 110)
    state['queue'] = [event]
    with pytest.raises(RuntimeErrorBase, match='removed, renamed or replaced'):
        monitor.verify(birth)
    # Draining again never erases the original conflict.
    with pytest.raises(RuntimeErrorBase):
        monitor.verify(birth)


@pytest.mark.parametrize('failure', [OSError(errno.ENOBUFS, 'lost'), packet(kind=4), b'bad'])
def test_loss_or_malformed_event_permanently_poisons_monitor(case, failure):
    monitor, state = case
    state['queue'] = [failure]
    with pytest.raises((OSError, RuntimeErrorBase)):
        monitor.drain()
    assert monitor.poisoned
    with pytest.raises(RuntimeErrorBase, match='lost'):
        monitor.drain()


def test_failed_record_cannot_adopt_consumed_datagram(case):
    monitor, state = case
    state['queue'] = [packet()]
    state['failure'] = 'events'
    with pytest.raises(OSError, match='record failure'):
        monitor.birth('dtp-one', 110)
    assert not monitor.events and monitor.poisoned
    state['failure'] = None
    with pytest.raises(RuntimeErrorBase):
        monitor.birth('dtp-one', 110)


@pytest.mark.parametrize('field', ['identity', 'epoch'])
def test_socket_or_runtime_replacement_cannot_receive(case, field):
    monitor, state = case
    state[field] = 11 if field == 'identity' else {'original': 2}
    state['queue'] = [packet()]
    with pytest.raises(RuntimeErrorBase):
        monitor.drain()
    assert len(state['queue']) == 1 and monitor.poisoned


def test_subscription_cannot_reopen_after_close(case):
    monitor, state = case
    monitor.close()
    with pytest.raises(RuntimeErrorBase, match='reopened'):
        monitor.open()
    assert state['closed']


@pytest.mark.parametrize('sender,flags', [((123, 1), 0), ((0, 0), 0),
                                       ((0, 1), socket.MSG_TRUNC), ((0, 1), socket.MSG_CTRUNC)])
def test_incomplete_or_non_kernel_datagrams_rejected(sender, flags):
    with pytest.raises(RuntimeErrorBase, match='complete kernel'):
        decode(packet(), sender, flags)


def test_birth_requires_original_newlink_event(case):
    monitor, state = case
    with pytest.raises(RuntimeErrorBase, match='NEWLINK birth'):
        monitor.birth('dtp-one', 110)
    state['queue'] = [packet(kind=17), packet()]
    with pytest.raises(RuntimeErrorBase, match='NEWLINK birth'):
        monitor.birth('dtp-one', 110)


@pytest.mark.parametrize('deletion', [True, False])
def test_monitored_diagnostic_uses_birth_continuity_and_final_delete(case, deletion):
    # Reuse only synthetic TAP syscalls; exercise the real monitor and wrapper.
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    from test_vm_tap_handoff_probe import Tap
    from vm_tap_handoff_monitor_probe import monitored_handoff, ProbeError
    monitor, state = case
    monitor.close()
    # The fixture opened the original socket. This wrapper needs a NEW monitor,
    # not a reopen of that subscription.
    monitor = TapLinkEvents(monitor.context, runtime=monitor.runtime, read_context=monitor.read_context,
                           record=monitor.record, socket_factory=monitor.socket_factory,
                           descriptor=monitor.descriptor)
    class ObservedTap(Tap):
        def attach(self, fd, exclusive=False):
            super().attach(fd, exclusive)
            state['queue'].append(packet())
        def capture(self, fd):
            super().capture(fd)
            return dict(name='dtp-one', ifindex=110, namespace=[4, 123], flags=0x1002)
        def close(self, fd):
            existed = self.exists
            super().close(fd)
            if existed and not self.exists and deletion:
                state['queue'].append(packet(kind=17))
    tap, events = ObservedTap(), []
    def save(phase, **proof):
        events.append(dict(phase=phase, **deepcopy(proof)))
    if deletion:
        monitored_handoff(tap, monitor, save)
        assert events[-2]['phase'] == 'monitor_deletion_observed'
        assert events[-1]['phase'] == 'completed'
        assert len([e for e in events if e['phase'] == 'monitor_continuity']) == 5
    else:
        with pytest.raises(ProbeError, match='deletion event missing'):
            monitored_handoff(tap, monitor, save)
        assert not any(e['phase'] == 'completed' for e in events)
    assert monitor.poisoned and not tap.live
