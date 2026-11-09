import importlib
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def probe(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools'))
    return importlib.import_module('nos_smoke')


def test_namespace_is_restored_when_console_connect_fails(probe, monkeypatch):
    switched, closed = [], []
    monkeypatch.setattr(probe.os, 'open', lambda *args: 99)
    monkeypatch.setattr(probe.os, 'setns', lambda fd, *args: switched.append(fd))
    monkeypatch.setattr(probe.os, 'close', lambda fd: closed.append(fd))
    def fail(*args, **kwargs):
        raise ConnectionRefusedError('fixture')
    monkeypatch.setattr(probe.socket, 'create_connection', fail)
    with pytest.raises(ConnectionRefusedError):
        probe.Console(5000, SimpleNamespace(fd=11))
    assert switched == [11, 99]
    assert closed == [99]


def test_rejected_replacement_console_is_closed_and_retried(probe, monkeypatch):
    clock, attempts, closed = [0.0], [], []
    class FakeConsole:
        def __init__(self, *args):
            self.index = len(attempts)
            attempts.append(self)
        def send(self, **kwargs):
            if self.index == 0:
                raise RuntimeError('console closed')
            return '\r\nRouter#'
        def close(self):
            closed.append(self.index)
    monkeypatch.setattr(probe, 'Console', FakeConsole)
    monkeypatch.setattr(probe.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(probe.time, 'sleep', lambda duration: clock.__setitem__(0, clock[0] + duration))
    console, hello = probe.open_console(5000)
    assert console.index == 1 and hello.endswith('Router#')
    assert closed == [0]


def test_console_reconnect_has_finite_deadline(probe, monkeypatch):
    clock = [0.0]
    def refused(*args):
        raise ConnectionRefusedError('fixture')
    monkeypatch.setattr(probe, 'Console', refused)
    monkeypatch.setattr(probe.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(probe.time, 'sleep', lambda duration: clock.__setitem__(0, clock[0] + duration))
    with pytest.raises(ConnectionRefusedError):
        probe.open_console(5000, timeout=.3)
    assert clock[0] < 1


def guest_fixture():
    return [{'kvm': True, 'nics': [f'e1000,netdev=p{i:02d}' for i in range(17)],
             'netdevs': [f'tap,id=p{i:02d},ifname=tap{i}' for i in range(17)]}]


def test_nos_guest_has_backend_for_every_management_and_data_nic(probe):
    probe.validate_guest(guest_fixture(), 16)


@pytest.mark.parametrize('bad', ['missing', 'duplicate', 'wrong', 'malformed', 'extra', 'reference'])
def test_nos_guest_rejects_incomplete_or_ambiguous_backend_mapping(probe, bad):
    guest = copy.deepcopy(guest_fixture())
    if bad == 'missing':
        guest[0]['netdevs'].pop()
    elif bad == 'duplicate':
        guest[0]['netdevs'][1] = guest[0]['netdevs'][0]
    elif bad == 'wrong':
        guest[0]['netdevs'][1] = 'tap,id=other'
    elif bad == 'malformed':
        guest[0]['netdevs'][1] = 'tap,ifname=tap1'
    elif bad == 'extra':
        guest[0]['netdevs'].append('tap,id=extra')
    else:
        guest[0]['nics'][1] = guest[0]['nics'][0]
    with pytest.raises(RuntimeError, match='backend'):
        probe.validate_guest(guest, 16)


@pytest.mark.parametrize('console,logs,stage', [
    (b'loader>', b'', 'loader_console'),
    (b'rommon 1 >', b'', 'loader_console'),
    (b'\xff\xfb\x01', b'NX-OS loader/ROMMON persisted', 'loader_reported_by_launcher'),
    (b'POAP', b'loader/ROMMON', 'nos_boot_output'),
    (b'', b'', 'unknown'),
])
def test_boot_stage_does_not_conflate_loader_with_nos_output(probe, console, logs, stage):
    assert probe.boot_stage(console, logs) == stage
