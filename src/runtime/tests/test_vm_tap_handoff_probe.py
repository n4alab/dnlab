"""Diagnostic protocol only: no native TUN/socket/namespace operations."""
from copy import deepcopy
import errno
from pathlib import Path
import sys
import json

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from vm_tap_handoff_probe import handoff, ProbeError
import vm_tap_handoff_probe as probe


class Tap:
    def __init__(self):
        self.live = set()
        self.next_fd = 40
        self.bound = None
        self.exists = False
        self.persistent = False
        self.second_error = errno.EBUSY
        self.change_identity = False
        self.calls = []

    def absent(self):
        return not self.exists

    def open(self):
        self.next_fd += 1
        self.live.add(self.next_fd)
        return self.next_fd

    def attach(self, fd, exclusive=False):
        self.calls.append(('attach', fd, exclusive))
        assert fd in self.live
        if exclusive:
            assert not self.exists
            self.exists = True
        elif self.bound is not None:
            if self.second_error:
                raise OSError(self.second_error, 'synthetic attach refusal')
        else:
            assert self.exists and self.persistent
        self.bound = fd

    def capture(self, fd):
        assert fd == self.bound
        return dict(name='dhp-synthetic', ifindex=12 if self.change_identity and fd == 42 else 11,
                    namespace=[4, 123], flags=0x1002)

    def persist(self, fd, enabled):
        assert fd == self.bound
        self.calls.append(('persist', enabled))
        self.persistent = enabled

    def close(self, fd):
        self.calls.append(('close', fd))
        self.live.remove(fd)
        if fd == self.bound:
            self.bound = None
            if not self.persistent:
                self.exists = False


def test_busy_release_acquire_and_cleanup_are_explicit():
    tap = Tap()
    events = []
    handoff(tap, lambda phase, **proof: events.append(dict(phase=phase, **deepcopy(proof))))
    assert [event['phase'] for event in events] == [
        'create_requested', 'created', 'persist_requested', 'busy_check_requested',
        'busy_observed', 'release_requested', 'creator_released', 'acquire_requested',
        'acquired', 'unpersist_requested', 'completed']
    assert events[1]['birth'] == events[5]['birth'] == events[8]['birth']
    assert events[-1]['cleanup_verified'] and not events[-1]['production_qualified']
    assert not tap.live and not tap.exists
    assert tap.calls == [('attach', 41, True), ('persist', True), ('attach', 42, False),
                         ('close', 41), ('attach', 42, False), ('persist', False), ('close', 42)]


@pytest.mark.parametrize('code', [errno.EPERM, errno.EINVAL])
def test_other_errno_does_not_release_creator(code):
    tap = Tap()
    tap.second_error = code
    with pytest.raises(OSError) as error:
        handoff(tap, lambda *args, **kwargs: None)
    assert error.value.errno == code
    assert ('close', 41) not in tap.calls
    assert tap.bound == 41


def test_unexpected_second_attach_blocks_handoff():
    tap = Tap()
    tap.second_error = None
    with pytest.raises(ProbeError, match='unexpectedly succeeded'):
        handoff(tap, lambda *args, **kwargs: None)
    assert not any(call[0] == 'close' for call in tap.calls)


def test_changed_identity_is_not_adopted_or_unpersisted():
    tap = Tap()
    tap.change_identity = True
    with pytest.raises(ProbeError, match='identity changed'):
        handoff(tap, lambda *args, **kwargs: None)
    assert ('persist', False) not in tap.calls
    assert tap.persistent


@pytest.mark.parametrize('phase', ['create_requested', 'persist_requested', 'release_requested',
                                 'acquire_requested', 'unpersist_requested'])
def test_failed_checkpoint_does_not_perform_its_mutation(phase):
    tap = Tap()
    def save(current, **proof):
        if current == phase:
            raise OSError('synthetic durability failure')
    with pytest.raises(OSError, match='durability'):
        handoff(tap, save)
    forbidden = {'create_requested': ('attach', 41, True),
                 'persist_requested': ('persist', True),
                 'release_requested': ('close', 41),
                 'acquire_requested': ('attach', 42, False),
                 'unpersist_requested': ('persist', False)}
    if phase == 'acquire_requested':
        assert tap.calls.count(forbidden[phase]) == 1  # the earlier, refused attempt
    else:
        assert forbidden[phase] not in tap.calls


def test_existing_name_rejected_without_open_or_mutation():
    tap = Tap()
    tap.exists = True
    with pytest.raises(ProbeError, match='occupied'):
        handoff(tap, lambda *args, **kwargs: None)
    assert not tap.live and not tap.calls


def test_entry_requires_explicit_execution(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    monkeypatch.setattr(sys, 'argv', ['probe', '--output', str(output)])
    with pytest.raises(SystemExit) as error:
        probe.main()
    assert error.value.code == 2 and not output.exists()


def test_unshare_failure_records_cause_without_opening_tun(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    monkeypatch.setattr(sys, 'argv', ['probe', '--execute', '--output', str(output)])
    monkeypatch.setattr(probe, 'namespace', lambda: [4, 100])
    def denied(*args):
        raise PermissionError(errno.EPERM, 'synthetic unshare denial')
    monkeypatch.setattr(probe.os, 'unshare', denied)
    monkeypatch.setattr(probe, 'KernelTap', lambda *args: pytest.fail('TUN opened before isolation'))
    with pytest.raises(PermissionError):
        probe.main()
    files = sorted(output.glob('*.json'))
    assert len(files) == 2
    final = json.loads(files[-1].read_text())['events'][-1]
    assert final['phase'] == 'failed' and final['namespace_destruction_required']


def test_unchanged_namespace_is_rejected_before_tun(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    monkeypatch.setattr(sys, 'argv', ['probe', '--execute', '--output', str(output)])
    monkeypatch.setattr(probe, 'namespace', lambda: [4, 100])
    monkeypatch.setattr(probe.os, 'unshare', lambda *args: None)
    monkeypatch.setattr(probe, 'KernelTap', lambda *args: pytest.fail('TUN opened in host namespace'))
    with pytest.raises(ProbeError, match='fresh isolated'):
        probe.main()
    assert json.loads(sorted(output.glob('*.json'))[-1].read_text())['events'][-1]['phase'] == 'failed'
