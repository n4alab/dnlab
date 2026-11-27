"""First release after a parent checkpoint, never a repeated worker release."""
import pytest

from dnlab_runtime.vm_template import TemplateError
from test_image_build_commands import control
from test_vm_runtime_process import runtime_process


def interrupt_parent(control, action, monkeypatch):
    hold, op, state, commands, *_ = control
    if action in ('start', 'restore_restart'):
        hold.acquire(op); state['cleanup'] = True
    save = hold._save
    def checkpoint(value):
        save(value)
        item = value['actions'].get(action)
        if item and item['phase'] == 'release_requested':
            assert commands._read(item['reference'])['phase'] == 'armed'
            raise OSError('after parent release checkpoint')
    monkeypatch.setattr(hold, '_save', checkpoint)
    with pytest.raises(OSError, match='parent release checkpoint'):
        (hold.restore if action in ('start', 'restore_restart') else hold.acquire)(op)
    monkeypatch.setattr(hold, '_save', save)
    reference = hold.read(op)['actions'][action]['reference']
    assert action not in state['dispatches']
    assert commands._read(reference)['phase'] == 'armed'
    return reference


@pytest.mark.parametrize('action', ['disable_restart', 'stop', 'start', 'restore_restart'])
def test_parent_handoff_recovers_the_first_dispatch_once(control, monkeypatch, action):
    hold, op, state, commands, *_ = control
    reference = interrupt_parent(control, action, monkeypatch)
    run = hold.restore if action in ('start', 'restore_restart') else hold.acquire
    run(op, recover=True)
    assert state['dispatches'].count(action) == 1
    assert commands._read(reference)['phase'] == 'completed'
    assert commands.resume_unreleased(reference) is False
    assert state['dispatches'].count(action) == 1


def test_current_preflight_blocks_first_release_after_parent_checkpoint(control, monkeypatch):
    hold, op, state, commands, *_ = control
    reference = interrupt_parent(control, 'stop', monkeypatch)
    state['window'] = False
    with pytest.raises(TemplateError): hold.acquire(op, recover=True)
    assert commands._read(reference)['phase'] == 'armed'
    assert state['dispatches'] == ['disable_restart']


def test_lower_release_request_never_allows_another_dispatch(control, monkeypatch):
    hold, op, state, commands, *_ = control
    state['failure'] = 'stop'
    with pytest.raises(OSError): hold.acquire(op)
    reference = hold.read(op)['actions']['stop']['reference']
    assert commands._read(reference)['phase'] == 'release_requested'
    assert commands.resume_unreleased(reference) is False
    with pytest.raises(TemplateError, match='uncertain'): hold.acquire(op, recover=True)
    assert state['dispatches'] == ['disable_restart', 'stop']
