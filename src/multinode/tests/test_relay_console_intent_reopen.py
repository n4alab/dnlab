"""Reopen a console workload intent using only temporary files and fake IO."""
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
import relay_console_smoke as fixture


@pytest.fixture
def options(tmp_path, monkeypatch):
    monkeypatch.setattr(fixture, 'Docker', lambda: object())
    return dict(root=tmp_path, lab='drsp-reopen', node='vd1',
        image='sha256:' + 'a' * 64, target={'host': 'master'},
        runtime=SimpleNamespace(expected_journal_id='b' * 32), store=object())


def test_console_workload_reopen_preserves_original_intent(options, monkeypatch):
    original = fixture.ConsoleWorkload(**options)
    original.record.update(phase='running',container_id='c'*64,revision=1)
    original.save()
    before = original.path.read_bytes()
    monkeypatch.setattr(fixture.ConsoleWorkload,'save',lambda self:pytest.fail('reopen attempted write'))
    reopened = fixture.ConsoleWorkload(**options)
    assert original.path.read_bytes() == before
    assert reopened.start == original.start and reopened.record == original.record


@pytest.mark.parametrize('fault',['image','target','journal','source','request'])
def test_conflicts_preserve_original_console_intent(options,fault,monkeypatch):
    original=fixture.ConsoleWorkload(**options)
    if fault=='image':options['image']='sha256:'+'d'*64
    elif fault=='target':options['target']={'host':'worker'}
    elif fault=='journal':options['runtime']=SimpleNamespace(expected_journal_id='e'*32)
    elif fault=='source':monkeypatch.setattr(fixture,'workload_program',lambda nonce:'changed-source')
    else:
        original.record['start']['request_id']='foreign';original.save()
    before=original.path.read_bytes()
    with pytest.raises(RuntimeError,match='original intent differs|source or original request differs'):
        fixture.ConsoleWorkload(**options)
    assert original.path.read_bytes()==before


def test_gate_context_is_bound_only_to_new_console_intents(options):
    context=dict(gate_id='gate',lab_id=options['lab'],host_id='master',coordinator_id='master',
                 boot_id='boot',window_id='window',image_build_hold_sha256='f'*64)
    original=fixture.ConsoleWorkload(**options,gate_context=context)
    assert original.record['phase']=='planned' and original.record['gate_context']==context
    before=original.path.read_bytes()
    assert fixture.ConsoleWorkload(**options,gate_context=context).record==original.record
    changed=dict(context,window_id='other-window')
    with pytest.raises(ValueError,match='original gate context'):
        fixture.ConsoleWorkload(**options,gate_context=changed)
    assert original.path.read_bytes()==before
    options['node']='vd2'
    legacy=fixture.ConsoleWorkload(**options);before=legacy.path.read_bytes()
    with pytest.raises(ValueError,match='original gate context'):
        fixture.ConsoleWorkload(**options,gate_context=context)
    assert legacy.path.read_bytes()==before
