"""Known policy ACK survives a later observation race without another update."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from dnlab_runtime.vm_template import TemplateError
from dnlab_runtime.manifest import canonical, fingerprint
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


def pending(executor, action):
    hold,op,state,native,commands,adapter=executor
    if action=='restore_restart':
        hold.acquire(op);state['cleanup']=True
    checkpoint=commands.checkpoint_policy_ack
    def after_ack(reference):
        result=checkpoint(reference)
        if commands._read(reference)['command']['action']==action:native['activity']=False
        return result
    commands.checkpoint_policy_ack=after_ack
    commands.recover_callback=adapter.recover
    with pytest.raises(TemplateError,match='activity'):
        (hold.restore if action=='restore_restart' else hold.acquire)(op)
    reference=hold.read(op)['actions'][action]['reference']
    return reference


@pytest.mark.parametrize('action',['disable_restart','restore_restart'])
def test_known_policy_ack_recovers_from_observation_failure_without_update(executor,action):
    hold,op,state,native,commands,_=executor
    reference=pending(executor,action)
    original=commands.qualified_snapshot(reference)
    assert original['policy_ack']['status']==200
    assert original['outcome'] is None
    native['activity']=True
    if action=='restore_restart':assert hold.restore(op,recover=True)['phase']=='restored'
    else:assert hold.acquire(op,recover=True)['held'] is True
    assert commands.details(reference)['details']['policy_ack']==original['policy_ack']
    assert state['actions'].count('policy')==(2 if action=='restore_restart' else 1)


def test_missing_policy_ack_cannot_be_inferred_from_actual_policy(executor):
    hold,op,state,native,commands,adapter=executor
    hold.acquire(op);state['cleanup']=True
    update=adapter.engine.update_policy
    def unknown(policy):
        update(policy)
        raise OSError('response lost')
    adapter.engine.update_policy=unknown;commands.recover_callback=adapter.recover
    with pytest.raises(OSError):hold.restore(op)
    reference=hold.read(op)['actions']['restore_restart']['reference']
    original=commands.qualified_snapshot(reference);actions=deepcopy(state['actions'])
    assert 'policy_ack' not in original
    with pytest.raises(TemplateError,match='uncertain'):hold.restore(op,recover=True)
    assert commands.qualified_snapshot(reference)==original and state['actions']==actions


@pytest.mark.parametrize('fault',['generation','binding','window','cleanup'])
def test_policy_recovery_rejects_changed_conditions_without_dispatch(executor,fault):
    hold,op,state,native,commands,_=executor
    reference=pending(executor,'restore_restart');original=commands.qualified_snapshot(reference)
    native['activity']=True
    if fault=='generation':native['inspect']['State']['StartedAt']='2026-11-18T09:02:00Z'
    elif fault=='binding':native['binding']['state']='drift'
    else:state[fault]=False
    actions=deepcopy(state['actions'])
    with pytest.raises(TemplateError):hold.restore(op,recover=True)
    assert commands.qualified_snapshot(reference)==original and state['actions']==actions


def test_reopen_rejects_policy_ack_for_another_target(executor):
    _,_,_,_,commands,_=executor
    reference=pending(executor,'restore_restart');value=commands.qualified_snapshot(reference)
    value['policy_ack']['container_id']='0'*64
    commands.journal.db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=? WHERE id=?',
        (canonical(value),fingerprint(value),reference['token']))
    with pytest.raises(TemplateError,match='policy acknowledgement'):commands._read(reference)


def test_acknowledged_policy_is_not_relabelled_as_unknown_by_administration(executor):
    from image_build_policy_retirement import policy_state
    hold,op,_,_,commands,_=executor
    reference=pending(executor,'restore_restart')
    with pytest.raises(TemplateError,match='original pending policy'):
        policy_state(hold.journal.db,hold_id=op,command_id=reference['token'],epoch=commands.runtime.check())
