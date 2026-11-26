"""Known-ACK startup recovery uses the saved generation and never resends."""
from copy import deepcopy

import pytest

from dnlab_runtime.vm_template import TemplateError
from dnlab_runtime.manifest import canonical, fingerprint
from image_build_session import ImageBuildSession
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


def pending_start(executor):
    hold,op,state,native,commands,adapter=executor
    hold.acquire(op);state['cleanup']=True
    start=adapter.engine.start
    def busy():
        start();native['activity']=False
    adapter.engine.start=busy
    with pytest.raises(TemplateError,match='activity'):hold.restore(op)
    reference=hold.read(op)['actions']['start']['reference']
    commands.recover_callback=adapter.recover
    return reference


def test_known_ack_and_first_identity_survive_readiness_failure_and_recover_without_start(executor):
    hold,op,state,native,commands,_=executor
    reference=pending_start(executor)
    original=commands.qualified_snapshot(reference)
    assert original['start_ack']==dict(container_id=native['inspect']['Id'],status=204,empty_body=True)
    assert original['start_progress']['capture']['process']['pid']==45
    assert original['outcome'] is None
    native['activity']=True
    assert hold.restore(op,recover=True)['phase']=='restored'
    assert commands.details(reference)['details']['startup']==original['start_progress']
    assert state['actions']==['policy','term','logs','start','policy']


@pytest.mark.parametrize('fault',['pid','starttime','generation','window','cleanup','binding','activity'])
def test_saved_start_rejects_replacement_or_failed_conditions_without_mutation(executor,fault):
    hold,op,state,native,commands,_=executor
    reference=pending_start(executor);original=commands.qualified_snapshot(reference)
    native['activity']=True
    if fault=='pid':native['inspect']['State']['Pid']=99
    elif fault=='starttime':native['capture']['process']['start_ticks']='999'
    elif fault=='generation':native['inspect']['State']['StartedAt']='2026-11-18T09:02:00Z'
    elif fault=='window':state['window']=False
    elif fault=='cleanup':state['cleanup']=False
    elif fault=='binding':native['binding']['state']='drift'
    else:native['activity']=False
    actions=deepcopy(state['actions'])
    with pytest.raises(TemplateError):hold.restore(op,recover=True)
    assert commands.qualified_snapshot(reference)==original
    assert state['actions']==actions
    assert hold.read(op)['phase']=='cleanup_verified'


@pytest.mark.parametrize('fault',['start_lost','start_304'])
def test_unknown_start_ack_cannot_be_recovered_from_running_service(executor,fault):
    hold,op,state,native,commands,adapter=executor
    hold.acquire(op);state.update(cleanup=True,fault=fault)
    commands.recover_callback=adapter.recover
    with pytest.raises((OSError,TemplateError)):hold.restore(op)
    reference=hold.read(op)['actions']['start']['reference']
    original=commands.qualified_snapshot(reference)
    assert 'start_ack' not in original and 'start_progress' not in original
    assert native['inspect']['State']['Running'] is True
    with pytest.raises(TemplateError,match='uncertain'):hold.restore(op,recover=True)
    assert commands.qualified_snapshot(reference)==original
    assert state['actions'].count('start')==1


def test_ack_without_saved_first_generation_stays_pending(executor,monkeypatch):
    hold,op,state,_,commands,adapter=executor
    hold.acquire(op);state['cleanup']=True;commands.recover_callback=adapter.recover
    def lost(*args,**kwargs):raise OSError('first identity not saved')
    monkeypatch.setattr(adapter.observation,'capture_start',lost)
    with pytest.raises(OSError,match='first identity'):hold.restore(op)
    reference=hold.read(op)['actions']['start']['reference']
    original=commands.qualified_snapshot(reference)
    assert 'start_ack' in original and 'start_progress' not in original
    with pytest.raises(TemplateError,match='uncertain'):hold.restore(op,recover=True)
    assert commands.qualified_snapshot(reference)==original
    assert state['actions'].count('start')==1


def test_first_start_checkpoint_is_immutable(executor):
    _,_,_,_,commands,_=executor;reference=pending_start(executor)
    original=commands.qualified_snapshot(reference);proof=deepcopy(original['start_progress'])
    assert commands.checkpoint_start(reference,proof)==proof
    proof['generation']['started_at']='2026-11-18T09:02:00Z'
    with pytest.raises(TemplateError,match='cannot be replaced'):commands.checkpoint_start(reference,proof)
    assert commands.qualified_snapshot(reference)==original


@pytest.mark.parametrize('field,value',[('status',304),('empty_body',1),('container_id','0'*64)])
def test_invalid_saved_ack_is_rejected_before_recovery_observation(executor,field,value):
    hold,op,state,_,commands,_=executor;reference=pending_start(executor)
    original=commands.qualified_snapshot(reference);original['start_ack'][field]=value
    commands.journal.db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=? WHERE id=?',
        (canonical(original),fingerprint(original),reference['token']))
    actions=deepcopy(state['actions'])
    with pytest.raises(TemplateError,match='acknowledgement'):hold.restore(op,recover=True)
    assert state['actions']==actions


def test_successor_session_recovers_saved_start_with_original_receipt(executor,runtime_process):
    hold,op,state,native,commands,adapter=executor;reference=pending_start(executor)
    original=commands.qualified_snapshot(reference);old=adapter.observation
    runtime=runtime_process[4]();runtime.start();commands.runtime.close();native['activity']=True
    successor=ImageBuildSession(runtime,old.profile,jobs_sha256=native['ledger']['jobs_sha256'],
        api=old.api,read_context=old.context,binding=old.binding,ledger=old.ledger,activity=old.activity,
        window=hold.window,cleanup=hold.cleanup,query=old.query,process=old.process,engine=adapter.engine,term=adapter.term)
    assert successor.restore(op,recover=True)['phase']=='restored'
    recovered=successor.commands.qualified_snapshot(reference)
    assert recovered['reference']==original['reference']
    assert recovered['epoch_id']==original['epoch_id']!=runtime.epoch['id']
    assert recovered['start_progress']==original['start_progress']
    assert state['actions']==['policy','term','logs','start','policy']


def test_lost_checkpoint_reply_recovers_only_the_saved_generation(executor,monkeypatch):
    hold,op,state,_,commands,adapter=executor
    hold.acquire(op);state['cleanup']=True;commands.recover_callback=adapter.recover
    save=commands._save
    def lost(value):
        save(value)
        if 'start_progress' in value:raise OSError('checkpoint reply lost')
    with monkeypatch.context() as patch:
        patch.setattr(commands,'_save',lost)
        with pytest.raises(OSError,match='checkpoint reply lost'):hold.restore(op)
    reference=hold.read(op)['actions']['start']['reference'];original=commands.qualified_snapshot(reference)
    assert hold.restore(op,recover=True)['phase']=='restored'
    assert commands.details(reference)['details']['startup']==original['start_progress']
    assert state['actions'].count('start')==1
