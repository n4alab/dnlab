"""Original pidfd checkpoints and observation-only completion after log failure."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_session import ImageBuildSession
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import TemplateError
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


def fail_logs(case):
    hold,op,state,_,commands,adapter=case;state['fault']='logs'
    with pytest.raises(TemplateError,match='truncated'):hold.acquire(op)
    item=hold.read(op)['actions']['stop']
    return hold,op,state,commands,adapter,item['reference']


def test_original_exit_survives_log_failure_and_recovery_only_reads(executor):
    hold,op,state,commands,adapter,reference=fail_logs(executor)
    saved=commands._read(reference)
    assert saved['exit_progress']['pidfd']['pidfd_exit_verified'] is True
    assert saved['phase']=='release_requested' and commands.outcome(reference) is None
    commands.recover_callback=adapter.recover_stop;state['fault']=None
    assert hold.acquire(op,recover=True)['held'] is True
    assert state['actions']==['policy','term','logs','logs']
    assert commands._read(reference)['exit_progress']==saved['exit_progress']
    assert commands.recover_outcome(reference)==commands.outcome(reference)
    assert state['actions']==['policy','term','logs','logs']


def test_same_checkpoint_is_idempotent_and_a_different_proof_cannot_replace_it(executor):
    _,_,_,commands,_,reference=fail_logs(executor)
    original=commands._read(reference)['exit_progress'];before=commands.journal.db.total_changes
    assert commands.checkpoint_exit(reference,original['pidfd'])==original
    assert commands.journal.db.total_changes==before
    changed=deepcopy(original['pidfd']);changed['namespace_pid']+=1
    with pytest.raises(TemplateError,match='cannot be replaced'):commands.checkpoint_exit(reference,changed)
    assert commands._read(reference)['exit_progress']==original


def test_missing_exit_event_does_not_learn_a_proof_from_exited_docker_state(executor):
    hold,op,state,_,commands,adapter=executor
    def lost():raise OSError('TERM event result unavailable')
    state['after_term']=lost;commands.recover_callback=adapter.recover_stop
    with pytest.raises(OSError):hold.acquire(op)
    reference=hold.read(op)['actions']['stop']['reference']
    assert 'exit_progress' not in commands._read(reference)
    with pytest.raises(TemplateError,match='uncertain'):hold.acquire(op,recover=True)
    assert state['actions']==['policy','term']


def test_qualified_successor_observes_original_exit_without_adopting_old_release(executor,runtime_process):
    hold,op,state,commands,adapter,reference=fail_logs(executor);saved=commands._read(reference)
    old=adapter.observation;runtime=runtime_process[4]();runtime.start();state['fault']=None
    commands.runtime.close()
    successor=ImageBuildSession(runtime,old.profile,jobs_sha256=executor[3]['ledger']['jobs_sha256'],
        api=old.api,read_context=old.context,binding=old.binding,ledger=old.ledger,activity=old.activity,
        window=hold.window,cleanup=hold.cleanup,query=old.query,process=old.process,engine=adapter.engine,term=adapter.term)
    assert successor.acquire(op,recover=True)['held'] is True
    recovered=successor.commands._read(reference)
    assert recovered['epoch_id']==saved['epoch_id']!=runtime.epoch['id']
    assert recovered['reference']==saved['reference'] and recovered['exit_progress']==saved['exit_progress']
    assert state['actions']==['policy','term','logs','logs']


def test_missing_claim_blocks_observational_completion_before_log_query(executor):
    hold,op,state,commands,adapter,reference=fail_logs(executor)
    commands.recover_callback=adapter.recover_stop;state['fault']=None
    commands.journal.db.execute('DELETE FROM resources')
    with pytest.raises(TemplateError,match='claim'):hold.acquire(op,recover=True)
    assert state['actions']==['policy','term','logs'] and commands.outcome(reference) is None


def test_invalid_saved_pidfd_event_is_refused_before_recovery_io(executor):
    hold,op,state,commands,adapter,reference=fail_logs(executor)
    commands.recover_callback=adapter.recover_stop
    value=commands._read(reference);value['exit_progress']['pidfd']['namespace_pid']=True
    commands.journal.db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=? WHERE id=?',
                               (canonical(value),fingerprint(value),reference['token']))
    with pytest.raises(TemplateError,match='single TERM'):hold.acquire(op,recover=True)
    assert state['actions']==['policy','term','logs']
