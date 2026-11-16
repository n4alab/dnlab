"""Original service exclusion/recovery with inert command and state providers."""
from copy import deepcopy
import uuid

import pytest

from dnlab_runtime.image_build_hold import ImageBuildHold, NO_RESTART
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def hold(tmp_path):
    journal = Journal(tmp_path/'journal')
    original = dict(container_id='a'*64,image_id='sha256:'+'b'*64,config_sha256='c'*64,
                    artifact_sha256='d'*64,context_sha256='e'*64,process_sha256='f'*64)
    policy = dict(Name='unless-stopped',MaximumRetryCount=0)
    state = dict(actor=deepcopy(original),policy=deepcopy(policy),running=True,idle=True,aligned=True,
                 window=True,cleanup=False,workers={},dispatches=[],lost_arm=False,lost_release=None,
                 outcome_missing=False,after_release=None)
    operation = '1'*32
    scope = {key:key for key in ('gate_id','lab_id','host_id','coordinator_id','boot_id','window_id')}
    scope['boot_id'] = 'synthetic'
    def observe(value):return dict(actor=deepcopy(state['actor']),restart_policy=deepcopy(state['policy']),
        running=state['running'],idle=state['idle'],binding_aligned=state['aligned'],binding_sha256='2'*64,jobs_sha256='3'*64)
    def cleanup(value):return dict(scope_sha256=fingerprint(scope),resources_absent=state['cleanup'],
                                  pending_operations=0,receipt_sha256='4'*64)
    class Commands:
        def arm(self,command):
            reference = dict(token=uuid.uuid4().hex,command_sha256=fingerprint(command),process_record=dict(
                boot_id='synthetic',pid=123,start_ticks=456,uid=0,gid=0,executable_sha256='5'*64,namespace_sha256='6'*64))
            state['workers'][reference['token']] = dict(command=deepcopy(command),reference=reference,phase='armed',outcome=None)
            if state['lost_arm']:state['lost_arm']=False;raise OSError('lost original arm reply')
            return deepcopy(reference)
        def original_reference(self,command):
            rows = [worker['reference'] for worker in state['workers'].values() if worker['command']==command]
            assert len(rows)<=1
            return deepcopy(rows[0]) if rows else None
        def verify(self,reference,command):
            worker = state['workers'][reference['token']]
            return worker['phase']=='armed' and worker['reference']==reference and worker['command']==command
        def release(self,reference):
            worker = state['workers'][reference['token']];assert worker['phase']=='armed'
            command = worker['command'];action = command['action'];state['dispatches'].append(action)
            evidence = dict(policy_verified=True)
            if action=='disable_restart':state['policy'] = deepcopy(NO_RESTART)
            elif action=='stop':
                state['running'] = False
                evidence = dict(process_sha256=original['process_sha256'],pidfd_exit_verified=True,
                    ordinary_shutdown_verified=True,drain_verified=True,term_count=1,force_used=False,exit_code=143)
            elif action=='start':
                state['running'] = True;state['actor']['process_sha256'] = '7'*64
                evidence = dict(actor=deepcopy(state['actor']),original_start_verified=True)
            else:state['policy'] = deepcopy(policy)
            worker.update(phase='completed',outcome=dict(reference=deepcopy(reference),command_sha256=fingerprint(command),
                          dispatch_count=1,evidence=evidence))
            if state['after_release']:state['after_release'](action,worker)
            if state['lost_release']==action:state['lost_release']=None;raise OSError('lost original dispatch reply')
        def outcome(self,reference):
            if state['outcome_missing']:return None
            return deepcopy(state['workers'][reference['token']]['outcome'])
    commands = Commands()
    def make():return ImageBuildHold(journal,observe=observe,commands=commands,
        window=lambda value:dict(active=state['window'],scope_sha256=fingerprint(scope)),cleanup=cleanup)
    driver = make();driver.prepare(operation,scope=scope,original_actor=original,restart_policy=policy,
                                  binding_sha256='2'*64,jobs_sha256='3'*64)
    yield driver,operation,state,make
    journal.close()


def test_acquire_and_restore_same_container_only_after_verified_cleanup(hold):
    driver,operation,state,make = hold
    proof = driver.acquire(operation);assert proof['held'] is True
    assert make().held(operation)==proof
    with pytest.raises(TemplateError,match='qualified cleanup'):driver.restore(operation)
    assert state['dispatches']==['disable_restart','stop']
    state['cleanup'] = True
    assert make().restore(operation)['phase']=='restored'
    assert state['dispatches']==['disable_restart','stop','start','restore_restart']
    assert make().restore(operation)['phase']=='restored'
    assert driver.journal.db.execute('SELECT 1 FROM resources').fetchone() is None


@pytest.mark.parametrize('action',['disable_restart','stop'])
def test_lost_dispatch_reply_recovers_without_repeating_update_or_term(hold,action):
    driver,operation,state,make = hold;state['lost_release'] = action
    with pytest.raises(OSError,match='lost original dispatch'):driver.acquire(operation)
    assert make().acquire(operation,recover=True)['held'] is True
    assert state['dispatches']==['disable_restart','stop']


def test_lost_arm_reply_recovers_original_worker_only(hold):
    driver,operation,state,make = hold;state['lost_arm'] = True
    with pytest.raises(OSError,match='lost original arm'):driver.acquire(operation)
    first = set(state['workers'])
    assert make().acquire(operation,recover=True)['held'] is True
    assert first<set(state['workers']) and len(state['workers'])==2
    assert state['dispatches']==['disable_restart','stop']


def test_unknown_dispatch_outcome_stays_pending_without_second_term(hold):
    driver,operation,state,make = hold;state['lost_release'] = 'stop'
    with pytest.raises(OSError):driver.acquire(operation)
    state['outcome_missing'] = True
    for _ in range(2):
        with pytest.raises(TemplateError,match='uncertain'):make().acquire(operation,recover=True)
    assert state['dispatches']==['disable_restart','stop']
    assert driver.read(operation)['phase']=='policy_disabled'


@pytest.mark.parametrize('fault',['window','actor','idle','aligned'])
def test_conflict_before_dispatch_preserves_original_intent(hold,fault):
    driver,operation,state,_ = hold
    if fault=='actor':state['actor']['process_sha256']='8'*64
    else:state[fault] = False
    before = driver.journal.db.total_changes
    with pytest.raises(TemplateError):driver.acquire(operation)
    assert not state['dispatches'] and not state['workers']
    assert driver.journal.db.total_changes==before


def test_window_rechecked_after_release_checkpoint_without_sending(hold,monkeypatch):
    driver,operation,state,_ = hold;save = driver._save
    def checkpoint(value):
        save(value)
        if value['actions']['disable_restart']['phase']=='release_requested':state['window']=False
    monkeypatch.setattr(driver,'_save',checkpoint)
    with pytest.raises(TemplateError,match='window'):driver.acquire(operation)
    assert state['dispatches']==[] and len(state['workers'])==1
    assert driver.read(operation)['actions']['disable_restart']['phase']=='release_requested'


def test_shutdown_exit_code_without_drain_never_establishes_hold(hold):
    driver,operation,state,_ = hold
    def fault(action,worker):
        if action=='stop':worker['outcome']['evidence']['drain_verified']=False
    state['after_release'] = fault
    with pytest.raises(TemplateError,match='shutdown/drain'):driver.acquire(operation)
    assert driver.read(operation)['phase']=='policy_disabled'
    assert state['dispatches']==['disable_restart','stop']


def test_new_start_not_aligned_stays_pending_and_is_not_repeated(hold):
    driver,operation,state,make = hold;driver.acquire(operation);state['cleanup']=True
    state['after_release'] = lambda action,worker:state.update(aligned=False) if action=='start' else None
    with pytest.raises(TemplateError):driver.restore(operation)
    with pytest.raises(TemplateError):make().restore(operation,recover=True)
    assert state['dispatches']==['disable_restart','stop','start']


def test_reopen_refuses_impossible_lifecycle_action_order(hold):
    driver,operation,_,make = hold
    value = driver.read(operation);value['phase']='held'
    driver.journal.db.execute('UPDATE image_build_holds SET payload=?,fingerprint=? WHERE id=?',
        (canonical(value),fingerprint(value),operation))
    with pytest.raises(TemplateError,match='lifecycle/action'):make().read(operation)


@pytest.mark.parametrize('action',['start','restore_restart'])
def test_lost_restore_reply_reuses_original_start_and_policy_outcomes(hold,action):
    driver,operation,state,make = hold;driver.acquire(operation)
    state.update(cleanup=True,lost_release=action)
    with pytest.raises(OSError):driver.restore(operation)
    assert make().restore(operation,recover=True)['phase']=='restored'
    assert state['dispatches']==['disable_restart','stop','start','restore_restart']


def test_process_replacement_after_term_checkpoint_blocks_original_signal(hold,monkeypatch):
    driver,operation,state,_ = hold;save = driver._save
    def checkpoint(value):
        save(value)
        if value['actions'].get('stop',{}).get('phase')=='release_requested':state['actor']['process_sha256']='9'*64
    monkeypatch.setattr(driver,'_save',checkpoint)
    with pytest.raises(TemplateError,match='generation'):driver.acquire(operation)
    assert state['dispatches']==['disable_restart']
    assert driver.read(operation)['actions']['stop']['phase']=='release_requested'


def test_cleanup_changed_after_checkpoint_blocks_start(hold,monkeypatch):
    driver,operation,state,_ = hold;driver.acquire(operation);state['cleanup']=True
    save = driver._save
    def checkpoint(value):
        save(value)
        if value['phase']=='cleanup_verified':state['cleanup']=False
    monkeypatch.setattr(driver,'_save',checkpoint)
    with pytest.raises(TemplateError,match='cleanup changed'):driver.restore(operation)
    assert state['dispatches']==['disable_restart','stop']


def test_worker_reference_from_another_boot_cannot_release(hold,monkeypatch):
    driver,operation,state,_ = hold;arm = driver.commands.arm
    def foreign(command):
        reference = arm(command);reference['process_record']['boot_id']='other-boot';return reference
    monkeypatch.setattr(driver.commands,'arm',foreign)
    with pytest.raises(TemplateError,match='worker boot'):driver.acquire(operation)
    assert not state['dispatches']
    assert driver.read(operation)['actions']['disable_restart']['phase']=='arming_requested'
