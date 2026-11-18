"""Persistent service commands with real journals and synthetic process/I/O."""
from copy import deepcopy

import pytest

from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.image_build_hold import ImageBuildHold, NO_RESTART
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import TemplateError
from test_vm_runtime_process import runtime_process


@pytest.fixture
def control(runtime_process):
    runtime,epoch,_,process,make_runtime=runtime_process
    context=ImageBuildCommands._context(epoch)
    original=dict(container_id='a'*64,image_id='sha256:'+'b'*64,config_sha256='c'*64,
                  artifact_sha256='d'*64,context_sha256=fingerprint(context),process_sha256='f'*64)
    policy=dict(Name='unless-stopped',MaximumRetryCount=0)
    scope={key:key for key in ('gate_id','lab_id','coordinator_id','window_id')}
    scope.update(host_id=context['host_id'],boot_id=context['boot_id'])
    state=dict(actor=deepcopy(original),policy=deepcopy(policy),running=True,cleanup=False,
               window=True,dispatches=[],failure=None)
    drivers={}
    def observe(value):
        return dict(actor=deepcopy(state['actor']),restart_policy=deepcopy(state['policy']),running=state['running'],
                    idle=True,binding_aligned=True,binding_sha256='2'*64,jobs_sha256='3'*64)
    def preflight(command):
        value=drivers['hold'].read(command['operation_id'])
        drivers['hold']._pre(value,command['action'])
        return dict(command_sha256=fingerprint(command),scope_sha256=fingerprint(scope),
                    actor_sha256=fingerprint(command['actor']),window_active=True)
    def execute(command,reference):
        action=command['action'];state['dispatches'].append(action)
        if state['failure']==action:raise OSError('uncertain executor result')
        evidence=dict(policy_verified=True)
        if action=='disable_restart':state['policy']=deepcopy(NO_RESTART)
        elif action=='stop':
            state['running']=False
            evidence=dict(process_sha256=original['process_sha256'],pidfd_exit_verified=True,
                ordinary_shutdown_verified=True,drain_verified=True,term_count=1,force_used=False,exit_code=143)
        elif action=='start':
            state['running']=True;state['actor']['process_sha256']='7'*64
            evidence=dict(actor=deepcopy(state['actor']),original_start_verified=True)
        else:state['policy']=deepcopy(policy)
        return dict(evidence=evidence,details=dict(synthetic=True,action=action))
    def make_commands(witness=runtime):
        return ImageBuildCommands(witness,read_hold=lambda op:drivers['hold'].read(op),preflight=preflight,execute=execute)
    commands=make_commands()
    def make_hold(provider=commands):
        return ImageBuildHold(runtime.journal,observe=observe,commands=provider,
            window=lambda value:dict(active=state['window'],scope_sha256=fingerprint(scope)),
            cleanup=lambda value:dict(scope_sha256=fingerprint(scope),resources_absent=state['cleanup'],
                                     pending_operations=0,receipt_sha256='4'*64))
    driver=make_hold();drivers['hold']=driver;operation='1'*32
    driver.prepare(operation,scope=scope,original_actor=original,restart_policy=policy,
                   binding_sha256='2'*64,jobs_sha256='3'*64)
    return driver,operation,state,commands,make_commands,make_hold,process,make_runtime


def test_persistent_commands_complete_hold_restore_and_read_receipts(control):
    driver,op,state,commands,make_commands,make_hold,_,_=control
    assert driver.acquire(op)['held'] is True
    state['cleanup']=True
    assert make_hold(make_commands()).restore(op)['phase']=='restored'
    assert state['dispatches']==['disable_restart','stop','start','restore_restart']
    for action,item in driver.read(op)['actions'].items():
        assert commands.details(item['reference'])['details']==dict(synthetic=True,action=action)
    assert driver.journal.db.execute('SELECT COUNT(*) FROM image_build_control_commands').fetchone()[0]==4
    assert driver.journal.db.execute('SELECT 1 FROM resources').fetchone() is None


def test_lost_arm_reply_reuses_original_persistent_reference(control,monkeypatch):
    driver,op,state,commands,_,_,_,_=control;arm=commands.arm
    def lost(command):
        arm(command)
        raise OSError('lost arm response')
    monkeypatch.setattr(commands,'arm',lost)
    with pytest.raises(OSError,match='lost arm'):driver.acquire(op)
    row=driver.journal.db.execute('SELECT id FROM image_build_control_commands').fetchone()[0]
    monkeypatch.setattr(commands,'arm',arm)
    assert driver.acquire(op,recover=True)['held'] is True
    assert driver.read(op)['actions']['disable_restart']['reference']['token']==row
    assert state['dispatches']==['disable_restart','stop']


def test_recover_parent_checkpoint_before_first_metadata_arm(control,monkeypatch):
    driver,op,state,commands,_,_,_,_=control;arm=commands.arm
    def before_arm(command):raise OSError('before metadata arm')
    monkeypatch.setattr(commands,'arm',before_arm)
    with pytest.raises(OSError):driver.acquire(op)
    assert driver.journal.db.execute('SELECT 1 FROM image_build_control_commands').fetchone() is None
    monkeypatch.setattr(commands,'arm',arm)
    assert driver.acquire(op,recover=True)['held'] is True
    assert state['dispatches']==['disable_restart','stop']


def test_unknown_execution_never_dispatches_again(control):
    driver,op,state,commands,_,_,_,_=control;state['failure']='stop'
    with pytest.raises(OSError,match='uncertain'):driver.acquire(op)
    item=driver.read(op)['actions']['stop']
    for _ in range(2):
        with pytest.raises(TemplateError,match='uncertain'):driver.acquire(op,recover=True)
        with pytest.raises(TemplateError,match='unreleased'):commands.release(item['reference'])
    assert commands.outcome(item['reference']) is None
    assert state['dispatches']==['disable_restart','stop']


def test_completed_dispatch_lost_response_recovers_without_resending(control,monkeypatch):
    driver,op,state,commands,_,_,_,_=control;release=commands.release
    def lost(reference):
        release(reference)
        raise OSError('lost completed response')
    monkeypatch.setattr(commands,'release',lost)
    with pytest.raises(OSError):driver.acquire(op)
    monkeypatch.setattr(commands,'release',release)
    assert driver.acquire(op,recover=True)['held'] is True
    assert state['dispatches']==['disable_restart','stop']


@pytest.mark.parametrize('fault',['window','runtime'])
def test_recheck_after_producer_dispatch_checkpoint_blocks_execution(control,monkeypatch,fault):
    driver,op,state,commands,_,_,process,_=control;save=commands._save
    def checkpoint(value):
        save(value)
        if value['phase']=='release_requested':
            if fault=='window':state['window']=False
            else:process['snapshot']['record']['start_ticks']+=1
    monkeypatch.setattr(commands,'_save',checkpoint)
    with pytest.raises(Conflict if fault=='runtime' else TemplateError):driver.acquire(op)
    assert state['dispatches']==[]
    assert driver.read(op)['actions']['disable_restart']['phase']=='release_requested'


def test_new_runtime_epoch_cannot_release_old_armed_command(control,monkeypatch):
    driver,op,state,commands,make_commands,_,_,make_runtime=control;arm=commands.arm
    def lost(command):
        arm(command)
        raise OSError('lost arm')
    monkeypatch.setattr(commands,'arm',lost)
    with pytest.raises(OSError):driver.acquire(op)
    item=driver.read(op)['actions']['disable_restart']
    other=make_runtime();other.start();replacement=make_commands(other)
    reference=replacement.original_reference(item['command'])
    with pytest.raises(TemplateError,match='epoch'):replacement.verify(reference,item['command'])
    assert state['dispatches']==[]


def test_completed_receipt_readable_by_qualified_successor_without_execution(control):
    driver,op,state,commands,make_commands,_,_,make_runtime=control
    driver.acquire(op)
    reference=driver.read(op)['actions']['stop']['reference']
    other=make_runtime();other.start();replacement=make_commands(other)
    assert replacement.outcome(reference)==commands.outcome(reference)
    assert state['dispatches']==['disable_restart','stop']


def test_runtime_change_after_execution_preserves_uncertain_result_without_resend(control,monkeypatch):
    driver,op,state,commands,_,_,process,_=control;execute=commands.execute
    def replaced(command,reference):
        result=execute(command,reference)
        process['snapshot']['record']['start_ticks']+=1
        return result
    monkeypatch.setattr(commands,'execute',replaced)
    with pytest.raises(Conflict,match='incarnation'):driver.acquire(op)
    process['snapshot']['record']['start_ticks']-=1
    with pytest.raises(TemplateError,match='uncertain'):driver.acquire(op,recover=True)
    assert state['dispatches']==['disable_restart']
    reference=driver.read(op)['actions']['disable_restart']['reference']
    assert commands.outcome(reference) is None


def test_substituted_reference_cannot_read_completed_receipt(control):
    driver,op,state,commands,_,_,_,_=control;driver.acquire(op)
    original=driver.read(op)['actions']['stop']['reference'];reference=deepcopy(original)
    reference['process_record']['start_ticks']+=1
    with pytest.raises(TemplateError,match='journal differs'):commands.outcome(reference)
    assert commands.outcome(original)['dispatch_count']==1
    assert state['dispatches']==['disable_restart','stop']


def test_retired_arm_cannot_be_verified_or_released_even_by_original_producer(control,monkeypatch):
    driver,op,state,commands,_,_,_,_=control;save=driver._save
    def pause(value):
        save(value)
        if value['actions'].get('stop',{}).get('phase')=='armed':raise OSError('pause before release')
    monkeypatch.setattr(driver,'_save',pause)
    with pytest.raises(OSError):driver.acquire(op)
    item=driver.read(op)['actions']['stop'];original=commands._read(item['reference'])
    commands.journal.db.execute('INSERT INTO image_build_arm_retirements VALUES(?,?,?,?,?)',
        ('a'*32,op,item['reference']['token'],'{}',fingerprint({})))
    with pytest.raises(TemplateError,match='arm retired'):commands.verify(item['reference'],item['command'])
    with pytest.raises(TemplateError,match='arm retired'):commands.release(item['reference'])
    assert commands._read(item['reference'],historical=True)==original
    assert state['dispatches']==['disable_restart']
