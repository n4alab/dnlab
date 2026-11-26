"""Only temporary journals and synthetic observations; no native recovery."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))

from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_unreleased_retirement import KIND, OBSERVATION, retire_unreleased, unreleased_state
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def unreleased(executor,monkeypatch):
    hold,operation,state,_,commands,_=executor;pre=hold._pre
    def stop_after_arm(value,action):
        pre(value,action)
        if value['actions'].get(action,{}).get('phase')=='armed':
            raise TemplateError('synthetic conflict before release')
    with monkeypatch.context() as patch:
        patch.setattr(hold,'_pre',stop_after_arm)
        with pytest.raises(TemplateError,match='synthetic conflict'):hold.acquire(operation)
    assert state['actions']==[]
    original=hold.read(operation);reference=original['actions']['disable_restart']['reference']
    epoch=commands.runtime.check()
    args=dict(hold_id=operation,command_id=reference['token'],epoch=epoch)
    proof=unreleased_state(hold.journal.db,**args)
    request=dict(kind=KIND,id='7'*32,nonce='8'*32,original_sha256=fingerprint(proof),
        owner_sha256=fingerprint(epoch['snapshot']),context_sha256=fingerprint(ImageBuildCommands._context(epoch)),
        sources_sha256=epoch['profile']['sources_sha256'],
        service_sha256=fingerprint({key:original[key] for key in ('actor','policy','binding_sha256','jobs_sha256')}))
    observed=dict(kind=OBSERVATION,journal_identity=proof['journal_identity'],
        **{key:request[key] for key in ('owner_sha256','context_sha256','sources_sha256','service_sha256')},
        owner_absent=True,execution_lock_held=True)
    return hold,commands,state,args,proof,request,observed


def history(db):
    return {table:[tuple(row) for row in db.execute('SELECT * FROM '+table)]
            for table in ('image_build_holds','image_build_control_commands','vm_runtime_epochs')}


def test_read_only_state_and_atomic_retirement_preserve_all_original_history(unreleased):
    hold,commands,state,args,proof,request,observed=unreleased;db=hold.journal.db
    before=history(db);changes=db.total_changes
    assert unreleased_state(db,**args)==proof and db.total_changes==changes
    receipt=retire_unreleased(db,request,**args,observe=lambda:deepcopy(observed))
    assert receipt['command_never_released'] is True and receipt['claim_released'] is True
    assert receipt['shutdown_claimed'] is receipt['start_claimed'] is False
    assert receipt['service_actions_performed']==0
    assert history(db)==before and unreleased_state(db,**args,claim_present=False)==proof
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0]==0
    reference=proof['command']['reference']
    with pytest.raises(TemplateError,match='administratively retired'):commands.release(reference)
    with pytest.raises(TemplateError,match='exclusive image-build control claim'):hold.acquire(args['hold_id'],recover=True)
    assert commands._read(reference,historical=True)==proof['command']
    assert state['actions']==[]


def test_reopen_after_lost_response_reads_same_retirement_without_writes(unreleased):
    hold,_,state,args,proof,request,observed=unreleased;db=hold.journal.db
    receipt=retire_unreleased(db,request,**args,observe=lambda:deepcopy(observed))
    path=db.execute('PRAGMA database_list').fetchone()[2]
    with sqlite3.connect(path,isolation_level=None) as reopened:
        reopened.row_factory=sqlite3.Row;reopened.execute('PRAGMA synchronous=FULL')
        assert retire_unreleased(reopened,request,**args,observe=lambda:deepcopy(observed))==receipt
        assert reopened.total_changes==0
        assert unreleased_state(reopened,**args,claim_present=False)==proof
    assert state['actions']==[]


@pytest.mark.parametrize('fault',['owner_absent','execution_lock_held','context_sha256','owner_sha256',
                                'sources_sha256','service_sha256','journal_identity','kind','missing','extra','typed'])
def test_missing_or_changed_observation_keeps_claim_and_no_tombstone(unreleased,fault):
    hold,_,state,args,_,request,observed=unreleased;db=hold.journal.db;before=history(db)
    if fault=='missing':observed.pop('owner_absent')
    elif fault=='extra':observed['pidfd_exit_verified']=True
    elif fault=='typed':observed['owner_absent']=1
    elif fault in ('owner_absent','execution_lock_held'):observed[fault]=False
    else:observed[fault]='foreign'
    with pytest.raises(TemplateError,match='qualified producer absence'):
        retire_unreleased(db,request,**args,observe=lambda:deepcopy(observed))
    assert history(db)==before and db.execute('SELECT COUNT(*) FROM resources').fetchone()[0]==1
    assert db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone() is None
    assert state['actions']==[]


@pytest.mark.parametrize('boundary',[1,2,3])
def test_conflicts_at_each_observation_roll_back_metadata_together(unreleased,boundary):
    hold,_,state,args,proof,request,observed=unreleased;db=hold.journal.db;calls=[]
    def observe():
        calls.append(True)
        if len(calls)==boundary:raise TemplateError('synthetic observation conflict')
        return deepcopy(observed)
    with pytest.raises(TemplateError,match='synthetic observation conflict'):
        retire_unreleased(db,request,**args,observe=observe)
    assert unreleased_state(db,**args)==proof
    assert db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone() is None
    assert state['actions']==[]


@pytest.mark.parametrize('fault',['upper_release','lower_release','dispatch','start_ack','foreign_claim',
                                'vm_intent','worker','unknown_record','epoch'])
def test_dispatched_or_foreign_state_is_never_retired(unreleased,fault):
    hold,_,state,args,_,request,observed=unreleased;db=hold.journal.db
    if fault=='upper_release':
        value=hold.read(args['hold_id']);value['actions']['disable_restart']['phase']='release_requested';hold._save(value)
    elif fault in ('lower_release','dispatch','start_ack'):
        row=db.execute('SELECT payload FROM image_build_control_commands').fetchone();value=json.loads(row[0])
        if fault=='lower_release':value['phase']='release_requested'
        elif fault=='dispatch':value['phase']='release_requested';value['native_dispatch_started']=True
        else:value['start_ack']={}
        db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=?',(canonical(value),fingerprint(value)))
    elif fault=='foreign_claim':db.execute('UPDATE resources SET operation_id=?',('0'*32,))
    elif fault=='epoch':args['epoch']=deepcopy(args['epoch']);args['epoch']['id']='0'*32
    else:
        table={'vm_intent':'vm_definition_intents','worker':'libvirt_account_processes','unknown_record':'foreign_activity'}[fault]
        db.execute('CREATE TABLE '+table+' (id TEXT)');db.execute('INSERT INTO '+table+' VALUES (?)',('foreign',))
    before=history(db)
    with pytest.raises(TemplateError):retire_unreleased(db,request,**args,observe=lambda:deepcopy(observed))
    assert history(db)==before and db.execute('SELECT COUNT(*) FROM resources').fetchone()[0]==1
    assert state['actions']==[]


def test_changed_request_or_receipt_cannot_replace_original_retirement(unreleased):
    hold,_,state,args,_,request,observed=unreleased;db=hold.journal.db
    retire_unreleased(db,request,**args,observe=lambda:deepcopy(observed))
    before=[tuple(row) for row in db.execute('SELECT * FROM image_build_administrative_retirements')]
    changed=deepcopy(request);changed['nonce']='9'*32
    with pytest.raises(TemplateError,match='cannot be replaced'):
        retire_unreleased(db,changed,**args,observe=lambda:deepcopy(observed))
    assert [tuple(row) for row in db.execute('SELECT * FROM image_build_administrative_retirements')]==before
    assert state['actions']==[]


@pytest.mark.parametrize('key',['original_sha256','owner_sha256','context_sha256','sources_sha256','service_sha256'])
def test_request_must_bind_all_original_proofs(unreleased,key):
    hold,_,state,args,proof,request,observed=unreleased;db=hold.journal.db
    request[key]='0'*64
    with pytest.raises(TemplateError,match='original administrative bindings differ'):
        retire_unreleased(db,request,**args,observe=lambda:deepcopy(observed))
    assert unreleased_state(db,**args)==proof and state['actions']==[]


def test_observer_cannot_mutate_the_captured_retirement_intent(unreleased):
    hold,_,_,args,_,request,observed=unreleased;db=hold.journal.db;original=deepcopy(request)
    def observe():
        request['id']='0'*32;request['nonce']='0'*32
        args['epoch']['id']='0'*32
        return deepcopy(observed)
    receipt=retire_unreleased(db,request,**args,observe=observe)
    saved=json.loads(db.execute('SELECT payload FROM image_build_administrative_retirements').fetchone()[0])
    assert saved['request']==original and receipt['recovery_id']==original['id']
