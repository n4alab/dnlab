"""Atomic original-claim retirement on synthetic runtime journals."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_admin_original import original_state, retire_original
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def original(executor):
    hold,operation,state,_,commands,_=executor
    hold.acquire(operation);state.update(cleanup=True,fault='start_lost')
    with pytest.raises(OSError,match='lost start ACK'):hold.restore(operation)
    start=hold.read(operation)['actions']['start']['reference']['token']
    epoch=commands.runtime.check()
    args=dict(hold_id=operation,start_id=start,epoch=epoch)
    proof=original_state(hold.journal.db,**args)
    request=dict(id='7'*32,nonce='8'*32,original_sha256=fingerprint(proof),
        owner_sha256=fingerprint(epoch['snapshot']),service_sha256='9'*64,
        restart_policy=dict(Name='unless-stopped',MaximumRetryCount=0))
    exited=dict(owner_sha256=request['owner_sha256'],pidfd_exit_verified=True,term_count=1,force_used=False)
    return hold,commands,args,proof,request,exited


def test_original_state_only_reads_and_binds_unknown_start(original):
    hold,_,args,proof,_,_=original;before=hold.journal.db.total_changes
    assert original_state(hold.journal.db,**args)==proof
    assert hold.journal.db.total_changes==before
    assert proof['commands'][-1]['phase']=='release_requested'
    assert proof['commands'][-1]['outcome'] is None


def test_retirement_preserves_original_rows_and_invalidates_references(original):
    hold,commands,args,proof,request,exited=original;db=hold.journal.db
    receipt=retire_original(db,request,exited,**args,check=lambda:None)
    assert receipt['old_start_uncertain'] is True and receipt['claim_released'] is True
    assert original_state(db,**args,claim_present=False)==proof
    reference=hold.read(args['hold_id'])['actions']['start']['reference']
    with pytest.raises(TemplateError,match='administratively retired'):commands.outcome(reference)
    assert commands._read(reference,historical=True)==proof['commands'][-1]
    before=db.total_changes
    assert retire_original(db,request,exited,**args,check=lambda:None)==receipt
    assert db.total_changes==before


@pytest.mark.parametrize('fault',['claim','workload','owner','start','epoch'])
def test_original_binding_conflicts_refuse_without_tombstone(original,fault):
    hold,_,args,_,request,exited=original;db=hold.journal.db
    if fault=='claim':db.execute("UPDATE resources SET operation_id=?",('0'*32,))
    elif fault=='workload':
        db.execute('CREATE TABLE vm_definition_intents (id TEXT)');db.execute('INSERT INTO vm_definition_intents VALUES(?)',('foreign',))
    elif fault=='owner':request['owner_sha256']='0'*64;exited['owner_sha256']=request['owner_sha256']
    elif fault=='start':args['start_id']='0'*32
    else:args['epoch']=deepcopy(args['epoch']);args['epoch']['id']='0'*32
    before=db.total_changes
    with pytest.raises(TemplateError):retire_original(db,request,exited,**args,check=lambda:None)
    assert db.total_changes==before
    assert db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone() is None
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0]==1


@pytest.mark.parametrize('boundary',[1,2,3])
def test_preflight_failure_rolls_back_claim_and_tombstone_together(original,boundary):
    hold,_,args,proof,request,exited=original;db=hold.journal.db;calls=[]
    def check():
        calls.append(True)
        if len(calls)==boundary:raise TemplateError('service changed')
    with pytest.raises(TemplateError,match='service changed'):
        retire_original(db,request,exited,**args,check=check)
    assert original_state(db,**args)==proof
    assert db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone() is None


def test_different_retirement_cannot_reuse_existing_tombstone(original):
    hold,_,args,proof,request,exited=original;db=hold.journal.db
    retire_original(db,request,exited,**args,check=lambda:None)
    changed=deepcopy(request);changed['id']='a'*32
    with pytest.raises(TemplateError,match='cannot be replaced'):
        retire_original(db,changed,exited,**args,check=lambda:None)
    assert original_state(db,**args,claim_present=False)==proof
