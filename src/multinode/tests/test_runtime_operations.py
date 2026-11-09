import copy
import json
import multiprocessing
import os
import signal

import pytest

from dnlab_multinode.services.runtime_operations import OperationDriver,OperationStore,RuntimeOperationError

JOURNAL='a'*32
TARGET={'host':'master','socket_path':'/run/dnlab-runtime/runtime.sock','container_name':'runtime-fixture'}
REQUEST={'schema_version':1,'lab_id':'lab','node_id':'a','request_id':'start-a','action':'start','expected_revision':0,
         'spec':{'kind':'linux','image':'sha256:'+'b'*64,'container_name':'vd-a','env':{'TOKEN':'fixture-private-manifest'}}}


class Client:
    def __init__(self):self.journal=JOURNAL;self.remote={};self.calls=[];self.lose_ack=False;self.on_submit=None
    def bound_to(self,journal_id):return self
    def qualify_node(self,**kwargs):self.calls.append('qualify');return {'journal_id':self.journal}
    def plan_node(self,request):
        self.calls.append('plan');return {'mutations_performed':False,'affected_nodes':[request['node_id']],'expected_revision':request['expected_revision']}
    def find_node_request(self,request,**kwargs):self.calls.append('lookup');return copy.deepcopy(self.remote.get(request['request_id']))
    def submit_node(self,request):
        self.calls.append('submit')
        value=self.remote.setdefault(request['request_id'],{'id':'1'*32,'lab':request['lab_id'],'node':request['node_id'],
            'request_id':request['request_id'],'phase':'queued','error':'','cancel_requested':False})
        if self.on_submit:self.on_submit()
        if self.lose_ack:self.lose_ack=False;raise RuntimeError('fixture-private-manifest')
        return copy.deepcopy(value)
    def cancel_node_request(self,request):
        self.calls.append('cancel')
        value=self.remote.setdefault(request['request_id'],{'id':'2'*32,'lab':request['lab_id'],'node':request['node_id'],
            'request_id':request['request_id'],'phase':'cancelled','error':''})
        value['cancel_requested']=True;return copy.deepcopy(value)
    def node_operation(self,identity):
        self.calls.append('status');return copy.deepcopy(next(v for v in self.remote.values() if v['id']==identity))


@pytest.fixture
def fixture(tmp_path):
    store=OperationStore(tmp_path/'private');client=Client();driver=OperationDriver(store,lambda target:client)
    yield store,client,driver
    store.close()


def test_prepare_is_durable_before_mutation_and_public_summary_has_no_manifest(fixture):
    store,client,driver=fixture
    value=driver.prepare(REQUEST,TARGET)
    assert value['phase']=='prepared' and client.calls==['qualify','plan']
    assert 'fixture-private-manifest' not in json.dumps(value) and 'request' not in value
    assert store.get('lab','start-a',private=True)['request']==REQUEST
    assert store.directory.stat().st_mode & 0o777==0o700
    assert (store.directory/'operations.sqlite3').stat().st_mode & 0o777==0o600
    assert store.pending()==[('lab','start-a')]


def test_lost_ack_recovers_existing_id_in_fresh_driver_without_resubmit(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);client.lose_ack=True
    with pytest.raises(RuntimeError):driver.advance('lab','start-a')
    assert store.get('lab','start-a')['phase']=='submit_unknown'
    assert 'fixture-private-manifest' not in store.get('lab','start-a')['error']
    fresh=OperationDriver(store,lambda target:client)
    assert fresh.advance('lab','start-a')['operation_id']=='1'*32
    assert client.calls.count('submit')==1


def test_cancel_before_first_submit_uses_request_seal(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET)
    store.request_cancel('lab','start-a');value=driver.advance('lab','start-a')
    assert value['phase']=='cancelled' and value['cancel_requested']
    assert 'submit' not in client.calls and client.calls.count('cancel')==1
    assert store.pending()==[]


def test_cancel_during_submit_cannot_be_overwritten_by_ack(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET)
    client.on_submit=lambda:store.request_cancel('lab','start-a')
    value=driver.advance('lab','start-a')
    assert value['cancel_requested'] and value['receipt']['cancel_requested']
    assert client.calls.count('submit')==1 and client.calls.count('cancel')==1


def test_journal_replacement_refuses_before_lookup_submit_or_cancel(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);client.journal='c'*32;before=list(client.calls)
    with pytest.raises(RuntimeOperationError,match='journal identity'):driver.advance('lab','start-a')
    assert client.calls==before+['qualify'] and store.get('lab','start-a')['phase']=='prepared'
    assert store.pending()==[('lab','start-a')]


def test_request_target_and_body_are_immutable(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET)
    with pytest.raises(RuntimeOperationError,match='identity'):
        store.prepare(REQUEST,{**TARGET,'host':'worker'},JOURNAL)
    changed=copy.deepcopy(REQUEST);changed['spec']['env']['TOKEN']='other'
    with pytest.raises(RuntimeOperationError,match='identity'):store.prepare(changed,TARGET,JOURNAL)
    with pytest.raises(RuntimeOperationError,match='unfinished'):
        store.prepare({**REQUEST,'request_id':'another'},TARGET,JOURNAL)


def test_completed_receipt_is_idempotent_and_filtered(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);driver.advance('lab','start-a')
    client.remote['start-a'].update(phase='completed',payload=REQUEST)
    value=driver.advance('lab','start-a');before=list(client.calls)
    assert value['phase']=='completed' and 'fixture-private-manifest' not in json.dumps(value)
    assert driver.advance('lab','start-a')==value and client.calls==before
    assert driver.prepare(REQUEST,TARGET)['phase']=='completed'


def test_recovery_required_is_retained_without_implicit_reconcile(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);driver.advance('lab','start-a')
    client.remote['start-a']['phase']='recovery_required'
    assert driver.advance('lab','start-a')['phase']=='recovery_required'
    assert store.pending()==[('lab','start-a')]
    with pytest.raises(RuntimeOperationError,match='unfinished'):
        store.prepare({**REQUEST,'request_id':'next'},TARGET,JOURNAL)
    assert 'submit'==next(c for c in client.calls if c=='submit') and client.calls.count('submit')==1


def test_process_death_after_intent_reopens_durable_request(tmp_path):
    directory=tmp_path/'private';context=multiprocessing.get_context('fork')
    def child():
        store=OperationStore(directory);store.prepare(REQUEST,TARGET,JOURNAL);os.kill(os.getpid(),signal.SIGKILL)
    process=context.Process(target=child);process.start();process.join(5)
    if process.is_alive():process.kill();process.join();pytest.fail('coordinator worker timeout')
    assert process.exitcode==-signal.SIGKILL
    store=OperationStore(directory)
    try:
        assert store.get('lab','start-a',private=True)['request']==REQUEST
        store.request_cancel('lab','start-a');client=Client()
        assert OperationDriver(store,lambda target:client).advance('lab','start-a')['phase']=='cancelled'
    finally:store.close()


def test_mutation_cannot_run_if_intent_persistence_fails(fixture,monkeypatch):
    store,client,driver=fixture
    def fail():raise OSError('fixture disk full')
    monkeypatch.setattr(store,'sync_directory',fail)
    with pytest.raises(OSError):driver.prepare(REQUEST,TARGET)
    assert 'submit' not in client.calls and 'cancel' not in client.calls


def test_tampered_private_intent_refuses_before_remote_calls(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);before=list(client.calls)
    store.db.execute('UPDATE operations SET request=?',(json.dumps({**REQUEST,'request_id':'other'}),))
    with pytest.raises(RuntimeOperationError,match='integrity'):driver.advance('lab','start-a')
    assert client.calls==before


def test_cancel_flag_is_writable_while_execution_lock_is_held(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET)
    with store.executing('lab','start-a'):
        assert store.request_cancel('lab','start-a')['cancel_requested']
        with pytest.raises(RuntimeOperationError,match='executing'):
            with store.executing('lab','start-a'):pass
    assert driver.advance('lab','start-a')['phase']=='cancelled'


def test_missing_known_remote_operation_never_resubmits(fixture):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);first=driver.advance('lab','start-a')
    client.remote.clear()
    with pytest.raises(StopIteration):driver.advance('lab','start-a')
    assert client.calls.count('submit')==1
    assert store.get('lab','start-a')['operation_id']==first['operation_id']
    assert store.pending()==[('lab','start-a')]


def test_stop_stage_intent_survives_lost_ack_and_requires_verified_phase(fixture):
    store,client,driver=fixture
    request={k:v for k,v in REQUEST.items() if k!='spec'}
    request.update(action='stop',stop_mode='coordinated')
    driver.prepare(request,TARGET);driver.advance('lab','start-a')
    with pytest.raises(RuntimeOperationError):store.request_stop_stage('lab','start-a','cleanup')
    client.remote['start-a'].update(phase='awaiting_link_cleanup',stop_stage='exit_verified',shutdown_verified=True)
    driver.advance('lab','start-a')
    store.request_stop_stage('lab','start-a','cleanup')
    calls=[]

    def stage(identity,lab,node,value):
        calls.append(value)
        assert store.get(lab,'start-a')['stop_requested_stage']==value
        client.remote['start-a'].update(phase='awaiting_finalization',stop_stage='links_cleaned')
        if len(calls)==1:raise OSError('fixture lost stage acknowledgement')
        return copy.deepcopy(client.remote['start-a'])

    client.node_stop_stage=stage
    with pytest.raises(OSError):driver.advance('lab','start-a')
    fresh=OperationDriver(store,lambda target:client)
    assert fresh.advance('lab','start-a')['phase']=='awaiting_finalization'
    assert client.calls.count('submit')==1 and calls==['cleanup','cleanup']
    store.request_stop_stage('lab','start-a','finalize')
    assert store.get('lab','start-a')['stop_requested_stage']=='finalize'
    store.request_stop_stage('lab','start-a','cleanup')
    assert store.get('lab','start-a')['stop_requested_stage']=='finalize'


def test_failed_directory_sync_blocks_remote_action_on_preexisting_intent(fixture,monkeypatch):
    store,client,driver=fixture;driver.prepare(REQUEST,TARGET);before=list(client.calls)
    monkeypatch.setattr(store,'sync_directory',lambda:(_ for _ in ()).throw(OSError('directory sync unavailable')))
    with pytest.raises(OSError):driver.advance('lab','start-a')
    assert client.calls==before


MANAGEMENT_PREFLIGHT='read-only management proof; request-bound apply and recovery before allocation'


class ManagedClient(Client):
    def __init__(self):super().__init__();self.network_id='original';self.submitted=[];self.bad_proof=None
    def qualify_node(self,**kwargs):
        self.calls.append('qualify');return {'journal_id':self.journal,'management_preflight':MANAGEMENT_PREFLIGHT}
    def plan_node(self,request):
        from dnlab_multinode.services.runtime_operations import digest
        result=super().plan_node(request)
        proof={'journal_id':self.journal,'request_fingerprint':digest({k:v for k,v in request.items() if k!='management_preflight'}),
               'management':request['spec']['management'],'network':{'Id':self.network_id,'Name':'mgmt'}}
        if self.bad_proof:self.bad_proof(proof)
        return {**result,'management_preflight':proof}
    def submit_node(self,request):self.submitted.append(copy.deepcopy(request));return super().submit_node(request)


def test_management_prepare_persists_observation_and_retry_never_replans(tmp_path):
    from dnlab_multinode.services.runtime_operations import digest
    store=OperationStore(tmp_path/'private');client=ManagedClient();driver=OperationDriver(store,lambda target:client)
    request={**REQUEST,'spec':{**REQUEST['spec'],'management':{'network':'mgmt','ipv4':'192.0.2.2'}}}
    try:
        public=driver.prepare(request,TARGET);original=store.get('lab','start-a',private=True)['request']
        assert 'management_preflight' not in request and 'management_preflight' not in json.dumps(public)
        assert original['management_preflight']['network']['Id']=='original'
        assert original['management_preflight']['request_fingerprint']==digest(request)
        client.network_id='replacement'
        driver.prepare(request,TARGET);assert client.calls.count('plan')==1
        driver.advance('lab','start-a');assert client.submitted==[original]
        forged={**original,'management_preflight':{**original['management_preflight'],'network':{'Id':'replacement','Name':'mgmt'}}}
        with pytest.raises(RuntimeOperationError,match='request identity'):driver.prepare(forged,TARGET)
    finally:store.close()


@pytest.mark.parametrize('change',['journal','request','missing','capability'])
def test_management_bad_preflight_never_creates_coordinator_intent(tmp_path,change):
    store=OperationStore(tmp_path/'private');client=ManagedClient();driver=OperationDriver(store,lambda target:client)
    request={**REQUEST,'spec':{**REQUEST['spec'],'management':{'network':'mgmt'}}}
    if change=='journal':client.bad_proof=lambda proof:proof.update(journal_id='f'*32)
    if change=='request':client.bad_proof=lambda proof:proof.update(request_fingerprint='f'*64)
    if change=='missing':client.bad_proof=lambda proof:proof.pop('network')
    if change=='capability':client.qualify_node=lambda **kwargs:{'journal_id':JOURNAL}
    try:
        with pytest.raises(RuntimeOperationError,match='management preflight'):driver.prepare(request,TARGET)
        assert not store.contains('lab','start-a') and client.submitted==[]
    finally:store.close()
