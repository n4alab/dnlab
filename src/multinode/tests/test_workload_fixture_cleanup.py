"""Repeatable shared fixture cleanup with original stop proofs; no real Docker."""
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from tests.test_runtime_initial_deploy import world
from dnlab_multinode.services.runtime_operations import OperationDriver

TOOLS=Path(__file__).resolve().parents[2]/'runtime/tools'
if str(TOOLS) not in sys.path:sys.path.insert(0,str(TOOLS))
from http_workload_fixture import Workload


@pytest.fixture
def workload(world,tmp_path,request):
    batch,store,clients,engines,members=world
    member=members[0];client=clients['master'];engine=engines['master']
    value=object.__new__(Workload)
    value.path=tmp_path/'workload.json';value.runtime=client;value.store=store
    value.driver=OperationDriver(store,lambda t:client if t==member['target'] else value.wrong_target())
    value.start=deepcopy(member['request']);value.spec=value.start['spec']
    if getattr(request,'param',False):value.start['lab_generation']=1
    value.record={'lab':'demo','target':deepcopy(member['target'])}
    value.drive(value.start);view=client.inspect_node('demo',value.start['node_id'])
    value.record={'phase':'running','lab':'demo','node':value.start['node_id'],'nonce':'a'*32,
                  'journal_id':engine.journal.identity,'target':deepcopy(member['target']),
                  'container_id':view['container_id'],'revision':view['revision'],'workload':view['workload'],
                  'cleanup_verified':False,'spec':value.spec,'start':value.start}
    value.api=SimpleNamespace(inspect=lambda cid:next((v for v in engine.backend.docker.containers.values() if v['Id']==cid),None))
    value.save()
    return value,client,engine


def test_cleanup_replay_reobserves_original_stop_without_new_mutations(workload):
    value,client,engine=workload
    value.cleanup();before=deepcopy(engine.backend.docker.calls)
    stop_id=value.store.get('demo',value.record['stop']['request_id'])['operation_id']
    for _ in range(3):
        value.cleanup()
        assert value.record['phase']=='cleaned' and value.record['cleanup_verified']
        assert engine.backend.docker.calls==before
        assert value.store.get('demo',value.record['stop']['request_id'])['operation_id']==stop_id
    assert sum(c[0]=='submit' and c[1]['action']=='stop' for c in client.calls)==1


def test_lost_stop_response_recovers_receipt_without_second_stop(workload,monkeypatch):
    value,client,engine=workload;submit=client.submit_node
    def lost(request):
        result=submit(request)
        if request['action']=='stop':raise TimeoutError('lost stop ACK')
        return result
    monkeypatch.setattr(client,'submit_node',lost)
    with pytest.raises(TimeoutError):value.cleanup()
    assert value.record['phase']=='cleanup_pending' and not value.record['cleanup_verified']
    before=deepcopy(engine.backend.docker.calls)
    assert value.store.get('demo',value.record['stop']['request_id'])['phase']!='completed'
    value.cleanup()
    assert value.record['cleanup_verified'] and engine.backend.docker.calls==before
    assert value.store.get('demo',value.record['stop']['request_id'])['phase']=='completed'
    assert sum(c[0]=='submit' and c[1]['action']=='stop' for c in client.calls)==1


@pytest.mark.parametrize('fault',['generation','creator','container','spec','revision','birth-phase','birth-revision',
                                  'present-container','pending','journal','lab','node','incomplete'])
def test_stopped_retry_refuses_conflicts_and_invalidates_previous_verified_flag(workload,monkeypatch,fault):
    value,client,engine=workload;value.cleanup();observe=client.inspect_node
    before=deepcopy(engine.backend.docker.calls)
    def changed(lab,node):
        view=deepcopy(observe(lab,node));birth=view['workload']
        if fault=='generation':birth['generation']+=1
        if fault=='creator':birth['creator_operation_id']='f'*32
        if fault=='container':birth['container_id']='f'*64
        if fault=='spec':birth['spec_fingerprint']='f'*64
        if fault=='revision':view['revision']+=1
        if fault=='birth-phase':birth['phase']='running'
        if fault=='birth-revision':birth['committed_revision']-=1
        if fault=='present-container':view.update(container_id='f'*64,container_state='running')
        if fault=='pending':view['operation']={'id':'f'*32}
        if fault=='journal':view['journal_id']='f'*32
        if fault=='lab':view['lab_id']='foreign'
        if fault=='node':view['node_id']='foreign'
        if fault=='incomplete':del view['container_id']
        return view
    monkeypatch.setattr(client,'inspect_node',changed)
    with pytest.raises(RuntimeError):value.cleanup()
    assert value.record['phase']=='cleanup_pending' and not value.record['cleanup_verified']
    assert engine.backend.docker.calls==before


@pytest.mark.parametrize('fault',['missing','id','node','phase','force'])
def test_stopped_retry_requires_original_completed_runtime_receipt(workload,monkeypatch,fault):
    value,client,engine=workload;value.cleanup();find=client.find_node_request
    before=deepcopy(engine.backend.docker.calls)
    def changed(request,**kwargs):
        if fault=='missing':return None
        receipt=deepcopy(find(request,**kwargs))
        if fault=='id':receipt['id']='f'*32
        if fault=='node':receipt['node']='foreign'
        if fault=='phase':receipt['phase']='applying'
        if fault=='force':receipt['recovery_force']=True
        return receipt
    monkeypatch.setattr(client,'find_node_request',changed)
    with pytest.raises(RuntimeError):value.cleanup()
    assert value.record['phase']=='cleanup_pending' and not value.record['cleanup_verified']
    assert engine.backend.docker.calls==before


def test_stop_request_cannot_be_replaced_or_invented_on_stopped_retry(workload):
    value,client,engine=workload;value.cleanup();before=deepcopy(engine.backend.docker.calls)
    original=deepcopy(value.record['stop']);value.record['stop']['request_id']='foreign'
    with pytest.raises(RuntimeError,match='original stop differs'):value.cleanup()
    value.record['stop']=original;del value.record['stop']
    with pytest.raises(RuntimeError,match='original stop intent missing'):value.cleanup()
    assert engine.backend.docker.calls==before and not value.record['cleanup_verified']


@pytest.mark.parametrize('committed',[False,True])
def test_uncertain_final_fixture_checkpoint_can_retry_without_second_stop(workload,monkeypatch,committed):
    value,client,engine=workload;save=value.save
    def uncertain():
        if value.record['phase']=='cleaned':
            if committed:save()
            raise OSError('cleanup checkpoint uncertain')
        save()
    monkeypatch.setattr(value,'save',uncertain)
    with pytest.raises(OSError):value.cleanup()
    before=deepcopy(engine.backend.docker.calls);monkeypatch.setattr(value,'save',save)
    value.cleanup()
    assert value.record['cleanup_verified'] and engine.backend.docker.calls==before


@pytest.mark.parametrize('workload',[True],indirect=True)
def test_old_default_generation_stop_request_is_reused_verbatim(workload):
    value,client,engine=workload
    stop={'schema_version':1,'lab_id':'demo','node_id':value.record['node'],
          'request_id':'http-stop-'+value.record['nonce'],'expected_revision':value.record['revision'],'action':'stop'}
    value.record['stop']=stop;value.save();value.drive(stop)
    before=deepcopy(engine.backend.docker.calls);value.cleanup()
    assert value.record['stop']==stop and 'lab_generation' not in value.record['stop']
    assert value.store.get('demo',stop['request_id'],private=True)['request']==stop
    assert value.record['cleanup_verified'] and engine.backend.docker.calls==before


@pytest.mark.parametrize('fault',['present','unavailable'])
def test_independent_absence_check_cannot_be_skipped_on_retry(workload,monkeypatch,fault):
    value,client,engine=workload;value.cleanup();before=deepcopy(engine.backend.docker.calls)
    def inspect(cid):
        if fault=='unavailable':raise OSError('Docker observation unavailable')
        return {'Id':cid}
    monkeypatch.setattr(value.api,'inspect',inspect)
    with pytest.raises((RuntimeError,OSError)):value.cleanup()
    assert value.record['phase']=='cleanup_pending' and not value.record['cleanup_verified']
    assert engine.backend.docker.calls==before


def test_first_cleanup_can_record_birth_from_original_completed_start(workload):
    value,client,engine=workload;identity=value.record['container_id']
    for field in ('container_id','revision','workload'):del value.record[field]
    value.cleanup()
    assert value.record['container_id']==identity and value.record['cleanup_verified']
    assert value.record['workload']['phase']=='running'  # Original proof remains immutable.


def test_recorded_birth_without_original_start_intent_remains_pending(workload,monkeypatch):
    value,client,engine=workload;before=deepcopy(engine.backend.docker.calls)
    contains=value.store.contains
    monkeypatch.setattr(value.store,'contains',lambda lab,key:False if key==value.start['request_id'] else contains(lab,key))
    with pytest.raises(RuntimeError,match='original start intent missing'):value.cleanup()
    assert value.record['phase']=='cleanup_pending' and not value.record['cleanup_verified']
    assert engine.backend.docker.calls==before
