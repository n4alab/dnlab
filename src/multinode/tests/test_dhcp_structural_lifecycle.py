"""Persist the entire desired service transition before stopping its generation."""
import copy
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from dnlab_multinode.services import jumphost_host as module
from tests.test_dhcp_structure_worker import world
from tests.test_dhcp_exec_journal import World as ExecWorld


@pytest.fixture
def lifecycle(world,monkeypatch):
    w,worker,record,receipt,request=world;original=copy.deepcopy(receipt['service'])
    state=SimpleNamespace(running=True,stops=0,fault=None,service=None,syntax_calls=0)
    class Service:
        def __init__(self,worker,record,fd):self.worker,self.record=worker,record;self.container_proof=original['container']
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def syntax(self,content):
            state.syntax_calls+=1
            if state.fault=='syntax':raise module.JumphostError('bad syntax')
            return {'syntax_verified':True}
        def observe(self,*args,**kwargs):return copy.deepcopy(state.service or original)
        def shutdown_status(self,expected):
            self.worker.dhcp_preflight(self.record)
            assert expected==original
            return {'state':'running','service':original} if state.running else {'state':'stopped',**receipt}
        def stop(self,expected):
            pending=worker.read()['dhcp_structural_operation']
            assert pending['request']==request and pending['stop']['attempted']
            assert pending['phase']=='stopping'
            state.stops+=1
            if state.fault=='stop-timeout':raise module.JumphostError('stop timeout')
            state.running=False
            if state.fault=='stop-reply':state.fault=None;raise module.JumphostError('stop reply lost')
            return copy.deepcopy(receipt)
        def readiness(self,expected):
            self.worker.dhcp_preflight(self.record)
            if state.fault=='readiness':raise module.JumphostError('listener missing')
            assert expected==state.service
            return {'level':'dhcp-listeners','service':copy.deepcopy(expected),'listeners':[{'inode':123,'table':'udp','port':67}],'interfaces':{'eth1':self.record['config']['attachment']},
                'configuration_sha256':{name:hashlib.sha256(value['content'].encode()).hexdigest()
                    for name,value in self.record['dhcp_assets']['files'].items()},'packet_readiness_verified':False}
        def reload(self,expected,files):
            assert expected==state.service
            return {'service':copy.deepcopy(expected),'reload_verified':True}
        def observe_launch(self,expected,nonce):
            self.worker.dhcp_preflight(self.record)
            if state.fault=='foreign':raise module.JumphostError('foreign daemon')
            if state.service is None:return None
            assert state.service['operation_nonce']==nonce
            return copy.deepcopy(state.service)
    monkeypatch.setattr(module,'DHCPHostService',Service)
    class Docker(ExecWorld):
        def call(self,*args,**kwargs):
            self.intent=worker.read()['dhcp_structural_operation']['launch']
            try:return super().call(*args,**kwargs)
            finally:
                w.values[record['container_id']]['ExecIDs']=list(self.execs)
                if self.service:
                    new=copy.deepcopy(original);new.update(operation_nonce=self.intent['nonce'],
                        host_pid=original['host_pid']+1,pid=original['pid']+1,start='new-generation')
                    new['log']['configuration_sha256']=hashlib.sha256(worker.read()['dhcp_assets']['files']['main']['content'].encode()).hexdigest()
                    self.service=copy.deepcopy(new);state.service=new
    docker=Docker();docker.container=copy.deepcopy(original['container'])
    return w,worker,record,request,state,docker


def begin(lifecycle):
    w,worker,r,request,state,docker=lifecycle
    with worker.locked():worker.begin_dhcp_structural_operation(r,request)
    return r


def resume(lifecycle):
    w,worker,r,request,state,docker=lifecycle
    r=worker.read()
    with worker.locked():service=worker.resume_dhcp_structural_operation(r,docker=docker)
    return r,service


def test_entire_intent_precedes_stop_and_service_ready_retains_pending_fence(lifecycle):
    w,worker,r,req,state,docker=lifecycle;old=copy.deepcopy(r['config']);begin(lifecycle)
    assert worker.read()['dhcp_structural_operation']['phase']=='stopping' and state.stops==0
    r,service=resume(lifecycle)
    assert state.stops==docker.starts==len(docker.execs)==1
    assert state.syntax_calls==1 and r['config']==old
    assert r['phase']=='dhcp_structure_pending' and r['dhcp_structural_operation']['phase']=='service-ready'
    assert service==state.service and service['start']=='new-generation'
    r,retry=resume(lifecycle)
    assert retry==service and state.stops==docker.starts==1
    assert worker.operate('delete')['cleanup_verified']
    assert worker.read()['dhcp_structural_history'][0]['phase']=='service-ready'


@pytest.mark.parametrize('fault',['stop-reply','after-create','after-start'])
def test_stop_and_exec_lost_replies_recover_from_outer_journal_without_duplicate_service(lifecycle,fault):
    w,worker,r,req,state,docker=lifecycle;begin(lifecycle)
    if fault=='stop-reply':state.fault=fault
    else:docker.fault=fault
    with pytest.raises(module.JumphostError):resume(lifecycle)
    docker.fault=None;state.fault=None
    r,service=resume(lifecycle)
    assert r['dhcp_structural_operation']['phase']=='service-ready'
    assert state.stops==docker.starts==len(docker.execs)==1


@pytest.mark.parametrize('boundary',['initial-intent','stop-intent','stop-commit','writing-phase','asset-commit','launch-intent','exec-start','service-commit'])
def test_journal_save_failures_do_not_cross_unpersisted_boundaries(lifecycle,monkeypatch,boundary):
    w,worker,r,req,state,docker=lifecycle;save=worker.save;armed=[True]
    def fail(record):
        op=record.get('dhcp_structural_operation') or {};phase=op.get('phase');stop=op.get('stop',{});launch=op.get('launch') or {}
        hit={'initial-intent':phase=='stopping' and stop.get('phase')=='intent',
            'stop-intent':phase=='stopping' and stop.get('phase')=='stopping',
            'stop-commit':phase=='stopping' and stop.get('phase')=='stopped',
            'writing-phase':phase=='writing' and not record.get('dhcp_structure'),
            'asset-commit':phase=='writing' and record.get('dhcp_structure',{}).get('assets',{}).get('phase')=='ready',
            'launch-intent':phase=='launching' and launch.get('phase')=='intent',
            'exec-start':phase=='launching' and launch.get('phase')=='starting',
            'service-commit':phase=='service-ready'}[boundary]
        if hit and armed[0]:armed[0]=False;raise OSError('injected fsync failure')
        save(record)
    with monkeypatch.context() as patch:
        patch.setattr(worker,'save',fail)
        with pytest.raises(OSError):
            begin(lifecycle);resume(lifecycle)
    assert not armed[0]
    if boundary in ('initial-intent','stop-intent'):assert state.stops==docker.starts==0
    if boundary=='initial-intent':
        r=worker.read()
        with worker.locked():worker.begin_dhcp_structural_operation(r,req)
    r,service=resume(lifecycle)
    assert state.stops==docker.starts==1 and r['dhcp_structural_operation']['phase']=='service-ready'


@pytest.mark.parametrize('change',['request','original-service','container','nonce','config'])
def test_unbound_root_operation_is_refused_without_signals_writes_or_exec(lifecycle,change):
    w,worker,r,req,state,docker=lifecycle;begin(lifecycle);r=worker.read()
    if change=='request':r['dhcp_structural_operation']['request']['content']+='port=0\n'
    if change=='original-service':r['dhcp_structural_operation']['original_service']['start']='foreign'
    if change=='container':r['container_id']='f'*64
    if change=='nonce':r['nonce']='9'*32
    if change=='config':r['config']['env']['INJECTED']='foreign'
    with pytest.raises(module.JumphostError):worker.resume_dhcp_structural_operation(r,docker=docker)
    assert state.stops==docker.starts==0


def test_stop_timeout_preserves_original_files_and_workload(lifecycle):
    w,worker,r,req,state,docker=lifecycle;before=copy.deepcopy(r['dhcp_assets']);begin(lifecycle);state.fault='stop-timeout'
    with pytest.raises(module.JumphostError,match='timeout'):resume(lifecycle)
    r=worker.read()
    assert r['dhcp_assets']==before and 'dhcp_structure' not in r and docker.starts==0
    assert state.running


def test_bad_syntax_prevents_intent_and_stop(lifecycle):
    w,worker,r,req,state,docker=lifecycle;state.fault='syntax';before=worker.path.read_bytes()
    with pytest.raises(module.JumphostError,match='syntax'):begin(lifecycle)
    assert worker.path.read_bytes()==before and state.stops==0


def test_foreign_daemon_before_exec_start_preserves_pending_operation(lifecycle):
    w,worker,r,req,state,docker=lifecycle;begin(lifecycle);state.fault='foreign'
    with pytest.raises(module.JumphostError,match='foreign'):resume(lifecycle)
    assert worker.read()['dhcp_structural_operation']['phase']=='launching' and docker.starts==0


@pytest.mark.parametrize('inventory',[[],[{'host_pid':10,'pid':2,'start':'1'}],[{'host_pid':10,'pid':2,'start':'1'},{'host_pid':11,'pid':3,'start':'2'}]])
def test_launch_observer_never_treats_ambiguous_inventory_as_absence(inventory):
    worker=SimpleNamespace(dhcp_preflight=Mock());service=module.DHCPHostService(worker,{},0)
    original={'original':'proof'};value={'host_pid':10,'pid':2,'start':'1','operation_nonce':'a'*32}
    service.launch_inventory=Mock(return_value=inventory);service.observe=Mock(return_value=value)
    service.shutdown_status=Mock(return_value={'state':'stopped','service':original,'exit_verified':True})
    if len(inventory)>1:
        with pytest.raises(module.JumphostError,match='ambiguous'):service.observe_launch(original,'a'*32)
        service.observe.assert_not_called();service.shutdown_status.assert_not_called()
    elif inventory:
        assert service.observe_launch(original,'a'*32)==value
        service.observe.assert_called_once_with(birth_nonce='a'*32)
    else:
        assert service.observe_launch(original,'a'*32) is None
        service.shutdown_status.assert_called_once_with(original)


def test_launch_inventory_changes_fail_before_qualifying_service():
    service=module.DHCPHostService(SimpleNamespace(dhcp_preflight=Mock()),{},0)
    value={'host_pid':10,'pid':2,'start':'1'}
    service.launch_inventory=Mock(side_effect=[[value],[]]);service.observe=Mock(return_value=value)
    with pytest.raises(module.JumphostError,match='inventory changed'):service.observe_launch({},'a'*32)


def test_finalization_binds_readiness_and_replays_without_another_launch(lifecycle):
    w,worker,r,req,state,docker=lifecycle;birth=copy.deepcopy(r['config']);begin(lifecycle);r,service=resume(lifecycle)
    with worker.locked():proof=worker.finalize_dhcp_structural_operation(r,req)
    assert r['phase']=='active' and r['config']==birth
    assert r['dhcp_expected_service']==service and r['dhcp_service_nonce']==service['operation_nonce']
    assert 'dhcp_structure' not in r and 'dhcp_structural_operation' not in r
    r=worker.read()
    with worker.locked():assert worker.finalize_dhcp_structural_operation(r,req)==proof
    assert docker.starts==1
    with pytest.raises(module.JumphostError,match='already finalized'):
        worker.begin_dhcp_structural_operation(r,req)
    # Reservation refresh compares the committed qualified main, not birth.
    req2=dict(req,request_id='b'*32,content=req['content'].replace('198.18.0.12','198.18.0.13'))
    assert worker.operate('dhcp-refresh',req2)['phase']=='active'
    with pytest.raises(module.JumphostError,match='assets superseded'):
        worker.finalize_dhcp_structural_operation(worker.read(),req)


def test_readiness_failure_keeps_original_pending_operation(lifecycle):
    w,worker,r,req,state,docker=lifecycle;begin(lifecycle);r,service=resume(lifecycle)
    state.fault='readiness';before=worker.path.read_bytes()
    with pytest.raises(module.JumphostError,match='listener missing'):
        worker.finalize_dhcp_structural_operation(r,req)
    assert worker.path.read_bytes()==before and worker.read()['phase']=='dhcp_structure_pending'


@pytest.mark.parametrize('after_replace',[False,True])
def test_final_commit_uncertainty_recovers_without_restarting(lifecycle,monkeypatch,after_replace):
    w,worker,r,req,state,docker=lifecycle;begin(lifecycle);r,service=resume(lifecycle);save=worker.save
    def fail(record):
        if after_replace:save(record)
        raise OSError('final commit uncertain')
    with monkeypatch.context() as patch:
        patch.setattr(worker,'save',fail)
        with pytest.raises(OSError):worker.finalize_dhcp_structural_operation(r,req)
    r=worker.read()
    with worker.locked():worker.finalize_dhcp_structural_operation(r,req)
    assert worker.read()['phase']=='active' and docker.starts==1
