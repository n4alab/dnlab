from copy import deepcopy
from pathlib import Path
import hashlib
import sys
import threading

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime'))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tests'))
from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import capabilities
from fakes import FakeClock,FakeDocker,FakeLinux
from dnlab_multinode.controllers import node as node_module
from dnlab_multinode.controllers.node import NodeLifecycleController
from dnlab_multinode.models.state import DeploymentState,NodeRuntimeState
from dnlab_multinode.services import native_public as public,state as state_svc
from dnlab_multinode.services.runtime_cleanup import make_binding,operation_directory
from dnlab_multinode.services.runtime_operations import OperationStore,OperationDriver
from tests.conftest import make_topology


class Docker(FakeDocker):
    def create(self,name,config):
        super().create(name,config)
        identity=hashlib.sha256(str(len(self.calls)).encode()).hexdigest()
        self.containers[name]['Id']=identity
        return {'Id':identity}


class SSH:
    def connect(self):pass
    def close(self):pass
    def cancel_active_commands(self):pass
    def __getattr__(self,name):raise AssertionError('legacy SSH mutation attempted: '+name)


class Client:
    def __init__(self,engine):self.engine=engine;self.journal=engine.journal;self.calls=[]
    def bound_to(self,value):assert value==self.journal.identity;return self
    def qualify_node(self,**options):return {**capabilities(),'journal_id':self.journal.identity}
    def inspect_node(self,lab,node):return self.engine.inspect(lab,node)
    def plan_node(self,request):return self.engine.plan(request)
    def submit_node(self,request):
        self.calls.append(('submit',deepcopy(request)))
        return self.engine.execute(self.journal.submit(request)['id'])
    def find_node_request(self,request,**options):return self.journal.find_matching_request(request)
    def node_operation(self,identity,*,action='status',force=False):
        if action=='reconcile':self.calls.append(('reconcile',force));return self.engine.reconcile(identity,force=force)
        return self.journal.get(identity)
    def cancel_node_request(self,request):return self.journal.cancel_request(request)
    def node_stop_stage(self,identity,lab,node,stage):
        self.calls.append(('stage',stage));self.engine.stops.request_stage(identity,lab,node,stage)
        return self.engine.execute(identity)


@pytest.fixture
def native(tmp_path,monkeypatch,request):
    journal=Journal(tmp_path/'native');docker=Docker();linux=FakeLinux();clock=FakeClock()
    linux.network_identity=lambda:{'boot':'fixture','namespace':'fixture'}
    engine=Engine(journal,Backend(docker,linux,clock=clock.clock,sleep=clock.sleep));client=Client(engine)
    monkeypatch.setattr(public,'RuntimeClient',lambda *args,**kwargs:client)
    ssh=SSH();monkeypatch.setattr('dnlab_multinode.services.ssh.create_clients',lambda hosts:{'master':ssh})
    monkeypatch.setattr(node_module,'create_clients',lambda hosts:{'master':ssh})
    store=OperationStore(operation_directory(tmp_path));driver=OperationDriver(store,lambda target:client)
    spec={'kind':'linux','container_name':'native-owned-R1','image':'sha256:'+'a'*64,'endpoints':[],'stop_timeout':1}
    if getattr(request,'param',False):spec['management']={'network':'mgmt','ipv4':'192.0.2.2'}
    start={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'initial','action':'start','expected_revision':0,'spec':spec}
    target={'host':'master','socket_path':'/tmp/native.sock','container_name':'runtime-fixture'}
    driver.prepare(start,target);assert driver.advance('demo','initial')['phase']=='completed'
    view=client.inspect_node('demo','R1');binding=make_binding(store,'demo','R1','initial',view)
    state=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'),runtime_mode='custom')
    state.node_runtime={'R1':NodeRuntimeState(node='R1',host='master',kind='linux',container=spec['container_name'],image=spec['image'],runtime_binding=binding)}
    state_svc.save_state(state,tmp_path)
    controller=object.__new__(NodeLifecycleController)
    controller.topo=make_topology(name='demo',num_workers=0);controller.state=state;controller.state_dir=tmp_path
    controller.cancel_event=threading.Event();controller.phase_callback=None;controller._active_clients={}
    yield controller,client,docker,store
    store.close();journal.close()


def test_public_stop_start_arbitrary_name_uses_native_generation_and_verified_stages(native):
    ctrl,client,docker,store=native
    original=ctrl.state.node_runtime['R1'].runtime_binding['container_id']
    state=ctrl.stop('R1',request_id='stop')
    assert state.node_runtime['R1'].state=='stopped' and docker.containers=={}
    assert ('stage','cleanup') in client.calls and ('stage','finalize') in client.calls
    assert state.node_runtime['R1'].runtime_status['committed_state']=='stopped'
    state=ctrl.start('R1',request_id='start')
    assert state.node_runtime['R1'].state=='running'
    assert state.node_runtime['R1'].runtime_binding['generation']==2
    assert state.node_runtime['R1'].runtime_binding['container_id']!=original
    assert state.node_runtime['R1'].runtime_status['guest_readiness']=='unknown'
    calls=deepcopy(client.calls);ctrl.start('R1',request_id='start');assert client.calls==calls


def test_restart_request_replay_does_not_stop_new_generation(native):
    ctrl,client,docker,store=native
    ctrl.restart('R1',request_id='restart')
    identity=ctrl.state.node_runtime['R1'].runtime_binding['container_id'];calls=deepcopy(client.calls)
    ctrl.restart('R1',request_id='restart')
    assert ctrl.state.node_runtime['R1'].runtime_binding['container_id']==identity and client.calls==calls


def test_shutdown_timeout_preserves_running_workload_then_explicit_force_recovers(native):
    ctrl,client,docker,store=native;docker.resist_term=True
    before=deepcopy(docker.containers)
    with pytest.raises(public.NativeOwnershipError,match='recovery_required'):ctrl.stop('R1',request_id='normal')
    assert docker.containers==before
    assert ('signal','SIGKILL') not in docker.calls
    ctrl.stop('R1',force=True,request_id='forced')
    assert docker.containers=={} and ctrl.state.node_runtime['R1'].state=='stopped'
    assert ('reconcile',True) in client.calls


def test_read_only_projection_never_claims_readiness_or_uses_name(native):
    ctrl,client,docker,store=native
    before=deepcopy(docker.calls);saved=state_svc.state_file_path('demo',ctrl.state_dir).read_bytes()
    nodes=ctrl.list_nodes()
    assert nodes['R1'].state=='running' and nodes['R1'].runtime_status['guest_readiness']=='unknown'
    assert docker.calls==before and state_svc.state_file_path('demo',ctrl.state_dir).read_bytes()==saved


def test_foreign_generation_refuses_before_any_mutation_or_legacy_fallback(native):
    ctrl,client,docker,store=native
    docker.containers['native-owned-R1']['Id']='f'*64
    before=deepcopy(docker.calls)
    with pytest.raises(Exception):ctrl.stop('R1')
    assert docker.calls==before and client.calls==[('submit',client.calls[0][1])]
    assert ctrl.list_nodes()['R1'].state=='unknown'


def test_remove_retains_verified_owner_tombstone_and_readd_new_generation(native):
    ctrl,client,docker,store=native
    ctrl.remove('R1',request_id='remove')
    assert 'R1' not in ctrl.state.node_runtime and 'R1' in ctrl.state.retired_native_nodes and docker.containers=={}
    ctrl.start('R1',request_id='readd')
    assert 'R1' not in ctrl.state.retired_native_nodes and ctrl.state.node_runtime['R1'].runtime_binding['generation']==2


@pytest.mark.parametrize('mutate',['missing','unknown','bad-cid','wrong-host'])
def test_owner_validation_precedes_any_public_mutation(native,mutate):
    ctrl,client,docker,store=native
    runtime=ctrl.state.node_runtime['R1']
    if mutate=='missing':runtime.runtime_binding={}
    elif mutate=='unknown':runtime.runtime_binding['backend']='other'
    elif mutate=='bad-cid':runtime.runtime_binding['container_id']='bad'
    else:runtime.host='unknown-host'
    state_svc.save_state(ctrl.state,ctrl.state_dir);before=deepcopy(client.calls)
    with pytest.raises(public.NativeOwnershipError):ctrl.stop('R1')
    assert client.calls==before


def test_same_docker_birth_does_not_authorize_untracked_revision(native):
    ctrl,client,docker,store=native
    initial=store.get('demo','initial',private=True)['request']
    # A direct native request can be a valid runtime operation while absent
    # from this coordinator's durable intent history.
    op=client.journal.submit({**initial,'request_id':'external-repeat','expected_revision':1})
    assert client.engine.execute(op['id'])['phase']=='completed'
    before=deepcopy(docker.calls)
    with pytest.raises(public.NativeOwnershipError,match='revision'):ctrl.stop('R1')
    assert docker.calls==before and ctrl.list_nodes()['R1'].state=='unknown'


def test_pending_stop_projects_actual_workload_and_operation_separately(native):
    ctrl,client,docker,store=native
    original=public.source(store,ctrl.state,'R1')
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'parked',
             'action':'stop','stop_mode':'coordinated','expected_revision':1}
    driver=OperationDriver(store,lambda target:client)
    driver.prepare(request,original['target']);driver.advance('demo','parked')
    nodes=ctrl.list_nodes();status=nodes['R1'].runtime_status
    assert nodes['R1'].state=='stopping' and status['committed_state']=='running' and status['container_state']=='stopped'
    assert status['operation']['phase']=='awaiting_link_cleanup' and status['guest_readiness']=='unknown'


def test_cancelled_new_attempt_preserves_committed_anchor_and_can_start_again(native):
    ctrl,client,docker,store=native
    ctrl.stop('R1',request_id='before-cancel')
    anchor=deepcopy(ctrl.state.node_runtime['R1'].runtime_binding)
    original=public.source(store,ctrl.state,'R1')
    request={**original['request'],'request_id':'cancelled-attempt','expected_revision':2}
    driver=OperationDriver(store,lambda target:client);driver.prepare(request,original['target'])
    pending=client.journal.submit(request);store.observe('demo','cancelled-attempt',pending)
    # Cancellation after Docker birth but before the node commit uses ordinary
    # verified compensation. It must not replace the committed source spec.
    docker.hook=lambda event:client.journal.cancel(pending['id']) if event=='start' else None
    result=client.engine.execute(pending['id'])
    assert result['phase']=='cancelled' and docker.containers=={}
    assert client.engine.inspect('demo','R1')['workload']['generation']==2
    view=ctrl.list_nodes()['R1']
    assert view.state=='stopped' and view.runtime_status['workload']['phase']=='cleaned'
    assert ctrl.state.node_runtime['R1'].runtime_binding==anchor
    ctrl.reconcile('R1')
    assert store.get('demo','cancelled-attempt')['phase']=='cancelled'
    docker.hook=lambda event:None
    ctrl.start('R1',request_id='after-cancel')
    assert ctrl.state.node_runtime['R1'].runtime_binding['generation']==3


def test_cancel_after_start_commit_performs_tracked_ordinary_stop(native):
    ctrl,client,docker,store=native
    ctrl.stop('R1',request_id='initial-stop')
    docker.hook=lambda event:ctrl.request_cancel() if event=='start' else None
    state=ctrl.start('R1',request_id='cancel-at-commit')
    assert state.node_runtime['R1'].state=='stopped' and docker.containers=={}
    assert ('signal','SIGKILL') not in docker.calls
    assert store.db.execute("SELECT phase FROM public_requests WHERE request_id='cancel-at-commit'").fetchone()[0]=='cancelled'
    assert any(c[0]=='submit' and c[1]['request_id'].startswith('cancel-stop-') for c in client.calls)


def test_cancellation_shutdown_timeout_retains_running_generation_and_recovery(native):
    ctrl,client,docker,store=native
    ctrl.stop('R1',request_id='initial-stop')
    docker.resist_term=True
    docker.hook=lambda event:ctrl.request_cancel() if event=='start' else None
    with pytest.raises(public.NativeOwnershipError,match='recovery_required'):
        ctrl.start('R1',request_id='cancel-timeout')
    status=ctrl.state.node_runtime['R1'].runtime_status
    assert status['container_state']=='running' and status['operation']['phase']=='recovery_required'
    assert ('signal','SIGKILL') not in docker.calls


def test_unknown_planned_peer_is_refused_before_shutdown(native):
    ctrl,client,docker,store=native;original=client.plan_node
    def unknown_peer(request):return {**original(request),'link_affected_nodes':['R1','unknown-peer']}
    client.plan_node=unknown_peer;before=deepcopy(docker.calls)
    with pytest.raises(public.NativeOwnershipError,match='owner unavailable'):ctrl.stop('R1')
    assert docker.calls==before and docker.containers['native-owned-R1']['State']['Running']


def test_status_ignores_docker_name_match_if_native_generation_is_foreign(native):
    from dnlab_multinode.controllers.status import StatusController,StatusReport,HostStatus
    ctrl,client,docker,store=native
    class Inventory(SSH):
        def run_no_check(self,*args,**kwargs):return 0,'native-owned-R1\trunning\tUp 9 years',''
    status_ctrl=object.__new__(StatusController);status_ctrl.topology_file=ctrl.state.topology_file
    report=StatusReport(lab_name='demo',deployed=True,hosts={'master':HostStatus(name='master',host='127.0.0.1',reachable=True)})
    status_ctrl._collect_node_status(ctrl.topo,ctrl.state,{'master':Inventory()},report)
    assert report.nodes['R1'].state=='running' and report.nodes['R1'].runtime_status['qualified'] is True
    assert report.nodes['R1'].runtime_status['guest_readiness']=='unknown'
    docker.containers['native-owned-R1']['Id']='f'*64
    status_ctrl._collect_node_status(ctrl.topo,ctrl.state,{'master':Inventory()},report)
    assert report.nodes['R1'].state=='unknown'
    assert report.nodes['R1'].can_start is False and report.nodes['R1'].can_stop is False


def test_public_api_accepts_stable_request_id_and_exposes_qualified_state(native,monkeypatch):
    import asyncio
    from dnlab_multinode import api
    ctrl,client,docker,store=native
    monkeypatch.setattr(api,'NodeLifecycleController',lambda *args,**kwargs:ctrl)
    stopped=asyncio.run(api.lab_node_stop(api.NodeStopRequest(topology_file=ctrl.state.topology_file,node='R1',request_id='api-stop')))
    assert stopped['node_runtime']['R1']['runtime_status']['container_state']=='absent'
    started=asyncio.run(api.lab_node_start(api.NodeRequest(topology_file=ctrl.state.topology_file,node='R1',request_id='api-start')))
    assert started['_operation_outcome']=='completed'
    assert started['node_runtime']['R1']['runtime_binding']['generation']==2
    assert store.db.execute("SELECT phase FROM public_requests WHERE request_id='api-start'").fetchone()[0]=='completed'


def test_old_completed_start_replay_does_not_readd_retired_owner(native):
    ctrl,client,docker,store=native
    ctrl.stop('R1',request_id='stop')
    ctrl.start('R1',request_id='old-start')
    ctrl.remove('R1',request_id='remove')
    before=deepcopy(client.calls)
    ctrl.start('R1',request_id='old-start')
    assert 'R1' in ctrl.state.retired_native_nodes and 'R1' not in ctrl.state.node_runtime
    assert docker.containers=={} and client.calls==before


def test_final_queued_ack_is_reobserved_completed_before_deadline_error(native,monkeypatch):
    from types import SimpleNamespace
    ctrl,client,docker,store=native
    original=client.node_stop_stage;finished=[False]
    def delayed_receipt(identity,lab,node,stage):
        result=original(identity,lab,node,stage)
        if stage=='finalize':finished[0]=True;return {**result,'phase':'queued'}
        return result
    client.node_stop_stage=delayed_receipt
    monkeypatch.setattr(public,'time',SimpleNamespace(monotonic=lambda:1000 if finished[0] else 0,sleep=lambda seconds:None))
    ctrl.stop('R1',request_id='delayed-final-ack')
    assert ctrl.state.node_runtime['R1'].state=='stopped'
    key=ctrl.state.node_runtime['R1'].runtime_binding['stop_request_id']
    assert store.get('demo',key)['phase']=='completed'


def test_pending_old_restart_never_advances_a_new_generation_stop(native):
    ctrl,client,docker,store=native
    docker.resist_term=True
    with pytest.raises(public.NativeOwnershipError):ctrl.restart('R1',request_id='old-restart')
    ctrl.stop('R1',force=True,request_id='explicit-force')
    docker.resist_term=False
    ctrl.start('R1',request_id='new-generation')
    source=public.source(store,ctrl.state,'R1')
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'new-stop',
        'action':'stop','stop_mode':'coordinated','expected_revision':3}
    driver=OperationDriver(store,lambda target:client);driver.prepare(request,source['target'])
    assert driver.advance('demo','new-stop')['phase']=='awaiting_link_cleanup'
    calls=deepcopy(client.calls)
    with pytest.raises(public.NativeOwnershipError,match='public operation generation'):
        ctrl.restart('R1',request_id='old-restart')
    assert client.calls==calls and store.get('demo','new-stop')['phase']=='awaiting_link_cleanup'


def test_api_native_cancellation_exception_cannot_use_cached_cleaned_status(native,monkeypatch):
    import asyncio
    from dnlab_multinode import api
    ctrl,client,docker,store=native
    ctrl.stop('R1',request_id='initial-stop')
    assert ctrl.state.node_runtime['R1'].runtime_status['container_state']=='absent'
    def interrupted(node,**kwargs):
        ctrl.cancel_event.set()
        raise OSError('lost SSH acknowledgement after possible creation')
    ctrl.start=interrupted
    def constructor(*args,**kwargs):
        ctrl.cancel_event=kwargs['cancel_event']
        return ctrl
    monkeypatch.setattr(api,'NodeLifecycleController',constructor)
    with pytest.raises(api.HTTPException) as error:
        asyncio.run(api.lab_node_start(api.NodeRequest(topology_file=ctrl.state.topology_file,node='R1')))
    assert error.value.status_code==422
    assert 'requires recovery' in error.value.detail


def test_api_native_cancel_ack_does_not_claim_verified_cleanup(native):
    import asyncio
    from dnlab_multinode import api
    ctrl,client,docker,store=native
    async def exercise():
        req=api.NodeStopRequest(topology_file=ctrl.state.topology_file,node='R1')
        key=api._node_operation_key(req)
        operation=api._ActiveNodeStart(ctrl.cancel_event,asyncio.Event())
        operation.controller=ctrl;operation.phase='reconciling'
        api._active_node_starts[key]=operation
        try:
            result=await api.lab_node_stop(req)
            assert result['_operation_outcome']=='cancellation_requested' and result['cancelled'] is False
            assert docker.containers and ctrl.cancel_event.is_set()
        finally:api._active_node_starts.pop(key,None)
    asyncio.run(exercise())


def test_start_preflights_declared_peer_birth_before_workload_creation(native):
    from dnlab_multinode.models.topology import Link
    ctrl,client,docker,store=native
    original=public.source(store,ctrl.state,'R1')
    request={**original['request'],'node_id':'R2','request_id':'initial-peer',
             'spec':{**original['request']['spec'],'container_name':'native-owned-R2',
                     'endpoints':[{'host_interface':'drsp-peer','node_interface':'eth1','mtu':1500}]}}
    driver=OperationDriver(store,lambda target:client);driver.prepare(request,original['target'])
    assert driver.advance('demo','initial-peer')['phase']=='completed'
    view=client.inspect_node('demo','R2')
    ctrl.state.node_runtime['R2']=NodeRuntimeState(node='R2',host='master',kind='linux',container='native-owned-R2',
        image=request['spec']['image'],runtime_binding=make_binding(store,'demo','R2','initial-peer',view))
    state_svc.save_state(ctrl.state,ctrl.state_dir)
    ctrl.stop('R1',request_id='initial-stop')
    ctrl.topo.links=[Link('R2','eth1','R1','eth1')]
    docker.containers['native-owned-R2']['Id']='f'*64
    calls=deepcopy(docker.calls)
    from dnlab_runtime.workload_generation import GenerationConflict
    with pytest.raises(GenerationConflict):ctrl.start('R1',request_id='foreign-peer')
    assert docker.calls==calls and 'native-owned-R1' not in docker.containers


@pytest.mark.parametrize('native',[True],indirect=True)
def test_management_restart_and_lost_start_ack_replay_keep_bound_original_proof(native):
    ctrl,client,docker,store=native
    ctrl.stop('R1',request_id='stop-managed')
    submit=client.submit_node;lost=[False]
    def lose_ack(request):
        result=submit(request)
        if not lost[0] and request['action']=='start':
            lost[0]=True;raise ConnectionError('fixture lost acknowledgement')
        return result
    client.submit_node=lose_ack
    with pytest.raises(ConnectionError):ctrl.start('R1',request_id='start-managed')
    identity=docker.containers['native-owned-R1']['Id'];calls=deepcopy(docker.calls)
    ctrl.start('R1',request_id='start-managed')
    assert docker.containers['native-owned-R1']['Id']==identity and docker.calls==calls
    ctrl.restart('R1',request_id='restart-managed')
    assert ctrl.state.node_runtime['R1'].runtime_binding['generation']==3
    for row in store.db.execute("SELECT request_id FROM operations WHERE lab='demo'").fetchall():
        original=store.get('demo',row[0],private=True)['request']
        if original['action']=='start':assert original['management_preflight']['network']['Id']=='mgmt-id'


def test_native_public_network_guard_failure_prevents_start_intent_and_docker_mutation(native,monkeypatch):
    from dnlab_multinode.models.state import MgmtState
    from dnlab_multinode.services import netsetup
    ctrl,client,docker,store=native;ctrl.stop('R1',request_id='stop-before-network-check')
    ctrl.state.mgmt=MgmtState(subnet='192.0.2.0/24',gateway='192.0.2.254',bridge='bm1',vrf='vrfa',vxlan_id=70001,vxlan_iface='vm1',infrastructure={'plans':{'master':{}}})
    state_svc.save_state(ctrl.state,ctrl.state_dir);calls=deepcopy(client.calls)
    def fail(state,clients,action,**kwargs):
        assert action=='mark-used' and set(clients)=={'master'}
        raise RuntimeError('network was replaced')
    monkeypatch.setattr(netsetup,'network_action',fail)
    with pytest.raises(RuntimeError,match='network was replaced'):ctrl.start('R1',request_id='blocked-start')
    assert client.calls==calls and docker.containers=={}
    assert store.db.execute("SELECT COUNT(*) FROM public_requests WHERE request_id='blocked-start'").fetchone()[0]==0
