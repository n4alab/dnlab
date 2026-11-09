import copy
import json
import shlex

import pytest

from dnlab_multinode.models.state import DeploymentState,NodeRuntimeState
from dnlab_multinode.services import lab_cleanup as cleanup,runtime_cleanup as guard,state as state_svc
from dnlab_multinode.services.runtime_operations import OperationStore,digest

JOURNAL='a'*32;CID='b'*64;BIRTH='c'*32;STOP='d'*32
TARGET={'host':'master','socket_path':'/run/runtime.sock','container_name':'runtime-test'}
SPEC={'kind':'linux','container_name':'clab-dnlab-demo-R1-R1','image':'sha256:'+'e'*64,'endpoints':[]}
START={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'start','action':'start','expected_revision':0,'spec':SPEC}
REQUEST={**{k:v for k,v in START.items() if k!='spec'},'request_id':'stop','action':'stop','expected_revision':1,'stop_mode':'coordinated'}


class Runtime:
    def __init__(self):
        self.calls=[]
        self.remote={'id':STOP,'lab':'demo','node':'R1','request_id':'stop','phase':'awaiting_link_cleanup','error':'',
            'stop_stage':'exit_verified','shutdown_verified':True,'cancel_requested':False,'recovery_force':False}
        self.view={'cleanup_inventory':{'nodes':['R1'],'blocked':[]},'lab_id':'demo','node_id':'R1','journal_id':JOURNAL,'revision':1,'committed_state':'running',
            'container_state':'stopped','container_id':CID,'workload':{'generation':1,'phase':'running','container_id':CID,
            'creator_operation_id':BIRTH,'spec_fingerprint':digest(SPEC),'committed_revision':1},
            'operation':{'id':STOP,'cleanup_scope':'local','footprint_nodes':['R1'],'shutdown_verified':True}}
    def lab_closure(self,lab,action,payload):
        return {'lab_id':lab,'journal_id':JOURNAL,'closure_id':payload['closure_id'],
                'generation':payload['generation'],'phase':'closing' if action=='close' else 'closed'}
    def bound_to(self,value):assert value==JOURNAL;return self
    def qualify_node(self,**kwargs):return {'journal_id':JOURNAL}
    def inspect_node(self,lab,node):return copy.deepcopy(self.view)
    def find_node_request(self,request,**kwargs):assert request==REQUEST;return copy.deepcopy(self.remote)
    def node_operation(self,identity):assert identity==STOP;return copy.deepcopy(self.remote)
    def node_stop_stage(self,identity,lab,node,stage):
        self.calls.append(stage)
        if stage=='cleanup' and self.remote['phase']!='completed':
            self.remote.update(phase='awaiting_finalization',stop_stage='links_cleaned')
        if stage=='finalize':
            self.remote.update(phase='completed',stop_stage='finished')
            self.view.update(revision=2,committed_state='stopped',container_state='absent',container_id=None,operation=None)
            self.view['workload']['phase']='cleaned';self.view['workload']['committed_revision']=2
        return copy.deepcopy(self.remote)


class InventoryClient:
    host='127.0.0.1'
    def __init__(self,runtime):self.runtime=runtime;self.commands=[];self.labels_lab='demo';self.fail_inventory=False;self.container_name=SPEC['container_name']
    def run_no_check(self,command,timeout=30):
        self.commands.append(command)
        if self.fail_inventory:return 1,'','unavailable'
        present=self.runtime.view['container_id'] is not None
        if command.startswith('docker ps -a'):return 0, self.container_name+'\texited\t2000-01-01 00:00:00 +0000 UTC' if present else '', ''
        if command.startswith('docker container ls'):return 0,CID if present else '', ''
        if command.startswith('docker inspect'):
            return 0,json.dumps({'id':CID,'name':'/'+self.container_name,'state':'exited','created':'2000-01-01T00:00:00Z',
                'backend':'v1','lab':self.labels_lab,'node':'R1','creator':BIRTH,'spec':digest(SPEC)}),''
        if command.startswith('docker rm'):raise AssertionError('generic VD removal forbidden')
        return 0,'',''


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    runtime=Runtime();client=InventoryClient(runtime)
    monkeypatch.setattr(guard,'RuntimeClient',lambda *args,**kwargs:runtime)
    store=OperationStore(guard.operation_directory(tmp_path))
    store.prepare(START,TARGET,JOURNAL);store.observe('demo','start',{'id':BIRTH,'lab':'demo','node':'R1','request_id':'start','phase':'completed'})
    owner_view={**runtime.view,'operation':None,'container_state':'running'}
    binding=guard.make_binding(store,'demo','R1','start',owner_view,stop_request_id='stop')
    store.prepare(REQUEST,TARGET,JOURNAL);store.observe('demo','stop',runtime.remote)
    state=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'),teardown_requested=True)
    state.node_runtime={'R1':NodeRuntimeState(node='R1',host='master',container=SPEC['container_name'],state='stopping',runtime_binding=binding)}
    state_svc.save_state(state,tmp_path)
    yield state,runtime,client,store,tmp_path
    store.close()


def artifacts(client):return cleanup._list_containers(client,'master',{'demo'})


def test_daemon_delegates_recorded_stages_and_keeps_infrastructure_until_done(fixture):
    state,runtime,client,store,directory=fixture
    for tick in range(3):
        plan=cleanup.LabCleanupPlan(lab='demo')
        cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
        if tick<2:assert plan.protected
        else:assert not plan.protected
    assert 'cleanup' in runtime.calls and 'finalize' in runtime.calls
    assert store.get('demo','stop')['phase']=='completed'
    assert not any(c.startswith('docker rm') for c in client.commands)
    from tests.test_lab_cleanup import _hosts
    status=cleanup._finalize_requested_teardowns({'demo':state},directory,_hosts(),clients={'master':client})
    assert status['demo']=='pending teardown state finalized'
    assert state_svc.load_state('demo',directory) is None


@pytest.mark.parametrize('change',['cid','journal','generation','spec','recovery','distributed','unknown-peer','missing-ledger','private-pending'])
def test_preflight_blocks_all_mutations_and_retains_state(fixture,change):
    state,runtime,client,store,directory=fixture
    if change=='cid':runtime.view['workload']['container_id']='f'*64
    elif change=='journal':state.node_runtime['R1'].runtime_binding['journal_id']='f'*32
    elif change=='generation':runtime.view['workload']['generation']=2
    elif change=='spec':runtime.view['workload']['spec_fingerprint']='f'*64
    elif change=='recovery':runtime.remote['phase']='recovery_required'
    elif change=='distributed':runtime.view['operation']['cleanup_scope']='distributed'
    elif change=='unknown-peer':runtime.view['operation']['footprint_nodes'].append('R2')
    elif change=='missing-ledger':directory=directory/'missing'
    else:
        store.prepare({**START,'node_id':'R2','request_id':'another','spec':{**SPEC,'container_name':'other'}},TARGET,JOURNAL)
    plan=cleanup.LabCleanupPlan(lab='demo')
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
    assert plan.protected and runtime.calls==[]


def test_native_labels_protect_arbitrary_names_without_state(fixture):
    state,runtime,client,store,directory=fixture
    client.container_name='opaque-custom-workload'
    live=artifacts(client)
    assert any(a.metadata.get('container_id')==CID for a in live)
    inventory={'master':cleanup.HostCleanupInventory(name='master',host=client.host,reachable=True,artifacts=live)}
    plan=cleanup.build_cleanup_plan(inventory,{},grace_seconds=0)['demo']
    assert plan.protected and plan.actions==[]
    assert 'birth' not in json.dumps([a.metadata for a in live])


def test_label_lab_conflict_protects_both_labs(fixture):
    state,runtime,client,store,directory=fixture;client.labels_lab='other'
    live=artifacts(client)
    inventory={'master':cleanup.HostCleanupInventory(name='master',host=client.host,reachable=True,artifacts=live)}
    plans=cleanup.build_cleanup_plan(inventory,{'demo':state},grace_seconds=0)
    assert plans['demo'].protected and plans['other'].protected


def test_finalization_retains_state_on_runtime_recovery_even_if_names_are_absent(fixture):
    state,runtime,client,store,directory=fixture
    runtime.remote['phase']='recovery_required';runtime.view.update(container_state='absent',container_id=None)
    from tests.test_lab_cleanup import _hosts
    status=cleanup._finalize_requested_teardowns({'demo':state},directory,_hosts(),clients={'master':client})
    assert 'retained' in status['demo'] and state_svc.load_state('demo',directory) is not None


def test_stale_generic_vd_action_never_reaches_shell(fixture):
    state,runtime,client,store,directory=fixture
    artifact=cleanup.CleanupArtifact('container',SPEC['container_name'],'master','demo',state='exited')
    action=cleanup.CleanupAction('remove-container',artifact,'docker rm -f '+SPEC['container_name'],'old plan')
    plan=cleanup.LabCleanupPlan(lab='demo',actions=[action])
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
    assert plan.protected and runtime.calls==[] and not action.executed


@pytest.mark.parametrize('inventory',[{'nodes':['R1'],'blocked':['operations']},
    {'nodes':['R1','unknown'],'blocked':[]},None])
def test_native_journal_veto_retains_state_after_bound_stop_completed(fixture,inventory):
    state,runtime,client,store,directory=fixture
    runtime.node_stop_stage(STOP,'demo','R1','finalize')
    runtime.view['cleanup_inventory']=inventory
    plan=cleanup.LabCleanupPlan(lab='demo')
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
    assert plan.protected
    assert state_svc.load_state('demo',directory) is not None


def test_unreadable_fresh_inventory_blocks_before_delegation(fixture):
    state,runtime,client,store,directory=fixture;client.fail_inventory=True
    plan=cleanup.LabCleanupPlan(lab='demo')
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
    assert plan.protected and runtime.calls==[]



def test_completed_native_receipt_is_durably_observed_after_async_finalization(fixture):
    state,runtime,client,store,directory=fixture
    runtime.node_stop_stage(STOP,'demo','R1','finalize')
    assert store.get('demo','stop')['phase']=='awaiting_link_cleanup'
    plan=cleanup.LabCleanupPlan(lab='demo')
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
    assert not plan.protected
    assert store.get('demo','stop')['phase']=='completed'


def test_native_unknown_pending_node_veto_precedes_any_stage(fixture):
    state,runtime,client,store,directory=fixture
    runtime.view['cleanup_inventory']={'nodes':['R1','unknown'],'blocked':['operations']}
    plan=cleanup.LabCleanupPlan(lab='demo')
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':state},state_directory=directory)
    assert plan.protected and runtime.calls==[]


def test_runtime_binding_survives_deployment_state_roundtrip(fixture):
    state,runtime,client,store,directory=fixture
    loaded=state_svc.load_state('demo',directory)
    assert loaded.node_runtime['R1'].runtime_binding==state.node_runtime['R1'].runtime_binding
    plan=cleanup.LabCleanupPlan(lab='demo')
    cleanup._execute_plans({'demo':plan},{'master':client},own_clients=False,states={'demo':loaded},state_directory=directory)
    assert runtime.calls==['cleanup'] and plan.protected
