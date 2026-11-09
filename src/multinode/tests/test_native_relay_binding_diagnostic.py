"""Inert regressions: console routing must honor the native VD generation."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from dnlab_multinode import api
from dnlab_multinode.models.state import RuntimeRelayState
from dnlab_multinode.services import relay_resolution as resolution
from tests.test_native_public import native,SSH


@pytest.fixture
def routing(native,monkeypatch):
    ctrl,client,docker,store=native
    runtime=ctrl.state.node_runtime['R1']
    relay=RuntimeRelayState(host='master',container='relay-original',bind_ip='127.0.0.1',port=19001,
        api_key='fixture-key',allowed=[runtime.container],generation='a'*32,container_id='b'*64)
    ctrl.state.runtime_relays={'master':relay}
    record={'phase':'active','container_id':relay.container_id,'config':{
        'lab':'demo','host':'master','generation':relay.generation,'name':relay.container,
        'bind_ip':relay.bind_ip,'port':relay.port,'api_key':relay.api_key},
        'image':{'Config':{'Labels':{'io.dnlab.runtime-relay.capabilities':resolution.CAPABILITY}}}}
    monkeypatch.setattr(api,'_lab_state',lambda req:ctrl.state)
    monkeypatch.setattr(resolution,'load_hosts_config',lambda path:SimpleNamespace(all_hosts={'master':object()}))
    monkeypatch.setattr(resolution,'create_clients',lambda hosts:{'master':SSH()})
    calls=[]
    def guard(*args):calls.append(args);return deepcopy(record)
    monkeypatch.setattr(resolution.relays,'_guard',guard)
    return ctrl,client,docker,store,record,calls


def request(ctrl):
    return api.NodeRequest(topology_file=ctrl.state.topology_file,lab_name='demo',node='R1')


@pytest.mark.parametrize('conflict',['replacement','missing-binding'])
def test_native_console_resolution_refuses_unqualified_generation(routing,conflict):
    ctrl,client,docker,store,record,calls=routing
    runtime=ctrl.state.node_runtime['R1'];original=runtime.runtime_binding['container_id']
    if conflict=='replacement':
        docker.containers[runtime.container]['Id']='c'*64
        assert docker.containers[runtime.container]['Id']!=original
    else:runtime.runtime_binding={}
    before=deepcopy(docker.calls)
    with pytest.raises(RuntimeError):api._runtime_relay(request(ctrl))
    assert docker.calls==before and calls==[]


def test_native_console_resolution_returns_original_id_without_mutation(routing):
    ctrl,client,docker,store,record,calls=routing
    before=deepcopy(docker.calls);state=deepcopy(ctrl.state.to_dict())
    result=api._runtime_relay(request(ctrl))
    assert result['container_id']==ctrl.state.node_runtime['R1'].runtime_binding['container_id']
    assert result['runtime_backend']=='custom' and len(calls)==2
    assert docker.calls==before and ctrl.state.to_dict()==state


@pytest.mark.parametrize('conflict',['relay-generation','relay-id','capability','pending','stopped','name'])
def test_native_console_resolution_refuses_incompatible_relay_or_vd(routing,conflict):
    ctrl,client,docker,store,record,calls=routing
    if conflict=='relay-generation':record['config']['generation']='c'*32
    if conflict=='relay-id':record['container_id']='d'*64
    if conflict=='capability':record['image']['Config']['Labels']={}
    if conflict=='pending':record['phase']='cleanup_pending'
    if conflict=='stopped':docker.containers[ctrl.state.node_runtime['R1'].container]['State']['Running']=False
    if conflict=='name':ctrl.state.node_runtime['R1'].container='another-name'
    before=deepcopy(docker.calls)
    with pytest.raises(RuntimeError):api._runtime_relay(request(ctrl))
    assert docker.calls==before


@pytest.mark.parametrize('field,value',[('generation',99),('revision',99),('journal_id','changed'),('spec_fingerprint','changed')])
def test_native_console_rejects_changed_binding_evidence(routing,field,value):
    ctrl,client,docker,store,record,calls=routing
    ctrl.state.node_runtime['R1'].runtime_binding[field]=value
    before=deepcopy(docker.calls)
    with pytest.raises(RuntimeError):api._runtime_relay(request(ctrl))
    assert docker.calls==before and not calls


def test_native_console_refuses_pending_original_stop(routing):
    from dnlab_multinode.services.runtime_operations import OperationDriver
    ctrl,client,docker,store,record,calls=routing
    driver=OperationDriver(store,lambda target:client)
    original=store.get('demo','initial',private=True)
    req={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'console-pending-stop',
         'action':'stop','stop_mode':'coordinated','expected_revision':1}
    driver.prepare(req,original['target']);driver.advance('demo',req['request_id'])
    before=deepcopy(docker.calls)
    with pytest.raises(RuntimeError):api._runtime_relay(request(ctrl))
    assert docker.calls==before and not calls


def test_native_console_refuses_relay_changed_between_observations(routing,monkeypatch):
    ctrl,client,docker,store,record,calls=routing
    count=[]
    def guard(*args):
        count.append(args);value=deepcopy(record)
        if len(count)>1:value['container_id']='c'*64
        return value
    monkeypatch.setattr(resolution.relays,'_guard',guard)
    with pytest.raises(RuntimeError,match='changed during observation'):api._runtime_relay(request(ctrl))
    assert len(count)==2
