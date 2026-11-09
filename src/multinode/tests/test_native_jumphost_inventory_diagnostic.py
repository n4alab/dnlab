"""Native inventory publication survives crashes without restarting the VD."""
from copy import deepcopy
import json
import pytest
from dnlab_multinode.models.state import JumphostState,RuntimeRelayState
from dnlab_multinode.services import jumphost,state as state_svc,runtime_relay
from tests.test_native_public import native


def configure(native):
    ctrl,client,docker,store=native
    runtime=ctrl.state.node_runtime['R1']
    ctrl.state.runtime_relays={'master':RuntimeRelayState(
        host='master',container='relay',bind_ip='127.0.0.1',port=19001,api_key='fixture-key',
        allowed=[runtime.container],generation='a'*32,container_id='b'*64)}
    ctrl.state.jumphost=JumphostState(node='master',container='jumphost',mgmt_ip='192.0.2.1',
        host_ip='198.51.100.2',ext_network='external',generation='c'*32)
    state_svc.save_state(ctrl.state,ctrl.state_dir)
    return ctrl,client,docker,store


@pytest.fixture
def inventory(native,monkeypatch):
    ctrl,client,docker,store=configure(native)
    relay=ctrl.state.runtime_relays['master']
    rr={'phase':'active','container_id':relay.container_id,'config':{
        'lab':'demo','host':'master','generation':relay.generation,'name':relay.container,
        'bind_ip':relay.bind_ip,'port':relay.port,'api_key':relay.api_key},
        'image':{'Config':{'Labels':{'io.dnlab.runtime-relay.capabilities':'qualified-container-id-v1'}}}}
    monkeypatch.setattr(runtime_relay,'_guard',lambda *a:deepcopy(rr))
    record={'config':{'lab':'demo','name':'jumphost','generation':'c'*32},'nonce':'d'*32,
            'container_id':'e'*64,'image':{'Id':'sha256:'+'f'*64,'Config':{'Labels':{
                'io.dnlab.jumphost.capabilities':'qualified-relay-inventory-v1'}}},
            'context':{'boot':'fixture'},'phase':'active','inventory_current':None,'inventory_operation':None}
    control={'record':record,'calls':[],'writes':0,'failure':None}
    def guard(ssh,lab,action,request=None):
        control['calls'].append((action,deepcopy(request)))
        row=control['record']
        if action=='read':return deepcopy(row)
        assert action in ('inventory-refresh','recover')
        parent=store.db.execute("SELECT phase,payload FROM public_requests WHERE lab='demo' AND phase='pending'").fetchone()
        assert parent and json.loads(parent['payload'])['inventory']['manifest']['desired']
        if action=='recover':
            request=row['inventory_operation']['desired']
        elif row['inventory_current']==request:
            return deepcopy(row)
        else:
            row['inventory_operation']={'desired':deepcopy(request),'previous':deepcopy(row['inventory_current'])}
            row.update(phase='inventory_pending',action='inventory')
        if control['failure']=='pending':
            control['failure']=None;raise OSError('lost before publication')
        row['inventory_current']=deepcopy(request);row.update(phase='active',inventory_operation=None)
        control['writes']+=1
        if control['failure']=='ack':
            control['failure']=None;raise OSError('lost publication acknowledgement')
        return deepcopy(row)
    monkeypatch.setattr(jumphost,'_guard',guard)
    return ctrl,client,docker,store,control


def job(store):
    row=store.db.execute("SELECT phase,payload FROM public_requests WHERE request_id='inventory-restart'").fetchone()
    return row['phase'],json.loads(row['payload'])


def test_native_inventory_carries_original_container_identity(inventory):
    ctrl,client,docker,store,control=inventory
    bindings={k:r.runtime_binding for k,r in ctrl.state.node_runtime.items()}
    row=jumphost.relay_inventory_from_state(ctrl.state,verified_bindings=bindings)[ctrl.state.node_runtime['R1'].container]
    assert row['runtime_backend']=='custom'
    assert row['container_id']==ctrl.state.node_runtime['R1'].runtime_binding['container_id']
    with pytest.raises(RuntimeError,match='verified bindings'):jumphost.relay_inventory_from_state(ctrl.state)


def test_native_restart_cannot_complete_without_publishing_new_inventory(inventory):
    ctrl,client,docker,store,control=inventory
    original=ctrl.state.node_runtime['R1'].runtime_binding['container_id']
    state=ctrl.restart('R1',request_id='inventory-restart')
    current=state.node_runtime['R1'].runtime_binding['container_id'];phase,payload=job(store)
    assert current!=original and phase=='completed' and payload['inventory_phase']=='published'
    assert current in control['record']['inventory_current']['relays'] and original not in control['record']['inventory_current']['relays']
    calls=deepcopy(docker.calls);ctrl.restart('R1',request_id='inventory-restart')
    assert docker.calls==calls and control['writes']==1


@pytest.mark.parametrize('failure',['pending','ack'])
@pytest.mark.parametrize('reconcile',[False,True])
def test_original_publication_recovers_without_second_restart(inventory,failure,reconcile):
    ctrl,client,docker,store,control=inventory;control['failure']=failure
    with pytest.raises(OSError):ctrl.restart('R1',request_id='inventory-restart')
    phase,payload=job(store);assert phase=='pending' and payload['1']=='completed'
    original=deepcopy(payload['inventory']);calls=deepcopy(docker.calls)
    current=ctrl.state.node_runtime['R1'].runtime_binding['container_id']
    assert docker.containers[ctrl.state.node_runtime['R1'].container]['State']['Running']
    if reconcile:state=ctrl.reconcile('R1')
    else:state=ctrl.restart('R1',request_id='inventory-restart')
    assert docker.calls==calls and state.node_runtime['R1'].runtime_binding['container_id']==current
    phase,payload=job(store);assert phase=='completed'
    assert payload['inventory']['manifest']==original['manifest'] and control['writes']==1


@pytest.mark.parametrize('conflict',['jumphost','vd','request','binding','capability'])
def test_recovery_preserves_conflicting_resources_without_write(inventory,conflict):
    ctrl,client,docker,store,control=inventory;control['failure']='pending'
    with pytest.raises(OSError):ctrl.restart('R1',request_id='inventory-restart')
    if conflict=='jumphost':control['record']['container_id']='1'*64
    if conflict=='vd':docker.containers[ctrl.state.node_runtime['R1'].container]['Id']='2'*64
    if conflict=='request':control['record']['inventory_operation']['desired']['request_id']='3'*32
    if conflict=='binding':
        state=state_svc.load_state('demo',ctrl.state_dir);state.node_runtime['R1'].runtime_binding['container_id']='4'*64;state_svc.save_state(state,ctrl.state_dir)
    if conflict=='capability':control['record']['image']['Config']['Labels']={}
    calls=deepcopy(docker.calls)
    with pytest.raises(Exception):ctrl.restart('R1',request_id='inventory-restart')
    assert docker.calls==calls and control['writes']==0 and job(store)[0]=='pending'


def test_pending_publication_fences_other_public_mutations(inventory):
    ctrl,client,docker,store,control=inventory;control['failure']='pending'
    with pytest.raises(OSError):ctrl.restart('R1',request_id='inventory-restart')
    calls=deepcopy(docker.calls)
    with pytest.raises(RuntimeError,match='publication pending'):ctrl.stop('R1',request_id='different-stop')
    assert docker.calls==calls


def test_preflight_failure_is_durable_and_reconcile_only_publishes(inventory):
    ctrl,client,docker,store,control=inventory
    labels=control['record']['image']['Config']['Labels'];value=labels.pop('io.dnlab.jumphost.capabilities')
    with pytest.raises(RuntimeError,match='capability'):ctrl.restart('R1',request_id='inventory-restart')
    assert job(store)[1]['inventory_phase']=='preparing'
    calls=deepcopy(docker.calls);labels['io.dnlab.jumphost.capabilities']=value
    ctrl.reconcile('R1')
    assert docker.calls==calls and job(store)[0]=='completed'


@pytest.mark.parametrize('boundary',['seal-before','seal-after','receipt-before','receipt-after'])
def test_checkpoint_loss_resumes_only_original_publication(inventory,monkeypatch,boundary):
    from dnlab_multinode.services.native_public import PublicLifecycle
    ctrl,client,docker,store,control=inventory;original=PublicLifecycle.save_job;armed=[True]
    def save(handler,parent,payload):
        publication=payload.get('inventory')
        match=publication and publication['phase']==('pending' if boundary.startswith('seal') else 'published')
        if armed[0] and match:
            armed[0]=False
            if boundary.endswith('after'):original(handler,parent,payload)
            raise OSError('injected checkpoint loss')
        return original(handler,parent,payload)
    monkeypatch.setattr(PublicLifecycle,'save_job',save)
    with pytest.raises(OSError,match='checkpoint loss'):ctrl.restart('R1',request_id='inventory-restart')
    calls=deepcopy(docker.calls);before=job(store)[1].get('inventory')
    assert job(store)[0]=='pending'
    ctrl.restart('R1',request_id='inventory-restart')
    assert docker.calls==calls and control['writes']==1 and job(store)[0]=='completed'
    if before:assert job(store)[1]['inventory']['manifest']==before['manifest']


def test_final_state_checkpoint_failure_keeps_publication_pending(inventory,monkeypatch):
    ctrl,client,docker,store,control=inventory;original=state_svc.save_state;armed=[True]
    def save(state,directory):
        row=store.db.execute("SELECT payload FROM public_requests WHERE request_id='inventory-restart'").fetchone()
        if armed[0] and row and json.loads(row['payload']).get('inventory_phase')=='published':
            armed[0]=False;raise OSError('final state checkpoint failed')
        return original(state,directory)
    monkeypatch.setattr(state_svc,'save_state',save)
    with pytest.raises(OSError,match='final state'):ctrl.restart('R1',request_id='inventory-restart')
    assert job(store)[0]=='pending' and control['writes']==1
    calls=deepcopy(docker.calls);ctrl.restart('R1',request_id='inventory-restart')
    assert job(store)[0]=='completed' and docker.calls==calls and control['writes']==1


@pytest.mark.parametrize('action',['stop','remove'])
def test_stop_and_remove_publish_without_recreating_workload(inventory,action):
    ctrl,client,docker,store,control=inventory
    original=ctrl.state.node_runtime['R1'].runtime_binding['container_id']
    state=getattr(ctrl,action)('R1',request_id='inventory-'+action)
    content=control['record']['inventory_current']
    if action=='stop':assert original in content['relays'] and state.node_runtime['R1'].state=='stopped'
    else:assert not content['relays'] and 'R1' not in state.node_runtime
    assert docker.containers=={} and control['writes']==1


def test_pending_publication_refuses_missing_jumphost_metadata(inventory):
    ctrl,client,docker,store,control=inventory;control['failure']='pending'
    with pytest.raises(OSError):ctrl.restart('R1',request_id='inventory-restart')
    state=state_svc.load_state('demo',ctrl.state_dir);state.jumphost=None;state_svc.save_state(state,ctrl.state_dir)
    calls=deepcopy(docker.calls)
    with pytest.raises(RuntimeError,match='metadata missing'):ctrl.restart('R1',request_id='inventory-restart')
    assert job(store)[0]=='pending' and docker.calls==calls and control['writes']==0


def test_publication_retry_and_conflicting_request_do_not_mark_management_again(inventory,monkeypatch):
    from dnlab_multinode.models.state import MgmtState
    from dnlab_multinode.services import netsetup
    ctrl,client,docker,store,control=inventory
    ctrl.state.mgmt=MgmtState(subnet='192.0.2.0/24',gateway='192.0.2.1',bridge='br-m',vrf='vrf-m',vxlan_id=123,vxlan_iface='vx-m')
    state_svc.save_state(ctrl.state,ctrl.state_dir);network_calls=[]
    monkeypatch.setattr(netsetup,'network_action',lambda *a,**kw:network_calls.append(a[2]))
    control['failure']='pending'
    with pytest.raises(OSError):ctrl.restart('R1',request_id='inventory-restart')
    assert network_calls==['mark-used']
    with pytest.raises(RuntimeError,match='publication pending'):ctrl.start('R1',request_id='different-start')
    assert network_calls==['mark-used']
    calls=deepcopy(docker.calls);ctrl.restart('R1',request_id='inventory-restart')
    assert network_calls==['mark-used'] and docker.calls==calls


def test_remove_recovers_after_tombstone_checkpoint_before_completion(inventory,monkeypatch):
    ctrl,client,docker,store,control=inventory;original=state_svc.save_state;armed=[True]
    def save(state,directory):
        original(state,directory)
        if armed[0] and 'R1' in state.retired_native_nodes:
            armed[0]=False;raise OSError('lost tombstone checkpoint acknowledgement')
    monkeypatch.setattr(state_svc,'save_state',save)
    with pytest.raises(OSError,match='tombstone'):ctrl.remove('R1',request_id='inventory-remove')
    calls=deepcopy(docker.calls)
    state=ctrl.remove('R1',request_id='inventory-remove')
    assert 'R1' not in state.node_runtime and 'R1' in state.retired_native_nodes
    assert control['writes']==1 and docker.calls==calls
    assert store.db.execute("SELECT phase FROM public_requests WHERE request_id='inventory-remove'").fetchone()[0]=='completed'


def test_pending_publication_blocks_reconcile_of_another_node(inventory):
    from dnlab_multinode.models.state import NodeRuntimeState
    from dnlab_multinode.services.runtime_operations import OperationDriver
    from dnlab_multinode.services.runtime_cleanup import make_binding
    ctrl,client,docker,store,control=inventory
    ctrl.topo.links=[]  # This fixture qualifies inventory, without data endpoints.
    original=store.get('demo','initial',private=True);spec=deepcopy(original['request']['spec']);spec['container_name']='native-owned-R2'
    request={'schema_version':1,'lab_id':'demo','node_id':'R2','request_id':'initial-R2',
             'action':'start','expected_revision':0,'spec':spec}
    driver=OperationDriver(store,lambda target:client);driver.prepare(request,original['target']);driver.advance('demo','initial-R2')
    binding=make_binding(store,'demo','R2','initial-R2',client.inspect_node('demo','R2'))
    ctrl.state.node_runtime['R2']=NodeRuntimeState(node='R2',host='master',kind='linux',
        container=spec['container_name'],image=spec['image'],runtime_binding=binding)
    ctrl.state.runtime_relays['master'].allowed.append(spec['container_name'])
    state_svc.save_state(ctrl.state,ctrl.state_dir);control['failure']='pending'
    with pytest.raises(OSError):ctrl.restart('R1',request_id='inventory-restart')
    calls=deepcopy(docker.calls)
    with pytest.raises(RuntimeError,match='publication pending'):ctrl.reconcile('R2')
    assert docker.calls==calls and control['writes']==0
