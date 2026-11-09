"""Real retirement/coordinator/runtime/network journals; no host operations."""
from copy import deepcopy
from types import SimpleNamespace
import json

import pytest

from tests.test_runtime_initial_deploy import world
from tests.test_native_lifecycle_parser import segmented
from tests.test_runtime_management_parent import managed, prepare
from tests.test_managed_initial_publication import fixture_state
from dnlab_multinode.services import management_barrier as barrier, state as states, runtime_lab_closure as closure
from dnlab_multinode.services.runtime_cleanup import make_binding
from dnlab_multinode.models.state import NodeRuntimeState
from dnlab_multinode.services.initial_retirement import Retirement,CleanupSteps
from dnlab_multinode.services.retirement_network import observe
from dnlab_multinode.services.management_network_host import NetworkError
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from dnlab_runtime import lab_closure as local_closure
from dnlab_runtime.manifest import RuntimeErrorBase


@pytest.fixture
def retirement(managed,tmp_path,monkeypatch):
    (batch,store,clients,engines,_),topo,schedule,options=managed
    transport=clients['master'].ssh;engine=engines['master'];docker=engine.backend.docker
    metadata=barrier.get(store,'demo')['infrastructure']['snapshot']['infrastructure']
    worker=transport.worker(metadata['plans']['master']);networks=transport.docker
    guard=worker.network_factory(worker,metadata['networks']['master'])
    hook=docker.hook
    def mirror(event):
        hook(event)
        for net in networks.networks.values():net['Containers']={}
        networks.plugin['endpoints']={}
        for name,container in docker.containers.items():
            container['Name']='/'+name;container['Image']=container['Config']['Image']
            for network,endpoint in container['NetworkSettings']['Networks'].items():
                eid=endpoint.get('EndpointID')
                if not eid:continue
                value=next(v for v in networks.networks.values() if v['Name']==network)
                value['Containers'][container['Id']]={'Name':name,'EndpointID':eid,
                    'IPv4Address':endpoint['IPAddress']+'/24','IPv6Address':endpoint['GlobalIPv6Address']+'/64'}
                networks.plugin['endpoints'][eid]={'network_id':value['Id'],'ipv4':endpoint['IPAddress'],
                    'ipv6':endpoint['GlobalIPv6Address'],'mac':endpoint.get('MacAddress','')}
    docker.hook=mirror
    def call(method,path):
        assert method=='GET' and path.startswith('/containers/') and path.endswith('/json')
        return deepcopy(docker.find(path.split('/')[2]))
    networks.call=call
    prepare(managed)
    with monkeypatch.context() as patch:
        # Reproduce only the historical missing handoff, without changing any
        # product guard. The original runtime generations remain real.
        patch.setattr(batch.management_usage,'ensure',lambda *a:None)
        assert batch.advance('demo','deploy')['phase']=='completed'
    state=fixture_state(tmp_path,schedule,management_plan=topo.raw['dnlab_management_plan'],
                        publish_service_inventory=True,managed_initial_batch=True)
    for member in batch.members('demo','deploy'):
        spec=member['request']['spec'];node=member['node'];view=clients['master'].inspect_node('demo',node)
        state.node_runtime[node]=NodeRuntimeState(node=node,host='master',container=spec['container_name'],kind='linux',
            image=spec['image'],state='running',mgmt_ipv4=spec['management']['ipv4'],
            runtime_binding=make_binding(store,'demo',node,member['request_id'],view))
    states.save_state(state,tmp_path)
    clients['master'].lab_closure=lambda lab,action,payload:local_closure.control(engine,lab,action,payload)
    load=lambda:states.load_state('demo',tmp_path)
    checkpoint=lambda value:states.save_state(value,tmp_path)
    class Observer:
        def __call__(self,allowed):
            assert set(allowed)=={'master'}
            return {'master':observe(guard,allowed['master'])}
        def verify_absent(self,births):
            for birth in births.values():
                if docker.inspect(birth['request']['spec']['container_name']) or any(v['Id']==birth['binding']['container_id'] for v in docker.containers.values()):
                    raise RuntimeOperationError('original VD ID/name remains or was replaced')
    events=[];owners={}
    class Owner:
        def __init__(self,name):self.name=name;self.phase='active';self.fail=None;self.deleted=0
        def identity(self):return {'owner':self.name,'generation':'original-'+self.name}
        def preflight(self,pin,*,retiring=False):
            assert pin==self.identity();events.append(('preflight',self.name))
            if self.fail=='preflight':raise RuntimeOperationError('owner conflict')
        def cleanup(self,pin):
            self.preflight(pin)
            assert not docker.containers
            assert closure.get(store,'demo')['phase']=='closed'
            if self.fail=='before':raise OSError('cleanup failed before mutation')
            if self.phase!='cleaned':
                self.deleted+=1;events.append(('delete',self.name))
                if self.name=='management':
                    guard.operate('cleanup');worker.cleanup()
                    for name in list(docker.networks):
                        if name in {v['network'] for v in metadata['networks']['master'].values()}:docker.networks.pop(name)
                self.phase='cleaned'
            if self.fail=='ack':self.fail=None;raise OSError('lost cleanup acknowledgement')
        def verify_cleaned(self,pin):
            assert pin==self.identity()
            if self.phase!='cleaned':raise RuntimeOperationError('cleanup not verified')
            if self.name=='management':guard.operate('verify-cleaned')
    owners={name:Owner(name) for name in CleanupSteps.ORDER}
    steps=CleanupSteps(owners);observer=Observer()
    op=Retirement(batch,load,checkpoint,observer,steps)
    return SimpleNamespace(op=op,batch=batch,store=store,clients=clients,engine=engine,docker=docker,
        networks=networks,worker=worker,guard=guard,load=load,checkpoint=checkpoint,observer=observer,
        steps=steps,owners=owners,events=events)


def seal(f):return f.op.prepare('demo','retire','deploy',{'R1':'original-retire-stop'})


def finish(f):
    for _ in range(8):
        value=f.op.advance('demo','retire')
        if value['phase']=='cleaned':return value
    pytest.fail('retirement did not finish')


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_original_retirement_ordinary_stop_then_guarded_cleanup(retirement):
    f=retirement;original=deepcopy(f.worker.read());sealed=seal(f)
    assert sealed['phase']=='prepared' and f.worker.read()==original and not f.events[-1][0]=='delete'
    assert f.batch.management_usage.get('demo','deploy') is None
    result=finish(f)
    assert result['phase']=='cleaned' and not f.docker.containers and not f.networks.networks
    assert [name for action,name in f.events if action=='delete']==list(CleanupSteps.ORDER)
    assert ('signal','SIGTERM') in f.docker.calls and ('signal','SIGKILL') not in f.docker.calls
    assert all(not row['used'] for row in f.worker.read()['networks'].values())
    assert closure.get(f.store,'demo')['phase']=='closed'
    assert f.op.advance('demo','retire')['phase']=='cleaned'
    assert all(owner.deleted==1 for owner in f.owners.values())


@pytest.mark.parametrize('fault',['foreign-endpoint','plugin-extra','replaced-network','helper-conflict','replaced-vd'])
@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_preflight_refuses_conflicts_without_stop_or_delete(retirement,fault):
    f=retirement;net=next(v for v in f.networks.networks.values() if v['Containers'])
    if fault=='foreign-endpoint':net['Containers']['f'*64]={'Name':'foreign'}
    elif fault=='plugin-extra':f.networks.plugin['endpoints']['f'*64]={'network_id':net['Id']}
    elif fault=='replaced-network':net['Id']='f'*64
    elif fault=='helper-conflict':f.owners['external'].fail='preflight'
    elif fault=='replaced-vd':next(iter(f.docker.containers.values()))['Id']='f'*64
    calls=deepcopy(f.docker.calls)
    with pytest.raises((RuntimeError,RuntimeErrorBase,AssertionError)):seal(f)
    assert f.docker.calls==calls and not any(owner.deleted for owner in f.owners.values())
    assert f.op.get('demo','retire') is None


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_recovery_after_cleanup_ack_loss_preserves_dependencies(retirement):
    f=retirement;seal(f);f.owners['management'].fail='ack'
    with pytest.raises(OSError,match='lost cleanup'):finish(f)
    assert f.op.get('demo','retire')['phase']=='infrastructure_cleanup'
    assert f.owners['external'].deleted==0 and not f.networks.networks
    f.op=Retirement(f.batch,f.load,f.checkpoint,f.observer,f.steps)
    result=finish(f)
    assert result['phase']=='cleaned' and all(owner.deleted==1 for owner in f.owners.values())


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_conflict_after_seal_preserves_original_intent_and_resources(retirement):
    f=retirement;before=deepcopy(seal(f));net=next(v for v in f.networks.networks.values() if v['Containers'])
    net['Containers']['f'*64]={'Name':'foreign'}
    calls=deepcopy(f.docker.calls)
    with pytest.raises(NetworkError):f.op.advance('demo','retire')
    assert f.op.get('demo','retire')==before and f.docker.calls==calls


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_shutdown_failure_never_cleans_infrastructure(retirement):
    f=retirement;seal(f);f.docker.resist_term=True
    with pytest.raises(RuntimeOperationError,match='ordinary shutdown'):
        for _ in range(8):
            f.op.advance('demo','retire');f.engine.backend.sleep(5)
    assert f.docker.containers and not any(owner.deleted for owner in f.owners.values())
    assert closure.get(f.store,'demo')['phase']=='closing'


@pytest.mark.parametrize('boundary',['intent','fencing','cleanup','completed'])
@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_uncertain_checkpoint_recovers_original_retirement(retirement,monkeypatch,boundary):
    f=retirement;sync=f.store.sync_directory;failed=[]
    def uncertain():
        sync();row=f.op.get('demo','retire')
        selected=row and ((boundary=='intent' and row['phase']=='prepared')
            or (boundary=='fencing' and row['phase']=='fencing')
            or (boundary=='cleanup' and 'deleting' in row['progress']['cleanup'].values()))
        selected=selected or (row and boundary=='completed' and row['phase']=='cleaned')
        if selected and not failed:failed.append(True);raise OSError('uncertain durable retirement checkpoint')
    monkeypatch.setattr(f.store,'sync_directory',uncertain)
    with pytest.raises(OSError,match='uncertain durable'):
        seal(f);finish(f)
    original=deepcopy(f.op.get('demo','retire')['intent'])
    if boundary in ('intent','fencing'):
        assert not any(owner.deleted for owner in f.owners.values())
        assert ('signal','SIGTERM') not in f.docker.calls
    assert finish(f)['phase']=='cleaned'
    assert f.op.get('demo','retire')['intent']==original
    assert all(owner.deleted==1 for owner in f.owners.values())


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_closed_fence_rejects_new_start_and_conflicting_retirement(retirement):
    f=retirement;seal(f)
    with pytest.raises(RuntimeOperationError,match='another original operation'):
        f.op.prepare('demo','different','deploy',{'R1':'another-stop'})
    f.op.advance('demo','retire')
    start=deepcopy(f.batch.members('demo','deploy')[0]['request']);start['request_id']='unexpected-start'
    with pytest.raises(RuntimeOperationError,match='closing or closed'):
        f.store.prepare(start,f.batch.members('demo','deploy')[0]['target'],f.engine.journal.identity)


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_network_must_match_original_preparation_receipt(retirement,monkeypatch):
    f=retirement;observe=f.observer.__call__
    class Changed:
        def __call__(self,allowed):
            result=observe(allowed);next(iter(result['master']['networks'].values()))['nonce']='f'*32
            return result
    f.op.network_observer=Changed()
    calls=deepcopy(f.docker.calls)
    with pytest.raises(RuntimeOperationError,match='original preparation proof'):seal(f)
    assert f.docker.calls==calls and f.op.get('demo','retire') is None


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_lost_stop_ack_recovers_same_operation_without_second_shutdown(retirement,monkeypatch):
    f=retirement;seal(f);client=f.clients['master'];submit=client.submit_node
    def lost(request):
        result=submit(request);monkeypatch.setattr(client,'submit_node',submit)
        raise OSError('lost ordinary stop acknowledgement')
    monkeypatch.setattr(client,'submit_node',lost)
    with pytest.raises(OSError,match='lost ordinary'):f.op.advance('demo','retire')
    original=deepcopy(f.op.get('demo','retire')['intent'])
    assert not any(owner.deleted for owner in f.owners.values())
    assert finish(f)['phase']=='cleaned'
    assert f.op.get('demo','retire')['intent']==original
    assert sum(call==('signal','SIGTERM') for call in f.docker.calls)==1


@pytest.mark.parametrize('managed',[{'single_host':True,'container_name':None}],indirect=True)
def test_name_reuse_after_management_cleanup_blocks_remaining_dependencies(retirement):
    f=retirement;seal(f);f.owners['management'].fail='ack'
    with pytest.raises(OSError):finish(f)
    name=next(iter(f.op.get('demo','retire')['intent']['births'].values()))['request']['spec']['container_name']
    f.docker.containers[name]={'Id':'f'*64}
    with pytest.raises(RuntimeOperationError,match='remains or was replaced'):f.op.advance('demo','retire')
    assert f.owners['external'].deleted==0 and f.op.get('demo','retire')['phase']=='infrastructure_cleanup'
