from copy import deepcopy
import json

import pytest

from dnlab_multinode.controllers.management_prepare import ManagementPreparation
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.services import netsetup,management_barrier as barrier
from dnlab_multinode.services.management_host import Worker,ManagementError
from dnlab_multinode.services.management_network_host import NetworkGuard
from dnlab_multinode.services.realnet_vni import Registry
from dnlab_multinode.services.runtime_operations import OperationStore,RuntimeOperationError
from tests.test_management_host import Host,SCOPE
from tests.test_management_network_host import Docker


class Runtime:
    def __init__(self,journal):self.journal=journal;self.value=None;self.calls=[];self.reject=False
    def bound_to(self,journal):assert journal==self.journal;return self
    def management_barrier(self,lab,action,payload):
        self.calls.append(action)
        if self.reject:raise RuntimeError('fixture runtime unavailable')
        phase={'plan':'planned','acquire':'held','activate':'applying','cancel':'cancelled','release':'released'}[action]
        result={'lab_id':lab,'journal_id':self.journal,**payload,'phase':phase,'workload_fingerprint':'e'*64,
                'mutations_performed':False,'acquisition_observed':action!='plan'}
        if action!='plan':self.value=deepcopy(result)
        return result


class Client:
    def __init__(self,host,directory,events):self.name=host;self.directory=directory;self.host=Host();self.docker=Docker();self.events=events;self.reject=None
    def worker(self,p):
        worker=Worker(p,directory=self.directory,run=self.host.run,host_context=lambda:SCOPE,kernel=self.host.kernel)
        worker.network_factory=lambda w,n,**kw:NetworkGuard(w,n,docker=self.docker,plugin=lambda:deepcopy(self.docker.plugin),**kw)
        return worker
    def run_input(self,command,payload,**kwargs):
        data=json.loads(payload);action=data['action'];self.events.append((self.name,action))
        if self.reject==action:raise RuntimeError('fixture management operation refused')
        worker=self.worker(data['plan'])
        if action.startswith('network-'):
            guard=worker.network_factory(worker,data['networks'],socket_path=data['socket_path'],plugin_path=data['plugin_path'])
            value=guard.operate(action.removeprefix('network-'),data.get('operation_id'))
        else:value=worker.operate(action,data.get('segments'))
        return json.dumps(value)


@pytest.fixture
def setup(topo_factory,tmp_path,monkeypatch):
    topo=topo_factory(name='demo',num_workers=1);state=DeploymentState(lab_name='demo',topology_file='fixture.yml',runtime_mode='custom')
    ips={'master':'192.0.2.1','worker1':'192.0.2.2'};events=[]
    clients={h:Client(h,tmp_path/h,events) for h in ips}
    runtimes={h:Runtime(str(i)*32) for i,h in enumerate(ips,1)}
    targets={h:{'target':{'host':h,'socket_path':'/run/runtime.sock','container_name':None},'journal_id':r.journal} for h,r in runtimes.items()}
    store=OperationStore(tmp_path/'coordinator');controller=ManagementPreparation(store,lambda target:runtimes[target['host']])
    schedule=SchedulePlan(lab_name='demo',assignments={},vrf_table_id=42000)
    registry=Registry(tmp_path/'vni');saves=[]
    monkeypatch.setattr(netsetup,'snapshots',lambda c,hs:{h:{'context':SCOPE,'links':deepcopy(list(clients[h].host.links.values()))} for h in hs})
    yield topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,lambda:saves.append(deepcopy(state.to_dict()))
    store.close()


def apply(f,**kwargs):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=f
    return controller.apply('prepare',topo,schedule,ips,targets,state,clients,kwargs.get('checkpoint',save),registry=registry)


def test_complete_infrastructure_is_ready_but_workload_fence_remains_for_services(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    result=apply(setup)
    assert result['phase']=='provisioning' and result['infrastructure']['phase']=='infrastructure-ready'
    assert set(result['infrastructure']['proofs'])==set(ips)
    assert all(r.value['phase']=='applying' for r in runtimes.values())
    assert state.mgmt.infrastructure['phase']=='active' and state.mgmt.infrastructure['network_phase']=='active'
    assert len(events)>0
    assert events.index(('worker1','network-preflight-provision-recover'))<events.index(('master','provision'))
    assert all(len(c.docker.networks)==1 for c in clients.values())
    with pytest.raises(RuntimeOperationError,match='before provisioning'):controller.driver.cancel('demo','prepare')


@pytest.mark.parametrize('failure',['kernel','network','checkpoint'])
def test_partial_apply_recovers_same_generation_and_network_id_without_recreation(setup,failure):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    if failure=='kernel':clients['master'].host.after='create'
    if failure=='network':clients['worker1'].docker.after='create'
    once=[True]
    def failing_save():
        save()
        if once[0] and state.mgmt and state.mgmt.infrastructure['phase']=='preflight':
            once[0]=False;raise OSError('injected checkpoint failure')
    with pytest.raises((RuntimeError,OSError)):apply(setup,checkpoint=failing_save if failure=='checkpoint' else save)
    original=barrier.get(store,'demo');generation=original['plan']['management_generation']
    ids={h:set(c.docker.networks) for h,c in clients.items()}
    with pytest.raises(RuntimeOperationError,match='before provisioning'):controller.driver.cancel('demo','prepare')
    result=apply(setup)
    assert result['plan']['management_generation']==generation
    assert result['infrastructure']['phase']=='infrastructure-ready'
    assert all(ids[h]<=set(c.docker.networks) for h,c in clients.items())
    assert all(len(c.docker.calls)==1 for c in clients.values())


def test_changed_input_on_retry_cannot_mutate_any_host(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    apply(setup);before=deepcopy(events);schedule.vrf_table_id+=1
    with pytest.raises(RuntimeOperationError,match='intent changed'):apply(setup)
    assert events==before


def test_runtime_replacement_or_unavailability_refuses_before_replay_mutations(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    apply(setup);before=deepcopy(events);runtimes['worker1'].reject=True
    with pytest.raises(RuntimeError,match='runtime unavailable'):apply(setup)
    assert events==before


def test_unqualified_state_replacement_is_not_overwritten_on_recovery(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    apply(setup);state.mgmt.infrastructure['generation']='f'*32;before=deepcopy(events)
    with pytest.raises(RuntimeOperationError,match='state differs'):apply(setup)
    assert state.mgmt.infrastructure['generation']=='f'*32 and events==before


def test_additional_segment_preserves_original_networks_and_kernel_identities(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    topo.raw={'management_networks':{'default':{'ipv4-subnet':'198.18.1.0/24','ipv6-subnet':'2001:db8:1::/64'}}}
    first=apply(setup)
    evidence={'plan_fingerprint':first['plan_fingerprint'],'hosts':first['infrastructure']['proofs']}
    controller.driver.release('demo','prepare',lambda *args:evidence)
    ids={h:set(c.docker.networks) for h,c in clients.items()}
    links={h:deepcopy(c.host.links) for h,c in clients.items()}
    generation=first['plan']['management_generation'];events.clear()
    topo.raw['management_networks']['blue']={'ipv4-subnet':'198.18.2.0/24','ipv6-subnet':'2001:db8:2::/64'}
    result=controller.apply('add-blue',topo,schedule,ips,targets,state,clients,save,registry=registry)
    assert result['infrastructure']['phase']=='infrastructure-ready'
    assert result['plan']['management_generation']==generation
    for host,client in clients.items():
        assert len(client.docker.networks)==2 and ids[host]<=set(client.docker.networks)
        assert all(client.host.links[name]==old for name,old in links[host].items())
        assert set(state.mgmt.infrastructure['plans'][host]['segments'])=={'default','blue'}


def test_failed_state_save_before_preparation_forbids_reservations_and_host_operations(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    def fail():raise OSError('state save rejected')
    with pytest.raises(OSError):apply(setup,checkpoint=fail)
    assert not registry.directory.exists() and events==[]
    assert barrier.get(store,'demo')['phase']=='provisioning'


def test_stale_saved_state_can_restore_only_original_journaled_checkpoints(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    clients['worker1'].docker.after='create'
    with pytest.raises(RuntimeError):apply(setup)
    original_ids={h:set(c.docker.networks) for h,c in clients.items()}
    state.mgmt=None  # Simulate the original pre-operation deployment file.
    fresh=OperationStore(store.directory)
    try:
        resumed=ManagementPreparation(fresh,lambda target:runtimes[target['host']])
        result=resumed.apply('prepare',topo,schedule,ips,targets,state,clients,save,registry=registry)
        assert result['infrastructure']['phase']=='infrastructure-ready'
        assert all(original_ids[h]==set(c.docker.networks) for h,c in clients.items())
    finally:fresh.close()


def test_readiness_failure_retains_barrier_and_original_network_generations(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    clients['worker1'].reject='network-verify-ready'
    with pytest.raises(RuntimeError):apply(setup)
    ids={h:set(c.docker.networks) for h,c in clients.items()}
    assert barrier.get(store,'demo')['phase']=='provisioning'
    assert barrier.get(store,'demo')['infrastructure']['phase']!='infrastructure-ready'
    clients['worker1'].reject=None
    assert apply(setup)['infrastructure']['phase']=='infrastructure-ready'
    assert all(ids[h]==set(c.docker.networks) for h,c in clients.items())


def test_release_cannot_run_concurrently_with_infrastructure_mutation(setup,monkeypatch):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    original=clients['master'].run_input;seen=[]
    def intercept(command,payload,**kwargs):
        if json.loads(payload)['action']=='provision':
            other=OperationStore(store.directory)
            try:
                driver=barrier.Driver(other,lambda target:runtimes[target['host']])
                with pytest.raises(RuntimeOperationError,match='already executing'):
                    driver.release('demo','prepare',lambda *args:pytest.fail('readiness callback crossed apply lock'))
                seen.append(True)
            finally:other.close()
        return original(command,payload,**kwargs)
    monkeypatch.setattr(clients['master'],'run_input',intercept)
    assert apply(setup)['infrastructure']['phase']=='infrastructure-ready'
    assert seen==[True]
