"""Original helper intent progresses under the same all-host offline fence."""
from copy import deepcopy
import json
import subprocess
import shlex
import sys

import pytest
from dnlab_multinode.services import management_service_runtime as transport,management_barrier as barrier
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_management_prepare import setup
from tests.test_management_service_intent import inputs


def applied(f):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=f
    topo,model,configs=inputs(topo)
    controller.apply('services',topo,schedule,ips,targets,state,clients,save,registry=registry,service_configs=configs)
    return controller.driver.original(topo.name,'services')['plan']['services']


def response(bundle,action):
    if action=='preflight':return {'phase':'preflight','intent_fingerprint':bundle['fingerprint']}
    return {'phase':'materialized','intent_fingerprint':bundle['fingerprint'],
        'external_network_id':'e'*64,'jumphost':{'container_id':'a'*64,'nonce':'1'*32},
        'dns':{'container_id':'b'*64,'nonce':'2'*32},'functional_readiness_verified':False}


def test_services_follow_infrastructure_and_remain_fenced(setup,monkeypatch):
    bundle=applied(setup)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    seen=[]
    def invoke(client,intent,action):
        assert intent==bundle and client is clients['master']
        assert all(r.value['phase']=='applying' for r in runtimes.values())
        seen.append(action);return response(bundle,action)
    monkeypatch.setattr(transport,'invoke',invoke)
    result=controller.provision_services('services',topo.name,state,clients,save)
    assert seen==['preflight','apply'] and result['services']['phase']=='materialized'
    assert result['phase']=='provisioning' and all(r.value['phase']=='applying' for r in runtimes.values())
    assert state.jumphost is None and state.dns is None,'public readiness not yet published'


def test_failed_save_or_worker_fence_prevents_service_apply(setup,monkeypatch):
    bundle=applied(setup)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    calls=[]
    monkeypatch.setattr(transport,'invoke',lambda client,intent,action:calls.append(action) or response(bundle,action))
    def fail():raise OSError('checkpoint failed')
    with pytest.raises(OSError):controller.provision_services('services','demo',state,clients,fail)
    assert calls==['preflight']
    runtimes['worker1'].reject=True;calls.clear()
    with pytest.raises(RuntimeError):controller.provision_services('services','demo',state,clients,save)
    assert not calls


def test_lost_apply_reply_reuses_original_configuration_and_barrier(setup,monkeypatch):
    bundle=applied(setup)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    deliveries=[];fail=[True]
    def invoke(client,intent,action):
        if action=='apply':
            deliveries.append(deepcopy(intent))
            if fail[0]:fail[0]=False;raise RuntimeOperationError('lost service reply')
        return response(bundle,action)
    monkeypatch.setattr(transport,'invoke',invoke)
    with pytest.raises(RuntimeOperationError):controller.provision_services('services','demo',state,clients,save)
    assert barrier.get(store,'demo')['services']['phase']=='applying'
    assert controller.provision_services('services','demo',state,clients,save)['services']['phase']=='materialized'
    assert deliveries==[bundle,bundle]
    assert all(r.value['phase']=='applying' for r in runtimes.values())


@pytest.mark.parametrize('action,phase',[('preflight','preflight'),('observe','observed'),('probe','probed')])
def test_source_transport_is_standalone_and_keeps_credentials_off_argv(monkeypatch,action,phase):
    source=transport.program();seen={}
    from dnlab_multinode.services.jumphost import _WORKER_BOOTSTRAP
    import json
    class Client:
        def run_input(self,command,payload,**kwargs):
            seen.update(command=command,payload=payload)
            message=json.loads(payload)
            # Exercise imports/composition in a fresh interpreter, without
            # executing a host action or requiring an installed dnlab package.
            message['source']=message['source'].replace("if __name__=='__main__':main()", "if __name__=='__main__':print(json.dumps("+repr({'phase':phase,'intent_fingerprint':'fixture'})+"))")
            result=subprocess.run([sys.executable,'-c',_WORKER_BOOTSTRAP],input=json.dumps(message),text=True,capture_output=True)
            assert result.returncode==0,result.stderr
            return result.stdout
    assert len(source)>131072,'real composite source exceeds single-argument limit'
    value=transport.invoke(Client(),{'fingerprint':'fixture','secret':'private-marker'},action)
    assert value['phase']==phase
    assert 'private-marker' not in seen['command'] and 'private-marker' in seen['payload']
    assert len(shlex.split(seen['command'])[-1])<2048


def observed_materialization(setup,monkeypatch):
    bundle=applied(setup)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    networks={'default':'c'*64,'blue':'d'*64}
    calls=[]
    def invoke(client,intent,action):
        calls.append(action)
        if action=='observe':
            return dict(response(bundle,'apply'),phase='observed',mutations_performed=False,management_networks=networks)
        if action=='preflight':return dict(response(bundle,action),management_networks=networks)
        return response(bundle,action)
    monkeypatch.setattr(transport,'invoke',invoke)
    controller.provision_services('services','demo',state,clients,save)
    calls.clear()
    return invoke,calls


def test_coordinator_observes_all_hosts_and_services_without_release(setup,monkeypatch):
    invoke,calls=observed_materialization(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    before=deepcopy({h:r.value for h,r in runtimes.items()});events.clear()
    result=controller.observe_services('services','demo',state,clients,save)
    assert calls==['observe']
    assert result['phase']=='provisioning' and result['services']['phase']=='materialized'
    observed=result['services']['observation']
    assert set(observed['infrastructure'])==set(targets)
    assert observed['services']['functional_readiness_verified'] is False
    assert all(action in ('verify-ready','network-verify-ready') for host,action in events)
    assert before=={h:r.value for h,r in runtimes.items()}
    assert state.jumphost is None and state.dns is None
    assert controller.observe_services('services','demo',state,clients,save)==result


@pytest.mark.parametrize('fault',['container','nonce','network','management','mutation','functional'])
def test_coordinator_refuses_observation_drift_and_keeps_barrier(setup,monkeypatch,fault):
    invoke,calls=observed_materialization(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    original=barrier.get(store,'demo')
    def changed(client,intent,action):
        value=deepcopy(invoke(client,intent,action))
        if fault=='container':value['jumphost']['container_id']='f'*64
        elif fault=='nonce':value['dns']['nonce']='f'*32
        elif fault=='network':value['external_network_id']='f'*64
        elif fault=='management':value['management_networks']['blue']='f'*64
        elif fault=='mutation':value['mutations_performed']=True
        elif fault=='functional':value['functional_readiness_verified']=True
        return value
    monkeypatch.setattr(transport,'invoke',changed)
    with pytest.raises(RuntimeOperationError,match='observed services differ'):
        controller.observe_services('services','demo',state,clients,save)
    assert barrier.get(store,'demo')==original


def test_failed_all_host_readiness_prevents_master_service_observation(setup,monkeypatch):
    invoke,calls=observed_materialization(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    clients['worker1'].reject='verify-ready'
    with pytest.raises(RuntimeError):controller.observe_services('services','demo',state,clients,save)
    assert not calls and 'observation' not in barrier.get(store,'demo')['services']


def test_observation_checkpoint_error_is_propagated_and_retry_remains_fenced(setup,monkeypatch):
    invoke,calls=observed_materialization(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    def fail():raise OSError('checkpoint failed')
    with pytest.raises(OSError,match='checkpoint failed'):
        controller.observe_services('services','demo',state,clients,fail)
    pending=barrier.get(store,'demo')
    assert pending['phase']=='provisioning' and 'observation' in pending['services']
    assert controller.observe_services('services','demo',state,clients,save)==pending
    assert calls==['observe','observe'] and all(r.value['phase']=='applying' for r in runtimes.values())


def test_coordinator_records_partial_probes_without_publishing_or_release(setup,monkeypatch):
    invoke,calls=observed_materialization(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    def probing(client,intent,action):
        if action!='probe':return invoke(client,intent,action)
        calls.append(action)
        return {'phase':'probed','intent_fingerprint':intent['fingerprint'],
            'observation':invoke(client,intent,'observe'),'dns':{'level':'dns-packets'},
            'dhcp':{'level':'dhcp-listeners'},'functional_readiness_verified':False,'service_mutations_performed':False}
    monkeypatch.setattr(transport,'invoke',probing)
    result=controller.probe_services('services','demo',state,clients,save)
    assert result['phase']=='provisioning'
    assert result['services']['probes']['dns']['level']=='dns-packets'
    assert result['services']['probes']['functional_readiness_verified'] is False
    assert state.jumphost is None and state.dns is None
    assert all(r.value['phase']=='applying' for r in runtimes.values())


def test_failed_dns_probe_keeps_materialized_resources_and_fence(setup,monkeypatch):
    invoke,calls=observed_materialization(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    def failing(client,intent,action):
        if action=='probe':raise RuntimeOperationError('DNS packet failure')
        return invoke(client,intent,action)
    monkeypatch.setattr(transport,'invoke',failing)
    with pytest.raises(RuntimeOperationError,match='DNS packet failure'):
        controller.probe_services('services','demo',state,clients,save)
    current=barrier.get(store,'demo')
    assert current['phase']=='provisioning' and current['services']['phase']=='materialized'
    assert 'probes' not in current['services']
    assert all(r.value['phase']=='applying' for r in runtimes.values())
