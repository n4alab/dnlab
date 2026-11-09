"""All-host endpoint attempts are original, sequential and cleanup gated."""
from copy import deepcopy
import pytest
from dnlab_multinode.services import management_probe_runtime as transport,management_service_runtime as services,management_barrier as barrier
from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_management_prepare import setup
from tests.test_management_service_intent import inputs


def ready(f,monkeypatch,*,static_segment=False,ipv6=False):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=f
    topo.raw['management_networks']={'default':{'ipv4-subnet':topo.mgmt.ipv4_subnet,'dhcp':True}}
    if static_segment:topo.raw['management_networks']['blue']={'ipv4-subnet':'198.18.77.0/24','dhcp':False}
    if ipv6:
        for index,cfg in enumerate(topo.raw['management_networks'].values()):cfg['ipv6-subnet']='2001:db8:'+str(177+index)+'::/64'
    topo,model=resolve(topo,prepare_probes=True);topo,model,configs=inputs(topo,model);state.management_plan=model
    networks={key:('c' if key=='default' else 'd')*64 for key in model['networks']}
    def service(client,intent,action):
        value={'phase':'materialized','intent_fingerprint':intent['fingerprint'],'external_network_id':'e'*64,
            'jumphost':{'container_id':'a'*64,'nonce':'1'*32},'dns':{'container_id':'b'*64,'nonce':'2'*32},'functional_readiness_verified':False}
        if action=='preflight':return {'phase':'preflight','intent_fingerprint':intent['fingerprint'],'management_networks':deepcopy(networks)}
        if action=='observe':value.update(phase='observed',mutations_performed=False,management_networks=deepcopy(networks))
        return value
    monkeypatch.setattr(services,'invoke',service)
    controller.apply('probe',topo,schedule,ips,targets,state,clients,save,registry=registry,service_configs=configs)
    controller.provision_services('probe',topo.name,state,clients,save)
    calls=[]
    def invoke(client,request,action,*,expected_birth=None,expected_execution=None):
        from dnlab_multinode.services.runtime_operations import digest
        calls.append((request['host'],action,deepcopy(request)))
        if action=='preflight':return {'phase':'preflight','request_fingerprint':digest(request)}
        key=digest(['management-probe-v1',request]);nonce='3'*32
        host_mac='02:'+':'.join(digest([key,nonce])[i:i+2] for i in range(0,10,2))
        proof={'container_id':('a' if request['host']=='master' else 'b')*64,'nonce':nonce,'namespace':{'device':1,'inode':2},'started_at':'started',
            'host':{'ifname':'dmp'+key[:12],'ifindex':20,'link_index':21,'address':host_mac,'ifalias':'dnlab-management-probe:'+nonce,'kind':'veth'},
            'peer':{'ifname':'probe0','ifindex':21,'link_index':20,'address':request['identity']['mac'],'ifalias':'dnlab-management-probe:'+nonce,'kind':'veth'}}
        result={'phase':'active' if action in ('ensure','inspect','prepare-packets') else 'cleaned','request_fingerprint':digest(request),
            'cleanup_verified':action in ('cleanup','verify-cleaned'),'resource_proof':proof}
        if 'packet_profile' in request:
            result['execution']={'id':'e'*64,'container_id':proof['container_id'],'nonce':digest(['probe-exec-v1',key,nonce])[:32],'command_sha256':'a'*64}
            result['execution_status']={'exit_verified':True,'exit_code':0}
        return result
    monkeypatch.setattr(transport,'invoke',invoke)
    return calls,invoke


def test_endpoint_attempts_are_sequential_and_replay_only_verifies_cleanup(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    result=controller.qualify_probe_lifecycle('probe','demo',state,clients,save)
    assert [(h,a) for h,a,r in calls]==[('master','preflight'),('worker1','preflight'),('master','ensure'),('master','cleanup'),('master','verify-cleaned'),('worker1','ensure'),('worker1','cleanup'),('worker1','verify-cleaned')]
    assert result['phase']=='provisioning' and result['probe_lifecycle']['phase']=='completed'
    assert result['probe_lifecycle']['endpoint_lifecycle_only'] is True
    calls.clear();controller.qualify_probe_lifecycle('probe','demo',state,clients,save)
    assert all(action in ('preflight','verify-cleaned') for host,action,request in calls)
    assert all(r.value['phase']=='applying' for r in runtimes.values())


def test_endpoint_lifecycle_also_qualifies_static_management(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch,static_segment=True)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    result=controller.qualify_probe_lifecycle('probe','demo',state,clients,save)
    assert {r['segment'] for r in result['probe_lifecycle']['requests']}=={'default','blue'}
    assert len(result['probe_lifecycle']['entries'])==4
    assert state.management_plan['networks']['blue']['dhcp'] is False


def test_lost_cleanup_ack_keeps_current_host_and_recovers_without_second_ensure(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    failed=[False]
    def lost(client,request,action,**kwargs):
        value=invoke(client,request,action,**kwargs)
        if action=='cleanup' and not failed[0]:failed[0]=True;raise RuntimeOperationError('lost cleanup')
        return value
    monkeypatch.setattr(transport,'invoke',lost)
    with pytest.raises(RuntimeOperationError,match='lost cleanup'):controller.qualify_probe_lifecycle('probe','demo',state,clients,save)
    row=barrier.get(store,'demo')['probe_lifecycle']
    assert len(row['entries'])==1 and next(iter(row['entries'].values()))['phase']=='cleanup_pending'
    assert not any(host=='worker1' and action=='ensure' for host,action,request in calls)
    calls.clear();controller.qualify_probe_lifecycle('probe','demo',state,clients,save)
    assert not any(host=='master' and action=='ensure' for host,action,request in calls)
    assert any(host=='worker1' and action=='ensure' for host,action,request in calls)


def test_failed_checkpoint_prevents_first_endpoint_allocation(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    count=[0]
    def checkpoint():
        count[0]+=1
        if count[0]==2:raise OSError('save failed')
        save()
    with pytest.raises(OSError):controller.qualify_probe_lifecycle('probe','demo',state,clients,checkpoint)
    assert calls and all(action=='preflight' for host,action,request in calls)
