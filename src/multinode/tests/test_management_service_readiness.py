"""Original packet coverage and fresh resource proofs gate workload admission."""
from copy import deepcopy
import pytest
from dnlab_multinode.services import management_service_runtime as services,management_probe_runtime as probes,management_barrier as barrier
from dnlab_multinode.services.management_packet_receipt import dns_expected
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_management_prepare import setup
from tests.test_management_probe_lifecycle import ready
from tests.test_management_packet_probes import receipt
from tests.test_management_routing_probe import result as routed_result


@pytest.fixture
def qualified(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch,static_segment=True,ipv6=True)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    previous=services.invoke;fault={'mode':None,'profiles':0}
    def service(client,intent,action):
        observed=previous(client,intent,'observe')
        if action=='probe':return {'observation':observed,'dns':{'level':'dns-packets'},'dhcp':{'level':'dhcp-listeners'},'functional_readiness_verified':False,'service_mutations_performed':False}
        if action=='packet_profiles':
            fault['profiles']+=1
            value={'observation':{'observation':observed},'service_mutations_performed':False,
                   'servers':{key:{'mac':'02:00:00:00:00:fe','link_local':'fe80::fe'} for key in intent['packet_probe_identities']}}
            if fault['mode']=='profile-drift' and fault['profiles']>1:value['servers']['blue']['mac']='02:00:00:00:00:ff'
            return value
        if action=='routing_snapshot':return {'observation':observed,'validation':{'status':'accepted'},'service_mutations_performed':False}
        value=previous(client,intent,action)
        if action=='observe' and fault['mode']=='service-replaced':value['dns']['container_id']='f'*64
        return value
    monkeypatch.setattr(services,'invoke',service)
    def packet(client,request,action,**kw):
        value=invoke(client,request,action,**kw)
        if action=='packets':
            p=request['packet_profile'];mode=p.get('mode')
            value['packet_result']=({'level':'dns-client-packets','answers':{k:dict(row,sent=1,checksum_status=['verified']) for k,row in dns_expected(p).items()}} if mode=='dns-client' else routed_result(p) if mode=='routed-pair' else receipt(p))
        if action=='verify-cleaned' and fault['mode']=='cleanup-conflict':raise RuntimeOperationError('original cleanup no longer verified')
        return value
    monkeypatch.setattr(probes,'invoke',packet)
    controller.probe_services('probe','demo',state,clients,save)
    controller.qualify_probe_lifecycle('probe','demo',state,clients,save)
    controller.qualify_probe_packets('probe','demo',state,clients,save)
    controller.qualify_routing('probe','demo',state,clients,save)
    controller.qualify_dns_clients('probe','demo',state,clients,save)
    calls.clear();fault['profiles']=0
    for runtime in runtimes.values():runtime.calls.clear()
    return setup,calls,fault


def test_complete_original_network_qualifications_release_without_new_packet_execution(qualified):
    setup,calls,fault=qualified
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    before=deepcopy(barrier.get(store,'demo'))
    result=controller.release_network_services('probe','demo',state,clients)
    assert result['phase']=='released' and result['readiness_fingerprint']==barrier.digest(result['readiness'])
    assert set(result['readiness']['hosts'])==set(targets)
    assert all(proof['scope']=='management-network-services-v1' for proof in result['readiness']['hosts'].values())
    assert calls and all(action=='verify-cleaned' for host,action,request in calls)
    assert all(runtime.calls==['release'] for runtime in runtimes.values())
    for field in ('packet_probes','dns_client_probes','routing_probes','probe_lifecycle'):
        assert before[field]==result[field]
    calls.clear();assert controller.release_network_services('probe','demo',state,clients)==result
    assert calls==[]


@pytest.mark.parametrize('fault_name',['missing-stage','missing-dns-host','missing-dhcp','missing-pair','orphan-entry','pending-cleanup','bad-packet','wrong-network','wrong-birth','wrong-exec','service-replaced','profile-drift','cleanup-conflict','state-model'])
def test_missing_or_changed_qualification_keeps_every_runtime_fenced(qualified,fault_name):
    setup,calls,fault=qualified
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    row=barrier.get(store,'demo');stage=row['dns_client_probes'];entry=next(iter(stage['entries'].values()))
    if fault_name=='missing-stage':row.pop('packet_probes')
    elif fault_name=='missing-dns-host':stage['requests'].pop()
    elif fault_name=='missing-dhcp':row['packet_probes']['requests']=[]
    elif fault_name=='missing-pair':row['routing_probes']['pairs'].pop()
    elif fault_name=='orphan-entry':stage['entries']['foreign']=deepcopy(entry)
    elif fault_name=='pending-cleanup':entry['phase']='cleanup_pending'
    elif fault_name=='bad-packet':entry['packets']['answers'].clear()
    elif fault_name=='wrong-network':stage['requests'][0]['network_id']='f'*64
    elif fault_name=='wrong-birth':entry['birth']['peer']['address']='02:00:00:00:00:ff'
    elif fault_name=='wrong-exec':entry['execution']['container_id']='f'*64
    elif fault_name=='state-model':state.management_plan['networks']['blue']['dhcp']=True
    else:fault['mode']=fault_name
    with store.transaction():barrier.put(store,'demo',row)
    with pytest.raises(RuntimeError):controller.release_network_services('probe','demo',state,clients)
    assert barrier.get(store,'demo')['phase']=='provisioning'
    assert all(runtime.calls==[] and runtime.value['phase']=='applying' for runtime in runtimes.values())
    assert all(action=='verify-cleaned' for host,action,request in calls)
