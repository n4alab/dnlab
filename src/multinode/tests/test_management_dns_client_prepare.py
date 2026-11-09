"""DNS from each management is original, sequential and cleanup gated."""
from copy import deepcopy
import pytest

from dnlab_multinode.services import management_probe_runtime as probes,management_service_runtime as services,management_barrier as barrier
from dnlab_multinode.services.management_packet_receipt import dns_expected,dns_profile
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_management_prepare import setup
from tests.test_management_probe_lifecycle import ready


def environment(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch,static_segment=True,ipv6=True)
    previous=services.invoke
    def service(client,intent,action):
        if action=='packet_profiles':
            return {'phase':'packet-profiles','intent_fingerprint':intent['fingerprint'],
                'observation':{'observation':previous(client,intent,'observe')},'service_mutations_performed':False,
                'servers':{key:{'mac':'02:00:00:00:00:fe','link_local':'fe80::fe'} for key in intent['packet_probe_identities']}}
        return previous(client,intent,action)
    monkeypatch.setattr(services,'invoke',service)
    def packet(client,request,action,**kwargs):
        dns_profile(request['packet_profile'],request)
        value=invoke(client,request,action,**kwargs)
        if action=='packets':
            answers={stage:dict(row,sent=2,checksum_status=['verified']) for stage,row in dns_expected(request['packet_profile']).items()}
            value.update(phase='active',cleanup_verified=False,packet_result={'level':'dns-client-packets','answers':answers})
        return value
    monkeypatch.setattr(probes,'invoke',packet)
    return calls,packet


def test_dns_covers_static_and_dhcp_segments_with_original_resolvers_and_replay(setup,monkeypatch):
    calls,invoke=environment(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    result=controller.qualify_dns_clients('probe','demo',state,clients,save)
    progress=deepcopy(result['dns_client_probes'])
    assert progress['phase']=='completed' and result['phase']=='provisioning'
    assert len(progress['requests'])==4 and {q['segment'] for q in progress['requests']}=={'default','blue'}
    for request in progress['requests']:
        p=request['packet_profile']
        assert p['records']==result['plan']['services']['dns_probe']['records']
        cfg=result['plan']['services']['management_plan']['networks'][request['segment']]
        assert p['resolvers']['4']==cfg['ipv4_gw']
        assert p['resolvers']['6']==cfg['ipv6_gw']
        assert set(p['resolvers'])=={'4','6'}
    calls.clear();assert controller.qualify_dns_clients('probe','demo',state,clients,save)['dns_client_probes']==progress
    assert all(action in ('preflight','verify-cleaned') for host,action,request in calls)
    assert all(r.value['phase']=='applying' for r in runtimes.values())


@pytest.mark.parametrize('action',['packets','cleanup'])
def test_lost_dns_ack_recovers_same_birth_and_exec_before_next_host(setup,monkeypatch,action):
    calls,invoke=environment(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    cut=[False]
    def lost(client,request,actual,**kwargs):
        result=invoke(client,request,actual,**kwargs)
        if actual==action and not cut[0]:cut[0]=True;raise RuntimeOperationError('lost DNS ack')
        return result
    monkeypatch.setattr(probes,'invoke',lost)
    with pytest.raises(RuntimeOperationError,match='lost DNS ack'):controller.qualify_dns_clients('probe','demo',state,clients,save)
    original=deepcopy(barrier.get(store,'demo')['dns_client_probes']);assert len(original['entries'])==1
    key,entry=next(iter(original['entries'].items()));calls.clear()
    result=controller.qualify_dns_clients('probe','demo',state,clients,save)['dns_client_probes']
    assert result['entries'][key]['birth']==entry['birth'] and result['entries'][key]['execution']==entry['execution']
    assert not any(r['request_id']==key and actual=='ensure' for host,actual,r in calls)
    assert result['phase']=='completed'


def test_partial_dns_response_preserves_attempt_without_cleanup_or_next_host(setup,monkeypatch):
    calls,invoke=environment(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    def wrong(client,request,action,**kwargs):
        value=invoke(client,request,action,**kwargs)
        if action=='packets':value['packet_result']['answers'].pop(next(iter(value['packet_result']['answers'])))
        return value
    monkeypatch.setattr(probes,'invoke',wrong)
    with pytest.raises(RuntimeOperationError,match='acknowledgement differs'):
        controller.qualify_dns_clients('probe','demo',state,clients,save)
    assert all(action not in ('cleanup','verify-cleaned') for host,action,request in calls)
    assert not any(host=='worker1' and action=='ensure' for host,action,request in calls)
    assert barrier.get(store,'demo')['phase']=='provisioning'
