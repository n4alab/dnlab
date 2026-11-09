"""Complete service inputs are bound before infrastructure admission/mutation."""
from copy import deepcopy

import pytest
from dnlab_multinode.services.management_service_intent import compile_service_intent
from dnlab_multinode.services.management_services import compile_services
from dnlab_multinode.services.management_segments import resolve,SegmentError
from dnlab_multinode.services.management_dhcp import compile_dhcp
from dnlab_multinode.services.mgmt_network import _expected_network
from dnlab_multinode.services.hostsfile import HostEntry
from dnlab_multinode.services.runtime_operations import digest,RuntimeOperationError
from dnlab_multinode.utils.naming import micro_vd_container_name
from tests.test_management_services import external
from tests.test_management_segments import input_topology
from tests.test_management_prepare import setup


def inputs(topo,previous=None):
    topo=deepcopy(topo)
    if 'management_networks' not in topo.raw:
        topo.raw['management_networks']={'default':{'ipv4-subnet':topo.mgmt.ipv4_subnet,'dhcp':True}}
    topo,model=resolve(topo,previous)
    services=compile_services(model,external(topo));network={('name' if key=='network' else key):value for key,value in services['jumphost']['external_network'].items()}
    import ipaddress
    subnet=ipaddress.IPv4Network(network['subnet']);resolver=str(subnet.network_address+2)
    dns={'lab':topo.name,'name':services['dns']['container_name'],'generation':'2'*32,
        'image':'sha256:'+'b'*64,'network':deepcopy(network),'ip':resolver,'upstream':['192.0.2.53']}
    jump={'lab':topo.name,'name':services['jumphost']['container_name'],'generation':'1'*32,
        'image':'sha256:'+'a'*64,'network':deepcopy(network),'ip':str(subnet.network_address+3),
        'env':{'JUMPHOST_PASSWORD':'private-marker','JUMPHOST_LAB_NAME':topo.name},
        'bind_ip':'127.0.0.1','port':2200,'dns':[resolver],'binds':[],
        'attachment':deepcopy(services['jumphost']['attachments']['default']['config']),
        'management_intent':_expected_network(topo,'master'),'dhcp':compile_dhcp(topo,model,services,resolver)}
    return topo,model,{'jumphost':jump,'dns':dns}


def test_pure_service_intent_scopes_both_management_networks_and_native_dns(topo_factory):
    topo=input_topology(topo_factory);topo.raw['management_networks']['blue']['dhcp']=True
    topo,model,configs=inputs(topo);before=deepcopy((topo,model,configs))
    result=compile_service_intent(topo,model,configs)
    assert (topo,model,configs)==before and result==compile_service_intent(topo,model,configs)
    assert result['fingerprint']==digest({k:v for k,v in result.items() if k!='fingerprint'})
    assert result['jumphost']['bind_ip']=='127.0.0.1'
    assert set(result['attachments'])=={'default','blue'}
    for name,node in topo.nodes.items():
        assert f' {name}\n' in result['dns']['content']
        assert f' {micro_vd_container_name(topo.name,name)}\n' in result['dns']['content']
        assert node.mgmt_ipv4 in result['dns']['content'] and node.mgmt_ipv6 in result['dns']['content']
    for key,row in result['attachments'].items():
        assert row['management_intent']['network']==model['networks'][key]['network']
        assert 'interface='+row['attachment']['interface'] in result['jumphost']['dhcp']


@pytest.mark.parametrize('change',['wrong-lab','wrong-name','image-tag','external-drift','duplicate-ip','gateway-ip','network-ip','broadcast-ip',
    'dns-loop','resolver-drift','attachment-drift','network-proof','dhcp-drift','missing-password','lab-env','missing-service'])
def test_invalid_provisioning_input_is_refused_without_caller_state_change(topo_factory,change):
    topo,model,configs=inputs(input_topology(topo_factory));jump,dns=configs['jumphost'],configs['dns']
    if change=='wrong-lab':dns['lab']='foreign'
    if change=='wrong-name':jump['name']='foreign'
    if change=='image-tag':jump['image']='helper:latest'
    if change=='external-drift':dns['network']['bridge']='foreign'
    if change=='duplicate-ip':dns['ip']=jump['ip'];jump['dns']=[dns['ip']]
    if change=='gateway-ip':jump['ip']=jump['network']['gateway']
    if change=='network-ip':jump['ip']=jump['network']['subnet'].split('/')[0]
    if change=='broadcast-ip':
        import ipaddress
        jump['ip']=str(ipaddress.IPv4Network(jump['network']['subnet']).broadcast_address)
    if change=='dns-loop':dns['upstream']=[jump['ip']]
    if change=='resolver-drift':jump['dns']=['192.0.2.99']
    if change=='attachment-drift':jump['attachment']['ipv4']='198.18.1.200/24'
    if change=='network-proof':jump['management_intent']['host_count']=1
    if change=='dhcp-drift':jump['dhcp']+='port=0\n'
    if change=='missing-password':jump['env'].pop('JUMPHOST_PASSWORD')
    if change=='lab-env':jump['env']['JUMPHOST_LAB_NAME']='foreign'
    if change=='missing-service':configs.pop('dns')
    before=deepcopy((topo,model,configs))
    with pytest.raises(SegmentError):compile_service_intent(topo,model,configs)
    assert (topo,model,configs)==before


def test_extra_dns_records_preserve_existing_support_and_refuse_conflicts(topo_factory):
    topo,model,configs=inputs(input_topology(topo_factory))
    result=compile_service_intent(topo,model,configs,extra_dns_entries=[HostEntry('extra','192.0.2.55','A')])
    assert '192.0.2.55' in result['dns']['content']
    with pytest.raises(SegmentError,match='alias conflicts'):
        compile_service_intent(topo,model,configs,extra_dns_entries=[HostEntry('r1','192.0.2.55','A')])


def test_coordinator_binds_services_in_original_plan_and_keeps_workload_fence(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    topo,model,configs=inputs(topo)
    result=controller.apply('services-bound',topo,schedule,ips,targets,state,clients,save,
        registry=registry,service_configs=configs)
    expected=compile_service_intent(topo,model,configs)
    assert result['plan']['services']==expected
    assert result['phase']=='provisioning' and result['infrastructure']['phase']=='infrastructure-ready'
    assert all(r.value['phase']=='applying' for r in runtimes.values())
    # No secret/config is sent to runtime admission: only immutable fingerprints.
    assert all('private-marker' not in str(r.value) for r in runtimes.values())
    assert state.jumphost is None and state.dns is None,'intent is not materialization'
    events_before=list(events);calls={h:list(r.calls) for h,r in runtimes.items()}
    changed=deepcopy(configs);changed['jumphost']['env']['JUMPHOST_PASSWORD']='changed'
    with pytest.raises(RuntimeOperationError,match='original intent changed'):
        controller.apply('services-bound',topo,schedule,ips,targets,state,clients,save,
            registry=registry,service_configs=changed)
    assert events==events_before and all(r.calls==calls[h] for h,r in runtimes.items())


def test_service_preflight_failure_precedes_runtime_admission_and_infrastructure(setup):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    topo,model,configs=inputs(topo);configs['jumphost']['dhcp']+='port=0\n'
    before=deepcopy(state.to_dict())
    with pytest.raises(SegmentError):
        controller.apply('services-invalid',topo,schedule,ips,targets,state,clients,save,
            registry=registry,service_configs=configs)
    assert not events and all(not r.calls for r in runtimes.values()) and state.to_dict()==before


def test_health_record_is_original_and_bound_even_without_vds(topo_factory):
    topo=topo_factory(name='empty',num_workers=0)
    topo.nodes={};topo.links=[]
    topo,model,configs=inputs(topo)
    result=compile_service_intent(topo,model,configs)
    record=result['dns_probe']['records'][0]
    assert record['name'].startswith('dnlab-health-') and record['name'].endswith('.invalid')
    assert record['address']==configs['dns']['ip']==result['dns_probe']['server']
    assert [record['address'],record['name']] in [line.split() for line in result['dns']['content'].splitlines()]
    with pytest.raises(SegmentError,match='alias conflicts'):
        compile_service_intent(topo,model,configs,extra_dns_entries=[HostEntry(record['name'],'192.0.2.55','A')])
