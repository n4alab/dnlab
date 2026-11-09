"""Probe reservations are separate infrastructure, sticky and preflight-only."""
from copy import deepcopy
import pytest

from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.management_probe_identity import identity,owner,validate
from dnlab_multinode.services.config import ConfigError
from dnlab_multinode.services.management_dhcp import compile_dhcp
from dnlab_multinode.services.management_services import compile_services
from dnlab_multinode.services.mgmt_ips import ipv4_reservations
from dnlab_multinode.services.mgmt_network import _expected_network
from dnlab_multinode.models.topology import VDNode
from tests.test_management_segments import input_topology,IMAGE
from tests.test_management_prepare import setup
from tests.test_management_services import external


def configured(factory):
    topo=input_topology(factory);topo.raw['management_networks']['blue']['dhcp']=True
    return topo


def test_opt_in_identity_is_pure_sticky_and_uses_reserved_anchor(topo_factory):
    topo=configured(topo_factory);before=deepcopy(topo)
    resolved,model=resolve(topo,prepare_probes=True)
    assert topo==before and set(model['probes'])=={'default','blue'}
    assert set(model['assignments'])==set(topo.nodes)
    for segment,row in model['probes'].items():
        assert row['ipv4']==ipv4_reservations(model['networks'][segment]['ipv4_subnet']).anchor
        assert model['ledgers']['ipv6'][segment][row['owner']]==row['ipv6']
        assert row['owner'] not in model['ledgers']['ipv4'][segment]
        assert all(model['ledgers'][family][row['owner']]==row[family] for family in ('mac','duid','iaid'))
    assert resolve(resolved,model)[1]==model
    assert resolve(topo)[1].get('probes') is None


def test_anchor_reuse_does_not_reduce_ipv4_vd_capacity_in_29(topo_factory):
    topo=configured(topo_factory)
    topo.raw['management_networks']={'default':{'ipv4-subnet':'198.18.1.0/29','ipv6-subnet':'2001:db8:1::/64','dhcp':True}}
    topo.nodes['r2'].management_network='default'
    resolved,model=resolve(topo,prepare_probes=True)
    assert {v.mgmt_ipv4 for v in resolved.nodes.values()}=={'198.18.1.2','198.18.1.3'}
    assert model['probes']['default']['ipv4']=='198.18.1.4'
    assert model['probes']['default']['ipv4'] in _expected_network(resolved,'master')['reserved']


@pytest.mark.parametrize('segment',['default','blue'])
@pytest.mark.parametrize('family',['ipv6','mac','duid'])
def test_existing_vd_identity_conflict_is_rejected_without_mutation(topo_factory,family,segment):
    topo=input_topology(topo_factory);resolved,prior=resolve(topo)
    probe=identity(topo.name,segment,prior['networks'][segment])
    if family=='ipv6':prior['ledgers']['ipv6'][segment]['retired']=probe['ipv6']
    else:prior['ledgers'][family]['retired']=probe[family].upper() if family=='duid' else probe[family]
    before=deepcopy((topo,prior))
    with pytest.raises(ConfigError,match='reserved by another owner'):resolve(topo,prior,prepare_probes=True)
    assert (topo,prior)==before


def test_explicit_guest_ipv6_cannot_claim_probe_address(topo_factory):
    topo=configured(topo_factory);_,plain=resolve(topo)
    row=identity(topo.name,'default',plain['networks']['default'])
    topo.nodes['r1'].mgmt_ipv6=row['ipv6'];topo.nodes['r1'].mgmt_ipv6_explicit=True
    before=deepcopy(topo)
    with pytest.raises(ConfigError,match='duplicate mgmt-ipv6'):resolve(topo,prepare_probes=True)
    assert topo==before


def test_orphan_probe_claim_is_not_adopted(topo_factory):
    topo=configured(topo_factory);_,plain=resolve(topo)
    row=identity(topo.name,'default',plain['networks']['default'])
    plain['ledgers']['mac'][row['owner']]=row['mac']
    with pytest.raises(ConfigError,match='without original identity'):resolve(topo,plain,prepare_probes=True)


@pytest.mark.parametrize('change',['row','ledger','missing','foreign'])
def test_original_probe_is_immutable_and_compiled_validation_rejects_drift(topo_factory,change):
    topo,model=resolve(configured(topo_factory),prepare_probes=True)
    if change=='row':model['probes']['default']['mac']='02:00:00:00:00:55'
    if change=='ledger':model['ledgers']['mac'][owner('default')]='02:00:00:00:00:55'
    if change=='missing':del model['probes']['default']
    if change=='foreign':model['probes']['foreign']=deepcopy(model['probes']['default'])
    before=deepcopy(model)
    with pytest.raises(ConfigError):validate(model)
    assert model==before


def test_probe_dhcp_reservations_are_bound_to_model_and_vds_stay_distinct(topo_factory):
    topo,model=resolve(configured(topo_factory),prepare_probes=True)
    services=compile_services(model,external(topo));text=compile_dhcp(topo,model,services,'10.100.0.2')
    for row in model['probes'].values():
        assert text.count('dhcp-host='+row['mac']+','+row['ipv4']+'\n')==1
        assert text.count('dhcp-host=id:'+row['duid']+',['+row['ipv6']+']\n')==1
    assert all(node.mgmt_mac not in {row['mac'] for row in model['probes'].values()} for node in topo.nodes.values())


def test_hot_spawn_and_offline_growth_preserve_all_probe_reservations(topo_factory):
    topo,model=resolve(configured(topo_factory),prepare_probes=True)
    original=deepcopy(model['probes'])
    topo.nodes['r3']=VDNode(name='r3',kind='linux',image=IMAGE,management_network='blue')
    topo.raw['management_networks']['green']={'ipv4-subnet':'198.18.3.0/24','ipv6-subnet':'2001:db8:3::/64','dhcp':True}
    topo.management_networks={}
    _,updated=resolve(topo,model)
    assert all(updated['probes'][k]==v for k,v in original.items()) and 'green' in updated['probes']


def test_disabled_dhcp_keeps_probe_without_enabling_service_and_small_ipv6_pool_refuses(topo_factory):
    topo=configured(topo_factory);topo.raw['management_networks']['blue']['dhcp']=False
    _,model=resolve(topo,prepare_probes=True)
    assert set(model['probes'])=={'default','blue'}
    assert model['networks']['blue']['dhcp'] is False
    services=compile_services(model,external(topo))
    text=compile_dhcp(topo,model,services,'10.100.0.2')
    assert services['dhcp_segments']==['default']
    assert 'no-dhcp-interface='+services['jumphost']['attachments']['blue']['config']['interface']+'\n' in text
    assert model['probes']['blue']['mac'] not in text and model['probes']['blue']['duid'] not in text
    topo.nodes={};topo.raw['management_networks']['default']['ipv6-subnet']='2001:db8:1::/127'
    with pytest.raises(ConfigError,match='no space'):resolve(topo,prepare_probes=True)


@pytest.mark.parametrize('explicit',[False,True])
def test_partial_original_probe_model_is_not_completed_implicitly(topo_factory,explicit):
    topo,model=resolve(input_topology(topo_factory),prepare_probes=True)
    row=model['probes'].pop('blue')
    for family in ('mac','duid','iaid'):del model['ledgers'][family][row['owner']]
    del model['ledgers']['ipv6']['blue'][row['owner']]
    before=deepcopy((topo,model))
    with pytest.raises(ConfigError,match='complete original'):
        resolve(topo,model,prepare_probes=explicit)
    assert (topo,model)==before


def test_static_only_networks_keep_dhcp_disabled_and_reservations_sticky(topo_factory):
    topo=input_topology(topo_factory)
    topo.raw['management_networks']['default']['dhcp']=False
    resolved,model=resolve(topo,prepare_probes=True)
    assert set(model['probes'])=={'default','blue'}
    assert resolve(resolved,model)[1]==model
    services=compile_services(model,external(resolved))
    assert services['dhcp_segments']==[]
    content=compile_dhcp(resolved,model,services,'10.100.0.2')
    assert 'port=53' in content and 'dhcp-range=' not in content and 'enable-ra' not in content


def test_ipv6_probe_is_reserved_in_docker_ipam_on_every_original_host(topo_factory):
    topo,model=resolve(configured(topo_factory),prepare_probes=True)
    from dnlab_multinode.vrf_plugin import PluginStore
    import ipaddress
    for segment,row in model['probes'].items():
        selected=deepcopy(topo);selected.mgmt=selected.management_networks[segment]
        for host in topo.all_hosts:
            expected=_expected_network(selected,host)
            assert row['ipv4'] in expected['reserved'] and row['ipv6'] in expected['reserved']
            assert PluginStore._parse_reserved(','.join(expected['reserved']),ipaddress.ip_network(expected['ipv6_subnet']))==[row['ipv6']]


def test_native_workload_compilation_keeps_probe_reservations_out_of_vds(topo_factory):
    from dnlab_multinode.services.runtime_manifest import compile_initial
    from dnlab_multinode.services.management_segments import validate_compilation
    from tests.test_management_services import schedule,targets
    topo,model=resolve(configured(topo_factory),prepare_probes=True)
    result=compile_initial(topo,schedule(topo),batch_id='initial',targets=targets(),management_plan=model)
    validate_compilation(result,topo.name)
    assert result['management_plan']==model
    assert {row['request']['node_id'] for row in result['members']}==set(topo.nodes)


def test_service_intent_and_network_plan_bind_same_probe_reservations(setup):
    from tests.test_management_service_intent import inputs
    from dnlab_multinode.services.management_service_intent import compile_service_intent
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    topo.raw['management_networks']={'default':{'ipv4-subnet':topo.mgmt.ipv4_subnet,'dhcp':True}}
    topo,model=resolve(topo,prepare_probes=True)
    topo,model,configs=inputs(topo,model)
    state.management_plan=deepcopy(model)
    expected=compile_service_intent(topo,model,configs)
    result=controller.apply('probe-reservations',topo,schedule,ips,targets,state,clients,save,registry=registry,service_configs=configs)
    assert result['plan']['services']==expected
    assert expected['packet_probe_identities']==model['probes']
    assert result['phase']=='provisioning'
    for host in targets:
        reserved=result['plan']['hosts'][host]['segments']['default']['network']['reserved']
        assert model['probes']['default']['ipv6'] in reserved
    assert controller.apply('probe-reservations',topo,schedule,ips,targets,state,clients,save,registry=registry,service_configs=configs)['plan']==result['plan']


def test_new_reservations_cannot_rewrite_an_already_sealed_service_intent(setup):
    from tests.test_management_service_intent import inputs
    from dnlab_multinode.services import management_barrier as barrier
    from dnlab_multinode.services.runtime_operations import RuntimeOperationError
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    topo.raw['management_networks']={'default':{'ipv4-subnet':topo.mgmt.ipv4_subnet,'dhcp':True},
        'blue':{'ipv4-subnet':'198.18.77.0/24','ipv6-subnet':'2001:db8:77::/64','dhcp':False}}
    topo,plain,configs=inputs(topo);state.management_plan=deepcopy(plain)
    controller.prepare('sealed',topo,schedule,ips,targets,state,service_configs=configs)
    original=deepcopy(barrier.get(store,topo.name));before=deepcopy((events,{h:r.calls for h,r in runtimes.items()}))
    prepared,model=resolve(topo,plain,prepare_probes=True)
    prepared,model,updated=inputs(prepared,model);state.management_plan=deepcopy(model)
    with pytest.raises(RuntimeOperationError,match='original intent changed'):
        controller.prepare('sealed',prepared,schedule,ips,targets,state,service_configs=updated)
    assert barrier.get(store,topo.name)==original
    assert (events,{h:r.calls for h,r in runtimes.items()})==before
