"""Pure, append-stable multi-segment service compilation and admission."""
from copy import deepcopy

import pytest

from dnlab_multinode.services.management_segments import resolve, SegmentError
from dnlab_multinode.services.management_services import compile_services, peer_interface, validate_compilation
from dnlab_multinode.services.runtime_manifest import compile_initial, NativeManifestError
from tests.test_management_segments import input_topology
from dnlab_multinode.models.schedule import SchedulePlan, HostAssignment


def schedule(topo):
    return SchedulePlan(lab_name=topo.name, assignments={
        "master":HostAssignment("master","unused",["r1"]),
        "worker1":HostAssignment("worker1","unused",["r2"])})


def targets():
    return {h:{"host":h,"socket_path":"/run/runtime.sock","container_name":"runtime"} for h in ("master","worker1")}


def external(topo):
    value = topo.jumphost_net
    return dict(network=value.network,bridge=value.bridge,subnet=value.ipv4_subnet,gateway=value.ipv4_gw)


def test_services_preserve_single_lab_access_and_allocate_no_state(topo_factory):
    topo = input_topology(topo_factory); resolved, model = resolve(topo)
    before = deepcopy((topo,model))
    services = compile_services(model,external(topo))
    assert (topo,model) == before
    assert services['jumphost']['container_name'] == 'dnlab-demo-jumphost'
    assert services['dns']['external_network'] == services['jumphost']['external_network'] == external(topo)
    assert services['dhcp_segments'] == ['default']
    attachments = services['jumphost']['attachments']
    assert attachments['default']['config']['interface'] == 'eth1'
    assert attachments['blue']['config']['interface'] != 'eth1'
    for segment, item in attachments.items():
        assert len(item['host_interface']) <= 15
        assert len(item['config']['interface']) <= 15 and item['config']['interface'] != 'eth0'
        assert item['config']['network'] == model['networks'][segment]['network']
        assert item['config']['ipv4'].endswith('.254/24')
    assert compile_services(model,external(topo),previous=services) == services


def test_adding_earlier_named_segment_preserves_original_attachment_ports(topo_factory):
    topo = input_topology(topo_factory); _, old_model = resolve(topo)
    previous = compile_services(old_model,external(topo)); before = deepcopy(previous)
    topo.raw['management_networks']['aaa'] = {'ipv4-subnet':'198.18.3.0/24','ipv6-subnet':'2001:db8:3::/64','dhcp':True}
    _, model = resolve(topo,old_model)
    current = compile_services(model,external(topo),previous=previous)
    assert previous == before
    assert all(current['jumphost']['attachments'][key] == value for key,value in previous['jumphost']['attachments'].items())
    assert current['dhcp_segments'] == ['aaa','default']


@pytest.mark.parametrize('change',['external','gateway','dhcp','remove','foreign-lab','peer','unknown-field'])
def test_existing_service_changes_require_an_operation(topo_factory,change):
    topo = input_topology(topo_factory); _, model = resolve(topo)
    previous = compile_services(model,external(topo)); ext = external(topo)
    if change == 'external': ext['gateway'] = '10.100.0.2'
    if change == 'gateway': model['networks']['blue']['ipv4_gw'] = '198.18.2.250'
    if change == 'dhcp': model['networks']['blue']['dhcp'] = True
    if change == 'remove': del model['networks']['blue']
    if change == 'foreign-lab': previous['lab'] = 'another'
    if change == 'peer': previous['jumphost']['attachments']['blue']['config']['interface'] = 'foreign'
    if change == 'unknown-field': previous['unknown'] = True
    before = deepcopy((model,ext,previous))
    with pytest.raises(SegmentError): compile_services(model,ext,previous=previous)
    assert (model,ext,previous) == before


@pytest.mark.parametrize('change',['network','bridge','dhcp-type','reserved-gateway','overlap','external-overlap','half-ipv6'])
def test_inconsistent_model_rejected_without_mutation(topo_factory,change):
    topo = input_topology(topo_factory); _, model = resolve(topo); cfg = model['networks']['blue']; ext = external(topo)
    if change == 'network': cfg['network'] = 'foreign'
    if change == 'bridge': cfg['bridge'] = 'foreign'
    if change == 'dhcp-type': cfg['dhcp'] = 1
    if change == 'reserved-gateway': cfg['ipv4_gw'] = '198.18.2.1'
    if change == 'overlap': cfg['ipv4_subnet'] = '198.18.1.0/24'; cfg['ipv4_gw'] = '198.18.1.254'
    if change == 'external-overlap': ext.update(subnet='198.18.2.0/24',gateway='198.18.2.1')
    if change == 'half-ipv6': cfg['ipv6_gw'] = ''
    before = deepcopy((model,ext))
    with pytest.raises(SegmentError): compile_services(model,ext)
    assert (model,ext) == before


def test_names_distinguish_complete_lab_and_segment_identities():
    values = {peer_interface(lab,segment) for lab in ('breakout-alpha','breakout-beta') for segment in ('blue','green')}
    assert len(values) == 4 and all(len(v) <= 15 for v in values)


def test_compilation_carries_service_metadata_inside_fingerprint(topo_factory):
    topo = input_topology(topo_factory)
    compiled = compile_initial(topo,schedule(topo),batch_id='services',targets=targets())
    validate_compilation(compiled)
    assert compiled['management_services']['lab'] == topo.name
    retry = compile_initial(topo,schedule(topo),batch_id='services',targets=targets(),management_services=compiled['management_services'])
    assert retry == compiled
    old = deepcopy(compiled['management_services']); old['jumphost']['external_network']['gateway'] = '10.100.0.2'
    with pytest.raises(NativeManifestError):
        compile_initial(topo,schedule(topo),batch_id='services',targets=targets(),management_services=old)


@pytest.mark.parametrize('change',['peer','host','subnet','dhcp','dns','routing'])
def test_recomputed_outer_hash_cannot_qualify_inconsistent_service_model(topo_factory,change):
    topo = input_topology(topo_factory)
    compiled = compile_initial(topo,schedule(topo),batch_id='services',targets=targets())
    services = compiled['management_services']
    if change == 'peer': services['jumphost']['attachments']['blue']['config']['interface'] = 'foreign'
    if change == 'host': services['jumphost']['attachments']['blue']['host_interface'] = 'foreign'
    if change == 'subnet': services['jumphost']['attachments']['blue']['config']['ipv4'] = '192.0.2.1/24'
    if change == 'dhcp': services['dhcp_segments'] = ['blue']
    if change == 'dns': services['dns']['external_network']['gateway'] = '10.100.0.2'
    if change == 'routing': services['routing']['via'] = 'host'
    with pytest.raises(SegmentError): validate_compilation(compiled)


def test_ipv4_only_service_plan_does_not_invent_guest_ipv6(topo_factory):
    topo = input_topology(topo_factory); _, model = resolve(topo)
    for cfg in model['networks'].values(): cfg['ipv6_subnet'] = ''; cfg['ipv6_gw'] = ''
    plan = compile_services(model,external(topo))
    assert plan['routing']['ipv6'] is False
    assert all(not item['config']['ipv6'] for item in plan['jumphost']['attachments'].values())


def test_interface_name_collision_fails_before_returning_a_plan(topo_factory,monkeypatch):
    topo = input_topology(topo_factory); _, model = resolve(topo)
    monkeypatch.setattr('dnlab_multinode.services.management_services.peer_interface', lambda *a: 'eth1')
    with pytest.raises(SegmentError,match='collide'): compile_services(model,external(topo))
