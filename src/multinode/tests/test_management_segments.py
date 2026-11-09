"""Pure segment parsing, stable identity ledgers and native compilation."""
from copy import deepcopy
from dataclasses import asdict
import ipaddress

import pytest
import yaml

from dnlab_multinode.models.topology import VDNode, Link, RealNetLink
from dnlab_multinode.models.schedule import SchedulePlan, HostAssignment
from dnlab_multinode.services.config import parse_topology, ConfigError
from dnlab_multinode.services.management_segments import normalize, resolve, segment_names, SegmentError
from dnlab_multinode.services.runtime_manifest import compile_initial, NativeManifestError
from tests.test_mgmt_subnet import _hosts_file

IMAGE='sha256:'+'a'*64


def input_topology(topo_factory):
    topo=topo_factory(name='demo',num_workers=1,links=[],nodes={
        'r1':VDNode(name='r1',kind='linux',image=IMAGE),
        'r2':VDNode(name='r2',kind='linux',image=IMAGE,management_network='blue')})
    topo.raw={'management_networks':{
        'default':{'ipv4-subnet':'198.18.1.0/24','ipv6-subnet':'2001:db8:1::/64','dhcp':True},
        'blue':{'ipv4-subnet':'198.18.2.0/24','ipv6-subnet':'2001:db8:2::/64'}}}
    return topo


def test_resolution_is_pure_and_scopes_addresses_to_segment(topo_factory):
    topo=input_topology(topo_factory);before=deepcopy(topo)
    resolved,model=resolve(topo)
    assert topo==before and resolved.mgmt==resolved.management_networks['default']
    assert model['assignments']=={'r1':{'network':'default','port':'eth0'},'r2':{'network':'blue','port':'eth0'}}
    for name,node in resolved.nodes.items():
        segment=node.management_network;cfg=resolved.management_networks[segment]
        assert ipaddress.ip_address(node.mgmt_ipv4) in ipaddress.ip_network(cfg.ipv4_subnet)
        assert ipaddress.ip_address(node.mgmt_ipv6) in ipaddress.ip_network(cfg.ipv6_subnet)
        assert model['ledgers']['ipv4'][segment][name]==node.mgmt_ipv4
        assert model['ledgers']['mac'][name]==node.mgmt_mac
    assert resolve(resolved,model)[1]==model


def test_added_segment_and_new_vd_preserve_original_ledgers(topo_factory):
    topo=input_topology(topo_factory);_,first=resolve(topo);before=deepcopy(first)
    topo.raw['management_networks']['green']={'ipv4-subnet':'198.18.3.0/24','ipv6-subnet':'2001:db8:3::/64'}
    topo.nodes['r3']=VDNode(name='r3',kind='linux',image=IMAGE,management_network='green')
    _,second=resolve(topo,first)
    assert first==before
    for family in ('ipv4','ipv6'):
        assert all(second['ledgers'][family][k]==v for k,v in first['ledgers'][family].items())
    assert all(second['ledgers'][key]['r1']==first['ledgers'][key]['r1'] for key in ('mac','duid','iaid'))
    del topo.nodes['r2']
    _,third=resolve(topo,second)
    assert third['ledgers']['ipv4']['blue']['r2']==first['ledgers']['ipv4']['blue']['r2']
    assert third['assignments']['r2']==first['assignments']['r2']


@pytest.mark.parametrize('change',['move','port','subnet','remove','foreign_lab','orphan_ledger'])
def test_reconfiguration_is_not_an_implicit_new_deploy(topo_factory,change):
    topo=input_topology(topo_factory);_,prior=resolve(topo);before=deepcopy(prior)
    if change=='move':topo.nodes['r1'].management_network='blue'
    if change=='port':topo.nodes['r1'].management_port='eth8'
    if change=='subnet':topo.raw['management_networks']['blue']['ipv4-subnet']='198.18.9.0/24'
    if change=='remove':del topo.raw['management_networks']['blue'];del topo.nodes['r2']
    if change=='foreign_lab':prior['lab']='another'
    if change=='orphan_ledger':prior['ledgers']['ipv4']['unknown']={'r3':'198.18.9.2'}
    untouched=deepcopy((topo,prior))
    with pytest.raises(ConfigError):resolve(topo,prior)
    assert (topo,prior)==untouched
    if change not in ('foreign_lab','orphan_ledger'):assert prior==before


@pytest.mark.parametrize('problem',['ipv4_overlap','ipv6_overlap','no_default','unknown_network','invalid_port','unknown_option','dhcp_string','noncanonical_subnet','gateway_reserved','typed_drift','bad_network_type','bad_port_type'])
def test_invalid_segment_model_is_refused_without_mutation(topo_factory,problem):
    topo=input_topology(topo_factory);blue=topo.raw['management_networks']['blue']
    if problem=='ipv4_overlap':blue['ipv4-subnet']='198.18.1.128/25'
    if problem=='ipv6_overlap':blue['ipv6-subnet']='2001:db8:1::/80'
    if problem=='no_default':del topo.raw['management_networks']['default']
    if problem=='unknown_network':topo.nodes['r2'].management_network='missing'
    if problem=='invalid_port':topo.nodes['r2'].management_port='lo'
    if problem=='unknown_option':blue['bridge']='foreign'
    if problem=='dhcp_string':blue['dhcp']='false'
    if problem=='noncanonical_subnet':blue['ipv4-subnet']='198.18.2.20/24'
    if problem=='gateway_reserved':blue['ipv4-gw']='198.18.2.1'
    if problem=='typed_drift':topo.management_networks={'foreign':topo.mgmt}
    if problem=='bad_network_type':topo.nodes['r2'].management_network=[]
    if problem=='bad_port_type':topo.nodes['r2'].management_port=None
    before=deepcopy(topo)
    with pytest.raises(ConfigError):resolve(topo)
    assert topo==before


@pytest.mark.parametrize('kind',['data','realnet'])
def test_selected_management_port_is_reserved_before_allocation(topo_factory,kind):
    topo=input_topology(topo_factory);topo.nodes['r1'].management_port='eth8'
    if kind=='data':topo.links=[Link('r1','eth8','r2','eth1')]
    else:topo.real_net_links=[RealNetLink('internet','r1','eth8')]
    with pytest.raises(SegmentError,match='management port'):resolve(topo)


def test_names_use_full_lab_segment_identity_and_allow_overlap_between_labs(topo_factory):
    a=input_topology(topo_factory);a.name='breakout-alpha'
    b=deepcopy(a);b.name='breakout-beta'
    aa,am=resolve(a);bb,bm=resolve(b)
    assert am['ledgers']['ipv4']==bm['ledgers']['ipv4']
    assert am['networks']['blue']['network']!=bm['networks']['blue']['network']
    assert len({segment_names(lab,segment)[1] for lab in ('breakout-alpha','breakout-beta') for segment in ('default','blue')})==4
    assert all(len(segment_names(a.name,segment)[1])<=15 for segment in ('default','blue'))


def test_parser_rejects_legacy_dispatch_and_opt_in_resolves_selections(tmp_path):
    file=tmp_path/'lab.yml'
    data={'name':'demo','management_networks':{'default':{'ipv4-subnet':'198.18.1.0/24'},'blue':{'ipv4-subnet':'198.18.2.0/24'}},
          'topology':{'nodes':{'r1':{'kind':'linux','image':IMAGE,'management_network':'blue','management_port':'eth0'}},'links':[]}}
    file.write_text(yaml.safe_dump(data));hosts=_hosts_file(tmp_path)
    with pytest.raises(ConfigError,match='opt-in'):parse_topology(file,hosts_file=hosts)
    parsed=parse_topology(file,hosts_file=hosts,native_management=True)
    assert parsed.nodes['r1'].management_network=='blue' and parsed.nodes['r1'].management_port=='eth0'
    assert 'management_network' not in parsed.nodes['r1'].extra and parsed.native_management
    resolved,model=resolve(parsed)
    assert resolved.nodes['r1'].mgmt_ipv4.startswith('198.18.2.')
    assert model['networks']['default']==asdict(parsed.mgmt)


def test_legacy_single_network_normalizes_to_default_without_changing_names(tmp_path):
    file=tmp_path/'lab.yml';file.write_text(yaml.safe_dump({'name':'demo','topology':{'nodes':{'r1':{'kind':'linux','image':IMAGE}}}}))
    parsed=parse_topology(file,hosts_file=_hosts_file(tmp_path),native_management=True)
    resolved,model=resolve(parsed)
    assert model['networks']=={'default':asdict(parsed.mgmt)}
    assert resolved.nodes['r1'].management_network=='default'


def test_compilation_embeds_segment_ledger_and_correct_network_per_member(topo_factory):
    topo=input_topology(topo_factory);before=deepcopy(topo)
    plan=SchedulePlan(lab_name=topo.name,assignments={'master':HostAssignment('master','unused',['r1']),'worker1':HostAssignment('worker1','unused',['r2'])})
    targets={h:{'host':h,'socket_path':'/run/runtime.sock','container_name':'runtime'} for h in plan.assignments}
    compiled=compile_initial(topo,plan,batch_id='deploy',targets=targets)
    model=compiled['management_plan']
    for member in compiled['members']:
        node=member['request']['node_id'];segment=model['assignments'][node]['network'];spec=member['request']['spec']
        assert spec['management']['network']==model['networks'][segment]['network']
        assert spec['management']['ipv4']==model['ledgers']['ipv4'][segment][node]
        assert spec['management']['mac']==model['ledgers']['mac'][node]
    assert topo==before
    topo.nodes['r2'].management_port='eth8'
    with pytest.raises(NativeManifestError,match='adapter qualification'):compile_initial(topo,plan,batch_id='another',targets=targets)


def test_management_cannot_overlap_jumphost_external_network(topo_factory):
    topo=input_topology(topo_factory)
    topo.raw['management_networks']['blue']['ipv4-subnet']=topo.jumphost_net.ipv4_subnet
    with pytest.raises(SegmentError,match='jumphost external'):resolve(topo)


def test_realnet_pseudo_node_cannot_request_management(tmp_path):
    file=tmp_path/'lab.yml';file.write_text(yaml.safe_dump({'name':'demo','topology':{
        'nodes':{'internet':{'kind':'_real_net','extra':{'ipv4':'192.0.2.1/24'},'management_network':'default'}}}}))
    with pytest.raises(ConfigError,match='RealNet is data-only'):
        parse_topology(file,hosts_file=_hosts_file(tmp_path),native_management=True)


def test_native_plan_resolves_before_resource_or_ssh_work_and_state_roundtrips(tmp_path,monkeypatch,topo_factory):
    from unittest.mock import MagicMock
    from dnlab_multinode.controllers import plan as module
    from dnlab_multinode.models.state import DeploymentState
    from dnlab_multinode.services import state as state_svc
    topo=input_topology(topo_factory);_,previous=resolve(topo)
    st=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'),management_plan=previous)
    state_svc.save_state(st,tmp_path)
    assert state_svc.load_state('demo',tmp_path).management_plan==previous
    def parse(*args,**kwargs):
        assert kwargs['native_management'] is True
        return normalize(topo)
    monkeypatch.setattr(module,'parse_topology',parse)
    clients=MagicMock();monkeypatch.setattr(module,'create_clients',clients)
    def resources(*args,**kwargs):
        assert kwargs['nodes']['r2'].mgmt_ipv4.startswith('198.18.2.')
        raise RuntimeError('reached resources after resolution')
    monkeypatch.setattr(module,'extract_resources',resources)
    with pytest.raises(RuntimeError,match='reached resources'):
        module.PlanController(str(tmp_path/'demo.yml'),native_management=True).run()
    clients.assert_not_called()
    assert state_svc.load_state('demo',tmp_path).management_plan==previous


def test_native_plan_refuses_implicit_legacy_state_conversion(tmp_path,monkeypatch,topo_factory):
    from unittest.mock import MagicMock
    from dnlab_multinode.controllers import plan as module
    from dnlab_multinode.models.state import DeploymentState
    from dnlab_multinode.services import state as state_svc
    topo=input_topology(topo_factory)
    state_svc.save_state(DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml')),tmp_path)
    monkeypatch.setattr(module,'parse_topology',lambda *a,**kw:normalize(topo))
    clients=MagicMock();monkeypatch.setattr(module,'create_clients',clients)
    with pytest.raises(SegmentError,match='legacy state conversion'):
        module.PlanController(str(tmp_path/'demo.yml'),native_management=True).run()
    clients.assert_not_called()


def test_compile_hundred_vds_across_five_existing_placements(topo_factory):
    topo=input_topology(topo_factory)
    template=topo_factory(name='demo',num_workers=4,links=[],nodes={})
    topo.workers=template.workers
    topo.nodes={f'r{i:03}':VDNode(name=f'r{i:03}',kind='linux',image=IMAGE,
        management_network='blue' if i%2 else 'default') for i in range(100)}
    hosts=list(topo.all_hosts)
    plan=SchedulePlan(lab_name='demo',assignments={h:HostAssignment(h,'unused',[]) for h in hosts})
    for i,name in enumerate(topo.nodes):plan.assignments[hosts[i%5]].vd_names.append(name)
    targets={h:{'host':h,'socket_path':'/run/runtime.sock','container_name':'runtime'} for h in hosts}
    original=deepcopy((topo,plan))
    value=compile_initial(topo,plan,batch_id='deploy',targets=targets)
    assert len(value['members'])==100 and {m['target']['host'] for m in value['members']}==set(hosts)
    assert all(m['target']['host']==plan.host_for_vd(m['request']['node_id']) for m in value['members'])
    assert all(len(v)==50 for v in value['management_plan']['ledgers']['ipv4'].values())
    assert (topo,plan)==original
