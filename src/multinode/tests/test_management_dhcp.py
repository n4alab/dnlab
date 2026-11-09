"""Range/interface and reservation scoping for pure management service config."""
from copy import deepcopy

import pytest

from dnlab_multinode.services.management_dhcp import compile_dhcp
from dnlab_multinode.services.management_segments import resolve, SegmentError
from dnlab_multinode.services.management_services import compile_services
from dnlab_multinode.services.jumphost_host import dhcp_files
from dnlab_multinode.models.topology import VDNode
from tests.test_management_segments import input_topology
from tests.test_management_services import external


def prepared(factory):
    topo = input_topology(factory)
    topo.raw['management_networks']['blue']['dhcp'] = True
    topo, model = resolve(topo)
    services = compile_services(model,external(topo))
    return topo,model,services


def test_ranges_use_separate_interface_and_tag_per_l2_segment_without_mutation(topo_factory):
    topo,model,services=prepared(topo_factory)
    original=deepcopy((topo,model,services))
    content=compile_dhcp(topo,model,services,'10.100.0.2')
    assert (topo,model,services)==original
    assert content==compile_dhcp(topo,model,services,'10.100.0.2')
    tags={}
    for segment,cfg in model['networks'].items():
        peer=services['jumphost']['attachments'][segment]['config']['interface']
        assert 'interface='+peer in content.splitlines()
        ranges=[line for line in content.splitlines() if line.startswith('dhcp-range=') and cfg['ipv4_subnet'].split('/')[0] in line]
        assert len(ranges)==1
        tag=ranges[0].split(',',1)[0].split(':',1)[1];tags[segment]=tag
        assert f'dhcp-option=tag:{tag},option:router,{cfg["ipv4_gw"]}' in content.splitlines()
        assert f'dhcp-option=tag:{tag},option:dns-server,{cfg["ipv4_gw"]}' in content.splitlines()
        assert f'dhcp-option=tag:{tag},option:dns-server,10.100.0.2' not in content.splitlines()
        assert f'dhcp-option=tag:{tag},option6:dns-server,[{cfg["ipv6_gw"]}]' in content.splitlines()
        assert f'ra-param={peer},60,1800' in content.splitlines()
    assert len(set(tags.values()))==2
    assert 'no-resolv' in content.splitlines() and 'server=10.100.0.2' in content.splitlines()
    for node in topo.nodes.values():
        assert content.count(f'dhcp-host={node.mgmt_mac},{node.mgmt_ipv4}\n')==1
        assert content.count(f'dhcp-host=id:{node.mgmt_duid},[{node.mgmt_ipv6}]\n')==1
    assert 'tag:mgmt' not in content


def test_disabling_dhcp_on_one_segment_emits_no_reservations_ranges_or_ra_for_it(topo_factory):
    topo=input_topology(topo_factory);topo,model=resolve(topo)
    services=compile_services(model,external(topo))
    content=compile_dhcp(topo,model,services,'10.100.0.2')
    blue=topo.nodes['r2']
    assert blue.mgmt_mac not in content and blue.mgmt_duid not in content
    assert model['networks']['blue']['ipv4_subnet'].split('/')[0] not in content
    peer=services['jumphost']['attachments']['blue']['config']['interface']
    assert 'interface='+peer in content.splitlines() and 'no-dhcp-interface='+peer in content.splitlines()
    assert 'ra-param='+peer+',60,1800' not in content.splitlines()


@pytest.mark.parametrize('change',['service-peer','service-dhcp','resolver-outside','resolver-gateway','resolver-injection','model-missing-node'])
def test_inconsistent_input_is_rejected_before_any_caller_state_change(topo_factory,change):
    topo,model,services=prepared(topo_factory);resolver='10.100.0.2'
    if change=='service-peer':services['jumphost']['attachments']['blue']['config']['interface']='eth9'
    if change=='service-dhcp':services['dhcp_segments']=['default']
    if change=='resolver-outside':resolver='192.0.2.1'
    if change=='resolver-gateway':resolver='10.100.0.1'
    if change=='resolver-injection':resolver='10.100.0.2\nconf-file=/foreign'
    if change=='model-missing-node':del model['assignments']['r2']
    original=deepcopy((topo,model,services))
    with pytest.raises(SegmentError):compile_dhcp(topo,model,services,resolver)
    assert (topo,model,services)==original


def test_empty_segments_keep_ranges_for_future_spawn_and_hosts_remain_dynamic(topo_factory):
    topo,model,services=prepared(topo_factory)
    topo.nodes={};topo,model=resolve(topo,model)
    content=compile_dhcp(topo,model,services,'10.100.0.2')
    files=dhcp_files(content)
    assert files['hosts']==''
    assert files['main'].count('dhcp-range=')==4
    assert all('tag:' in line for line in files['options'].splitlines())


def test_added_segment_does_not_change_existing_tags_or_interfaces(topo_factory):
    topo,model,services=prepared(topo_factory)
    before=compile_dhcp(topo,model,services,'10.100.0.2')
    topo.raw['management_networks']['aaa']={'ipv4-subnet':'198.18.3.0/24','dhcp':True}
    topo.management_networks={}
    topo,updated=resolve(topo,model)
    after_services=compile_services(updated,external(topo),previous=services)
    after=compile_dhcp(topo,updated,after_services,'10.100.0.2')
    assert set(before.splitlines())<=set(after.splitlines())


def test_no_dhcp_keeps_dns_proxy_without_dhcp_or_ra(topo_factory):
    topo=input_topology(topo_factory)
    topo.raw['management_networks']['default']['dhcp']=False
    topo,model=resolve(topo);services=compile_services(model,external(topo))
    content=compile_dhcp(topo,model,services,'10.100.0.2')
    assert 'port=53' in content.splitlines() and 'server=10.100.0.2' in content.splitlines()
    assert not any(line.startswith(('dhcp-range=','dhcp-host=','dhcp-option=','ra-param=','enable-ra','dhcp-authoritative')) for line in content.splitlines())
    assert content.count('no-dhcp-interface=')==len(model['networks'])


def test_spawn_on_a_prepared_segment_changes_only_dynamic_reservations(topo_factory):
    topo,model,services=prepared(topo_factory)
    before=dhcp_files(compile_dhcp(topo,model,services,'10.100.0.2'))
    topo.nodes['r3']=VDNode(name='r3',kind='linux',image=topo.nodes['r2'].image,management_network='blue')
    topo,updated=resolve(topo,model)
    after_services=compile_services(updated,external(topo),previous=services)
    after=dhcp_files(compile_dhcp(topo,updated,after_services,'10.100.0.2'))
    assert after['main']==before['main'] and after['options']==before['options']
    assert set(before['hosts'].splitlines())<set(after['hosts'].splitlines())
