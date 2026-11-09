"""Regression for exact allocation-to-YAML WebUI binding translation."""
from copy import deepcopy

import pytest
import yaml

from dnlab_multinode.models.topology import VDNode
from dnlab_multinode.models.schedule import HostAssignment,SchedulePlan
from dnlab_multinode.services.generator import generate_micro_topology_files,generate_topology_files


@pytest.mark.parametrize('bind_ip',['127.0.0.1','192.0.2.10','::1'])
@pytest.mark.parametrize('generator',['micro','host'])
def test_generators_preserve_explicit_webui_allocation_address(topo_factory,bind_ip,generator):
    topo=topo_factory(nodes={'R1':VDNode(name='R1',kind='linux',image='sha256:'+'a'*64)},links=[],num_workers=0)
    plan=SchedulePlan(lab_name=topo.name,assignments={'master':HostAssignment('master','10.0.0.10',['R1'])})
    allocations={'R1':[{'container_port':443,'host_port':8456,'bind_ip':bind_ip,'proto':'tcp'}]}
    original=deepcopy(allocations)
    if generator=='micro':text=generate_micro_topology_files(topo,plan,allocations)['master']['R1']
    else:text=generate_topology_files(topo,plan,allocations)['master']
    port=yaml.safe_load(text)['topology']['nodes']['R1']['ports']
    address='['+bind_ip+']' if ':' in bind_ip else bind_ip
    assert port==[address+':8456:443/tcp']
    assert allocations==original


@pytest.mark.parametrize('bad',[None,'','localhost','127.0.0.1/32','[::1]','::1%lo',' 127.0.0.1'])
def test_invalid_binding_address_cannot_fall_back_to_wildcard(bad):
    from dnlab_multinode.services.webui_bindings import containerlab_binding
    with pytest.raises(ValueError,match='bind_ip'):
        containerlab_binding({'bind_ip':bad,'container_port':443,'host_port':8456})


def test_missing_binding_address_does_not_fall_back_to_wildcard():
    from dnlab_multinode.services.webui_bindings import runtime_binding
    with pytest.raises(ValueError,match='bind_ip'):runtime_binding({'container_port':443,'host_port':8456})


@pytest.mark.parametrize('field,value',[('host_port',True),('host_port',0),('container_port',65536),('proto','sctp')])
def test_invalid_allocation_refused(field,value):
    from dnlab_multinode.services.webui_bindings import containerlab_binding
    allocation={'bind_ip':'127.0.0.1','container_port':443,'host_port':8456};allocation[field]=value
    with pytest.raises(ValueError):containerlab_binding(allocation)


@pytest.mark.parametrize('address',['0.0.0.0','::','127.0.0.1','::1'])
def test_native_binding_uses_exact_explicit_address_and_protocol(address):
    from dnlab_multinode.services.webui_bindings import runtime_binding
    assert runtime_binding({'bind_ip':address,'container_port':443,'host_port':8456,'proto':'udp'})=={
        'host_ip':address,'container_port':443,'host_port':8456,'protocol':'udp'}


def test_existing_ports_are_preserved_and_exact_allocations_not_duplicated(topo_factory):
    existing=['127.0.0.1:8456:443/tcp','127.0.0.1:8022:22/tcp']
    topo=topo_factory(nodes={'R1':VDNode(name='R1',kind='linux',image='alpine',extra={'ports':list(existing)})},links=[],num_workers=0)
    plan=SchedulePlan(lab_name=topo.name,assignments={'master':HostAssignment('master','10.0.0.10',['R1'])})
    allocations={'R1':[{'container_port':443,'host_port':8456,'bind_ip':'127.0.0.1','proto':'tcp'}]}
    text=generate_micro_topology_files(topo,plan,allocations)['master']['R1']
    assert yaml.safe_load(text)['topology']['nodes']['R1']['ports']==existing
