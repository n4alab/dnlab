"""Native sticky management MAC contract and legacy parity diagnostic.

The native assertions verify the agreed contract; legacy parity remains explicit.
No guest DHCP traffic or Docker/kernel side effects are involved.
"""
from copy import deepcopy

import pytest

from tests.test_runtime_initial_deploy import world
from dnlab_multinode.models.topology import VDNode
from dnlab_multinode.models.schedule import HostAssignment,SchedulePlan
from dnlab_multinode.services.config import assign_sticky_mgmt_identities
from dnlab_multinode.services.jumphost import render_dhcp_config
from dnlab_multinode.services.generator import generate_micro_topology_files
from dnlab_runtime.manifest import RuntimeErrorBase


@pytest.fixture
def identity_topology(topo_factory):
    topo=topo_factory(name='demo',num_workers=0,links=[],
        nodes={'vd0':VDNode(name='vd0',kind='linux',image='sha256:'+'a'*64,mgmt_ipv4='192.0.2.2')})
    topo.mgmt.network='mgmt';topo.mgmt.ipv4_subnet='192.0.2.0/24';topo.mgmt.ipv4_gw='192.0.2.1'
    topo.mgmt.ipv6_subnet='2001:db8::/64';topo.mgmt.ipv6_gw='2001:db8::1';topo.mgmt.dhcp=True
    assign_sticky_mgmt_identities(topo.nodes,topo.mgmt,lab_name=topo.name)
    assert 'dhcp-host='+topo.nodes['vd0'].mgmt_mac+',192.0.2.2' in render_dhcp_config(topo)
    return topo


def test_native_start_accepts_the_mac_needed_by_existing_dhcp_reservation(world,identity_topology):
    batch,store,clients,engines,members=world
    request=deepcopy(members[0]['request'])
    request['spec']['management']={'network':'mgmt','ipv4':'192.0.2.2','mac':identity_topology.nodes['vd0'].mgmt_mac}
    assert engines['master'].plan(request)['management_preflight']['management']['mac']==identity_topology.nodes['vd0'].mgmt_mac
    assert engines['master'].backend.docker.calls==[]
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0


def test_omitting_sticky_mac_allows_start_but_does_not_request_it_from_docker(world,identity_topology):
    batch,store,clients,engines,members=world
    member=deepcopy(members[0]);member['request']['spec']['management']={'network':'mgmt','ipv4':'192.0.2.2'}
    batch.prepare('demo','deploy',[member]);assert batch.advance('demo','deploy')['phase']=='completed'
    container=engines['master'].backend.docker.inspect(member['request']['spec']['container_name'])
    config=container['Config']
    assert 'MacAddress' not in config
    assert all('MacAddress' not in endpoint for endpoint in config['NetworkingConfig']['EndpointsConfig'].values())
    assert identity_topology.nodes['vd0'].mgmt_mac not in str(config)


def test_legacy_linux_generation_also_does_not_forward_the_reserved_mac(identity_topology):
    topo=identity_topology
    plan=SchedulePlan(lab_name=topo.name,assignments={'master':HostAssignment('master','10.0.0.10',['vd0'])})
    files=generate_micro_topology_files(topo,plan)
    assert files
    assert topo.nodes['vd0'].mgmt_mac not in str(files)
