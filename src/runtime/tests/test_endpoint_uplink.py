import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

from dnlab_runtime.endpoint_uplink import resolve_endpoint, vrf_host_peer
from dnlab_runtime.manifest import Conflict


def fixture(driver='dnlab-vrf', name='eth17'):
    network_id, endpoint_id = 'a' * 64, 'b' * 64
    bridge = 'mgmt-owned'
    host_peer = vrf_host_peer(network_id, endpoint_id) if driver == 'dnlab-vrf' else 'vethfixture'
    labels = {'io.dnlab.managed': 'mgmt-vrf', 'io.dnlab.lab': 'lab', 'io.dnlab.spike': 'probe'}
    network = {'Id': network_id, 'Name': 'management', 'Driver': driver, 'IPAM': {'Driver': driver}, 'Labels': labels, 'Options': {'dnlab.bridge': bridge, 'dnlab.vrf': 'vrf-owned', 'com.docker.network.bridge.name': bridge}, 'Containers': {'owned': {'EndpointID': endpoint_id}}}
    mac = '02:00:00:00:00:01'
    container = {'Id': 'owned', 'Config': {'Labels': {'org.dnlab.runtime.lab': 'lab', 'io.dnlab.spike': 'probe'}}, 'NetworkSettings': {'Networks': {'management': {'EndpointID': endpoint_id, 'NetworkID': network_id, 'MacAddress': mac, 'IPAddress': '192.0.2.2', 'IPPrefixLen': 24, 'Gateway': '192.0.2.1'}}}}
    connection = {'network_id': network_id, 'network_name': network['Name'], 'cidr': '192.0.2.2/24', 'gateway': '192.0.2.1'}
    host = [{'ifname': bridge, 'ifindex': 100, 'master': 'vrf-owned', 'linkinfo': {'info_kind': 'bridge'}}, {'ifname': host_peer, 'ifindex': 200, 'link_index': 300, 'master': bridge, 'linkinfo': {'info_kind': 'veth'}}, {'ifname': 'vrf-owned', 'linkinfo': {'info_kind': 'vrf'}}]
    links = [{'ifname': name, 'ifindex': 300, 'link_index': 200, 'address': mac, 'linkinfo': {'info_kind': 'veth'}}, {'ifname': 'eth1', 'ifindex': 50, 'link_index': 51, 'address': mac, 'linkinfo': {'info_kind': 'veth'}}]
    return network, container, connection, host, links


@pytest.mark.parametrize('driver', ['dnlab-vrf', 'bridge'])
@pytest.mark.parametrize('name', ['eth0', 'eth2', 'eth17'])
def test_endpoint_is_found_by_peer_not_interface_name_or_shared_guest_mac(driver, name):
    result = resolve_endpoint(*fixture(driver, name))
    assert result['name'] == name and result['ifindex'] == 300
    assert result['peer_ifindex'] == 200


@pytest.mark.parametrize('bad', ['metadata', 'membership', 'bridge', 'reciprocal', 'host-name', 'mac', 'foreign-lab', 'ambiguous', 'ip', 'vrf'])
def test_inconsistent_or_foreign_endpoint_is_never_selected(bad):
    network, container, connection, host, links = fixture()
    if bad == 'metadata':
        container['NetworkSettings']['Networks']['management']['EndpointID'] = 'c' * 64
    elif bad == 'membership':
        network['Containers'] = {}
    elif bad == 'bridge':
        host[1]['master'] = 'another-lab'
    elif bad == 'reciprocal':
        host[1]['link_index'] = 301
    elif bad == 'host-name':
        host[1]['ifname'] = 'another-peer'
    elif bad == 'mac':
        links[0]['address'] = '02:00:00:00:00:02'
    elif bad == 'foreign-lab':
        network['Labels']['io.dnlab.lab'] = 'other'
    elif bad == 'ip':
        container['NetworkSettings']['Networks']['management']['IPAddress'] = '192.0.2.99'
    elif bad == 'vrf':
        host[0]['master'] = 'other-vrf'
    else:
        links.append(deepcopy(links[0]))
    with pytest.raises(Conflict):
        resolve_endpoint(network, container, connection, host, links)


def test_resolution_survives_address_relocation_and_replays_current_endpoint():
    values = fixture()
    before = resolve_endpoint(*values)
    network, container, connection, host, links = values
    new_id = 'c' * 64
    network['Containers']['owned']['EndpointID'] = new_id
    container['NetworkSettings']['Networks']['management']['EndpointID'] = new_id
    host[1].update(ifname=vrf_host_peer(network['Id'], new_id), ifindex=201, link_index=301)
    links[0].update(ifname='eth18', ifindex=301, link_index=201)
    after = resolve_endpoint(*values)
    assert after['endpoint_id'] != before['endpoint_id'] and after['name'] == 'eth18'
    assert after['mac'] == before['mac']


def test_peer_naming_matches_current_multinode_driver_contract():
    path = Path(__file__).resolve().parents[2] / 'multinode/dnlab_multinode/vrf_plugin.py'
    spec = importlib.util.spec_from_file_location('uplink_driver_contract', path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    network_id, endpoint_id = 'a' * 64, 'b' * 64
    assert vrf_host_peer(network_id, endpoint_id) == driver._endpoint_interface_names(network_id, endpoint_id)[0]
