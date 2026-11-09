"""Resolve an owned Docker endpoint to its current kernel veth, read-only."""

import hashlib
import ipaddress
import re

from .manifest import Conflict


def vrf_host_peer(network_id, endpoint_id):
    # Internal dnlab-vrf contract, shared with _endpoint_interface_names.
    digest = hashlib.sha256(f'{network_id}\x00{endpoint_id}'.encode()).hexdigest()[:12]
    return 'dvh' + digest


def resolve_endpoint(network, container, connection, host_links, namespace_links):
    if network.get('Id') != connection['network_id'] or network.get('Name') != connection['network_name']:
        raise Conflict('uplink network identity changed')
    endpoints = container['NetworkSettings']['Networks']
    if set(endpoints) != {network['Name']}:
        raise Conflict('uplink requires exactly one management endpoint')
    endpoint = endpoints[network['Name']]
    address = ipaddress.ip_interface(connection['cidr'])
    if endpoint.get('IPAddress') != str(address.ip) or endpoint.get('IPPrefixLen') != address.network.prefixlen or endpoint.get('Gateway') != connection['gateway']:
        raise Conflict('uplink address/gateway differs from the recorded connection')
    endpoint_id = endpoint.get('EndpointID')
    if not isinstance(endpoint_id, str) or not re.fullmatch('[0-9a-f]{64}', endpoint_id) or endpoint.get('NetworkID') != network['Id']:
        raise Conflict('uplink endpoint identity is incomplete')
    member = network.get('Containers', {}).get(container['Id'], {})
    if member.get('EndpointID') != endpoint_id:
        raise Conflict('container is not a member of the inspected network endpoint')
    options = network.get('Options') or {}
    labels = network.get('Labels') or {}
    expected_peer = None
    if network.get('Driver') == 'dnlab-vrf':
        if network.get('IPAM', {}).get('Driver') != 'dnlab-vrf' or labels.get('io.dnlab.managed') != 'mgmt-vrf' or labels.get('io.dnlab.lab') != container['Config']['Labels'].get('org.dnlab.runtime.lab'):
            raise Conflict('uplink dnlab-vrf ownership mismatch')
        bridge = options.get('dnlab.bridge')
        expected_peer = vrf_host_peer(network['Id'], endpoint_id)
    elif network.get('Driver') == 'bridge':
        owner = container['Config']['Labels'].get('io.dnlab.spike')
        if not owner or labels.get('io.dnlab.spike') != owner:
            raise Conflict('stock bridge uplink is allowed only for owned spike fixtures')
        bridge = options.get('com.docker.network.bridge.name') or 'br-' + network['Id'][:12]
    else:
        raise Conflict('management uplink driver is unqualified')
    host_bridge = next((link for link in host_links if link.get('ifname') == bridge), None)
    if not host_bridge or host_bridge.get('linkinfo', {}).get('info_kind') != 'bridge':
        raise Conflict('uplink host bridge is missing or changed')
    if network.get('Driver') == 'dnlab-vrf':
        vrf = next((link for link in host_links if link.get('ifname') == options.get('dnlab.vrf')), None)
        if not vrf or vrf.get('linkinfo', {}).get('info_kind') != 'vrf' or host_bridge.get('master') != vrf['ifname']:
            raise Conflict('uplink bridge/VRF attachment changed')
    matches = []
    for link in namespace_links:
        if link.get('ifname') in {'mgmt0', 'dmu0', 'dnlab-mgmt'} or link.get('linkinfo', {}).get('info_kind') != 'veth':
            continue
        for peer in host_links:
            if peer.get('linkinfo', {}).get('info_kind') != 'veth' or peer.get('master') != bridge:
                continue
            if expected_peer and peer.get('ifname') != expected_peer:
                continue
            if link.get('link_index') == peer.get('ifindex') and peer.get('link_index') == link.get('ifindex'):
                matches.append((link, peer))
    if len(matches) != 1:
        raise Conflict('management endpoint has no unique reciprocal kernel peer')
    link, peer = matches[0]
    mac = endpoint.get('MacAddress', '').lower()
    if mac and link.get('address') != mac:
        raise Conflict('kernel uplink MAC differs from Docker endpoint MAC')
    return {'network_id': network['Id'], 'endpoint_id': endpoint_id,
            'name': link['ifname'], 'ifindex': link['ifindex'], 'mac': link['address'],
            'peer_name': peer['ifname'], 'peer_ifindex': peer['ifindex']}
