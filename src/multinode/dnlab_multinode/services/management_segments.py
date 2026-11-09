"""Pure management segment resolution for the opt-in native coordinator path."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import ipaddress
import re

from dnlab_multinode.models.topology import MgmtConfig
from dnlab_multinode.utils import naming
from .config import ConfigError, assign_sticky_management
from .mgmt_ips import ipv4_reservations, ipv6_gateway, derive_ipv6_subnet_from_ipv4


class SegmentError(ConfigError):
    pass


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', value):
        raise SegmentError('invalid management segment identity')
    return value


def segment_names(lab, segment):
    identifier(lab); identifier(segment)
    if segment == 'default':
        return naming.mgmt_network_name(lab), naming.mgmt_bridge_name(lab)
    token = hashlib.sha256(('management-segment-v1\0' + lab + '\0' + segment).encode()).hexdigest()
    return 'mgmt-' + token[:24], 'bm' + token[:13]


def configured_segment(lab, segment, value):
    if not isinstance(value, dict) or set(value) - {'ipv4-subnet', 'ipv6-subnet', 'ipv4-gw', 'ipv6-gw', 'dhcp'}:
        raise SegmentError('unknown management segment configuration')
    if any(not isinstance(v, str) or not v for k, v in value.items() if k != 'dhcp'):
        raise SegmentError('management subnet/gateway values must be strings')
    if type(value.get('dhcp', False)) is not bool:
        raise SegmentError('management DHCP must be a boolean')
    try:
        subnet4 = ipaddress.IPv4Network(value['ipv4-subnet'], strict=True)
        reserved = ipv4_reservations(str(subnet4))
        subnet6 = ipaddress.IPv6Network(value.get('ipv6-subnet') or derive_ipv6_subnet_from_ipv4(str(subnet4)), strict=True)
        gateway4 = ipaddress.IPv4Address(value.get('ipv4-gw') or reserved.jumphost)
        gateway6 = ipaddress.IPv6Address(value.get('ipv6-gw') or ipv6_gateway(str(subnet6)))
    except (ValueError, TypeError, KeyError) as error:
        raise SegmentError('invalid management segment subnet/gateway') from error
    if (gateway4 not in subnet4 or gateway4 in (subnet4.network_address, subnet4.broadcast_address)
            or str(gateway4) in (reserved.docker_gw, reserved.anchor, reserved.dns)
            or gateway6 not in subnet6 or gateway6 == subnet6.network_address
            or subnet4.is_multicast or gateway4.is_unspecified or subnet6.is_multicast
            or gateway6.is_unspecified or gateway6.ipv4_mapped is not None or gateway6.scope_id is not None):
        raise SegmentError('invalid or reserved management segment gateway')
    network, bridge = segment_names(lab, segment)
    return MgmtConfig(network=network, bridge=bridge, ipv4_subnet=str(subnet4), ipv4_gw=str(gateway4),
        docker_ipv4_gw=reserved.docker_gw, ipv6_subnet=str(subnet6), ipv6_gw=str(gateway6), dhcp=value.get('dhcp', False))


def normalize(topo):
    """Return a validated topology copy, with mgmt as the default segment view."""
    topo = deepcopy(topo); identifier(topo.name)
    if not isinstance(topo.raw, dict): raise SegmentError('invalid management source topology')
    raw = topo.raw
    if 'management_networks' in raw:
        definitions = raw['management_networks']
        if not isinstance(definitions, dict) or not definitions or 'default' not in definitions:
            raise SegmentError('management_networks requires an explicit default segment')
        segments = {identifier(key): configured_segment(topo.name, key, value) for key, value in definitions.items()}
        if raw.get('mgmt') and asdict(segments['default']) != asdict(topo.mgmt):
            raise SegmentError('mgmt and management_networks.default disagree')
        if topo.management_networks and topo.management_networks != segments:
            raise SegmentError('parsed management segments differ from source')
    elif topo.management_networks:
        if topo.management_networks != {'default': topo.mgmt}:
            raise SegmentError('management segment definitions require original source')
        segments = {'default': deepcopy(topo.mgmt)}
    else:
        segments = {'default': deepcopy(topo.mgmt)}
    network_names, bridge_names = set(), set()
    for segment, cfg in segments.items():
        external = ipaddress.IPv4Network(topo.jumphost_net.ipv4_subnet, strict=False)
        if ipaddress.IPv4Network(cfg.ipv4_subnet).overlaps(external):
            raise SegmentError('management segment overlaps jumphost external network')
        identifier(cfg.network)
        if cfg.network in network_names or cfg.bridge in bridge_names:
            raise SegmentError('management segment resource names collide')
        network_names.add(cfg.network); bridge_names.add(cfg.bridge)
    values = list(segments.items())
    for index, (left, cfg) in enumerate(values):
        for right, other in values[index + 1:]:
            for field in ('ipv4_subnet', 'ipv6_subnet'):
                if getattr(cfg, field) and getattr(other, field) and ipaddress.ip_network(getattr(cfg, field)).overlaps(ipaddress.ip_network(getattr(other, field))):
                    raise SegmentError(f'management segments {left!r} and {right!r} overlap: {field}')
    for name, node in topo.nodes.items():
        if not isinstance(node.management_network, str) or node.management_network not in segments:
            raise SegmentError(f'unknown management network on node {name!r}')
        if not isinstance(node.management_port, str): raise SegmentError('invalid management port')
        port = node.management_port or 'eth0'
        if not isinstance(port, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', port) or port == 'lo':
            raise SegmentError('invalid management port')
        node.management_port = port
    for link in topo.links:
        for node, port in ((link.source, link.source_iface), (link.target, link.target_iface)):
            if node not in topo.nodes or port == topo.nodes[node].management_port:
                raise SegmentError('management port cannot also be used by a data link')
    for link in topo.real_net_links:
        if link.node not in topo.nodes or link.iface == topo.nodes[link.node].management_port:
            raise SegmentError('management port cannot attach to RealNet')
    topo.management_networks = segments; topo.mgmt = segments['default']
    topo.native_management = True
    return topo


def resolve(topo, previous=None, *, prepare_probes=False):
    """Resolve every segment and all VD identities without mutating caller state.

    A prepared topology cannot silently move an existing VD, change an existing
    segment, or release a segment or reservation. Those require lifecycle intents.
    """
    topo = normalize(topo)
    empty = {'schema_version': 1, 'lab': topo.name, 'networks': {}, 'assignments': {},
             'ledgers': {'ipv4': {}, 'ipv6': {}, 'mac': {}, 'duid': {}, 'iaid': {}}}
    prior = deepcopy(previous) if previous is not None else empty
    if (not isinstance(prior, dict) or set(prior) not in (set(empty),set(empty)|{'probes'}) or type(prior['schema_version']) is not int or prior['schema_version'] != 1 or prior['lab'] != topo.name
            or not isinstance(prior['networks'], dict) or not isinstance(prior['assignments'], dict)
            or not isinstance(prior['ledgers'], dict) or set(prior['ledgers']) != set(empty['ledgers'])
            or any(not isinstance(v, dict) for v in prior['ledgers'].values())):
        raise SegmentError('invalid or foreign management ledger')
    networks = {key: asdict(value) for key, value in sorted(topo.management_networks.items())}
    if 'probes' in prior:
        # A replay must not silently complete an older/partial sealed model.
        # Fresh reservations belong to an explicit preparation before sealing.
        from .management_probe_identity import validate
        validate(prior)
    for key, old in prior['networks'].items():
        if key not in networks or networks[key] != old:
            raise SegmentError('existing segment change/removal requires a tracked operation')
    ledgers = prior['ledgers']
    for family in ('ipv4', 'ipv6'):
        if set(ledgers[family]) - set(prior['networks']):
            raise SegmentError('management ledger references an unknown segment')
    assignments = prior['assignments']
    for name, value in assignments.items():
        if (not isinstance(name, str) or not name or not isinstance(value, dict) or set(value) != {'network', 'port'}
                or not isinstance(value['network'], str) or value['network'] not in prior['networks']
                or not isinstance(value['port'], str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', value['port']) or value['port'] == 'lo'):
            raise SegmentError('invalid previous management assignment')
    for name, node in topo.nodes.items():
        selected = {'network': node.management_network, 'port': node.management_port}
        if name in assignments and assignments[name] != selected:
            raise SegmentError('management move or port change requires a tracked operation')
        assignments[name] = selected
    probes=None
    if prepare_probes or 'probes' in prior:
        from .management_probe_identity import reserve
        ledgers,probes=reserve(topo.name,networks,ledgers,prior.get('probes',{}))
        if any(row['owner'] in topo.nodes for row in probes.values()):
            raise SegmentError('VD name collides with infrastructure probe owner')
    # Identity maps are global to the VD within the lab; address maps are per
    # segment. Each resolver call validates all identity owners, including retired.
    for segment, cfg in sorted(topo.management_networks.items()):
        members = {name: node for name, node in topo.nodes.items() if node.management_network == segment}
        result = assign_sticky_management(members, cfg, lab_name=topo.name,
            ipv4_reservations=ledgers['ipv4'].get(segment), ipv6_reservations=ledgers['ipv6'].get(segment),
            mac_reservations=ledgers['mac'], duid_reservations=ledgers['duid'], iaid_reservations=ledgers['iaid'])
        ledgers['ipv4'][segment], ledgers['ipv6'][segment], ledgers['mac'], ledgers['duid'], ledgers['iaid'] = result
    snapshot = {'schema_version': 1, 'lab': topo.name, 'networks': networks, 'assignments': assignments, 'ledgers': ledgers}
    if probes is not None:
        from .management_probe_identity import validate
        snapshot['probes']=probes;validate(snapshot)
    topo.raw['dnlab_management_plan'] = deepcopy(snapshot)
    return topo, snapshot


def validate_compilation(compilation, lab):
    """Ensure immutable segment metadata describes the submitted workloads."""
    model = compilation['management_plan']
    fields={'schema_version','lab','networks','assignments','ledgers'}
    if (not isinstance(model, dict) or set(model) not in (fields,fields|{'probes'})
            or type(model['schema_version']) is not int or model['schema_version'] != 1 or model['lab'] != lab
            or any(not isinstance(model[key], dict) for key in ('networks','assignments','ledgers'))
            or set(model['ledgers']) != {'ipv4','ipv6','mac','duid','iaid'}):
        raise SegmentError('invalid compiled management metadata')
    if 'probes' in model:
        from .management_probe_identity import validate
        validate(model)
    for member in compilation['members']:
        request = member['request']; name = request['node_id']; assignment = model['assignments'][name]
        if set(assignment) != {'network','port'} or assignment['port'] != 'eth0':
            raise SegmentError('unqualified compiled management port')
        segment = assignment['network']; cfg = model['networks'][segment]; ledgers = model['ledgers']
        expected = {'network':cfg['network'], 'ipv4':ledgers['ipv4'][segment][name],
                    'ipv6':ledgers['ipv6'][segment][name], 'mac':ledgers['mac'][name]}
        if request['spec'].get('management') != expected:
            raise SegmentError('compiled management metadata differs from workload')


def validate_observed_network(model, node, actual):
    """Check desired segment configuration against the runtime's original proof."""
    cfg = model['networks'][model['assignments'][node]['network']]
    options = actual.get('Options') or {}
    if not isinstance(options, dict): raise SegmentError('malformed observed segment options')
    options = options.get('com.docker.network.generic', options)
    labels = actual.get('Labels') or {}; ipam = actual.get('IPAM') or {}
    if (not isinstance(options, dict) or actual.get('Name') != cfg['network'] or actual.get('Driver') != 'dnlab-vrf'
            or labels.get('io.dnlab.managed') != 'mgmt-vrf' or labels.get('io.dnlab.lab') != model['lab']
            or options.get('dnlab.bridge') != cfg['bridge'] or options.get('dnlab.vrf') != naming.vrf_name(model['lab'])
            or options.get('dnlab.lab') != model['lab'] or ipam.get('Driver') != 'dnlab-vrf'
            or (ipam.get('Options') or {}).get('dnlab.tenant') != cfg['network']
            or actual.get('EnableIPv6') is not True):
        raise SegmentError('observed management segment differs from desired configuration')
    expected = [{'Subnet':cfg['ipv4_subnet'],'Gateway':cfg['docker_ipv4_gw']},
                {'Subnet':cfg['ipv6_subnet'],'Gateway':cfg['ipv6_gw']}]
    if sorted(ipam.get('Config', []),key=lambda x:x.get('Subnet','')) != sorted(expected,key=lambda x:x['Subnet']):
        raise SegmentError('observed management IPAM differs from desired segment')
