"""Pure service intent compilation for the opt-in management coordinator.

One jumphost and one DNS helper retain the existing lab access model. Additional
management attachments belong to that jumphost, with stable lab/segment names.
This is desired metadata, not an assertion that services have been materialized.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import ipaddress

from .management_segments import identifier, configured_segment, SegmentError
from .jumphost_network_host import config as external_config, NetworkError
from .jumphost_host import names as host_interface
from dnlab_multinode.utils.naming import jumphost_container_name


def peer_interface(lab, segment):
    identifier(lab); identifier(segment)
    if segment == 'default': return 'eth1'
    identity = ('jumphost-management-port-v1\0' + lab + '\0' + segment).encode()
    return 'jm' + hashlib.sha256(identity).hexdigest()[:13]


def compile_services(model, external, *, previous=None):
    """Describe service attachments without allocating IPs, interfaces or hosts.

    Existing attachments and external access cannot be changed or removed by
    recomputing a plan; such changes require an explicit lifecycle operation.
    """
    try:
        if (not isinstance(model, dict) or type(model.get('schema_version')) is not int
                or model['schema_version'] != 1 or not isinstance(model.get('networks'), dict)
                or 'default' not in model['networks']):
            raise SegmentError('complete resolved management model required for services')
        lab = identifier(model['lab']); external = external_config(deepcopy(external))
        attachments = {}; dhcp = []; subnets = []; peers = {'eth0'}; hosts = set(); bridges = {external['bridge']}
        for segment, cfg in sorted(model['networks'].items()):
            identifier(segment)
            inputs = {'ipv4-subnet':cfg['ipv4_subnet'], 'ipv4-gw':cfg['ipv4_gw'], 'dhcp':cfg['dhcp']}
            if bool(cfg['ipv6_subnet']) != bool(cfg['ipv6_gw']):
                raise SegmentError('incomplete service IPv6 configuration')
            if cfg['ipv6_subnet']: inputs.update({'ipv6-subnet':cfg['ipv6_subnet'], 'ipv6-gw':cfg['ipv6_gw']})
            normalized = configured_segment(lab, segment, inputs)
            if not cfg['ipv6_subnet']: normalized.ipv6_subnet = ''; normalized.ipv6_gw = ''
            if asdict(normalized) != cfg: raise SegmentError('service segment metadata differs from resolved network')
            for subnet in (ipaddress.ip_network(value) for value in (cfg['ipv4_subnet'],cfg['ipv6_subnet']) if value):
                if any(old.version == subnet.version and old.overlaps(subnet) for old in subnets):
                    raise SegmentError('service management subnets overlap')
                if subnet.version == 4 and subnet.overlaps(ipaddress.ip_network(external['subnet'])):
                    raise SegmentError('service management overlaps external network')
                subnets.append(subnet)
            peer, host = peer_interface(lab, segment), host_interface(lab, segment)
            if peer in peers or host in hosts or cfg['bridge'] in bridges:
                raise SegmentError('service attachment resource names collide')
            peers.add(peer); hosts.add(host); bridges.add(cfg['bridge'])
            attachments[segment] = {'host_interface':host, 'config':{
                'segment':segment, 'network':cfg['network'], 'bridge':cfg['bridge'], 'interface':peer,
                'ipv4':str(ipaddress.ip_interface(cfg['ipv4_gw'] + '/' + str(ipaddress.ip_network(cfg['ipv4_subnet']).prefixlen))),
                'ipv6':str(ipaddress.ip_interface(cfg['ipv6_gw'] + '/' + str(ipaddress.ip_network(cfg['ipv6_subnet']).prefixlen))) if cfg['ipv6_subnet'] else ''}}
            if cfg['dhcp']: dhcp.append(segment)
        result = {'schema_version':1, 'lab':lab,
            'jumphost':{'container_name':jumphost_container_name(lab), 'external_network':external, 'attachments':attachments},
            'dns':{'container_name':'dnlab-' + lab + '-dns', 'external_network':deepcopy(external),
                   'management_resolvers':{key:{'ipv4':cfg['ipv4_gw'],'ipv6':cfg['ipv6_gw']} for key,cfg in sorted(model['networks'].items())}},
            'dhcp_segments':dhcp, 'routing':{'via':'jumphost', 'ipv4':True, 'ipv6':any(v['config']['ipv6'] for v in attachments.values())}}
        if previous is not None:
            if not isinstance(previous, dict): raise SegmentError('invalid previous service intent')
            old = previous['jumphost']['attachments']
            if not isinstance(old, dict) or 'default' not in old or not old.keys() <= attachments.keys():
                raise SegmentError('service attachment removal requires a tracked operation')
            projected = deepcopy(result)
            projected['jumphost']['attachments'] = {key:attachments[key] for key in old}
            projected['dns']['management_resolvers'] = {key:result['dns']['management_resolvers'][key] for key in old}
            projected['dhcp_segments'] = [key for key in dhcp if key in old]
            projected['routing']['ipv6'] = any(attachments[key]['config']['ipv6'] for key in old)
            if previous != projected: raise SegmentError('existing service change requires a tracked operation')
        return result
    except SegmentError:
        raise
    except (ValueError, TypeError, KeyError, NetworkError) as error:
        raise SegmentError('invalid management service intent') from error


def validate_compilation(compilation):
    services = compilation['management_services']
    if not isinstance(services, dict): raise SegmentError('complete management services required')
    expected = compile_services(compilation['management_plan'], services['jumphost']['external_network'])
    if services != expected: raise SegmentError('compiled management services differ from network model')
