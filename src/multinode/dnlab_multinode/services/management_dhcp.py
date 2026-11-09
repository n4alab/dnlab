"""Pure DHCP/RA config for the opt-in multi-management service coordinator.

Generation does not start, reload or replace a service. Structural config must
be provisioned under the existing offline barrier, separately from reservations.
"""
import hashlib
import ipaddress

from .management_segments import resolve, SegmentError
from .management_services import compile_services


def compile_dhcp(topo, model, services, resolver_ipv4):
    """Bind every reservation and range to the original resolved service intent."""
    try:
        resolved, checked = resolve(topo, model)
        if checked != model:
            raise SegmentError('DHCP requires a complete original management identity model')
        expected = compile_services(model, services['jumphost']['external_network'])
        if expected != services:
            raise SegmentError('DHCP service intent differs from resolved management')
        if 'probes' in model:
            from .management_probe_identity import validate
            validate(model)
        resolver = ipaddress.IPv4Address(resolver_ipv4)
        external = services['jumphost']['external_network']
        network = ipaddress.IPv4Network(external['subnet'])
        if (resolver not in network or resolver in (network.network_address, network.broadcast_address)
                or str(resolver) == external['gateway']):
            raise SegmentError('DHCP resolver must be the qualified external DNS service address')
        main = ['bind-dynamic', 'port=53', 'pid-file=/run/dnlab-dnsmasq.pid',
                'no-resolv', 'server=' + str(resolver)]
        ranges, options, reservations = [], [], []
        if services['dhcp_segments']: main.append('dhcp-authoritative')
        ra = False
        for segment in sorted(services['jumphost']['attachments']):
            cfg = model['networks'][segment]
            peer = services['jumphost']['attachments'][segment]['config']['interface']
            tag = 'dm' + hashlib.sha256((model['lab'] + '\0' + segment).encode()).hexdigest()[:20]
            subnet4 = ipaddress.IPv4Network(cfg['ipv4_subnet'])
            main.append('interface=' + peer)
            for address in (cfg['ipv4_gw'],cfg['ipv6_gw']):
                if address: main.append('listen-address=' + address)
            if not cfg['dhcp']:
                main.append('no-dhcp-interface=' + peer)
                continue
            ranges.append(f'dhcp-range=set:{tag},{subnet4.network_address},static,12h')
            options.extend([f'dhcp-option=tag:{tag},option:router,{cfg["ipv4_gw"]}',
                            f'dhcp-option=tag:{tag},option:dns-server,{cfg["ipv4_gw"]}'])
            if cfg['ipv6_subnet']:
                subnet6 = ipaddress.IPv6Network(cfg['ipv6_subnet'])
                ranges.extend([f'dhcp-range=set:{tag},{subnet6.network_address},static,{subnet6.prefixlen},12h',
                               f'ra-param={peer},60,1800'])
                # dnsmasq forwards IPv6 DNS requests to the same qualified lab
                # resolver; the external DNS helper retains its current IPv4 WAN.
                options.append(f'dhcp-option=tag:{tag},option6:dns-server,[{cfg["ipv6_gw"]}]')
                ra = True
            for name, node in sorted(resolved.nodes.items()):
                if node.management_network != segment:
                    continue
                reservations.append(f'dhcp-host={node.mgmt_mac},{node.mgmt_ipv4}')
                if node.mgmt_ipv6:
                    reservations.append(f'dhcp-host=id:{node.mgmt_duid},[{node.mgmt_ipv6}]')
            if segment in model.get('probes',{}):
                probe=model['probes'][segment]
                reservations.append(f'dhcp-host={probe["mac"]},{probe["ipv4"]}')
                if probe['ipv6']:reservations.append(f'dhcp-host=id:{probe["duid"]},[{probe["ipv6"]}]')
        return '\n'.join(main + (['enable-ra'] if ra else []) + ranges + options + reservations) + '\n'
    except SegmentError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise SegmentError('invalid multi-management DHCP service input') from error
