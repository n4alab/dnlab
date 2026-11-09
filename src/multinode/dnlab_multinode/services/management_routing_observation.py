"""Read-only routing prerequisites; these never certify packet forwarding."""
import ipaddress


def validate(attachments, external, forwarding, routes, rules):
    """Require the original connected paths without alternate policy routing.

    Raw observations remain available to diagnostics. No route, address,
    firewall rule or sysctl is changed to make this check pass.
    """
    if forwarding != {'ipv4': '1', 'ipv6': '1'}:
        raise ValueError('jumphost forwarding differs from original service intent')
    expected = {4: {}, 6: {}}
    for row in attachments.values():
        for version, key in ((4, 'ipv4'), (6, 'ipv6')):
            if row[key]:
                address = ipaddress.ip_interface(row[key])
                if address.version != version:
                    raise ValueError('routing attachment address family differs')
                expected[version][str(address.network)] = (row['interface'], str(address.ip))
    expected[4][external['subnet']] = ('eth0', external['ip'])
    paths = {}
    for version in (4, 6):
        policy = [(0, 'local'), (32766, 'main')] + ([(32767, 'default')] if version == 4 else [])
        observed = rules[str(version)]
        if (not isinstance(observed, list) or len(observed) != len(policy)
                or any(not isinstance(row, dict) or set(row) - {'priority', 'src', 'table', 'protocol'}
                       or row.get('src') != 'all' or row.get('protocol', 'kernel') != 'kernel'
                       for row in observed)
                or sorted((row.get('priority'), row.get('table')) for row in observed) != policy):
            raise ValueError('jumphost routing policy differs from service paths')
        seen = set(); default = 0
        for row in routes[str(version)]:
            if (not isinstance(row, dict) or row.get('type', 'unicast') != 'unicast'
                    or any(key in row for key in ('nexthops', 'nhid', 'encap', 'from', 'via'))):
                raise ValueError('unsupported jumphost routing path')
            destination = row.get('dst')
            if destination == 'default':
                if (version != 4 or row.get('dev') != 'eth0'
                        or row.get('gateway') != external['gateway']):
                    raise ValueError('jumphost default path differs from external network')
                default += 1
                continue
            if version == 6 and destination == 'fe80::/64':
                if row.get('dev') not in {'eth0'} | {v['interface'] for v in attachments.values()}:
                    raise ValueError('unexpected link-local routing interface')
                continue
            wanted = expected[version].get(destination)
            if (wanted is None or destination in seen or row.get('dev') != wanted[0]
                    or row.get('protocol') != 'kernel' or row.get('gateway') is not None
                    or version == 4 and row.get('prefsrc') != wanted[1]):
                raise ValueError('jumphost connected path differs from original attachment')
            seen.add(destination)
        if seen != set(expected[version]) or default != (1 if version == 4 else 0):
            raise ValueError('jumphost connected or default path missing or ambiguous')
        paths[str(version)] = sorted(seen)
    return {'level': 'routing-control-plane', 'connected_prefixes': paths,
            'packet_forwarding_verified': False, 'external_ipv6_verified': False}
