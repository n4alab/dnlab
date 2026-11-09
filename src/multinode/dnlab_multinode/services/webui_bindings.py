"""Translate allocated WebUI bindings without losing the requested host address."""
import ipaddress


def runtime_binding(allocation):
    """Return the native manifest port binding; never infer a wildcard address."""
    if not isinstance(allocation,dict):raise ValueError('invalid allocated WebUI binding')
    address=allocation.get('bind_ip')
    try:
        if not isinstance(address,str) or '%' in address:raise ValueError()
        ipaddress.ip_address(address)
    except ValueError:
        raise ValueError('allocated WebUI bind_ip must be an explicit IPv4 or IPv6 address') from None
    for field in ('host_port','container_port'):
        if type(allocation.get(field)) is not int or not 1<=allocation[field]<=65535:
            raise ValueError('invalid allocated WebUI '+field)
    protocol=allocation.get('proto','tcp')
    if protocol not in ('tcp','udp'):raise ValueError('invalid allocated WebUI protocol')
    return {'host_ip':address,'host_port':allocation['host_port'],
            'container_port':allocation['container_port'],'protocol':protocol}


def containerlab_binding(allocation):
    binding=runtime_binding(allocation)
    host=binding['host_ip']
    if ipaddress.ip_address(host).version==6:host='['+host+']'
    return f"{host}:{binding['host_port']}:{binding['container_port']}/{binding['protocol']}"
