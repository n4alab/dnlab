"""Execute original packet expectations inside a prequalified probe namespace."""
import ipaddress
import json
import socket
import sys
import time

try:
    DHCPv4Probe
except NameError:
    from .management_dhcpv4_probe import Probe as DHCPv4Probe
    from .management_dhcpv6_probe import run as run_v6
    from .management_routing_probe import run as run_routing
    from .management_dns_client_probe import run as run_dns_client


def run(profile,progress=None):
    if profile.get('mode')=='dns-client':return run_dns_client(profile,progress=progress)
    if profile.get('mode')=='routed-pair':return run_routing(profile,progress=progress)
    four={key:profile[key] for key in ('interface','client_mac','client_ip','server_mac','server_ip','dns_ip','subnet','xid')}
    result={'level':'dhcp-packets','ipv4':DHCPv4Probe(**four).run(progress=progress),'ipv6':None}
    if profile['ipv6'] is not None:
        six=dict(profile['ipv6']);six['interface']=profile['interface']
        for key in ('duid','iaid','solicit_xid','request_xid'):six[key]=bytes.fromhex(six[key].replace(':',''))
        for key in ('client_mac','server_mac'):six[key]=bytes.fromhex(profile[key].replace(':',''))
        # The kernel creates the client's link-local address after link-up.
        # Query it through a socket without configuring any address or route.
        deadline=time.monotonic()+5
        while True:
            with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as sock:
                index=socket.if_nametoindex(profile['interface'])
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,profile['interface'].encode()+b'\0')
                try:
                    sock.connect(('ff02::1:2',547,0,index));local=sock.getsockname()[0]
                    if not ipaddress.IPv6Address(local).is_link_local:raise ValueError('probe link-local unavailable')
                    break
                except (OSError,ValueError):
                    if time.monotonic()>=deadline:raise RuntimeError('probe link-local readiness timeout')
            time.sleep(.05)
        six['client_ip']=local
        result['ipv6']=run_v6(**six,progress=progress)
    return result


if __name__=='__main__':print(json.dumps(run(json.load(sys.stdin))))
