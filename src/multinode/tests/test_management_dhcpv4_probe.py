"""Different management profiles share no fixed fixture addresses or netmask."""
import socket
import struct
import pytest
from dnlab_multinode.services.management_dhcpv4_probe import Probe,checksum


def profile(subnet,client,server,xid):
    return Probe(interface='probe0',client_mac='02:12:34:56:78:90',client_ip=client,
        server_mac='02:00:00:00:00:fe',server_ip=server,dns_ip='198.19.100.2',subnet=subnet,xid=xid)


def wire(p,kind=5):
    def option(code,value):return bytes([code,len(value)])+value
    opts=b''.join(option(k,v) for k,v in ((53,bytes([kind])),(54,socket.inet_aton(p.server_ip)),
        (3,socket.inet_aton(p.server_ip)),(6,socket.inet_aton(p.dns_ip)),(1,socket.inet_aton(p.netmask)),(51,struct.pack('!I',43200))))+b'\xff'
    bootp=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',2,1,6,0,p.xid,0,0x8000,
        bytes(4),socket.inet_aton(p.client_ip),socket.inet_aton(p.server_ip),bytes(4),p.client_mac+bytes(10),bytes(64),bytes(128))+bytes.fromhex('63825363')+opts
    udp=struct.pack('!HHHH',67,68,len(bootp)+8,0)+bootp
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(udp)+20,0,0,64,17,0,socket.inet_aton(p.server_ip),b'\xff'*4)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return b'\xff'*6+p.server_mac+b'\x08\x00'+ip+udp


@pytest.mark.parametrize('subnet,client,server',[('198.19.233.0/24','198.19.233.252','198.19.233.1'),('198.19.234.0/29','198.19.234.4','198.19.234.1')])
def test_profile_qualifies_own_subnet_and_rejects_other_management(subnet,client,server):
    p=profile(subnet,client,server,123);value=p.decode_frame(wire(p),5)
    assert value['offered']==client and value['router']==server and value['dns']=='198.19.100.2'
    other=profile('198.19.235.0/24','198.19.235.252','198.19.235.1',123)
    assert p.decode_frame(wire(other),5) is None
    p.xid=124
    assert p.decode_frame(wire(profile(subnet,client,server,123)),5) is None


@pytest.mark.parametrize('change',[
 {'client_ip':'198.19.233.0'},{'server_ip':'198.19.233.255'}, {'client_ip':'198.19.234.4'},
 {'server_mac':'ff:ff:ff:ff:ff:ff'}, {'xid':True},{'xid':0},{'interface':'probe0;ip'},
])
def test_invalid_profile_cannot_open_a_socket(change):
    args={'interface':'probe0','client_mac':'02:12:34:56:78:90','client_ip':'198.19.233.252',
        'server_mac':'02:00:00:00:00:fe','server_ip':'198.19.233.1','dns_ip':'198.19.100.2','subnet':'198.19.233.0/24','xid':123}
    args.update(change)
    with pytest.raises(ValueError):Probe(**args)
