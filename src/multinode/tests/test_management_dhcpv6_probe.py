"""Bounded positive/negative wire qualification for management reservations."""
import socket
import struct
import pytest
from dnlab_multinode.services.management_dhcpv6_probe import (ProbeError,decode_message,ipv6_payload,decode_ra,checksum)

CLIENT=bytes.fromhex('020000000011');SERVER=bytes.fromhex('0200000000fe')
LL='fe80::11';SL='fe80::fe';ADDRESS='2001:db8:233::abcd';DNS='2001:db8:233::fe'
DUID=bytes.fromhex('000400000000000000000000000000000011');SID=bytes.fromhex('000300010200000000fe');IAID=bytes.fromhex('12345678');XID=bytes.fromhex('123456')


def option(code,value):return struct.pack('!HH',code,len(value))+value


def message(*,kind=2,xid=XID,duid=DUID,sid=SID,iaid=IAID,address=ADDRESS,dns=DNS,preferred=43200,valid=43200,t1=21600,t2=34560,extra=b'',iaextra=b'',addrextra=b''):
    addr=socket.inet_pton(socket.AF_INET6,address)+struct.pack('!II',preferred,valid)+addrextra
    ia=iaid+struct.pack('!II',t1,t2)+option(5,addr)+iaextra
    return bytes([kind])+xid+option(1,duid)+option(2,sid)+option(3,ia)+option(23,socket.inet_pton(socket.AF_INET6,dns))+extra


def qualify(data,**kwargs):
    return decode_message(data,kind=kwargs.get('kind',2),transaction=XID,duid=DUID,iaid=IAID,address=ADDRESS,dns=DNS,server_id=kwargs.get('server_id'))


def test_advertise_and_reply_bind_original_reservation_and_selected_server():
    offer=qualify(message());assert offer['address']==ADDRESS
    reply=qualify(message(kind=7),kind=7,server_id=bytes.fromhex(offer['server_id']))
    assert reply['iaid']==IAID.hex() and reply['dns']==DNS and reply['preferred_lifetime']>0


@pytest.mark.parametrize('changes',[
 {'kind':7},{'xid':b'abc'},{'duid':DUID[:-1]},{'sid':b'\0'},{'iaid':b'abcd'},
 {'address':'2001:db8:234::abcd'},{'dns':'2001:db8:234::fe'},
 {'preferred':0},{'preferred':50,'valid':49},{'valid':0},{'t1':10,'t2':9},
 {'extra':option(13,b'\0\2')},{'iaextra':option(13,b'\0\2')},
 {'addrextra':option(13,b'\0\2')},{'extra':option(1,DUID)},
 {'extra':option(3,bytes(12))},{'iaextra':option(5,bytes(24))},
 {'extra':b'\x12'},{'addrextra':b'\x01\x02\x00\x05a'},
 {'extra':option(14,b'')},{'extra':option(25,bytes(12))},
])
def test_wrong_identity_options_and_lease_cannot_qualify(changes):
    with pytest.raises(ProbeError):qualify(message(**changes))


def test_reply_cannot_switch_server_duid():
    with pytest.raises(ProbeError):qualify(message(kind=7,sid=b'changed'),kind=7,server_id=SID)


@pytest.mark.parametrize('size',[0,1,3,8,20,40,60])
def test_truncated_message_cannot_qualify(size):
    with pytest.raises(ProbeError):qualify(message()[:size])


def ra(*,prefix='2001:db8:233::',length=64,preferred=43200,valid=43200,flags=0xc0,lifetime=1800,extra=b''):
    return struct.pack('!BBHBBHII',134,0,0,64,flags,lifetime,0,0)+bytes([3,4,length,0x80])+struct.pack('!III',valid,preferred,0)+socket.inet_pton(socket.AF_INET6,prefix)+extra


def frame(body,protocol=17,*,source=SL,target=LL,smac=SERVER,dmac=CLIENT,hop=None):
    src=socket.inet_pton(socket.AF_INET6,source);dst=socket.inet_pton(socket.AF_INET6,target)
    if protocol==17:body=struct.pack('!HHHH',547,546,len(body)+8,0)+body
    at=6 if protocol==17 else 2
    value=checksum(src+dst+struct.pack('!I',len(body))+bytes(3)+bytes([protocol])+body) or 65535
    body=body[:at]+struct.pack('!H',value)+body[at+2:]
    return dmac+smac+b'\x86\xdd'+struct.pack('!IHBB',6<<28,len(body),protocol,hop if hop is not None else (255 if protocol==58 else 1))+src+dst+body


def payload(data,protocol=17,**kwargs):
    return ipv6_payload(data,protocol=protocol,server_mac=SERVER,server_ip=SL,client_mac=CLIENT,client_ip=LL,**kwargs)


def test_direct_dhcpv6_and_ra_frames_qualify_checksums_sources_and_prefix():
    assert qualify(payload(frame(message())))['address']==ADDRESS
    data=payload(frame(ra(),58,target='ff02::1',dmac=bytes.fromhex('333300000001')),58)
    assert decode_ra(data,prefix='2001:db8:233::/64')['prefixes'][0]['prefix']=='2001:db8:233::/64'


@pytest.mark.parametrize('changes',[
 {'source':'fe80::ff'},{'source':'2001:db8::1'},{'target':'fe80::22'},
 {'smac':bytes.fromhex('020000000099')},{'dmac':bytes.fromhex('020000000099')},
 {'target':'ff02::1','dmac':bytes.fromhex('333300000001')},
])
def test_wrong_direct_ipv6_source_destination_rejected(changes):
    with pytest.raises(ProbeError):payload(frame(message(),**changes))


def test_ipv6_checksum_offload_requires_kernel_metadata_and_never_bypasses_identity():
    data=bytearray(frame(message()));data[60]^=1
    with pytest.raises(ProbeError):payload(bytes(data))
    assert payload(bytes(data),checksum_pending=True)==message()
    assert payload(bytes(data),checksum_valid=True)==message()
    with pytest.raises(ProbeError):payload(bytes(data),checksum_pending=True,checksum_valid=True)
    with pytest.raises(ProbeError):payload(frame(message(),source='fe80::99'),checksum_pending=True)


@pytest.mark.parametrize('size',[0,13,14,53,54,60])
def test_truncated_ipv6_frames_rejected(size):
    with pytest.raises(ProbeError):payload(frame(message())[:size])


def test_ra_requires_original_hop_limit():
    with pytest.raises(ProbeError):payload(frame(ra(),58,hop=64),58)


@pytest.mark.parametrize('changes',[
 {'prefix':'2001:db8:234::'},{'length':63},{'preferred':0},{'preferred':50,'valid':49},
 {'lifetime':0},{'flags':0x80},{'flags':0x40},{'extra':bytes([3,0])},
 {'extra':b'\x01'},{'extra':bytes([3,4])+bytes(30)},
])
def test_wrong_ra_prefix_lifetimes_or_malformed_options_rejected(changes):
    with pytest.raises(ProbeError):decode_ra(ra(**changes),prefix='2001:db8:233::/64')
