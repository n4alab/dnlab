"""Wire admission: peers require routing, preserved IPs and original identities."""
from copy import deepcopy
import ipaddress
import struct

import pytest

from dnlab_multinode.services.management_routing_probe import Probe,checksum,ip_packet,pseudo
from dnlab_multinode.services.management_packet_receipt import validate,validate_progress,routing_profile
from dnlab_multinode.services.management_probe_host import validate as validate_request
from dnlab_multinode.services.management_probe_runtime import packet_program
from tests.test_management_probe_host import fixture


def profile(side=0):
    local=233+side;remote=234-side
    return {'mode':'routed-pair','interface':'probe0','client_mac':'02:00:00:00:00:0'+str(side+1),
        'server_mac':'02:00:00:00:00:f'+str(side+1),'server_ip':f'198.19.{local}.254',
        'server_ipv6':f'2001:db8:{local}::ffff','server_link_local':'fe80::f'+str(side+1),
        'addresses':{'4':f'198.19.{local}.252','6':f'2001:db8:{local}::fe'},
        'peer_addresses':{'4':f'198.19.{remote}.252','6':f'2001:db8:{remote}::fe'},
        'peer_segment':'blue' if side==0 else 'default','token':'a'*64,'side':side,'port':50000}


def delivered(version,kind='probe',*,hops=63,source=None,target=None,payload=None):
    local=Probe(profile());peer=Probe(profile(1));frame=peer.udp(version,kind)
    offset=34 if version==4 else 54;body=frame[offset:]
    src=ipaddress.ip_address(source).packed if source else peer.ips[str(version)]
    dst=ipaddress.ip_address(target).packed if target else local.ips[str(version)]
    if payload is not None:body=body[:8]+payload
    body=struct.pack('!HHHH',50000,50000,len(body),0)+body[8:]
    value=checksum(pseudo(version,src,dst,17,len(body))+body) or 65535
    body=body[:6]+struct.pack('!H',value)+body[8:]
    return local.client+local.router+frame[12:14]+ip_packet(version,src,dst,17,body,hops)


@pytest.mark.parametrize('version',[4,6])
def test_both_protocols_require_forwarded_hop_preserved_source_and_matching_token(version):
    probe=Probe(profile())
    assert probe.decode_udp(delivered(version))==(str(version),'probe')
    assert probe.decode_udp(delivered(version,'ack'))==(str(version),'ack')
    assert probe.decode_udp(delivered(version,hops=64)) is None  # direct L2 is insufficient
    assert probe.decode_udp(delivered(version,source=profile()['server_ip'] if version==4 else profile()['server_ipv6'])) is None
    assert probe.decode_udp(delivered(version,payload=b'dnlab-route-v1:'+b'b'*64+b':1:probe')) is None
    assert probe.decode_udp(delivered(version,payload=probe.payload+b'0:probe')) is None
    frame=delivered(version)
    for offset in (0,6,len(frame)-1):
        changed=bytearray(frame);changed[offset]^=1
        assert probe.decode_udp(changed) is None
    assert probe.decode_udp(frame[:-1]) is None
    assert probe.decode_udp(frame+b'\0\0')==(str(version),'probe')
    assert probe.decode_udp(frame+b'\0\1') is None


def arp_request(probe):
    return b'\xff'*6+probe.router+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,1)+probe.router+ipaddress.ip_address(probe.profile['server_ip']).packed+b'\0'*6+probe.ips['4']


def test_arp_responder_never_answers_for_another_owner_or_router():
    probe=Probe(profile());frame=arp_request(probe);answer=probe.arp(frame)
    assert answer[:6]==probe.router and answer[6:12]==probe.client
    assert answer[20:22]==b'\0\x02' and answer[28:32]==probe.ips['4']
    for offset in (0,6,21,22,28,41):
        bad=bytearray(frame);bad[offset]^=1
        assert probe.arp(bad) is None
    assert probe.arp(frame[:-1]) is None


def solicitation(probe,*,source=None,target=None,hops=255,options=None):
    source=ipaddress.IPv6Address(source or probe.profile['server_link_local']).packed
    target=target or probe.ips['6']
    destination=ipaddress.IPv6Address('ff02::1:ff00:0').packed[:13]+target[-3:]
    options=b'\x01\x01'+probe.router if options is None else options
    body=struct.pack('!BBHI',135,0,0,0)+target+options
    value=checksum(pseudo(6,source,destination,58,len(body))+body)
    body=body[:2]+struct.pack('!H',value)+body[4:]
    return b'\x33\x33\xff'+target[-3:]+probe.router+b'\x86\xdd'+ip_packet(6,source,destination,58,body,hops)


def test_nd_responder_requires_original_router_and_rfc4861_message_checks():
    probe=Probe(profile());answer=probe.neighbour(solicitation(probe))
    assert answer[:6]==probe.router and answer[6:12]==probe.client and answer[21]==255
    body=answer[54:];source,target=answer[22:38],answer[38:54]
    assert body[:2]==b'\x88\0' and int.from_bytes(body[4:8],'big')==0x60000000
    assert body[8:24]==probe.ips['6'] and body[24:]==b'\x02\x01'+probe.client
    assert checksum(pseudo(6,source,target,58,len(body))+body)==0
    assert probe.neighbour(solicitation(probe,source=probe.profile['server_ipv6'])) is not None
    for kwargs in ({'hops':254},{'source':'::'},{'source':'fe80::abcd'},
            {'target':ipaddress.IPv6Address('2001:db8:233::1').packed},
            {'options':b''},{'options':b'\x01\0'},
            {'options':b'\x01\x01'+probe.client},{'options':(b'\x01\x01'+probe.router)*2}):
        assert probe.neighbour(solicitation(probe,**kwargs)) is None
    bad=bytearray(solicitation(probe));bad[-1]^=1
    assert probe.neighbour(bad) is None


def result(p):
    return {'level':'routed-pair','families':{key:{'source':p['peer_addresses'][key],'target':value,
        'router_mac':p['server_mac'],'hops':63,'peer_acknowledged':True,'sent':1} for key,value in p['addresses'].items()}}


@pytest.mark.parametrize('fault',['hops','source','router_mac','peer_acknowledged','sent','family','field'])
def test_receipts_cannot_substitute_direct_delivery_nat_or_partial_families(fault):
    p=profile();r=result(p);validate(p,r)
    if fault=='family':del r['families']['6']
    elif fault=='field':r['families']['4']['foreign']=True
    else:r['families']['4'][fault]={'hops':64,'source':p['server_ip'],'router_mac':p['client_mac'],'peer_acknowledged':False,'sent':0}[fault]
    with pytest.raises(ValueError):validate(p,r)


def bind(request):
    p=profile();p['client_mac']=request['identity']['mac'];p['server_ip']=str(ipaddress.ip_interface(request['attachment']['ipv4']).ip)
    p['addresses']['4']=request['identity']['ipv4']
    if request['identity']['ipv6']:
        p['addresses']['6']=request['identity']['ipv6'];p['server_ipv6']=str(ipaddress.ip_interface(request['attachment']['ipv6']).ip)
    else:
        for key in ('addresses','peer_addresses'):del p[key]['6']
        p['server_ipv6']=p['server_link_local']=None
    return p


def test_request_binds_local_reservations_and_distinct_peer_subnet(fixture):
    request=deepcopy(fixture[0].request);request['packet_profile']=bind(request)
    assert validate_request(request)==request
    for field,value in (('client_mac','02:00:00:00:00:99'),('peer_segment',request['segment']),('side',True),('port',22)):
        bad=deepcopy(request);bad['packet_profile'][field]=value
        with pytest.raises(RuntimeError):validate_request(bad)
    for where in ('addresses','peer_addresses'):
        bad=deepcopy(request);bad['packet_profile'][where]['4']=request['attachment']['ipv4'].split('/')[0]
        with pytest.raises(RuntimeError):validate_request(bad)


def test_standalone_packet_source_contains_routing_decoder_without_installed_package():
    scope={'__name__':'_test_packet_source'};exec(packet_program(),scope)
    assert scope['routing']['Probe'](profile()).decode_udp(delivered(6))==('6','probe')
