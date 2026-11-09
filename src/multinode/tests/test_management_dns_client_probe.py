"""Client-side DNS framing, transport closure and immutable receipts."""
from copy import deepcopy
import ipaddress
import socket
import struct

import pytest

from dnlab_multinode.services.management_dns_client_probe import Probe,ProbeError
from dnlab_multinode.services.management_routing_probe import checksum,pseudo,ip_packet
from dnlab_multinode.services.management_packet_receipt import dns_profile,dns_expected,validate
from dnlab_multinode.services.management_probe_host import validate as validate_request
from dnlab_multinode.services.management_probe_runtime import packet_program
from tests.test_management_dns_probe import response
from tests.test_management_routing_probe import profile as routing_profile
from tests.test_management_probe_host import fixture


def profile(address='192.0.2.53'):
    p=routing_profile()
    return {key:deepcopy(p[key]) for key in ('interface','client_mac','server_mac','server_ip','server_ipv6','server_link_local','addresses','token')} | {
        'mode':'dns-client','resolvers':{'4':'198.19.100.2','6':p['server_ipv6']},
        'records':[{'name':'health.invalid','address':address}]}


def incoming(probe,protocol,data,*,sequence=10,ack=20,flags=0x18,source=None,port=None):
    source=ipaddress.ip_address(source).packed if source else probe.target
    if protocol==17:body=struct.pack('!HHHH',port or 53,probe.port,8+len(data),0)+data;offset=6
    else:body=struct.pack('!HHIIBBHHH',port or 53,probe.port,sequence,ack,5<<4,flags,8192,0,0)+data;offset=16
    value=checksum(pseudo(probe.version,source,probe.source,protocol,len(body))+body)
    if protocol==17 and not value:value=65535
    body=body[:offset]+struct.pack('!H',value)+body[offset+2:]
    return probe.client+probe.router+struct.pack('!H',0x800 if probe.version==4 else 0x86dd)+ip_packet(probe.version,source,probe.source,protocol,body)


class Server:
    def __init__(self,probe,*,reset=False,early_fin=False):
        self.probe=probe;self.queue=[];self.sent=[];self.peer=0x12345678;self.offset=1
        self.responded=False;self.reset=reset;self.early_fin=early_fin;self.closed=False
    def __enter__(self):return self
    def __exit__(self,*args):self.closed=True
    def setsockopt(self,*args):pass
    def bind(self,target):assert target==(self.probe.profile['interface'],0)
    def settimeout(self,value):assert value==.05
    def send(self,frame):
        self.sent.append(frame);probe=self.probe;packet=frame[14:];offset=20 if probe.version==4 else 40
        protocol=packet[9] if probe.version==4 else packet[6];body=packet[offset:]
        answer=struct.pack('!H',probe.transaction)+response(probe.record['address'])[2:]
        if protocol==17:self.queue.append(incoming(probe,17,answer));return
        sequence,ack=struct.unpack_from('!II',body,4);flags=body[13];data=body[(body[12]>>4)*4:]
        if self.reset:self.queue.append(incoming(probe,6,b'',flags=0x14,ack=(sequence+1)&0xffffffff));return
        if flags==2:
            self.queue.append(incoming(probe,6,b'',sequence=self.peer,ack=(sequence+1)&0xffffffff,flags=0x12))
        elif data and not self.responded:
            self.responded=True;answer=struct.pack('!H',len(answer))+answer
            chunks=(answer[:1],answer[1:])
            for index,chunk in enumerate(chunks):
                packet=incoming(probe,6,chunk,sequence=self.peer+self.offset,ack=(sequence+len(data))&0xffffffff,
                    flags=0x19 if self.early_fin and index==1 else 0x18)
                self.queue.append(packet)
                if index==0:self.queue.append(packet)  # retransmitted byte is not appended twice
                self.offset+=len(chunk)
            if self.early_fin:self.offset+=1
        elif flags==0x11:
            self.queue.append(incoming(probe,6,b'',sequence=self.peer+self.offset,ack=(sequence+1)&0xffffffff,flags=0x10))
            if not self.early_fin:
                self.queue.append(incoming(probe,6,b'',sequence=self.peer+self.offset,ack=(sequence+1)&0xffffffff,flags=0x11))
    def recvmsg(self,*args):
        if not self.queue:raise socket.timeout()
        return self.queue.pop(0),[],0,('probe0',)


@pytest.mark.parametrize('family',['4','6'])
@pytest.mark.parametrize('transport',['udp','tcp'])
@pytest.mark.parametrize('address',['192.0.2.53','2001:db8::53'])
def test_original_resolver_answers_both_rr_types_and_tcp_closes(monkeypatch,family,transport,address):
    probe=Probe(profile(address),family,transport,0);server=Server(probe)
    monkeypatch.setattr(socket,'socket',lambda *args:server)
    row=probe.run()
    assert row['address']==address and row['server']==probe.profile['resolvers'][family]
    assert row['tcp_closed'] is (transport=='tcp') and row['checksum_status']==['verified']
    assert server.closed and probe.state=='completed'
    if transport=='tcp':assert probe.sent>=5 and server.responded


def test_tcp_peer_fin_with_answer_is_acknowledged_before_own_fin(monkeypatch):
    probe=Probe(profile(),'4','tcp',0);server=Server(probe,early_fin=True)
    monkeypatch.setattr(socket,'socket',lambda *args:server)
    assert probe.run()['tcp_closed'] is True


def test_tcp_reset_is_failure_not_dns_readiness(monkeypatch):
    probe=Probe(profile(),'4','tcp',0);server=Server(probe,reset=True)
    monkeypatch.setattr(socket,'socket',lambda *args:server)
    with pytest.raises(ProbeError,match='reset'):probe.run()
    assert server.closed and probe.state=='tcp-syn'


@pytest.mark.parametrize('family',['4','6'])
@pytest.mark.parametrize('protocol',[6,17])
def test_packet_decoder_checks_tuple_length_identity_and_checksum(family,protocol):
    probe=Probe(profile(),family,'tcp' if protocol==6 else 'udp',0)
    frame=incoming(probe,protocol,b'payload')
    assert probe.decode(frame,protocol) is not None
    for offset in (0,6,len(frame)-1):
        bad=bytearray(frame);bad[offset]^=1
        assert probe.decode(bad,protocol) is None
    assert probe.decode(incoming(probe,protocol,b'payload',source='198.19.100.9' if family=='4' else '2001:db8::9'),protocol) is None
    assert probe.decode(incoming(probe,protocol,b'payload',port=54),protocol) is None
    assert probe.decode(frame[:-1],protocol) is None
    bad=bytearray(frame);bad[-1]^=1
    assert probe.decode(bad,protocol,status=8) is not None
    assert probe.decode(bad,protocol,status=128) is not None
    assert probe.decode(bad,protocol,status=136) is None


def test_tcp_checksum_zero_is_valid_when_pseudo_checksum_verifies():
    probe=Probe(profile(),'4','tcp',0)
    # Ones-complement zero is legal for TCP, unlike an omitted UDP checksum.
    base=incoming(probe,6,b'\0\0');offset=14+20
    packet=base[offset:];tail=checksum(pseudo(4,probe.target,probe.source,6,len(packet))+packet[:16]+b'\0\0'+packet[18:])
    frame=incoming(probe,6,struct.pack('!H',tail))
    assert frame[offset+16:offset+18]==b'\0\0' and probe.decode(frame,6) is not None


def test_profile_bound_to_original_probe_and_expected_dns_receipt(fixture):
    request=deepcopy(fixture[0].request);p=profile();identity=request['identity'];attachment=request['attachment']
    p['client_mac']=identity['mac'];p['addresses']={'4':identity['ipv4']}
    p['server_ip']=str(ipaddress.ip_interface(attachment['ipv4']).ip)
    if identity['ipv6']:
        p['addresses']['6']=identity['ipv6'];p['server_ipv6']=str(ipaddress.ip_interface(attachment['ipv6']).ip)
        p['resolvers']['6']=p['server_ipv6']
    else:p['server_ipv6']=p['server_link_local']=None;p['resolvers'].pop('6')
    request['packet_profile']=p
    assert validate_request(request)==request
    answers={stage:dict(row,sent=1,checksum_status=['verified']) for stage,row in dns_expected(p).items()}
    result={'level':'dns-client-packets','answers':answers};validate(p,result)
    for field,value in (('client_mac','02:00:00:00:ff:ff'),('token','z'*64),('records',[])):
        bad=deepcopy(request);bad['packet_profile'][field]=value
        with pytest.raises(RuntimeError):validate_request(bad)
    for field,value in (('tcp_closed',False),('address','192.0.2.99'),('server','192.0.2.99'),('checksum_status',[])):
        bad=deepcopy(result);stage=next(s for s in bad['answers'] if '.tcp.' in s);bad['answers'][stage][field]=value
        with pytest.raises(ValueError):validate(p,bad)
    partial=deepcopy(result);partial['answers'].pop(next(iter(answers)))
    with pytest.raises(ValueError):validate(p,partial)


def test_standalone_source_contains_shared_router_and_dns_decoders():
    scope={'__name__':'_test_packet_source'};exec(packet_program(),scope)
    probe=scope['dnsclient']['Probe'](profile(),'6','udp',0)
    assert probe.decode(incoming(probe,17,b'payload'),17) is not None
