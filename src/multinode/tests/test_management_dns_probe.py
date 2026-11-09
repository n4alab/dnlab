"""DNS readiness accepts exact question-bound A/AAAA wire answers only."""
import ipaddress
import struct
import pytest
from dnlab_multinode.services import management_dns_probe as probe

NAME='health.invalid'


def response(address='192.0.2.53'):
    ip=ipaddress.ip_address(address);kind=1 if ip.version==4 else 28
    question=probe.wire_name(NAME)+struct.pack('!HH',kind,1)
    answer=b'\xc0\x0c'+struct.pack('!HHIH',kind,1,0,len(ip.packed))+ip.packed
    return struct.pack('!HHHHHH',123,0x8180,1,1,0,0)+question+answer


@pytest.mark.parametrize('ip',['192.0.2.53','2001:db8::53'])
def test_exact_compressed_answer_and_case_insensitive_owner(ip):
    assert probe.validate_response(response(ip),123,NAME.upper(),ip)['address']==ip


@pytest.mark.parametrize('fault',['id','query','opcode','truncated','rcode','reserved','no-question','no-answer','question-name','question-type','question-class','answer-name','answer-type','answer-class','address','length','trailing','pointer-forward','pointer-loop','label-kind'])
def test_wrong_or_malformed_answer_is_rejected(fault):
    packet=bytearray(response());answer=12+len(probe.wire_name(NAME))+4
    if fault=='id':struct.pack_into('!H',packet,0,124)
    elif fault in ('query','opcode','truncated','rcode','reserved'):
        struct.pack_into('!H',packet,2,{'query':0x0180,'opcode':0x8980,'truncated':0x8380,'rcode':0x8183,'reserved':0x81c0}[fault])
    elif fault=='no-question':struct.pack_into('!H',packet,4,0)
    elif fault=='no-answer':struct.pack_into('!H',packet,6,0)
    elif fault=='question-name':packet[13]=ord('x')
    elif fault=='question-type':struct.pack_into('!H',packet,answer-4,28)
    elif fault=='question-class':struct.pack_into('!H',packet,answer-2,3)
    elif fault=='answer-name':packet[answer:answer+2]=b'\xc0\x13'
    elif fault=='answer-type':struct.pack_into('!H',packet,answer+2,28)
    elif fault=='answer-class':struct.pack_into('!H',packet,answer+4,3)
    elif fault=='address':packet[-1]=54
    elif fault=='length':struct.pack_into('!H',packet,answer+10,5)
    elif fault=='trailing':packet+=b'X'
    elif fault=='pointer-forward':packet[answer:answer+2]=b'\xff\xff'
    elif fault=='pointer-loop':packet[answer:answer+2]=struct.pack('!H',0xc000|answer)
    elif fault=='label-kind':packet[answer]=0x40
    with pytest.raises(probe.ProbeError):probe.validate_response(bytes(packet),123,NAME,'192.0.2.53')


def test_expected_address_hidden_in_unrelated_data_is_not_an_answer():
    packet=response('192.0.2.54')+ipaddress.ip_address('192.0.2.53').packed
    with pytest.raises(probe.ProbeError):probe.validate_response(packet,123,NAME,'192.0.2.53')


@pytest.mark.parametrize('name',['','a..invalid','a'*64+'.invalid','.'.join(['a'*63]*4),'h\u00e9alth.invalid'])
def test_name_limits(name):
    with pytest.raises(probe.ProbeError):probe.wire_name(name)


def test_short_frames_never_qualify():
    packet=response()
    for length in range(len(packet)):
        with pytest.raises(probe.ProbeError):probe.validate_response(packet[:length],123,NAME,'192.0.2.53')


@pytest.mark.parametrize('tcp',[False,True])
def test_query_uses_connected_server_and_fragmented_tcp(monkeypatch,tcp):
    class Socket:
        def __init__(self):self.data=None;self.sent=[];self.target=None
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):assert 0<value<=2
        def connect(self,target):self.target=target
        def send(self,data):self.sent.append(data);return len(data)
        def sendall(self,data):self.sent.append(data)
        def recv(self,count):
            if self.data is None:
                assert self.sent
                self.data=(struct.pack('!H',len(response())) if tcp else b'')+response()
            size=min(count,1 if tcp else count);out=self.data[:size];self.data=self.data[size:];return out
    stream=Socket();monkeypatch.setattr(probe.socket,'socket',lambda *args:stream)
    monkeypatch.setattr(probe.os,'urandom',lambda size:struct.pack('!H',123))
    result=probe.query('192.0.2.53',NAME,'192.0.2.53',tcp=tcp)
    assert stream.target==('192.0.2.53',53)
    assert result['transport']==('tcp' if tcp else 'udp')
