"""Execute the actual namespace-local program with a captured netlink socket."""
import copy
import json
import socket
import struct
import subprocess
import sys

import pytest

from dnlab_multinode.services.jumphost_host import MUTATE_PROGRAM, context, signature


@pytest.mark.parametrize('operation,value,kind',[
    ('alias','dnlab-jumphost:proof',16),('up',None,16),('master','bridge',16),
    ('address','198.18.0.254/24',20),('address','2001:db8::254/64',20),
])
def test_kernel_program_uses_original_ifindex_and_checks_ack(monkeypatch,operation,value,kind):
    source={'ifname':'jh-original','ifindex':17,'address':'02:00:00:00:00:01','ifalias':'proof','link_index':19,'linkinfo':{'info_kind':'veth'}}
    bridge={'ifname':'br-original','ifindex':23,'address':'02:00:00:00:00:02','linkinfo':{'info_kind':'bridge'}}
    payload={'context':context(),'link':signature(source),'operation':operation,'value':signature(bridge) if value=='bridge' else value}
    packet=[]
    class Netlink:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def bind(self,*args):pass
        def settimeout(self,*args):pass
        def getsockname(self):return (999,0)
        def sendto(self,data,destination):packet.append(data);assert destination==(0,0)
        def recvfrom(self,*args):
            length,message,flags,seq,port=struct.unpack_from('=IHHII',packet[0])
            return struct.pack('=IHHIIi',20,2,0,seq,port,0),(0,0)
    monkeypatch.setattr(socket,'socket',lambda *a:Netlink())
    monkeypatch.setattr(subprocess,'check_output',lambda *a:json.dumps([source,bridge]).encode())
    monkeypatch.setattr(sys,'argv',['kernel',json.dumps(payload)])
    exec(compile(MUTATE_PROGRAM,'jumphost-kernel','exec'),{'__name__':'__gate__'})
    length,message,flags,seq,port=struct.unpack_from('=IHHII',packet[0])
    assert message==kind and length==len(packet[0])
    if kind==16:
        assert struct.unpack_from('=BBHiII',packet[0],16)[3]==17
        # No IFLA_IFNAME attribute may cause a replacement with the same name to be addressed.
        offset=32
        while offset<len(packet[0]):
            size,attr_kind=struct.unpack_from('=HH',packet[0],offset)
            assert attr_kind!=3
            if operation=='master':assert struct.unpack_from('=I',packet[0],offset+4)[0]==23
            offset+=(size+3)&~3
    else:assert struct.unpack_from('=BBBBI',packet[0],16)[4]==17


@pytest.mark.parametrize('replacement',['source','target','namespace'])
def test_kernel_program_refuses_replacement_before_send(monkeypatch,replacement):
    source={'ifname':'jh-original','ifindex':17,'address':'02:00:00:00:00:01','ifalias':'proof','link_index':19,'linkinfo':{'info_kind':'veth'}}
    target={'ifname':'br-original','ifindex':23,'address':'02:00:00:00:00:02','linkinfo':{'info_kind':'bridge'}}
    payload={'context':context(),'link':signature(source),'operation':'master','value':signature(target)}
    links=copy.deepcopy([source,target])
    if replacement=='source':links[0]['ifindex']=40
    if replacement=='target':links[1]['ifindex']=41
    if replacement=='namespace':payload['context']['inode']+=1
    class Netlink:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def bind(self,*args):pass
        def settimeout(self,*args):pass
        def getsockname(self):return (999,0)
        def sendto(self,*args):pytest.fail('replacement was mutated')
    monkeypatch.setattr(socket,'socket',lambda *a:Netlink())
    monkeypatch.setattr(subprocess,'check_output',lambda *a:json.dumps(links).encode())
    monkeypatch.setattr(sys,'argv',['kernel',json.dumps(payload)])
    with pytest.raises(RuntimeError):exec(compile(MUTATE_PROGRAM,'jumphost-kernel','exec'),{'__name__':'__gate__'})
