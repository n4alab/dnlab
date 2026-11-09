"""Bounded DNS packet probe (RFC1035 sections 4.1 and 4.2).

A/AAAA answers must belong to the exact original question. This is a health
probe for local hosts data, not a general resolver: aliases and referrals do
not qualify readiness. The program runs in an already qualified namespace.
"""
import ipaddress
import json
import os
import socket
import struct
import sys
import time


class ProbeError(RuntimeError):
    pass


def wire_name(name):
    if not isinstance(name,str):raise ProbeError('DNS question name required')
    try:labels=[part.encode('ascii') for part in name.rstrip('.').split('.')]
    except UnicodeEncodeError:raise ProbeError('ASCII DNS question required') from None
    if any(not part or len(part)>63 for part in labels):raise ProbeError('DNS label length differs')
    value=b''.join(bytes([len(part)])+part for part in labels)+b'\0'
    if len(value)>255:raise ProbeError('DNS name too long')
    return value


def read_name(message,offset):
    labels=[];visited=set();end=None;size=1
    while True:
        if offset in visited or offset>=len(message):raise ProbeError('invalid DNS name pointer')
        visited.add(offset);length=message[offset]
        if length&0xc0==0xc0:
            if offset+2>len(message):raise ProbeError('short DNS name pointer')
            target=((length&63)<<8)|message[offset+1]
            if target<12 or target>=offset:raise ProbeError('invalid DNS compression target')
            if end is None:end=offset+2
            offset=target;continue
        if length&0xc0:raise ProbeError('unsupported DNS label')
        offset+=1
        if not length:return b'.'.join(labels).lower(),end if end is not None else offset
        if offset+length>len(message):raise ProbeError('short DNS label')
        labels.append(message[offset:offset+length]);offset+=length;size+=length+1
        if size>255:raise ProbeError('expanded DNS name too long')


def validate_response(message,transaction,name,expected):
    address=ipaddress.ip_address(expected);kind=1 if address.version==4 else 28
    if len(message)<12:raise ProbeError('short DNS header')
    token,flags,questions,answers,authority,additional=struct.unpack_from('!HHHHHH',message)
    if token!=transaction or not flags&0x8000 or flags&0x7a4f or questions!=1:
        raise ProbeError('DNS header differs from successful standard answer')
    asked,offset=read_name(message,12)
    if offset+4>len(message):raise ProbeError('short DNS question')
    qtype,qclass=struct.unpack_from('!HH',message,offset);offset+=4
    wanted=name.rstrip('.').lower().encode('ascii')
    if asked!=wanted or qtype!=kind or qclass!=1:raise ProbeError('DNS question differs')
    found=set()
    for section,count in enumerate((answers,authority,additional)):
        for _ in range(count):
            owner,offset=read_name(message,offset)
            if offset+10>len(message):raise ProbeError('short DNS resource header')
            rtype,rclass,ttl,length=struct.unpack_from('!HHIH',message,offset);offset+=10
            if offset+length>len(message):raise ProbeError('short DNS resource data')
            data=message[offset:offset+length];offset+=length
            if section==0:
                if owner!=wanted or rtype!=kind or rclass!=1 or length!=len(address.packed):
                    raise ProbeError('DNS answer ownership/type differs')
                found.add(str(ipaddress.ip_address(data)))
    if offset!=len(message) or found!={str(address)}:raise ProbeError('DNS answer address or framing differs')
    return {'name':name,'type':'A' if kind==1 else 'AAAA','address':str(address)}


def query(server,name,expected,*,tcp=False,timeout=2):
    server=str(ipaddress.IPv4Address(server));address=ipaddress.ip_address(expected)
    transaction=int.from_bytes(os.urandom(2),'big')
    packet=struct.pack('!HHHHHH',transaction,0x100,1,0,0,0)+wire_name(name)+struct.pack('!HH',1 if address.version==4 else 28,1)
    deadline=time.monotonic()+timeout
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
        def bounded():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ProbeError('DNS probe deadline exceeded')
            stream.settimeout(remaining)
        bounded();stream.connect((server,53))
        if tcp:
            bounded();stream.sendall(struct.pack('!H',len(packet))+packet)
            def read(count):
                output=b''
                while len(output)<count:
                    bounded();block=stream.recv(count-len(output))
                    if not block:raise ProbeError('short DNS TCP frame')
                    output+=block
                return output
            length=struct.unpack('!H',read(2))[0]
            response=read(length)
        else:
            bounded();stream.send(packet);bounded();response=stream.recv(65535)
    result=validate_response(response,transaction,name,expected)
    result['transport']='tcp' if tcp else 'udp'
    return result


def main():
    request=json.load(sys.stdin)
    if set(request)!={'server','records'} or not isinstance(request['records'],list) or not 1<=len(request['records'])<=2:
        raise ProbeError('bounded original DNS probe input required')
    results=[]
    for record in request['records']:
        if not isinstance(record,dict) or set(record)!={'name','address'}:raise ProbeError('DNS record input differs')
        for tcp in (False,True):results.append(query(request['server'],record['name'],record['address'],tcp=tcp))
    print(json.dumps({'level':'dns-packets','server':request['server'],'answers':results},sort_keys=True))


if __name__=='__main__':main()
