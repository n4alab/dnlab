"""Bounded addressless DNS client using the original management router.

Only its infrastructure reservation answers ARP/ND. TCP is limited to one small
DNS exchange per connection, with verified FIN/ACK closure. No host routes,
addresses, listeners, sysctls or firewall rules are installed.
"""
import hashlib
import ipaddress
import socket
import struct
import time

try:
    Endpoint
except NameError:
    from .management_routing_probe import Endpoint,checksum,pseudo,ip_packet
    from .management_dns_probe import wire_name,validate_response,ProbeError


class Probe(Endpoint):
    def __init__(self,profile,family,transport,index):
        super().__init__(profile)
        self.family=family;self.version=int(family);self.transport=transport
        self.record=profile['records'][index]
        self.source=self.ips[family];self.target=ipaddress.ip_address(profile['resolvers'][family]).packed
        seed=hashlib.sha256((profile['token']+'\0'+family+'\0'+transport+'\0'+str(index)).encode()).digest()
        self.transaction=int.from_bytes(seed[:2],'big');self.port=49152+int.from_bytes(seed[2:4],'big')%16384
        self.sequence=int.from_bytes(seed[4:8],'big');self.peer_sequence=None
        self.state='new';self.sent=0;self.received=0;self.rejected=0;self.last=[]
        self.checksums=set();self.sock=None
        kind=1 if ipaddress.ip_address(self.record['address']).version==4 else 28
        self.question=struct.pack('!HHHHHH',self.transaction,0x100,1,0,0,0)+wire_name(self.record['name'])+struct.pack('!HH',kind,1)

    def send(self,body,protocol):
        self.sent+=1
        if self.sent>32:raise ProbeError('DNS client packet limit exceeded')
        self.sock.send(self.frame(self.version,ip_packet(self.version,self.source,self.target,protocol,body)))

    def udp(self):
        body=struct.pack('!HHHH',self.port,53,8+len(self.question),0)+self.question
        value=checksum(pseudo(self.version,self.source,self.target,17,len(body))+body) or 65535
        self.send(body[:6]+struct.pack('!H',value)+body[8:],17)

    def tcp(self,sequence,ack,flags,payload=b''):
        body=struct.pack('!HHIIBBHHH',self.port,53,sequence&0xffffffff,ack&0xffffffff,5<<4,flags,8192,0,0)+payload
        value=checksum(pseudo(self.version,self.source,self.target,6,len(body))+body)
        self.send(body[:16]+struct.pack('!H',value)+body[18:],6)

    def decode(self,frame,protocol,*,status=0):
        if len(frame)<14 or frame[:6]!=self.client or frame[6:12]!=self.router:return None
        packet=frame[14:]
        if self.version==4:
            if (frame[12:14]!=b'\x08\x00' or len(packet)<20 or packet[0]!=0x45 or packet[9]!=protocol
                    or not packet[8] or int.from_bytes(packet[6:8],'big')&0xbfff or checksum(packet[:20])):return None
            length=int.from_bytes(packet[2:4],'big');source,target=packet[12:16],packet[16:20];body=packet[20:length]
        else:
            if frame[12:14]!=b'\x86\xdd' or len(packet)<40 or packet[0]>>4!=6 or packet[6]!=protocol or not packet[7]:return None
            length=40+int.from_bytes(packet[4:6],'big');source,target=packet[8:24],packet[24:40];body=packet[40:length]
        if (source!=self.target or target!=self.source or length>len(packet)
                or len(body)<(8 if protocol==17 else 20) or len(frame)>14+length and any(frame[14+length:])):return None
        if len(self.last)==2:self.last.pop(0)
        self.last.append(frame[:80].hex());self.received+=1
        if struct.unpack('!HH',body[:4])!=(53,self.port):return None
        pending,valid=bool(status&8),bool(status&128)
        if pending and valid:return None
        offset=6 if protocol==17 else 16;value=int.from_bytes(body[offset:offset+2],'big')
        if not value and self.version==6 and protocol==17:return None
        if (value or protocol==6) and not (pending or valid) and checksum(pseudo(self.version,source,target,protocol,len(body))+body):return None
        if protocol==17:
            if int.from_bytes(body[4:6],'big')!=len(body):return None
        else:
            size=(body[12]>>4)*4
            if size<20 or size>len(body) or body[12]&15:return None
            options=body[20:size]
            while options:
                if options[0]==0:
                    if any(options):return None
                    break
                if options[0]==1:options=options[1:];continue
                if len(options)<2 or options[1]<2 or options[1]>len(options):return None
                options=options[options[1]:]
        self.checksums.add('kernel-offload-pending' if pending else 'kernel-validated' if valid else 'absent' if not value and protocol==17 else 'verified')
        return body

    def receive(self,protocol):
        try:frame,ancillary,flags,peer=self.sock.recvmsg(65535,1024)
        except socket.timeout:return None
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):return None
        aux=[data for level,kind,data in ancillary if level==263 and kind==8]
        if len(aux)>1 or aux and len(aux[0])<20:return None
        status=struct.unpack_from('=I',aux[0])[0] if aux else 0
        reply=self.arp(frame) or self.neighbour(frame)
        if reply:self.sock.send(reply)
        return self.decode(frame,protocol,status=status)

    def timeout(self):
        raise ProbeError('DNS client timeout '+str({'state':self.state,'family':self.family,'transport':self.transport,
            'received':self.received,'rejected':self.rejected,'sent':self.sent,'last':self.last}))

    def exchange_udp(self):
        self.state='udp-query';deadline=time.monotonic()+4;next_send=0
        while time.monotonic()<deadline:
            if time.monotonic()>=next_send:self.udp();next_send=time.monotonic()+1
            body=self.receive(17)
            if body:
                try:return validate_response(body[8:],self.transaction,self.record['name'],self.record['address'])
                except ProbeError:self.rejected+=1
        self.timeout()

    def wait_tcp(self,sequence,ack,flags,payload=b'',*,wanted,timeout=4):
        deadline=time.monotonic()+timeout;next_send=0
        while time.monotonic()<deadline:
            if time.monotonic()>=next_send:
                self.tcp(sequence,ack,flags,payload);next_send=time.monotonic()+1
            body=self.receive(6)
            if not body:continue
            if body[13]&4:raise ProbeError('original DNS TCP peer reset connection in '+self.state)
            if wanted(body):return body
        self.timeout()

    def exchange_tcp(self):
        self.state='tcp-syn';local=(self.sequence+1)&0xffffffff
        def syn(body):
            return body[13]==0x12 and struct.unpack_from('!I',body,8)[0]==local and len(body)==(body[12]>>4)*4
        initial=self.wait_tcp(self.sequence,0,2,wanted=syn)
        remote=(struct.unpack_from('!I',initial,4)[0]+1)&0xffffffff
        payload=struct.pack('!H',len(self.question))+self.question;local_end=(local+len(payload))&0xffffffff
        self.state='tcp-dns';answer=bytearray();length=None;closed=False;deadline=time.monotonic()+4;next_send=0
        while time.monotonic()<deadline:
            if time.monotonic()>=next_send:
                self.tcp(local,remote,0x18,payload);next_send=time.monotonic()+1
            body=self.receive(6)
            if not body:continue
            sequence,ack=struct.unpack_from('!II',body,4);flags=body[13];offset=(body[12]>>4)*4;data=body[offset:]
            if flags&4:raise ProbeError('original DNS TCP peer reset connection in '+self.state)
            if flags&~0x19 or not flags&0x10 or ack!=local_end:continue
            if sequence!=remote:
                self.tcp(local_end,remote,0x10);continue
            if len(answer)+len(data)>4098:raise ProbeError('bounded DNS TCP response limit exceeded')
            answer.extend(data);remote=(remote+len(data))&0xffffffff
            if flags&1:remote=(remote+1)&0xffffffff;closed=True
            if data or flags&1:self.tcp(local_end,remote,0x10)
            if length is None and len(answer)>=2:
                length=int.from_bytes(answer[:2],'big')
                if not 12<=length<=4096:raise ProbeError('bounded DNS TCP length differs')
            if length is not None and len(answer)>=length+2:
                if len(answer)!=length+2:raise ProbeError('unexpected DNS TCP trailing data')
                result=validate_response(bytes(answer[2:]),self.transaction,self.record['name'],self.record['address'])
                break
            if closed:raise ProbeError('original DNS TCP peer closed before complete answer')
        else:self.timeout()
        self.state='tcp-fin';fin_acked=False;deadline=time.monotonic()+2;next_send=0
        while time.monotonic()<deadline:
            if time.monotonic()>=next_send:
                self.tcp(local_end,remote,0x11);next_send=time.monotonic()+1
            body=self.receive(6)
            if not body:continue
            sequence,ack=struct.unpack_from('!II',body,4);flags=body[13];offset=(body[12]>>4)*4
            if flags&4:raise ProbeError('original DNS TCP peer reset before verified closure')
            if flags&~0x11 or not flags&0x10 or len(body)!=offset:continue
            if ack==(local_end+1)&0xffffffff:fin_acked=True
            if flags&1 and sequence==remote:
                remote=(remote+1)&0xffffffff;closed=True
                self.tcp(local_end+1,remote,0x10)
            if closed and fin_acked:return result
        self.timeout()

    def run(self):
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
            self.sock=sock;sock.setsockopt(263,8,1);sock.bind((self.profile['interface'],0));sock.settimeout(.05)
            result=self.exchange_udp() if self.transport=='udp' else self.exchange_tcp()
        self.state='completed'
        return dict(result,family='ipv'+self.family,transport=self.transport,server=self.profile['resolvers'][self.family],
            client=self.profile['addresses'][self.family],router_mac=self.profile['server_mac'],sent=self.sent,
            tcp_closed=self.transport=='tcp',checksum_status=sorted(self.checksums))


def run(profile,progress=None):
    answers={}
    for family in sorted(profile['resolvers']):
        for index,record in enumerate(profile['records']):
            for transport in ('udp','tcp'):
                stage='dns.ipv'+family+'.'+transport+'.'+str(index)
                answers[stage]=Probe(profile,family,transport,index).run()
                if progress:progress(stage,answers[stage])
    return {'level':'dns-client-packets','answers':answers}
