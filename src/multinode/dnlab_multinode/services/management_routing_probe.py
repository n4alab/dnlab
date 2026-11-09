"""Bounded addressless UDP pair, with ARP/ND only for its own reservation.

The router must forward to the other reserved probe through another L2 segment.
No address, route, neighbour, sysctl or firewall configuration is changed.
"""
import ipaddress
import socket
import struct
import time


def checksum(raw):
    if len(raw)%2:raw+=b'\0'
    value=sum(struct.unpack('!'+str(len(raw)//2)+'H',raw))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535


def mac(value):return bytes.fromhex(value.replace(':',''))


def pseudo(version,source,target,protocol,length):
    if version==4:return source+target+struct.pack('!BBH',0,protocol,length)
    return source+target+struct.pack('!I3xB',length,protocol)


def ip_packet(version,source,target,protocol,body,hops=64):
    if version==6:return struct.pack('!IHBB',6<<28,len(body),protocol,hops)+source+target+body
    header=struct.pack('!BBHHHBBH',0x45,0,20+len(body),0,0,hops,protocol,0)+source+target
    return header[:10]+struct.pack('!H',checksum(header))+header[12:]+body


class Endpoint:
    def __init__(self,profile):
        self.profile=profile
        self.client=mac(profile['client_mac']);self.router=mac(profile['server_mac'])
        self.ips={v:ipaddress.ip_address(ip).packed for v,ip in profile['addresses'].items()}

    def frame(self,version,body,target=None):
        return (target or self.router)+self.client+struct.pack('!H',0x0800 if version==4 else 0x86dd)+body


    def arp(self,frame):
        if (len(frame)<42 or frame[12:14]!=b'\x08\x06' or frame[6:12]!=self.router
                or frame[:6] not in (b'\xff'*6,self.client)):return None
        body=frame[14:42]
        if (body[:8]!=struct.pack('!HHBBH',1,0x0800,6,4,1) or body[8:14]!=self.router
                or body[14:18]!=ipaddress.ip_address(self.profile['server_ip']).packed
                or body[24:28]!=self.ips['4']):return None
        reply=struct.pack('!HHBBH',1,0x0800,6,4,2)+self.client+self.ips['4']+self.router+body[14:18]
        return self.router+self.client+b'\x08\x06'+reply


    def neighbour(self,frame):
        if '6' not in self.ips or len(frame)<78 or frame[12:14]!=b'\x86\xdd' or frame[6:12]!=self.router:return None
        packet=frame[14:];length=40+int.from_bytes(packet[4:6],'big')
        if packet[0]>>4!=6 or packet[6]!=58 or packet[7]!=255 or length>len(packet):return None
        source,target=packet[8:24],packet[24:40];body=packet[40:length]
        solicited=ipaddress.IPv6Address('ff02::1:ff00:0').packed[:13]+self.ips['6'][-3:]
        if (source not in [ipaddress.ip_address(v).packed for v in (self.profile['server_ipv6'],self.profile['server_link_local'])]
                or target not in (solicited,self.ips['6']) or body[:2]!=b'\x87\0' or len(body)<24
                or body[8:24]!=self.ips['6'] or checksum(pseudo(6,source,target,58,len(body))+body)):return None
        options=body[24:];seen=set()
        while options:
            if len(options)<2 or options[1]==0 or options[1]*8>len(options):return None
            kind,size=options[0],options[1]*8
            if kind in seen or kind!=1 or size!=8 or options[2:8]!=self.router:return None
            seen.add(kind);options=options[size:]
        if target==solicited and 1 not in seen:return None
        destination_mac=b'\x33\x33\xff'+self.ips['6'][-3:] if target==solicited else self.client
        if frame[:6]!=destination_mac:return None
        reply=struct.pack('!BBHI',136,0,0,0x60000000)+self.ips['6']+b'\x02\x01'+self.client
        value=checksum(pseudo(6,self.ips['6'],source,58,len(reply))+reply)
        reply=reply[:2]+struct.pack('!H',value)+reply[4:]
        return self.frame(6,ip_packet(6,self.ips['6'],source,58,reply,255))



class Probe(Endpoint):
    def __init__(self,profile):
        super().__init__(profile)
        self.peers={v:ipaddress.ip_address(ip).packed for v,ip in profile['peer_addresses'].items()}
        self.payload=b'dnlab-route-v1:'+profile['token'].encode()+b':'
        self.port=profile['port']

    def udp(self,version,kind):
        key=str(version);source,target=self.ips[key],self.peers[key]
        body=self.payload+str(self.profile['side']).encode()+b':'+kind.encode()
        udp=struct.pack('!HHHH',self.port,self.port,8+len(body),0)+body
        value=checksum(pseudo(version,source,target,17,len(udp))+udp) or 65535
        udp=udp[:6]+struct.pack('!H',value)+udp[8:]
        return self.frame(version,ip_packet(version,source,target,17,udp))


    def decode_udp(self,frame):
        if len(frame)<14 or frame[:6]!=self.client or frame[6:12]!=self.router:return None
        packet=frame[14:];kind=frame[12:14]
        if kind==b'\x08\x00':
            version=4
            if (len(packet)<28 or packet[0]!=0x45 or packet[8]!=63 or packet[9]!=17
                    or int.from_bytes(packet[6:8],'big')&0xbfff or checksum(packet[:20])):return None
            length=int.from_bytes(packet[2:4],'big');source,target=packet[12:16],packet[16:20];udp=packet[20:length]
        elif kind==b'\x86\xdd':
            version=6
            if len(packet)<48 or packet[0]>>4!=6 or packet[6]!=17 or packet[7]!=63:return None
            length=40+int.from_bytes(packet[4:6],'big');source,target=packet[8:24],packet[24:40];udp=packet[40:length]
        else:return None
        key=str(version)
        if (key not in self.ips or source!=self.peers[key] or target!=self.ips[key] or length>len(packet)
                or len(udp)<8 or len(frame)>14+length and any(frame[14+length:])):return None
        sport,dport,size,value=struct.unpack('!HHHH',udp[:8])
        if (sport!=self.port or dport!=self.port or size!=len(udp) or not value
                or checksum(pseudo(version,source,target,17,len(udp))+udp)):return None
        prefix=self.payload+str(1-self.profile['side']).encode()+b':'
        if not udp[8:].startswith(prefix):return None
        kind=udp[8+len(prefix):]
        if kind not in (b'probe',b'ack'):return None
        return key,kind.decode()


def run(profile,progress=None):
    probe=Probe(profile);families=sorted(probe.ips);received=set();acknowledged=set();completed={}
    counts={key:0 for key in families};deadline=time.monotonic()+15;next_send=0;finish=None
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind((profile['interface'],0));sock.settimeout(.05)
        while time.monotonic()<deadline:
            now=time.monotonic()
            if now>=next_send:
                for key in families:
                    if counts[key]<30:
                        sock.send(probe.udp(int(key),'probe'));counts[key]+=1
                next_send=now+.25
            try:frame=sock.recv(65536)
            except socket.timeout:frame=None
            if frame:
                reply=probe.arp(frame) or probe.neighbour(frame)
                if reply:sock.send(reply)
                row=probe.decode_udp(frame)
                if row:
                    key,kind=row
                    if kind=='probe':received.add(key);sock.send(probe.udp(int(key),'ack'))
                    else:acknowledged.add(key)
            for key in families:
                if key in received & acknowledged and key not in completed:
                    row={'source':profile['peer_addresses'][key],'target':profile['addresses'][key],
                        'router_mac':profile['server_mac'],'hops':63,'peer_acknowledged':True,'sent':counts[key]}
                    completed[key]=row
                    if progress:progress('routing.ipv'+key,row)
            if len(completed)==len(families):
                if finish is None:finish=time.monotonic()+1
                if time.monotonic()>=finish:
                    return {'level':'routed-pair','families':completed}
    raise RuntimeError('routed pair timeout; completed families: '+','.join(sorted(completed)))
