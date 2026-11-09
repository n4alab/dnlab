"""Bounded wire validators for the original direct DHCPv6/RA service profile.

DHCPv6 wire format: RFC9915 sections 8 and 21; RA: RFC4861 sections 4.2,
4.6.2 and 6.1.2. These checks qualify one IA_NA reservation and one advertised
prefix, not a general DHCP client, relays, extension headers or RFC compliance.
Callers must bind expectations to original service/namespace identity first.
"""
import ipaddress
import socket
import struct


class ProbeError(ValueError):
    pass


def checksum(data):
    if len(data)%2:data+=b'\0'
    value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535


def options(data):
    result={}
    while data:
        if len(data)<4:raise ProbeError('short DHCPv6 option header')
        code,size=struct.unpack_from('!HH',data)
        if len(data)<4+size or code in result:raise ProbeError('short or duplicate DHCPv6 option')
        result[code]=data[4:4+size];data=data[4+size:]
    return result


def successful(opts):
    if 13 in opts and (len(opts[13])<2 or opts[13][:2]!=b'\0\0'):
        raise ProbeError('DHCPv6 negative or malformed status')


def decode_message(message,*,kind,transaction,duid,iaid,address,dns,server_id=None):
    if kind not in (2,7) or len(transaction)!=3 or len(message)<4 or message[0]!=kind or message[1:4]!=transaction:
        raise ProbeError('DHCPv6 message type or transaction differs')
    opts=options(message[4:]);successful(opts)
    if opts.get(1)!=duid or not 2<=len(opts.get(2,b''))<=128 or server_id is not None and opts[2]!=server_id:
        raise ProbeError('DHCPv6 client/server identity differs')
    if 4 in opts or 25 in opts or 14 in opts:raise ProbeError('unexpected DHCPv6 association or rapid commit')
    ia=opts.get(3,b'')
    if len(ia)<12 or ia[:4]!=iaid:raise ProbeError('DHCPv6 IA_NA differs')
    t1,t2=struct.unpack_from('!II',ia,4)
    if t1 and t2 and t1>t2:raise ProbeError('DHCPv6 association timers differ')
    nested=options(ia[12:]);successful(nested)
    value=nested.get(5,b'')
    if len(value)<24 or value[:16]!=socket.inet_pton(socket.AF_INET6,address):raise ProbeError('DHCPv6 reservation differs')
    preferred,valid=struct.unpack_from('!II',value,16)
    if not 0<preferred<=valid:raise ProbeError('DHCPv6 lease lifetimes differ')
    successful(options(value[24:]))
    if opts.get(23)!=socket.inet_pton(socket.AF_INET6,dns):raise ProbeError('DHCPv6 resolver differs')
    return {'type':kind,'server_id':opts[2].hex(),'iaid':iaid.hex(),'address':str(ipaddress.IPv6Address(address)),
            'dns':str(ipaddress.IPv6Address(dns)),'preferred_lifetime':preferred,'valid_lifetime':valid,'t1':t1,'t2':t2}


def ipv6_payload(frame,*,protocol,server_mac,server_ip,client_mac,client_ip,
                 checksum_pending=False,checksum_valid=False):
    """Validate a direct Ethernet packet before decoding DHCPv6 or RA.

    Offload exceptions require trusted receiving-kernel AUXDATA flags, as with
    the IPv4 probe; callers reject outgoing/truncated packets and metadata.
    """
    if protocol not in (17,58) or len(frame)<54 or frame[12:14]!=b'\x86\xdd':raise ProbeError('short/non-IPv6 frame')
    if checksum_pending and checksum_valid:raise ProbeError('ambiguous checksum metadata')
    source=ipaddress.IPv6Address(server_ip);client=ipaddress.IPv6Address(client_ip)
    if not source.is_link_local or not client.is_link_local:raise ProbeError('qualified link-local identities required')
    ip=frame[14:];size=int.from_bytes(ip[4:6],'big');body=ip[40:40+size]
    destination=ipaddress.IPv6Address(ip[24:40])
    if (ip[0]>>4!=6 or ip[6]!=protocol or size==0 or len(body)!=size
            or ip[8:24]!=source.packed or frame[6:12]!=server_mac):raise ProbeError('IPv6 source or transport differs')
    if destination==client:target=client_mac
    elif protocol==58 and destination==ipaddress.IPv6Address('ff02::1'):target=bytes.fromhex('333300000001')
    else:raise ProbeError('IPv6 destination differs')
    if frame[:6]!=target:raise ProbeError('Ethernet destination differs')
    if protocol==58 and ip[7]!=255:raise ProbeError('RA hop limit differs')
    if protocol==17:
        if len(body)<12 or struct.unpack_from('!HHH',body)!=(547,546,len(body)) or body[6:8]==b'\0\0':
            raise ProbeError('DHCPv6 UDP header differs')
    elif len(body)<16:raise ProbeError('short RA')
    pseudo=ip[8:40]+struct.pack('!I',len(body))+bytes(3)+bytes([protocol])
    if not checksum_pending and not checksum_valid and checksum(pseudo+body)!=0:raise ProbeError('IPv6 transport checksum differs')
    return body[8:] if protocol==17 else body


def decode_ra(packet,*,prefix,router_lifetime=1800):
    network=ipaddress.IPv6Network(prefix)
    if len(packet)<16 or packet[:2]!=b'\x86\0' or packet[5]&0xc0!=0xc0 or int.from_bytes(packet[6:8],'big')!=router_lifetime:
        raise ProbeError('RA header/profile differs')
    data=packet[16:];prefixes=[];seen=set()
    while data:
        if len(data)<2 or not data[1] or len(data)<8*data[1]:raise ProbeError('short or zero-length RA option')
        kind,units=data[:2];value=data[:units*8];data=data[units*8:]
        # This profile expects one prefix and single-valued link/MTU options.
        if kind in (1,3,5) and kind in seen:raise ProbeError('duplicate RA profile option')
        seen.add(kind)
        if kind==3:
            if units!=4 or value[2]!=network.prefixlen or not value[3]&0x80 or value[16:]!=network.network_address.packed:
                raise ProbeError('RA management prefix differs')
            valid,preferred=struct.unpack_from('!II',value,4)
            if not 0<preferred<=valid:raise ProbeError('RA prefix lifetimes differ')
            prefixes.append({'prefix':str(network),'preferred_lifetime':preferred,'valid_lifetime':valid,'flags':value[3]})
    if len(prefixes)!=1:raise ProbeError('exactly one original RA prefix required')
    return {'router_lifetime':router_lifetime,'flags':packet[5],'prefixes':prefixes}


def run(*,interface,client_mac,client_ip,server_mac,server_ip,duid,iaid,address,dns,prefix,solicit_xid,request_xid,progress=None):
    """Use only sockets in the caller's already qualified namespace.

    Transactions are supplied by the caller's durable attempt, never regenerated
    during a replay. No address, route, sysctl or firewall change is made.
    """
    import time
    def option(code,value):return struct.pack('!HH',code,len(value))+value
    if len(solicit_xid)!=3 or len(request_xid)!=3 or solicit_xid==request_xid:
        raise ProbeError('distinct original DHCPv6 transactions required')
    index=socket.if_nametoindex(interface)
    udp=raw=rs=None
    try:
        udp=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
        udp.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,index)
        udp.bind((client_ip,546,0,index))
        raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd))
        raw.setsockopt(263,8,1);raw.bind((interface,0));raw.settimeout(.25)
        rs=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
        rs.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
        rs.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_HOPS,255)
        rs.bind((client_ip,0,0,index))
        observed_ra=None;rejected=0
        def receive():
            nonlocal observed_ra,rejected
            try:data,ancillary,flags,peer=raw.recvmsg(65535,1024)
            except socket.timeout:return None
            if peer[2]==socket.PACKET_OUTGOING:return None
            if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):raise ProbeError('truncated IPv6 packet or checksum metadata')
            metadata=[v for level,kind,v in ancillary if level==263 and kind==8]
            if len(metadata)!=1 or len(metadata[0])<20:raise ProbeError('missing IPv6 kernel checksum metadata')
            status=struct.unpack_from('I',metadata[0])[0]
            protocol=data[20] if len(data)>20 else None
            try:
                payload=ipv6_payload(data,protocol=protocol,server_mac=server_mac,server_ip=server_ip,
                    client_mac=client_mac,client_ip=client_ip,checksum_pending=bool(status&8),checksum_valid=bool(status&128))
                if protocol==58:
                    qualified=decode_ra(payload,prefix=prefix)
                    if observed_ra is None:
                        observed_ra=qualified
                        if progress:progress('ipv6.ra',qualified)
                    return None
                return payload
            except ProbeError:rejected+=1;return None
        def exchange(wire,kind,transaction,selected=None):
            deadline=time.monotonic()+8;next_send=0;sent=0
            while time.monotonic()<deadline:
                if time.monotonic()>=next_send:
                    udp.sendto(wire,('ff02::1:2',547,0,index))
                    rs.sendto(bytes([133,0,0,0])+bytes(4),('ff02::2',0,0,index))
                    sent+=1;next_send=time.monotonic()+2
                payload=receive()
                if payload is None:continue
                try:result=decode_message(payload,kind=kind,transaction=transaction,duid=duid,iaid=iaid,address=address,dns=dns,server_id=selected)
                except ProbeError:continue
                return dict(result,sent=sent)
            raise ProbeError('no qualified DHCPv6 type '+str(kind)+'; rejected frames '+str(rejected))
        common=option(1,duid)+option(8,bytes(2))+option(6,struct.pack('!H',23))
        offer=exchange(b'\x01'+solicit_xid+common+option(3,iaid+bytes(8)),2,solicit_xid)
        if progress:progress('ipv6.advertise',offer)
        sid=bytes.fromhex(offer['server_id'])
        hint=socket.inet_pton(socket.AF_INET6,address)+bytes(8)
        reply=exchange(b'\x03'+request_xid+common+option(2,sid)+option(3,iaid+bytes(8)+option(5,hint)),7,request_xid,sid)
        if progress:progress('ipv6.reply',reply)
        deadline=time.monotonic()+5
        while observed_ra is None and time.monotonic()<deadline:receive()
        if observed_ra is None:raise ProbeError('no qualified RA from original management server')
        return {'advertise':offer,'reply':reply,'ra':observed_ra,'reception':'AF_PACKET','rejected_frames':rejected}
    finally:
        for stream in (rs,raw,udp):
            if stream is not None:stream.close()
