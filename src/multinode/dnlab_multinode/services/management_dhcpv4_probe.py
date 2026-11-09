"""Bounded addressless DHCPv4 probe for an already qualified namespace.

The caller binds this profile to the original management/service intent. This
probe allocates no network resources and configures no client addresses/routes.
It qualifies a direct Ethernet DHCP service, not arbitrary relays or RFC compliance.
"""
import ipaddress
import json
import re
import socket
import struct
import sys
import time

SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_CSUMNOTREADY = 1 << 3
TP_STATUS_CSUM_VALID = 1 << 7


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


class Probe:
    def __init__(self, *, interface, client_mac, client_ip, server_mac, server_ip,
                 dns_ip, subnet, xid):
        if not isinstance(interface,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',interface):
            raise ValueError('literal probe interface required')
        self.interface=interface
        for key,value in (('client_mac',client_mac),('server_mac',server_mac)):
            if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{2}(?::[0-9a-f]{2}){5}',value):
                raise ValueError('qualified Ethernet identity required')
            raw=bytes.fromhex(value.replace(':',''))
            if raw[0]&1 or not any(raw):raise ValueError('unicast Ethernet identity required')
            setattr(self,key,raw)
        if self.client_mac==self.server_mac:raise ValueError('client and server identities must differ')
        network=ipaddress.IPv4Network(subnet)
        self.client_ip=str(ipaddress.IPv4Address(client_ip));self.server_ip=str(ipaddress.IPv4Address(server_ip))
        self.dns_ip=str(ipaddress.IPv4Address(dns_ip));self.netmask=str(network.netmask)
        for value in (self.client_ip,self.server_ip):
            if ipaddress.IPv4Address(value) not in network or value in (str(network.network_address),str(network.broadcast_address)):
                raise ValueError('probe and server must be usable addresses in the original subnet')
        if self.client_ip==self.server_ip or type(xid) is not int or not 0<xid<=0xffffffff:
            raise ValueError('distinct identities and explicit transaction required')
        self.xid=xid

    def decode_frame(self, frame, expected_type, *, checksum_pending=False,
                     checksum_valid=False):
        """Return a qualified OFFER/ACK, or None for unrelated/invalid frames.

        Pending checksums are accepted only with the receiving kernel's AUXDATA
        flag. Unflagged nonzero UDP checksums are verified over the pseudo-header.
        """
        if (len(frame) < 14 + 20 + 8 + 240 or len(self.server_mac) != 6
                or frame[12:14] != b'\x08\x00' or frame[6:12] != self.server_mac
                or frame[:6] not in (b'\xff' * 6, self.client_mac)):
            return None
        ip = frame[14:]
        size = (ip[0] & 15) * 4
        length = int.from_bytes(ip[2:4], 'big')
        fragment = int.from_bytes(ip[6:8], 'big')
        if (ip[0] >> 4 != 4 or size < 20 or length > len(ip)
                or length < size + 8 + 240 or fragment & 0xbfff
                or ip[8] == 0 or ip[9] != 17 or checksum(ip[:size]) != 0
                or ip[12:16] != socket.inet_aton(self.server_ip)
                or ip[16:20] not in (b'\xff' * 4, socket.inet_aton(self.client_ip))):
            return None
        udp = ip[size:length]
        source, target, udp_length, udp_checksum = struct.unpack('!HHHH', udp[:8])
        if source != 67 or target != 68 or udp_length != len(udp):
            return None
        if checksum_pending and checksum_valid:
            return None
        if udp_checksum and not checksum_pending and not checksum_valid:
            pseudo = ip[12:20] + b'\0\x11' + struct.pack('!H', len(udp))
            if checksum(pseudo + udp) != 0:
                return None
        bootp = udp[8:]
        if (bootp[:4] != b'\x02\x01\x06\x00'
                or bootp[4:8] != struct.pack('!I', self.xid)
                or bootp[28:34] != self.client_mac or bootp[236:240] != b'\x63\x82\x53\x63'
                or bootp[16:20] != socket.inet_aton(self.client_ip)):
            return None
        opts = {}
        i = 240
        ended = False
        while i < len(bootp):
            code = bootp[i]
            i += 1
            if code == 255:
                ended = not any(bootp[i:])
                break
            if code == 0:
                continue
            if i >= len(bootp):
                return None
            count = bootp[i]
            i += 1
            if i + count > len(bootp) or code in opts or code == 52:
                return None
            opts[code] = bootp[i:i + count]
            i += count
        if (not ended or opts.get(53) != bytes([expected_type])
                or opts.get(54) != socket.inet_aton(self.server_ip)
                or opts.get(3) != socket.inet_aton(self.server_ip)
                or opts.get(6) != socket.inet_aton(self.dns_ip)
                or opts.get(1) != socket.inet_aton(self.netmask)
                or len(opts.get(51, b'')) != 4 or int.from_bytes(opts[51], 'big') <= 0):
            return None
        return {'offered':self.client_ip, 'server':self.server_ip, 'router':self.server_ip,
                'dns':self.dns_ip, 'type':expected_type,
                'udp_checksum_status':'kernel-offload-pending' if checksum_pending else
                    'kernel-validated' if checksum_valid else 'absent' if not udp_checksum else 'verified'}


    def run(self,progress=None):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        try:
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode()+b'\0')
            udp.bind(('0.0.0.0', 68))
            raw.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
            raw.bind((self.interface, 0))
            raw.settimeout(.5)
            header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, self.xid, 0, 0x8000,
                bytes(4), bytes(4), bytes(4), bytes(4), self.client_mac + bytes(10), bytes(64), bytes(128))
            header += b'\x63\x82\x53\x63'

            def exchange(message, expected):
                deadline = time.monotonic() + 6
                next_send = 0
                sent = 0
                rejected = 0
                while time.monotonic() < deadline:
                    if time.monotonic() >= next_send:
                        udp.sendto(header + message, ('255.255.255.255', 67))
                        sent += 1
                        next_send = time.monotonic() + 2
                    try:
                        data, ancillary, flags, peer = raw.recvmsg(65535, 1024)
                    except socket.timeout:
                        continue
                    if peer[2] == socket.PACKET_OUTGOING:
                        continue
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        raise RuntimeError('truncated DHCP frame or checksum metadata')
                    metadata = [value for level, kind, value in ancillary
                                if level == SOL_PACKET and kind == PACKET_AUXDATA]
                    if len(metadata) != 1 or len(metadata[0]) < 20:
                        raise RuntimeError('missing kernel checksum metadata')
                    status = struct.unpack_from('I', metadata[0])[0]
                    value = self.decode_frame(data, expected,
                        checksum_pending=bool(status & TP_STATUS_CSUMNOTREADY),
                        checksum_valid=bool(status & TP_STATUS_CSUM_VALID))
                    if value is not None:
                        return dict(value, sent=sent, rejected_frames=rejected)
                    rejected += 1
                raise RuntimeError(f'no qualified DHCPv4 type {expected}; rejected {rejected} frames')

            offer = exchange(bytes.fromhex('350101370303060fff'), 2)
            if progress:progress('ipv4.offer',offer)
            request = bytes.fromhex('3501033204') + socket.inet_aton(offer['offered'])
            request += bytes.fromhex('3604') + socket.inet_aton(offer['server']) + bytes.fromhex('370303060fff')
            ack = exchange(request, 5)
            if progress:progress('ipv4.ack',ack)
            if ack['server'] != offer['server']:
                raise RuntimeError('DHCPv4 server changed during handshake')
            return {'offer':offer, 'ack':ack, 'reception':'AF_PACKET', 'client_addressless':True}
        finally:
            raw.close()
            udp.close()


if __name__ == '__main__':
    print(json.dumps(Probe(**json.load(sys.stdin)).run()))
