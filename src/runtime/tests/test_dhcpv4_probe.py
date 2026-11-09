"""Negative wire acceptance cases for the isolated addressless DHCP client."""
import importlib.util
from pathlib import Path
import socket
import struct

import pytest

spec = importlib.util.spec_from_file_location('dhcpv4_probe', Path(__file__).resolve().parents[1] / 'tools/dhcpv4_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
SERVER_MAC = bytes.fromhex('0200000000fe')


def option(code, value):
    return bytes([code, len(value)]) + value


def packet(*, msg=2, xid=probe.XID, client=probe.CLIENT_MAC,
           source_mac=SERVER_MAC, target_mac=b'\xff'*6,
           source_ip=probe.SERVER_IP, target_ip='255.255.255.255',
           source_port=67, target_port=68, fragment=0, bootp_type=2,
           offered=probe.CLIENT_IP, options=None):
    if options is None:
        options = (option(53,bytes([msg])) + option(54,socket.inet_aton(probe.SERVER_IP))
            + option(3,socket.inet_aton(probe.SERVER_IP)) + option(6,socket.inet_aton(probe.DNS_IP))
            + option(1,socket.inet_aton('255.255.255.0')) + option(51,struct.pack('!I',43200)) + b'\xff')
    body = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',bootp_type,1,6,0,xid,0,0x8000,
        bytes(4),socket.inet_aton(offered),socket.inet_aton(probe.SERVER_IP),bytes(4),
        client+bytes(10),bytes(64),bytes(128)) + b'\x63\x82\x53\x63' + options
    src,dst = socket.inet_aton(source_ip),socket.inet_aton(target_ip)
    udp = struct.pack('!HHHH',source_port,target_port,len(body)+8,0) + body
    value = probe.checksum(src+dst+b'\0\x11'+struct.pack('!H',len(udp))+udp) or 0xffff
    udp = udp[:6]+struct.pack('!H',value)+udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s',0x45,0,len(udp)+20,1,fragment,64,17,0,src,dst)
    ip = ip[:10]+struct.pack('!H',probe.checksum(ip))+ip[12:]
    return target_mac+source_mac+b'\x08\x00'+ip+udp


def test_offer_and_ack_require_their_own_message_type_and_qualified_server():
    for kind in (2,5):
        record=probe.decode_frame(packet(msg=kind),kind,SERVER_MAC)
        assert record['offered']==probe.CLIENT_IP and record['dns']==probe.DNS_IP
        assert record['udp_checksum_status']=='verified'
    assert probe.decode_frame(packet(msg=2),5,SERVER_MAC) is None


@pytest.mark.parametrize('change',[
    {'xid':probe.XID+1}, {'client':bytes.fromhex('020000000012')},
    {'source_mac':bytes.fromhex('0200000000aa')}, {'target_mac':bytes.fromhex('0200000000bb')},
    {'source_ip':'172.20.0.2'}, {'target_ip':'172.20.0.12'},
    {'source_port':68}, {'target_port':67}, {'fragment':0x2000}, {'fragment':1},
    {'bootp_type':1}, {'offered':'172.20.0.12'}, {'msg':6},
])
def test_unrelated_or_invalid_wire_identity_is_rejected_even_with_valid_checksums(change):
    assert probe.decode_frame(packet(**change),2,SERVER_MAC) is None


@pytest.mark.parametrize('length',[0,13,14,33,41,100,280])
def test_truncated_frames_do_not_qualify(length):
    assert probe.decode_frame(packet()[:length],2,SERVER_MAC) is None


def test_invalid_ip_and_udp_lengths_and_checksums_do_not_qualify():
    for offset in (14+2,14+10,14+20+4,14+20+6,14+20+8+44):
        data=bytearray(packet());data[offset]^=1
        assert probe.decode_frame(bytes(data),2,SERVER_MAC) is None


def test_checksum_offload_requires_explicit_kernel_metadata():
    data=bytearray(packet());data[14+20+6]^=1
    assert probe.decode_frame(bytes(data),2,SERVER_MAC) is None
    assert probe.decode_frame(bytes(data),2,SERVER_MAC,checksum_pending=True)['udp_checksum_status']=='kernel-offload-pending'
    assert probe.decode_frame(bytes(data),2,SERVER_MAC,checksum_valid=True)['udp_checksum_status']=='kernel-validated'
    assert probe.decode_frame(bytes(data),2,SERVER_MAC,checksum_valid=True,checksum_pending=True) is None
    assert probe.decode_frame(packet(xid=probe.XID+1),2,SERVER_MAC,checksum_pending=True) is None


@pytest.mark.parametrize('options',[
    b'\x35', b'\x35\x05\x02', option(53,b'\x02')+b'\xff',
    option(53,b'\x02')+option(53,b'\x02')+b'\xff',
    option(52,b'\x01')+b'\xff',
])
def test_truncated_duplicate_or_incomplete_options_are_rejected(options):
    assert probe.decode_frame(packet(options=options),2,SERVER_MAC) is None


@pytest.mark.parametrize('code,bad',[
    (54,socket.inet_aton('172.20.0.2')),(3,socket.inet_aton('172.20.0.2')),
    (6,socket.inet_aton('172.20.0.54')),(1,socket.inet_aton('255.255.0.0')),
    (51,bytes(4)),(54,b'\x00'),
])
def test_wrong_server_or_network_options_cannot_pass(code,bad):
    opts={53:b'\x02',54:socket.inet_aton(probe.SERVER_IP),3:socket.inet_aton(probe.SERVER_IP),
          6:socket.inet_aton(probe.DNS_IP),1:socket.inet_aton('255.255.255.0'),51:struct.pack('!I',43200)}
    opts[code]=bad
    wire=b''.join(option(key,value) for key,value in opts.items())+b'\xff'
    assert probe.decode_frame(packet(options=wire),2,SERVER_MAC) is None


def test_standalone_direct_fixture_program_needs_no_checkout_imports():
    import subprocess,sys
    source=probe.standalone_program()
    at=source.rindex('print(json.dumps(Probe(')
    source=source[:at]+"Probe.run=lambda self:dict(interface=self.interface,server=self.server_mac.hex(':'))\n"+source[at:]
    completed=subprocess.run([sys.executable,'-I','-c',source,'02:00:00:00:00:fe'],text=True,capture_output=True,cwd='/tmp')
    assert completed.returncode==0,completed.stderr
    import json
    assert json.loads(completed.stdout)=={'interface':'client0','server':'02:00:00:00:00:fe'}
