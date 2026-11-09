"""Addressless DHCPv4 canary: UDP transmission, qualified AF_PACKET reception.

This deliberately accepts only the fixture's Ethernet/IPv4 DHCP server profile.
It is not a general DHCP client or an RFC compliance validator.
"""
import json
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'multinode'))
from dnlab_multinode.services.management_dhcpv4_probe import Probe,checksum,SOL_PACKET,PACKET_AUXDATA,TP_STATUS_CSUMNOTREADY,TP_STATUS_CSUM_VALID


CLIENT_MAC = bytes.fromhex('020000000011')
CLIENT_IP = '172.20.0.11'
SERVER_IP = '172.20.0.1'
DNS_IP = '172.20.0.53'
XID = 0xd1a60401
def profile(server_mac):
    return Probe(interface='client0',client_mac=CLIENT_MAC.hex(':'),client_ip=CLIENT_IP,
        server_mac=server_mac.hex(':') if isinstance(server_mac,bytes) else server_mac,
        server_ip=SERVER_IP,dns_ip=DNS_IP,subnet='172.20.0.0/24',xid=XID)


def decode_frame(frame,expected_type,server_mac,**kwargs):
    return profile(server_mac).decode_frame(frame,expected_type,**kwargs)


def run(server_mac):
    return profile(server_mac).run()


def standalone_program():
    source=Path(__file__).resolve().parents[2]/'multinode/dnlab_multinode/services/management_dhcpv4_probe.py'
    source=source.read_text().rsplit("if __name__ == '__main__':",1)[0]
    return source+"\nprint(json.dumps(Probe(interface='client0',client_mac='02:00:00:00:00:11',client_ip='172.20.0.11',server_mac=sys.argv[1],server_ip='172.20.0.1',dns_ip='172.20.0.53',subnet='172.20.0.0/24',xid=0xd1a60401).run()))\n"


if __name__ == '__main__':
    print(json.dumps(run(sys.argv[1])))
