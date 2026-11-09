"""Read-only snapshots and header-only traffic capture for owned NOS fixtures."""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path


def network_bridge(network):
    options = network.get('Options') or {}
    if network.get('Driver') == 'dnlab-vrf':
        bridge = options.get('dnlab.bridge')
        if not bridge:
            raise RuntimeError('dnlab-vrf diagnostic requires its explicit owned bridge')
        return bridge
    return options.get('com.docker.network.bridge.name') or 'br-' + network['Id'][:12]


class Headers:
    def __init__(self, label, interface, namespace=None):
        self.label, self.rows, self.stop = label, [], threading.Event()
        original = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            if namespace:
                os.setns(namespace.fd, 0)
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.socket.bind((interface, 0))
            self.socket.settimeout(.2)
        finally:
            os.setns(original, 0)
            os.close(original)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        while not self.stop.is_set():
            try:
                packet, address = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            if len(packet) < 14:
                continue
            row = {'time': time.monotonic(), 'interface': self.label, 'packet_type': address[2], 'src_mac': packet[6:12].hex(':'), 'dst_mac': packet[:6].hex(':')}
            kind = struct.unpack('!H', packet[12:14])[0]
            if kind == 0x806 and len(packet) >= 42:
                row.update(protocol='arp', operation=struct.unpack('!H', packet[20:22])[0], src_ip=socket.inet_ntoa(packet[28:32]), dst_ip=socket.inet_ntoa(packet[38:42]))
            elif kind == 0x800 and len(packet) >= 34:
                row.update(protocol=packet[23], src_ip=socket.inet_ntoa(packet[26:30]), dst_ip=socket.inet_ntoa(packet[30:34]))
                offset = 14 + (packet[14] & 15) * 4
                if packet[23] == 1 and len(packet) > offset:
                    row['icmp_type'] = packet[offset]
            else:
                continue
            if len(self.rows) < 5000:
                self.rows.append(row)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.socket.close()
        return self.rows


class Diagnostics:
    def __init__(self, root, backend, request, spec, port, networks):
        self.root, self.backend, self.request, self.spec, self.port = root, backend, request, spec, port
        self.networks, self.captures = networks, []

    def start_capture(self, name, network):
        container = self.port.container()
        bridge = network_bridge(network)
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            endpoint = container['NetworkSettings']['Networks'][network['Name']]
            connection = {'network_id': network['Id'], 'network_name': network['Name'], 'cidr': f"{endpoint['IPAddress']}/{endpoint['IPPrefixLen']}", 'gateway': endpoint['Gateway']}
            uplink = self.port.uplink(connection)['name']
            for interface in (uplink, 'dnlab-mgmt', 'dmu0', 'mgmt0', 'tap0'):
                if self.backend.linux.link(interface, namespace):
                    self.captures.append((name, Headers(interface, interface, namespace)))
        self.captures.append((name, Headers('host-bridge', bridge)))

    def end_capture(self):
        groups = {}
        for name, capture in self.captures:
            groups.setdefault(name, []).extend(capture.close())
        self.captures = []
        for name, rows in groups.items():
            (self.root / (name + '-packets.json')).write_text(json.dumps(sorted(rows, key=lambda row: row['time']), indent=2) + '\n')

    def control_arp(self, connection, network, guest_mac):
        """A/B/A/B destination-MAC control on the fixture bridge only."""
        observed = self.backend.docker.network(network['Id'])
        if observed.get('Labels', {}).get('io.dnlab.spike') != network.get('Labels', {}).get('io.dnlab.spike') or len(observed.get('Containers', {})) != 1:
            raise RuntimeError('ARP control requires the owned single-fixture network')
        container = self.port.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            endpoint_mac = self.port.uplink(connection, namespace)['mac']
        bridge = network_bridge(network)
        address = str(ipaddress.ip_interface(connection['cidr']).ip)
        before = json.loads(self.backend.linux.run(['ip', '-j', 'neigh', 'show', 'to', address, 'dev', bridge]))
        result = {'before': before, 'guest_mac': guest_mac, 'docker_endpoint_mac': endpoint_mac, 'trials': []}
        self.start_capture('arp-control', network)
        try:
            for name, mac in [('guest-mac-1', guest_mac), ('endpoint-mac', endpoint_mac), ('guest-mac-2', guest_mac)]:
                self.backend.linux.run(['ip', 'neigh', 'replace', address, 'lladdr', mac, 'nud', 'permanent', 'dev', bridge])
                ping = subprocess.run(['ping', '-n', '-c', '3', '-W', '2', address], capture_output=True, text=True, timeout=15)
                result['trials'].append({'name': name, 'mac': mac, 'returncode': ping.returncode, 'output': ping.stdout})
        finally:
            # The isolated bridge is deleted by fixture cleanup. Remove this
            # one diagnostic entry as well; never flush global neighbors.
            self.backend.linux.run(['ip', 'neigh', 'del', address, 'dev', bridge])
            self.end_capture()
            (self.root / 'arp-control.json').write_text(json.dumps(result, indent=2) + '\n')
        return result

    def snapshot(self, name, console=None):
        container = self.port.container()
        result = {'container_id': container['Id'], 'pid': container['State']['Pid'], 'started_at': container['State']['StartedAt'], 'docker_endpoints': container['NetworkSettings']['Networks'], 'links': {}, 'tc': {}}
        linux = self.backend.linux
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            def run(argv):
                return linux.run(['nsenter', f'--net={namespace}', '--', *argv], pass_fds=(namespace.fd,))
            endpoint_name, endpoint = next(iter(container['NetworkSettings']['Networks'].items()))
            network = self.backend.docker.network(endpoint_name)
            connection = {'network_id': network['Id'], 'network_name': endpoint_name, 'cidr': f"{endpoint['IPAddress']}/{endpoint['IPPrefixLen']}", 'gateway': endpoint['Gateway']}
            uplink = self.port.uplink(connection)['name']
            for interface in (uplink, 'dnlab-mgmt', 'dmu0', 'mgmt0', 'tap0'):
                if linux.link(interface, namespace):
                    result['links'][interface] = json.loads(run(['ip', '-j', '-s', '-d', 'link', 'show', 'dev', interface]))
                    result['tc'][interface] = json.loads(run(['tc', '-j', '-s', 'filter', 'show', 'dev', interface, 'ingress']))
            result['addresses'] = json.loads(run(['ip', '-j', 'addr']))
            result['routes'] = json.loads(run(['ip', '-j', 'route']))
            result['neighbors'] = json.loads(run(['ip', '-j', 'neigh']))
            result['fdb'] = json.loads(run(['bridge', '-j', 'fdb', 'show', 'br', 'dnlab-mgmt']))
            result['arp_ignore'] = run(['sysctl', '-n', 'net.ipv4.conf.mgmt0.arp_ignore']).strip()
        for network in self.networks:
            bridge = network_bridge(network)
            result['host_neighbors_' + network['Name']] = json.loads(linux.run(['ip', '-j', 'neigh', 'show', 'dev', bridge]))
        path = self.root / (name + '-snapshot.json')
        path.write_text(json.dumps(result, indent=2) + '\n')
        if console:
            result['guest'] = {}
            for cmd in ('show running-config interface GigabitEthernet0/0', 'show interfaces GigabitEthernet0/0', 'show ip interface brief', 'show ip route connected', 'show arp'):
                try:
                    result['guest'][cmd] = console.send(cmd)
                except (OSError, RuntimeError) as error:
                    result['guest'][cmd] = {'error': str(error), 'received': getattr(console, 'last_response', '')}
                path.write_text(json.dumps(result, indent=2) + '\n')
        return result
