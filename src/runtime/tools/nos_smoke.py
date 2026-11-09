"""Isolated vIOS candidate boot and legacy-slot datapath probe; opt-in only.

This is not qualification for arbitrary data-port selection or guest shutdown.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.backend import Backend, labels
from dnlab_runtime.bootstrap import Bootstrap
from dnlab_runtime.image_commands import python_command, healthcheck_command
from dnlab_runtime.journal import Journal
from dnlab_runtime.stable_management import Handoff, StablePort
from nos_fixture import NosFixture
from smoke import command
from management_smoke import available_port


class Console:
    def __init__(self, port, namespace=None):
        # Current GUI uses docker exec + container loopback. An unconfigured
        # NOS cannot answer ARP for Docker published management ports yet.
        if namespace is None:
            self.socket = socket.create_connection(('127.0.0.1', port), timeout=3)
        else:
            original = os.open('/proc/self/ns/net', os.O_RDONLY)
            try:
                os.setns(namespace.fd, 0)
                self.socket = socket.create_connection(('127.0.0.1', port), timeout=3)
            finally:
                os.setns(original, 0)
                os.close(original)
        self.socket.settimeout(1)
    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()
    def send(self, text='', timeout=20):
        self.last_command, self.last_response = text, ''
        self.socket.sendall(text.encode() + b'\r')
        deadline, data = time.monotonic() + timeout, b''
        while time.monotonic() < deadline:
            try:
                chunk = self.socket.recv(65536)
                if not chunk:
                    raise RuntimeError('console closed')
                data += chunk
                data = re.sub(rb'\xff[\xfb-\xfe].', b'', data)
                textdata = data.decode(errors='replace')
                self.last_response = textdata
                if re.search(r'[\r\n][^\r\n]*[>#]\s*$', textdata):
                    if any(marker in textdata for marker in ('% Invalid', '% Incomplete', '% Ambiguous', '% Bad')):
                        raise RuntimeError('guest rejected console command')
                    return textdata
            except socket.timeout:
                pass
        raise RuntimeError('console prompt timed out')


def open_console(port, namespace=None, timeout=10):
    # QEMU serial chardev allows one client. After the launcher/client closes,
    # a replacement can be rejected until QEMU observes the previous FIN.
    deadline = time.monotonic() + timeout
    while True:
        console = None
        try:
            console = Console(port, namespace)
            hello = console.send(timeout=min(3, max(.1, deadline - time.monotonic())))
            return console, hello
        except (OSError, RuntimeError):
            if console:
                console.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(.2)


def qemu_identity(backend, identity, image):
    program = r"""import glob,json
rows=[]
for path in glob.glob('/proc/[0-9]*'):
    try:
        name=open(path+'/comm').read().strip()
        if name.startswith('qemu-system'):
            args=open(path+'/cmdline','rb').read().decode().split('\0')
            nics=[args[i+1] for i,arg in enumerate(args[:-1]) if arg=='-device' and 'netdev=' in args[i+1]]
            netdevs=[args[i+1] for i,arg in enumerate(args[:-1]) if arg=='-netdev']
            rows.append({'pid':int(path.split('/')[-1]),'start_ticks':open(path+'/stat').read().rsplit(')',1)[1].split()[19], 'kvm':'-enable-kvm' in args, 'nics':nics, 'netdevs':netdevs})
    except FileNotFoundError:
        pass
print(json.dumps(rows))"""
    return json.loads(command(['docker', 'exec', identity, *python_command(image, program)]))


def validate_guest(guest, warm_ports):
    if len(guest) != 1 or not guest[0]['kvm'] or len(guest[0]['nics']) != warm_ports + 1:
        raise RuntimeError('expected one KVM guest with the complete warm NIC mapping')
    references = [re.search(r'(?:^|,)netdev=([^,]+)', nic) for nic in guest[0]['nics']]
    backends = [re.search(r'(?:^|,)id=([^,]+)', value) for value in guest[0]['netdevs']]
    if not all(references) or not all(backends):
        raise RuntimeError('guest NIC/backend identifiers are incomplete')
    refs, ids = [match[1] for match in references], [match[1] for match in backends]
    if len(set(refs)) != len(refs) or len(set(ids)) != len(ids) or set(refs) != set(ids):
        raise RuntimeError('every guest NIC must have exactly one matching netdev backend')


def boot_stage(console, launcher_log):
    # Process boot and stage evidence do not establish NOS readiness. ROMMON
    # is accepted for boot-only scope; guest boot settings/config are manual.
    if any(marker in console for marker in (b'POAP', b'NX-OS', b'Power On Auto')):
        return 'nos_boot_output'
    if b'loader>' in console.lower() or b'rommon' in console.lower():
        return 'loader_console'
    if b'loader/ROMMON' in launcher_log:
        return 'loader_reported_by_launcher'
    return 'unknown'


def run(image, kind="cisco_vios", boot_only=False, diagnose=False, passive=False, arp_control=False, test_rollback=False, network_context=None, interface_only=False, selected_slot=None, data_traffic=False):
    token = 'nosp-' + uuid.uuid4().hex[:8]
    root = Path(tempfile.mkdtemp(prefix='dnlab-nos-smoke-'))
    (root / 'persist').mkdir(mode=0o700)
    backend, journal = Backend(), Journal(root / 'state')
    request = {'lab_id': network_context['lab_id'] if network_context else token, 'node_id': kind}
    warm_ports = 15 if kind == 'cisco_vios' else 16
    spec = {'kind': 'linux', 'image': image, 'container_name': 'dnlab-' + token, 'stop_timeout': 3}
    fixture = NosFixture(journal, backend, request, spec)
    networks, created, console = [], None, None
    transcript = []
    diagnostic = None
    data_probe = None
    report = {'scope': 'vIOS legacy p00 slot; arbitrary data-port and shutdown unqualified' if kind == 'cisco_vios' else 'n9kv OOB boot only; guest traffic and shutdown unqualified', 'image_id': image, 'checks': []}
    try:
        if interface_only and (kind != 'cisco_n9kv' or not boot_only):
            raise RuntimeError('structural OOB interface mode requires n9kv boot-only')
        if data_traffic and (kind != 'cisco_vios' or selected_slot != 8):
            raise RuntimeError('data traffic fixture requires vIOS selected management slot8')
        image_config = backend.docker.request('GET', '/images/' + image + '/json')
        # Reject incomplete candidate contracts before creating any resources.
        if image_config.get('Id') != image or image_config['Config'].get('Labels', {}).get('org.dnlab.patch.kind') != kind:
            raise RuntimeError('NOS fixture requires an immutable candidate ID matching the requested kind')
        if selected_slot is not None:
            image_labels = image_config['Config'].get('Labels') or {}
            if (kind != 'cisco_vios' or type(selected_slot) is not int or not 0 <= selected_slot <= 15
                    or 'runtime-selected-management-v1' not in image_labels.get('org.dnlab.capabilities', '').split(',')
                    or image_labels.get('org.dnlab.runtime-selected-management.status') != 'experimental-unqualified'):
                raise RuntimeError('selected management requires an explicitly labelled vIOS candidate and valid slot')
            backend.docker.require_endpoint_name_support()
            report['selected_management_slot'] = selected_slot
            report['scope'] = f'vIOS selected p{selected_slot:02d} local IPv4; shutdown and other slot qualifications excluded'
        if network_context and arp_control:
            raise RuntimeError('ARP mutation control is restricted to the single-fixture stock bridge')
        python_command(image_config, '')
        healthcheck = healthcheck_command(image_config)
        report['python_profile'] = image_config['Config']['Labels']['org.dnlab.runtime-management.python']
        report['healthcheck_command'] = healthcheck
        if network_context:
            networks = network_context['networks']
            report['network_scope'] = 'borrowed owned dnlab-vrf; structural OOB only; guest traffic and host publishing unqualified' if kind == 'cisco_n9kv' else 'borrowed owned dnlab-vrf; native client traffic; container-loopback console; host publishing unqualified'
        for color in (() if network_context else ('blue', 'red')):
            name = 'dnlab-' + token + '-' + color
            network_id = command(['docker', 'network', 'create', '--driver', 'bridge', '--label', 'io.dnlab.spike=' + token, name])
            networks.append(backend.docker.network(network_id))
        host_port = available_port()
        mac = '02:da:ab:00:00:03'
        config = {'Image': image, 'Env': ['DNLAB_RUNTIME_BOOT_WAIT=true', 'DNLAB_RUNTIME_BOOT_TIMEOUT=120', 'DNLAB_RUNTIME_MGMT_INTF=mgmt0', 'CLAB_MGMT_PASSTHROUGH=true', 'CLAB_MGMT_MAC=' + mac, 'CLAB_INTFS=' + str(warm_ports), 'DNLAB_WARM_PORTS=' + str(warm_ports), 'DNLAB_WARM_VM_INDEX=0', 'CONNECTION_MODE=tc'], 'Labels': {**labels(request, spec), 'io.dnlab.spike': token}, 'ExposedPorts': {'5000/tcp': {}}, 'HostConfig': {'NetworkMode': networks[0]['Name'], 'Privileged': True, 'Memory': (2 if kind == 'cisco_vios' else 14) * 1024**3, 'NanoCpus': (1 if kind == 'cisco_vios' else 4) * 10**9, 'RestartPolicy': {'Name': 'no'}, 'Binds': [str(root / 'persist') + ':/persist'], 'PortBindings': {'5000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(host_port)}]}}}
        # n9kv_V2 does not read CONNECTION_MODE; pass its launcher CLI contract.
        config['Cmd'] = ['--connection-mode', 'tc']
        report['launcher_command'] = config['Cmd']
        if selected_slot is not None:
            config['Env'].append('DNLAB_RUNTIME_MGMT_SLOT=' + str(selected_slot))
            config['NetworkingConfig'] = {'EndpointsConfig': {networks[0]['Name']: {
                'DriverOpts': {'com.docker.network.endpoint.ifname': 'dnmu0'}, 'MacAddress': mac}}}
            if network_context:
                observation = network_context['name_probe'].check(networks[0], 'dnmu0', creation_mode='create')
                if observation.get('name') != 'dnmu0' or observation.get('network_id') != networks[0]['Id'] or not observation.get('cleanup_verified') or observation.get('creation_mode') != 'create':
                    raise RuntimeError('initial selected-slot uplink naming probe failed')
                report['initial_naming_observation'] = observation
        created = fixture.create(config)
        fixture.start()
        proof = fixture.get()
        report['fixture_birth'] = {'intent_id': proof['id'], 'container_id': proof['container_id'],
                                   'intent_fingerprint': proof['fingerprint'], 'phase': proof['phase']}
        port = StablePort(backend, request, spec, mac)
        handoff = Handoff(journal, backend, request, spec, port, spike_owner=None if network_context else token, name_probe=network_context['name_probe'] if network_context else None)
        source = handoff.capture(networks[0])
        if selected_slot is not None and port.uplink(source)['name'] != 'dnmu0':
            raise RuntimeError('Docker did not reserve the initial management uplink name')
        stable = port.prepare(source)
        with backend.namespace(request, spec, port.container()) as namespace:
            for index in range(0 if selected_slot else 1, warm_ports + 1):
                backend.linux.command(['link', 'add', f'eth{index}', 'type', 'veth', 'peer', 'name', f'wmp{index}'], namespace)
                backend.linux.command(['link', 'set', f'eth{index}', 'up'], namespace)
        assert not qemu_identity(backend, created, image_config), 'guest booted before preparation release'
        Bootstrap(backend, request, spec, port).release(stable, source)
        report['checks'].append('verified stable management before actual QEMU boot')
        (root / 'progress.json').write_text(json.dumps({'phase': 'waiting_for_guest', 'container_id': created}))
        deadline = time.monotonic() + (360 if kind == "cisco_vios" else 600)
        while True:
            try:
                backend.docker.exec_checked(created, healthcheck)
                break
            except Exception:
                if not port.container()['State']['Running'] or time.monotonic() >= deadline:
                    raise RuntimeError('guest readiness timed out or container stopped')
                time.sleep(3)
        guest = qemu_identity(backend, created, image_config)
        validate_guest(guest, warm_ports)
        report['guest_identity'], report['stable_identity'] = guest, stable
        selected_datapath = None
        if selected_slot is not None:
            from nos_interface_probe import snapshot, validate_selected
            selected_datapath = snapshot(backend, request, spec, port, warm_ports, data_zero=bool(selected_slot))
            validate_selected(guest, selected_datapath, mac, warm_ports, selected_slot)
            report['selected_interface_datapath'] = selected_datapath
            control = "import socket; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5); s.connect('/run/dnlab-link-control.sock'); s.sendall(" + repr(f'eth{selected_slot} down\n'.encode()) + "); response=s.recv(4096); s.close(); assert response.startswith(b'ERROR ValueError: carrier request targets management'), response"
            backend.docker.exec_checked(created, python_command(image_config, control))
            assert snapshot(backend, request, spec, port, warm_ports, data_zero=bool(selected_slot)) == selected_datapath
            report['checks'].append('selected slot has an exclusive management TC path; warm carrier rejects a data stop request on that slot')
        with backend.namespace(request, spec, port.container()) as namespace:
            console = Console(5000, namespace)
        if boot_only:
            console.socket.sendall(b'\r')
            deadline, data = time.monotonic() + 15, b''
            while time.monotonic() < deadline:
                try:
                    chunk = console.socket.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    pass
            (root / 'boot-console.txt').write_text(data.decode(errors='replace'))
            logs = subprocess.run(['docker', 'logs', created], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30).stdout
            path = root / 'boot-launcher.log'
            path.write_bytes(logs)
            path.chmod(0o600)
            report['guest_stage'] = boot_stage(data, logs)
            report['guest_readiness'] = 'unqualified'
            report['boot_console_bytes'] = len(data)
            assert qemu_identity(backend, created, image_config) == guest
            assert port.snapshot() == stable
            report['checks'].append(('n9kv V2 OOB' if kind == 'cisco_n9kv' else 'vIOS V2') + ' KVM process with complete matching NIC/backend mapping')
            if kind == 'cisco_vios':
                report['scope'] = 'vIOS V2 structural boot and selected NIC/TC mapping; guest traffic/readiness/shutdown unqualified'
            report['checks'].append('container-side console connects without guest restart; loader/ROMMON accepted for boot-only scope')
            if interface_only:
                from nos_interface_probe import snapshot, validate_oob
                datapath = snapshot(backend, request, spec, port, warm_ports)
                validate_oob(guest, datapath, mac, warm_ports)
                report['interface_datapath'] = datapath
                report['checks'].append('QEMU OOB p00/tap0 uses only stable mgmt0; every warm data NIC has its own separate bidirectional TC path')
                target_pool = ipaddress.ip_network(networks[1]['IPAM']['Config'][0]['Subnet'])
                target_ip = network_context['target_ip'] if network_context else str(target_pool.network_address + 10)
                handoff.submit('oob-structural-move', networks[1]['Name'], target_ip)
                moved = handoff.execute(handoff.by_request('oob-structural-move')['id'])
                assert moved['phase'] == 'completed', moved
                assert qemu_identity(backend, created, image_config) == guest and port.snapshot() == stable
                assert snapshot(backend, request, spec, port, warm_ports) == datapath
                console.close()
                with backend.namespace(request, spec, port.container()) as namespace:
                    console = Console(5000, namespace)
                report['checks'].append('structural OOB move preserves QEMU/NIC/MAC, stable/data kernel link identities, TC paths and loopback console')
                handoff.submit('oob-structural-rollback', networks[0]['Name'], source['cidr'].split('/')[0])
                def fail_after_connect(phase):
                    if phase == 'connected':
                        raise RuntimeError('injected structural OOB post-connect failure')
                rolled = handoff.execute(handoff.by_request('oob-structural-rollback')['id'], checkpoint=fail_after_connect)
                assert rolled['phase'] == 'rolled_back', rolled
                assert qemu_identity(backend, created, image_config) == guest and port.snapshot() == stable
                assert snapshot(backend, request, spec, port, warm_ports) == datapath
                console.close()
                with backend.namespace(request, spec, port.container()) as namespace:
                    console = Console(5000, namespace)
                report['checks'].append('structural OOB rollback preserves stable/data link identities and TC paths without reusing data NICs for management')
                report['capability_observations'] = moved['payload'].get('capability_observations', [])
                report['uplink'] = port.uplink(moved['payload']['target'])
                report['move_phase'], report['rollback_phase'] = moved['phase'], rolled['phase']
                report['scope'] = 'n9kv V2 OOB structural NIC/TC move/rollback; guest OOB traffic/NX-OS readiness/shutdown unqualified'
            report['status'] = 'passed'
            report['report'] = str(root / 'report.json')
            return report
        console.close()
        with backend.namespace(request, spec, port.container()) as namespace:
            console, hello = open_console(5000, namespace)
        transcript = [hello, console.send('enable'), console.send('terminal length 0'), console.send('show ip interface brief')]
        (root / 'interface-inventory.txt').write_text(transcript[-1])
        if 'GigabitEthernet0/0' not in transcript[-1]:
            raise RuntimeError('observed vIOS interface mapping differs from expected p00 slot')
        from vios_port_mapping import collect_interface_macs, match_slots
        observed_macs = collect_interface_macs(console, root, warm_ports)
        report['observed_interface_macs'] = observed_macs
        report['port_mapping'] = match_slots(guest, observed_macs, warm_ports, management_slot=selected_slot or 0)
        report['checks'].append('every vIOS guest interface name matches its QEMU slot by observed hardware MAC')
        if diagnose:
            from nos_move_diagnostics import Diagnostics
            diagnostic = Diagnostics(root, backend, request, spec, port, networks)
        configured_gateway = None
        def configure(connection):
            nonlocal configured_gateway
            address = ipaddress.ip_interface(connection['cidr'])
            lines = ['configure terminal', f'interface GigabitEthernet0/{selected_slot or 0}', f'ip address {address.ip} {address.network.netmask}', 'no shutdown', 'exit']
            if network_context:
                if configured_gateway:
                    lines.append(f'no ip route 0.0.0.0 0.0.0.0 {configured_gateway}')
                lines.append(f"ip route 0.0.0.0 0.0.0.0 {connection['gateway']}")
                configured_gateway = connection['gateway']
            lines.append('end')
            for line in lines:
                response = console.send(line)
                transcript.append({"command": line, "response": response} if diagnose else response)
        def traffic(connection):
            attempts = report.setdefault('ping_attempts', [])
            deadline = time.monotonic() + 30
            while True:
                result = network_context['ping'](connection['cidr'].split('/')[0]) if network_context else subprocess.run(['ping', '-n', '-c', '1', '-W', '2', connection['cidr'].split('/')[0]], capture_output=True, text=True)
                attempts.append({'time': time.monotonic(), 'target': connection['cidr'].split('/')[0], 'returncode': result.returncode, 'output': result.stdout})
                if result.returncode == 0:
                    return
                if time.monotonic() >= deadline:
                    raise RuntimeError('real guest ICMP datapath failed')
                time.sleep(1)
        def reopen_console():
            if network_context:
                with backend.namespace(request, spec, port.container()) as namespace:
                    return open_console(5000, namespace)
            return open_console(host_port)
        configure(source)
        if diagnostic:
            if not passive:
                diagnostic.snapshot("source-configured", console)
            diagnostic.start_capture("source", networks[0])
        traffic(source)
        if diagnostic:
            diagnostic.end_capture()
        console.close()
        console, _ = reopen_console()
        console.close()
        with backend.namespace(request, spec, port.container()) as namespace:
            console, _ = open_console(5000, namespace)
        report['checks'].append('actual vIOS ' + ('legacy' if selected_slot is None else 'selected') + ' slot configured manually and guest ICMP reachable')
        if data_traffic:
            from nos_data_probe import DataProbe
            report['data_traffic_slots'] = [0, 1, 15]
            def data_address(index):
                return f'198.18.{100 + index}'
            def attach_data(index):
                with backend.namespace(request, spec, port.container()) as ns:
                    backend.linux.command(['address', 'add', data_address(index) + '.1/24', 'dev', f'wmp{index}'], ns)
                    backend.linux.command(['link', 'set', f'wmp{index}', 'up'], ns)
            def detach_data(index):
                with backend.namespace(request, spec, port.container()) as ns:
                    backend.linux.command(['address', 'del', data_address(index) + '.1/24', 'dev', f'wmp{index}'], ns)
            def configure_data(index):
                for line in ['configure terminal', f'interface GigabitEthernet0/{index}', 'ip address ' + data_address(index) + '.2 255.255.255.0', 'no shutdown', 'end']:
                    transcript.append({'command': line, 'response': console.send(line)})
            def carrier_data(index, state):
                message = f'eth{index} {state}\n'
                program = "import socket; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5); s.connect('/run/dnlab-link-control.sock'); s.sendall(" + repr(message.encode()) + "); response=s.recv(4096); s.close(); assert response == " + repr(('OK ' + message).encode()) + ", response"
                backend.docker.exec_checked(created, python_command(image_config, program))
            def ping_data(index):
                with backend.namespace(request, spec, port.container()) as ns:
                    return subprocess.run(['nsenter', f'--net={ns}', '--', 'ping', '-n', '-I', f'wmp{index}', '-c', '1', '-W', '1', data_address(index) + '.2'], capture_output=True, text=True, timeout=4, pass_fds=(ns.fd,))
            data_probe = DataProbe([0, 1, 15], 8, configure_data, carrier_data, attach_data, detach_data, ping_data, root / 'data-traffic.json')
            data_probe.prepare()
            traffic(source)
            assert snapshot(backend, request, spec, port, warm_ports, data_zero=True) == selected_datapath
            report['checks'].append('data slots0/1/15 pass ICMP and warm down/up, detach/reattach without changing management or TC identities')
        target_pool = ipaddress.ip_network(networks[1]['IPAM']['Config'][0]['Subnet'])
        handoff.submit('move', networks[1]['Name'], network_context['target_ip'] if network_context else str(target_pool.network_address + 10))
        moved = handoff.execute(handoff.by_request('move')['id'])
        if moved['phase'] != 'completed':
            raise RuntimeError('management handoff failed: ' + moved['phase'])
        if diagnostic:
            if not passive:
                diagnostic.snapshot('target-before-guest-config', console)
            diagnostic.start_capture('target', networks[1])
        configure(moved['payload']['target'])
        if diagnostic and not passive:
            diagnostic.snapshot('target-configured', console)
        try:
            traffic(moved['payload']['target'])
        except RuntimeError:
            if diagnostic and arp_control:
                diagnostic.snapshot('target-original-failure', console)
                diagnostic.end_capture()
                report['arp_control'] = diagnostic.control_arp(moved['payload']['target'], networks[1], port.mac)
                report['identity_unchanged_during_control'] = qemu_identity(backend, created, image_config) == guest and port.snapshot() == stable
            raise
        finally:
            if diagnostic:
                diagnostic.snapshot('target-after-traffic', console)
                diagnostic.end_capture()
                report['diagnostic_profile'] = 'passive' if passive else 'snapshots'
        console.close()
        console, _ = reopen_console()
        assert qemu_identity(backend, created, image_config) == guest
        assert port.snapshot() == stable
        if selected_datapath is not None:
            assert snapshot(backend, request, spec, port, warm_ports, data_zero=bool(selected_slot)) == selected_datapath
        if data_probe:
            data_probe.verify('after-management-move')
        report['checks'].append('live move preserves QEMU process/NIC/MAC and container-loopback console' if network_context else 'live move preserves QEMU process/NIC/MAC and fixed console port')
        if test_rollback:
            console.close()
            with backend.namespace(request, spec, port.container()) as namespace:
                console, _ = open_console(5000, namespace)
            handoff.submit('rollback-probe', networks[0]['Name'], source['cidr'].split('/')[0])
            def fail_after_connect(phase):
                if phase == 'connected':
                    raise RuntimeError('injected failure after connecting the wrong target')
            rolled = handoff.execute(handoff.by_request('rollback-probe')['id'], checkpoint=fail_after_connect)
            if rolled['phase'] != 'rolled_back':
                raise RuntimeError('injected failure did not restore the prior management network')
            if diagnostic:
                diagnostic.start_capture('rollback', networks[1])
            try:
                traffic(moved['payload']['target'])  # Guest IP is deliberately unchanged.
            finally:
                if diagnostic:
                    diagnostic.snapshot('rollback-after-traffic', console)
                    diagnostic.end_capture()
            console.close()
            console, _ = reopen_console()
            assert qemu_identity(backend, created, image_config) == guest and port.snapshot() == stable
            if selected_datapath is not None:
                assert snapshot(backend, request, spec, port, warm_ports, data_zero=bool(selected_slot)) == selected_datapath
            if data_probe:
                data_probe.verify('after-management-rollback')
            report['checks'].append('failure after target connect restores traffic and console without guest reconfiguration')
            report['rollback_phase'] = rolled['phase']
        if data_probe:
            data_probe.finish()
            traffic(moved['payload']['target'])
            assert qemu_identity(backend, created, image_config) == guest and port.snapshot() == stable
            assert snapshot(backend, request, spec, port, warm_ports, data_zero=True) == selected_datapath
            report['checks'].append('data ICMP remains reachable across management move/rollback; data carrier down precedes final peer detach')
            report['data_traffic_slots'] = data_probe.slots
        report['guest_identity'], report['stable_identity'] = guest, stable
        if network_context:
            report['capability_observations'] = moved['payload']['capability_observations']
            report['uplink'] = port.uplink(moved['payload']['target'])
        report['status'] = 'passed'
        (root / 'console.txt').write_text(json.dumps(transcript, indent=2) if diagnose else '\n'.join(transcript))
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        if created:
            try:
                observed = backend.inspect(request, spec)
                report['failure_container_state'] = observed['State'] if observed else None
            except Exception as inspection_error:
                report['failure_inspection_error'] = type(inspection_error).__name__
            if transcript:
                (root / 'console.txt').write_text(json.dumps(transcript, indent=2) if diagnose else '\n'.join(transcript))
            logs_result = subprocess.run(['docker', 'logs', created], capture_output=True, text=True)
            path = root / 'container.log'
            path.write_text(logs_result.stdout + logs_result.stderr)
            path.chmod(0o600)
        raise
    finally:
        cleanup_errors = []
        for name, close in (('diagnostics', diagnostic.end_capture if diagnostic else None),
                            ('console', console.close if console else None)):
            if close:
                try:close()
                except Exception as cleanup_error:cleanup_errors.append(name + ': ' + type(cleanup_error).__name__)
        try:
            # Explicit forced fixture teardown, without asserting guest shutdown.
            # Includes a recorded Docker response even if create() never returned.
            fixture.cleanup(force=True)
            proof = fixture.get()
            report['fixture_cleanup_phase'] = proof['phase'] if proof else 'no_creation_intent'
        except Exception as cleanup_error:
            cleanup_errors.append('workload: ' + type(cleanup_error).__name__)
        if not cleanup_errors:
            for network in ([] if network_context else reversed(networks)):
                try:
                    observed = backend.docker.network(network['Id'])
                    assert observed['Id'] == network['Id'] and observed['Labels'].get('io.dnlab.spike') == token and not observed.get('Containers')
                    backend.docker.request('DELETE', '/networks/' + network['Id'])
                    assert backend.docker.request('GET', '/networks/' + network['Id'], missing_ok=True) is None
                except Exception as cleanup_error:
                    cleanup_errors.append('network: ' + type(cleanup_error).__name__)
                    break
        journal.close()
        report['cleanup_verified'] = not cleanup_errors
        report['cleanup_errors'] = cleanup_errors
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'report': str(root / 'report.json'), 'status': report.get('status'),
                          'cleanup_verified': report['cleanup_verified'], 'error': report.get('error')}, indent=2))
        if cleanup_errors:
            raise RuntimeError('NOS fixture cleanup incomplete; evidence and dependent infrastructure retained')
    return {'report': str(root / 'report.json'), **report}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--kind', choices=['cisco_vios', 'cisco_n9kv'], default='cisco_vios')
    parser.add_argument('--boot-only', action='store_true')
    parser.add_argument('--diagnose', action='store_true')
    parser.add_argument('--diagnose-passive', action='store_true')
    parser.add_argument('--diagnose-arp-control', action='store_true')
    parser.add_argument('--test-rollback', action='store_true')
    parser.add_argument('--interface-only', action='store_true', help='n9kv boot-only structural OOB/data TC, move and rollback; no guest traffic qualification.')
    parser.add_argument('--selected-slot', type=int, choices=range(16), help='vIOS source-built selected-management candidate only.')
    args = parser.parse_args()
    if args.execute:
        if args.kind == "cisco_n9kv" and not args.boot_only:
            parser.error("n9kv datapath adapter is not implemented by this probe; use --boot-only")
        run(args.image, args.kind, args.boot_only, args.diagnose or args.diagnose_passive or args.diagnose_arp_control, args.diagnose_passive or args.diagnose_arp_control, args.diagnose_arp_control, args.test_rollback, interface_only=args.interface_only, selected_slot=args.selected_slot)
    else:
        print(json.dumps({'mutations_performed': False, 'scope': args.kind + ' candidate, two isolated bridges, copied overlay in /tmp; explicit forced fixture teardown'}))
