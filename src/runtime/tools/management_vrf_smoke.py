"""Isolated native IPv4 dnlab-vrf probe; no NOS or distributed certification."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.backend import Backend, Docker, UnixConnection
from dnlab_runtime.journal import Journal
from dnlab_runtime.endpoint_name_probe import EndpointNameProbe
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase
from dnlab_runtime.stable_management import Handoff, StablePort
from management_smoke import fixture
from smoke import command, wait_for

PLUGIN_STATE = Path('/var/lib/dnlab-vrf-plugin/state.json')
PLUGIN_SOURCE = Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
CHECKOUT_SOURCE = Path(__file__).resolve().parents[2] / 'multinode/dnlab_multinode/vrf_plugin.py'


class ProbeDocker(Docker):
    """Keep connect failure detail private to the controlled native fixture."""
    def __init__(self, root, token, *, reject_name_probe=False):
        super().__init__()
        self.root, self.token, self.errors = root, token, []
        self.reject_name_probe = reject_name_probe

    def connect(self, network_id, container_id, ipv4, *, mac=None, interface_name=None):
        container = self.inspect(container_id)
        if not container or container['Config']['Labels'].get('org.dnlab.runtime.creator') != self.token:
            raise Conflict('connect diagnostic refuses an unowned fixture')
        endpoint = {'IPAMConfig': {'IPv4Address': ipv4}}
        if mac is not None:
            endpoint['MacAddress'] = mac
        is_canary = container['Config']['Labels'].get('org.dnlab.runtime.node', '').startswith('endpoint-probe-')
        if interface_name is not None and not (self.reject_name_probe and is_canary):
            endpoint['DriverOpts'] = {'com.docker.network.endpoint.ifname': interface_name}
        path = '/networks/' + quote(network_id, safe='') + '/connect'
        payload = {'Container': container_id, 'EndpointConfig': endpoint}
        connection = UnixConnection(self.socket_path)
        try:
            connection.request('POST', path, body=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read()
            if response.status >= 400:
                self.errors.append({'path': path, 'request': payload, 'status': response.status, 'response': data.decode(errors='replace')})
                evidence = self.root / 'connect-errors.json'
                evidence.write_text(json.dumps(self.errors, indent=2) + '\n')
                evidence.chmod(0o600)
                raise RuntimeErrorBase(f'Docker POST {path} returned HTTP {response.status}')
            return json.loads(data) if data else {}
        finally:
            connection.close()


def plugin_state():
    return json.loads(PLUGIN_STATE.read_text())


def require_link_owner(link, owner, kind):
    if not link or link.get('ifalias') != owner or link.get('linkinfo', {}).get('info_kind') != kind:
        raise Conflict('probe host link ownership/type mismatch; refusing mutation')


def require_creation_identity(link, intent):
    if not link or link.get('address') != intent['mac'] or link.get('linkinfo', {}).get('info_kind') != intent['kind'] or link.get('ifalias', '') not in {'', intent['owner']}:
        raise Conflict('probe creation identity mismatch')
    if intent['kind'] == 'vrf' and link.get('linkinfo', {}).get('info_data', {}).get('table') != intent['table']:
        raise Conflict('probe VRF table identity mismatch')
    if intent.get('ifindex') is not None and link.get('ifindex') != intent['ifindex']:
        raise Conflict('probe host link was replaced')


def preflight(backend):
    if os.geteuid() != 0:
        raise RuntimeError('dnlab-vrf probe requires root')
    if hashlib.sha256(PLUGIN_SOURCE.read_bytes()).digest() != hashlib.sha256(CHECKOUT_SOURCE.read_bytes()).digest():
        raise Conflict('installed dnlab-vrf differs from checkout; do not reinstall in a probe')
    if command(['systemctl', 'is-active', 'dnlab-vrf-plugin.service']) != 'active':
        raise Conflict('existing dnlab-vrf service is not active')
    if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
        raise Conflict('host forwarding is disabled; probe will not change global sysctls')
    links = json.loads(backend.linux.command(['-j', '-d', 'link', 'show']))
    routes = json.loads(backend.linux.command(['-j', 'route', 'show', 'table', 'all']))
    used = {link.get('linkinfo', {}).get('info_data', {}).get('table') for link in links}
    used.update(route.get('table') for route in routes)
    return used


def run(image, data_slot=True, reject_name_probe=False, nos_image=None, nos_kind='cisco_vios', nos_selected_slot=None, nos_data_traffic=False):
    token = 'vrsp-' + uuid.uuid4().hex[:8]
    root = Path(tempfile.mkdtemp(prefix='dnlab-vrf-smoke-'))
    backend, journal = Backend(docker=ProbeDocker(root, token, reject_name_probe=reject_name_probe)), Journal(root / 'state')
    probe_journal = Journal(root / 'endpoint-name-probes')
    name_probe = EndpointNameProbe(probe_journal, backend, token + '-a', image, token)
    networks, containers, host_links = [], [], []
    baseline = None
    report = {'scope': 'native IPv4 on installed dnlab-vrf; NOS, publishing and cross-host unqualified', 'image_id': image, 'data_slot_fixture': data_slot, 'reject_name_probe': reject_name_probe, 'checks': []}
    owner = 'dnlab-vrf-spike:' + token
    labs = {'a': token + '-a', 'b': token + '-b'}
    suffix = token[-6:]
    vrfs = {lab: 'drspv' + suffix + lab for lab in labs}
    tables = {}
    intents = {}
    firewall_rules = []
    firewall_before = None

    def create_link(name, kind, extra):
        if backend.linux.link(name) is not None:
            raise Conflict('dedicated host link name already exists')
        digest = hashlib.sha256((owner + ':' + name).encode()).hexdigest()[:10]
        mac = '02:' + ':'.join(digest[i:i+2] for i in range(0, 10, 2))
        intent = {'owner': owner, 'kind': kind, 'mac': mac, 'absent_before_create': True}
        if kind == 'vrf':
            intent['table'] = int(extra[1])
        intents[name] = intent
        (root / 'host-resource-intent.json').write_text(json.dumps(intents, indent=2) + '\n')
        host_links.append((name, kind))
        backend.linux.command(['link', 'add', name, 'address', mac, 'type', kind, *extra])
        link = backend.linux.link(name)
        require_creation_identity(link, intent)
        intent['ifindex'] = link['ifindex']
        (root / 'host-resource-intent.json').write_text(json.dumps(intents, indent=2) + '\n')
        backend.linux.command(['link', 'set', name, 'alias', owner])
        require_link_owner(backend.linux.link(name), owner, kind)
        backend.linux.command(['link', 'set', name, 'up'])

    def network(lab, color, subnet):
        name = 'dnlab-' + labs[lab] + '-' + color
        bridge = 'drspb' + suffix + lab + color[0]
        pool = ipaddress.ip_network(subnet)
        gateway = str(pool.network_address + 1)
        create_link(bridge, 'bridge', [])
        backend.linux.command(['link', 'set', bridge, 'master', vrfs[lab]])
        backend.linux.command(['addr', 'add', gateway + '/' + str(pool.prefixlen), 'dev', bridge])
        # Same prerequisite as multinode netsetup: Docker's FORWARD DROP
        # also filters intra-bridge IPv4 when br_netfilter is enabled.
        for direction in ('i', 'o'):
            rule = ['-' + direction, bridge, '-m', 'comment', '--comment', owner, '-j', 'ACCEPT']
            firewall_rules.append(rule)
            (root / 'firewall-intent.json').write_text(json.dumps(firewall_rules, indent=2) + '\n')
            backend.linux.run(['iptables', '-w', '5', '-I', 'DOCKER-USER', '1', *rule])
        payload = {'Name': name, 'Driver': 'dnlab-vrf', 'EnableIPv6': False,
                   'Options': {'dnlab.bridge': bridge, 'dnlab.vrf': vrfs[lab], 'dnlab.lab': labs[lab]},
                   'Labels': {'io.dnlab.spike': token, 'io.dnlab.managed': 'mgmt-vrf', 'io.dnlab.lab': labs[lab]},
                   'IPAM': {'Driver': 'dnlab-vrf', 'Options': {'dnlab.tenant': name, 'dnlab.reserved': gateway, 'dnlab.host-index': '0', 'dnlab.host-count': '1'}, 'Config': [{'Subnet': str(pool), 'Gateway': gateway}]}}
        networks.append(name)  # Intent allows cleanup after a lost create response.
        backend.docker.request('POST', '/networks/create', payload)
        return backend.docker.network(name)

    def node(lab, label, network, offset, port):
        name = 'dnlab-' + token + '-' + label
        request, spec = fixture(labs[lab], label, name, image, port)
        pool = ipaddress.ip_network(network['IPAM']['Config'][0]['Subnet'])
        address = str(pool.network_address + offset)
        spec['management'] = {'network': network['Name'], 'ipv4': address}
        containers.append((request, spec))
        backend.create(request, spec, token)
        backend.start(request, spec)
        return (request, spec), address

    def fetch(node, address, port=5000):
        request, spec = node
        container = backend.inspect(request, spec)
        with backend.namespace(request, spec, container) as ns:
            program = "import sys,urllib.request; u='http://'+sys.argv[1]+':'+sys.argv[2]; print(urllib.request.build_opener(urllib.request.ProxyHandler({})).open(u,timeout=2).read().decode())"
            return backend.linux.run(['nsenter', f'--net={ns}', '--', sys.executable, '-c', program, address, str(port)], pass_fds=(ns.fd,)).strip()

    try:
        used = preflight(backend)
        baseline = plugin_state()
        firewall_before = backend.linux.run(['iptables', '-S', 'DOCKER-USER'])
        seed = 40000 + int(suffix, 16) % 15000
        for index, lab in enumerate(labs):
            table = seed + index
            if table in used:
                raise Conflict('dedicated VRF table is already used')
            tables[lab] = table
            create_link(vrfs[lab], 'vrf', ['table', str(table)])
            # Prevent lookup falling through to main-table routes outside the probe.
            backend.linux.command(['route', 'add', 'unreachable', 'default', 'table', str(table), 'metric', '4278198272'])
        blue = network('a', 'blue', '198.19.80.0/24')
        twin = network('b', 'blue', '198.19.80.0/24')
        vd, source_ip = node('a', 'vd-a', blue, 10, 5000)
        sentinel, sentinel_ip = node('b', 'vd-b', twin, 10, 5000)
        client, _ = node('a', 'client-a', blue, 20, 6000)
        isolated_client, _ = node('b', 'client-b', twin, 20, 6000)
        port = StablePort(backend, *vd, '02:da:ab:00:00:04')
        handoff = Handoff(journal, backend, *vd, port, name_probe=name_probe)
        source = handoff.capture(blue)
        identity = port.prepare(source)
        if data_slot:
            with backend.namespace(*vd, port.container()) as ns:
                if backend.linux.link('eth1', ns) is not None:
                    raise Conflict('native data-slot fixture name is already occupied')
                backend.linux.command(['link', 'add', 'eth1', 'address', port.mac, 'type', 'veth', 'peer', 'name', 'data-peer1'], ns)
                data_identity = backend.linux.link('eth1', ns)
        report['uplinks'] = {'initial': port.uplink(source)}
        report['phase'] = 'stable_prepared_before_first_traffic'
        before = wait_for(lambda: fetch(client, source_ip))
        twin_before = wait_for(lambda: fetch(isolated_client, sentinel_ip))
        assert before.startswith('vd-a ') and twin_before.startswith('vd-b ')
        assert source_ip == sentinel_ip
        report['checks'].append('identical IP/subnet in two lab VRFs resolves to distinct owned workloads')
        sentinel_identity = backend.inspect(*sentinel)['State']
        # Add a segment and a VD only after the first segment's workloads run.
        red = network('a', 'red', '198.19.81.0/24')
        red_client, red_ip = node('a', 'client-red', red, 20, 6000)
        report['phase'] = 'testing_reciprocal_routing'
        assert wait_for(lambda: fetch(client, red_ip, 6000)).startswith('client-red ')
        assert wait_for(lambda: fetch(red_client, '198.19.80.20', 6000)).startswith('client-a ')
        report['checks'].append('live segment/workload addition and reciprocal inter-management routing inside lab VRF')
        target_ip = '198.19.81.10'
        if reject_name_probe:
            original_uplink = port.uplink(source)
            try:
                handoff.submit('rejected-move', red['Name'], target_ip)
            except Conflict as error:
                assert 'remote driver did not apply' in str(error), error
            else:
                raise AssertionError('unsupported naming probe incorrectly authorized handoff')
            assert port.snapshot() == identity
            assert handoff.capture(blue) == source
            assert port.uplink(source) == original_uplink
            assert fetch(client, source_ip) == before
            assert fetch(isolated_client, sentinel_ip) == twin_before
            assert backend.inspect(*sentinel)['State'] == sentinel_identity
            if data_slot:
                with backend.namespace(*vd, port.container()) as ns:
                    assert backend.linux.link('eth1', ns) == data_identity
            assert journal.db.execute('SELECT count(*) FROM management_moves').fetchone()[0] == 0
            assert probe_journal.db.execute("SELECT count(*) FROM endpoint_name_probes WHERE phase != 'cleaned'").fetchone()[0] == 0
            report['checks'].append('unsupported canary naming rejects move before VD detach; original endpoint, stable/data links, traffic and other lab preserved')
            report['phase'], report['status'] = 'rejection_verified', 'passed'
            return
        handoff.submit('move', red['Name'], target_ip)
        report['phase'] = 'moving'
        moved = handoff.execute(handoff.by_request('move')['id'])
        assert moved['phase'] == 'completed', moved
        assert wait_for(lambda: fetch(client, target_ip)) == before
        assert wait_for(lambda: fetch(red_client, target_ip)) == before
        assert port.snapshot() == identity
        report['uplinks']['moved'] = port.uplink(moved['payload']['target'])
        report['checks'].append('real dnlab-vrf move preserves stable links/MAC/PID and routes from both networks')
        handoff.submit('rollback', blue['Name'], source_ip)
        report['phase'] = 'rollback'
        def fail_after_connect(phase):
            if phase == 'connected':
                raise RuntimeError('injected post-connect failure')
        rolled = handoff.execute(handoff.by_request('rollback')['id'], checkpoint=fail_after_connect)
        assert rolled['phase'] == 'rolled_back', rolled
        assert wait_for(lambda: fetch(client, target_ip)) == before
        assert port.snapshot() == identity
        report['uplinks']['rolled_back'] = port.uplink(rolled['payload']['source'])
        report['checks'].append('post-connect failure rolls back endpoint with same guest MAC and continued traffic')
        try:
            fetch(isolated_client, target_ip)
        except Exception:
            report['checks'].append('other lab cannot reach target subnet through dedicated VRF')
        else:
            raise AssertionError('cross-lab connectivity leaked')
        assert fetch(isolated_client, sentinel_ip) == twin_before
        assert backend.inspect(*sentinel)['State'] == sentinel_identity
        report['checks'].append('overlapping lab sentinel remains unchanged across move and rollback')
        # A real persisted connecting phase is replayed through fresh journal,
        # handoff and port instances. Already connected endpoint must survive.
        report['phase'] = 'crash_replay'
        handoff.submit('crash-replay', blue['Name'], source_ip)
        def crash_after_connect(phase):
            if phase == 'connected':
                raise SystemExit('simulated runtime crash after connect and bind')
        try:
            handoff.execute(handoff.by_request('crash-replay')['id'], checkpoint=crash_after_connect)
        except SystemExit:
            pass
        else:
            raise AssertionError('crash checkpoint was not reached')
        connected = port.uplink(source)
        journal.close()
        journal = Journal(root / 'state')
        port = StablePort(backend, *vd, '02:da:ab:00:00:04')
        handoff = Handoff(journal, backend, *vd, port, name_probe=name_probe)
        replayed = handoff.execute(handoff.by_request('crash-replay')['id'])
        assert replayed['phase'] == 'completed'
        assert port.uplink(source) == connected
        assert port.snapshot() == identity
        assert wait_for(lambda: fetch(client, source_ip)) == before
        assert wait_for(lambda: fetch(red_client, source_ip)) == before
        assert handoff.execute(handoff.by_request('crash-replay')['id'])['phase'] == 'completed'
        assert port.uplink(source) == connected
        if data_slot:
            with backend.namespace(*vd, port.container()) as ns:
                assert backend.linux.link('eth1', ns) == data_identity
        assert fetch(isolated_client, sentinel_ip) == twin_before
        assert backend.inspect(*sentinel)['State'] == sentinel_identity
        report['checks'].append('fresh-journal replay preserves the connected endpoint and stable identity without a second connect')
        if data_slot:
            report['checks'].append('same-MAC native data-slot eth1 remains untouched across reconnect, rollback and replay')
        report['uplinks']['replayed'] = connected
        report['endpoint_observations'] = replayed['payload']['endpoint_observations']
        report['capability_observations'] = replayed['payload']['capability_observations']
        report['checks'].append('fresh owned native canary verifies remote endpoint naming and cleanup before each handoff preflight')
        report['stable_identity'] = identity
        report['move_phase'], report['rollback_phase'] = moved['phase'], rolled['phase']
        if nos_image:
            if nos_selected_slot is not None:
                report['delayed_readiness_canary'] = name_probe.check(blue, 'dnmu0', creation_mode='create', startup_delay=2)
                assert report['delayed_readiness_canary']['process_readiness_verified']
                assert report['delayed_readiness_canary']['cleanup_verified']
                report['checks'].append('initial-create canary with delayed signal handler reaches bounded readiness and exits safely without recovery')
            from nos_smoke import run as run_nos
            def ping_from_client(address):
                client_container = backend.inspect(*client)
                with backend.namespace(*client, client_container) as ns:
                    return subprocess.run(['nsenter', f'--net={ns}', '--', 'ping', '-n', '-c', '1', '-W', '2', address], capture_output=True, text=True, pass_fds=(ns.fd,))
            report['phase'] = 'nos_qualification'
            (root / 'progress.json').write_text(json.dumps({'phase': report['phase'], 'image': nos_image}))
            report['nos'] = run_nos(nos_image, kind=nos_kind, boot_only=nos_kind=='cisco_n9kv', interface_only=nos_kind=='cisco_n9kv', test_rollback=True, diagnose=True, passive=True, selected_slot=nos_selected_slot, data_traffic=nos_data_traffic, network_context={'networks': [blue, red], 'lab_id': labs['a'], 'name_probe': name_probe, 'ping': ping_from_client, 'target_ip': '198.19.81.30'})
            assert report['nos']['status'] == 'passed' and report['nos']['cleanup_verified']
            assert fetch(isolated_client, sentinel_ip) == twin_before
            assert backend.inspect(*sentinel)['State'] == sentinel_identity
            assert fetch(client, source_ip) == before
            report['checks'].append('new ' + nos_kind + ' V2 guest on owned dnlab-vrf preserves NIC/process through move and rollback; native workloads unchanged')
        report['phase'] = 'verified'
        report['status'] = 'passed'
    except BaseException as error:
        report['status'], report['error'] = 'failed', str(error)
        snapshots = {}
        for request, spec in containers:
            try:
                container = backend.inspect(request, spec)
                if container and container['State']['Running']:
                    with backend.namespace(request, spec, container) as ns:
                        snapshots[spec['container_name']] = {'id': container['Id'], 'pid': container['State']['Pid'], 'endpoints': container['NetworkSettings']['Networks'], 'kernel': {key: json.loads(backend.linux.command(args, ns)) for key, args in [('addresses', ['-j', 'addr', 'show']), ('routes', ['-j', 'route', 'show']), ('neighbors', ['-j', 'neigh', 'show'])]}}
            except Exception as snapshot_error:
                snapshots[spec['container_name']] = {'snapshot_error': str(snapshot_error)}
        (root / 'failure-snapshot.json').write_text(json.dumps(snapshots, indent=2) + '\n')
        raise
    finally:
        errors = []
        try:
            name_probe.recover()
        except Exception as error:
            errors.append('endpoint naming canary: ' + str(error))
        for request, spec in reversed(containers):
            try:
                backend.stop(request, spec, force=True)
                backend.remove(request, spec)
                assert backend.inspect(request, spec) is None
            except Exception as error:
                errors.append('container ' + spec['container_name'] + ': ' + str(error))
        for name in reversed(networks):
            try:
                observed = backend.docker.request('GET', '/networks/' + name, missing_ok=True)
                if observed:
                    if observed.get('Labels', {}).get('io.dnlab.spike') != token or observed.get('Containers'):
                        raise Conflict('refusing cleanup of foreign or occupied probe network')
                    backend.docker.request('DELETE', '/networks/' + observed['Id'])
            except Exception as error:
                errors.append('network ' + name + ': ' + str(error))
        for rule in reversed(firewall_rules):
            try:
                # Exact bridge and unique comment; no policy/chain reset.
                present = subprocess.run(['iptables', '-w', '5', '-C', 'DOCKER-USER', *rule], capture_output=True)
                if present.returncode == 0:
                    backend.linux.run(['iptables', '-w', '5', '-D', 'DOCKER-USER', *rule])
                elif present.returncode != 1:
                    raise RuntimeError('cannot inspect dedicated firewall rule')
            except Exception as error:
                errors.append('firewall: ' + str(error))
        for name, kind in reversed(host_links):
            try:
                link = backend.linux.link(name)
                if link:
                    # The atomic MAC/type/table marker also covers a failure
                    # between creation and explicit alias verification.
                    require_creation_identity(link, intents[name])
                    peers = json.loads(backend.linux.command(['-j', 'link', 'show', 'master', name]))
                    if peers:
                        raise Conflict('refusing cleanup of occupied host link')
                    if kind == 'vrf':
                        table = link['linkinfo']['info_data']['table']
                        routes = json.loads(backend.linux.command(['-j', 'route', 'show', 'table', str(table)]))
                        if routes and (len(routes) != 1 or routes[0].get('type') != 'unreachable' or routes[0].get('dst') != 'default' or routes[0].get('metric') != 4278198272):
                            raise Conflict('dedicated VRF route table has unexpected resources')
                        if routes:
                            backend.linux.command(['route', 'del', 'unreachable', 'default', 'table', str(table), 'metric', '4278198272'])
                    backend.linux.command(['link', 'delete', 'dev', name])
                    assert backend.linux.link(name) is None
            except Exception as error:
                errors.append('host link ' + name + ': ' + str(error))
        if baseline is not None:
            try:
                assert plugin_state() == baseline, 'plugin state differs from pre-probe state'
                report['plugin_state_restored'] = True
            except Exception as error:
                errors.append(str(error))
        if firewall_before is not None:
            try:
                assert backend.linux.run(['iptables', '-S', 'DOCKER-USER']) == firewall_before, 'firewall differs from pre-probe state'
                report['firewall_restored'] = True
            except Exception as error:
                errors.append(str(error))
        journal.close()
        probe_journal.close()
        report['cleanup_verified'] = not errors
        if errors:
            report['cleanup_errors'] = errors
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'report': str(root / 'report.json'), **report}, indent=2))
        if errors:
            raise RuntimeError('probe cleanup incomplete; see dedicated report')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='python@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--without-data-slot', action='store_true', help='Diagnostic control only; does not qualify warm-port coexistence.')
    parser.add_argument('--reject-name-probe', action='store_true', help='Negative control: omit the requested name only on owned native canaries; verify rejection before VD detach.')
    parser.add_argument('--nos-image', help='Optional immutable V2 NOS candidate ID; one new KVM guest, forced owned teardown; n9kv is structural-only and host publishing is excluded.')
    parser.add_argument('--nos-selected-slot', type=int, choices=range(16), help='Optional source-built vIOS selected management slot.')
    parser.add_argument('--nos-data-traffic', action='store_true', help='Isolated vIOS data slots0/1/15 ICMP and warm carrier; requires selected slot8.')
    parser.add_argument('--nos-kind', choices=['cisco_vios', 'cisco_n9kv'], default='cisco_vios', help='n9kv scope is structural OOB only, accepting ROMMON boot and leaving guest traffic unqualified.')
    args = parser.parse_args()
    if args.execute:
        image = command(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.image])
        if args.nos_selected_slot is not None and (not args.nos_image or args.nos_kind != 'cisco_vios'):
            parser.error('--nos-selected-slot requires --nos-image and kind cisco_vios')
        if args.nos_data_traffic and (not args.nos_image or args.nos_kind != 'cisco_vios' or args.nos_selected_slot != 8):
            parser.error('--nos-data-traffic requires vIOS --nos-image and --nos-selected-slot 8')
        run(image, data_slot=not args.without_data_slot, reject_name_probe=args.reject_name_probe, nos_image=args.nos_image, nos_kind=args.nos_kind, nos_selected_slot=args.nos_selected_slot, nos_data_traffic=args.nos_data_traffic)
    else:
        print(json.dumps({'mutations_performed': False, 'scope': 'installed dnlab-vrf, two dedicated host VRFs, three bridges/networks, native workloads; forced owned fixture teardown', 'excludes': ['NOS', 'Docker port publication', 'DNS/jumphost', 'IPv6', 'distributed VXLAN']}))
