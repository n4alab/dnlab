#!/usr/bin/env python3
"""Explicit retirement of an interrupted local management gate's networks.

This does not resume a gate or modify its birth journals. The output journal is
separate and boot-bound. No ordinary worker context check is overridden.
"""
import argparse
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import fcntl
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import socket
import stat
import subprocess
import sys
import tempfile
import threading

SOURCE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(SOURCE), str(SOURCE.parent / 'multinode')]
from dnlab_multinode.services.management_host import Worker, context, signature
from dnlab_multinode.services.management_network_host import NetworkGuard, Docker, plugin_state
from dnlab_multinode.services.jumphost_network_host import Worker as ExternalWorker
from dnlab_multinode.services.runtime_operations import digest, encoded
from dnlab_multinode.services.runtime_cleanup import management_cleanup_check


class RetirementError(RuntimeError):
    pass


def private(path, directory=False):
    path = Path(path)
    if path.resolve() != path.absolute(): raise RetirementError('source/output path contains a symlink')
    info = path.lstat()
    mode = 0o700 if directory else 0o600
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise RetirementError('source/output ownership or mode differs')
    return path


def read(path):
    path = private(path); private(path.parent, True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream: raw = stream.read()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def sync(directory):
    for path in (directory, directory.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


class Engine(Docker):
    def inventory(self):
        values = self.call('GET', '/networks')
        if not isinstance(values, list) or any(not isinstance(v, dict) or not re.fullmatch('[0-9a-f]{64}', v.get('Id', '')) for v in values):
            raise RetirementError('Docker network inventory incomplete')
        if len({v['Id'] for v in values}) != len(values): raise RetirementError('ambiguous Docker network inventory')
        return values

    def container(self, identity):
        return self.call('GET', '/containers/' + identity + '/json', absent=True)


class GateSources:
    """Complete sealed local gate footprint; never open a runtime for writing."""
    def __init__(self, root):
        self.root = private(Path(root).absolute(), True)

    @contextmanager
    def locked(self):
        coordinator = self.root / 'coordinator'
        # Identify the lab read-only before taking the existing coordinator locks.
        with self.database(coordinator / 'operations.sqlite3') as db:
            rows = db.execute('SELECT lab FROM management_barriers').fetchall()
            if len(rows) != 1: raise RetirementError('complete single-lab gate coordinator required')
            lab = rows[0][0]
        paths = [coordinator / ('op-' + digest({'lab': lab, 'key': key}) + '.lock')
                 for key in ('management-barrier', 'public-lifecycle', 'initial-deployment:all')]
        paths += [self.root / directory / '.lock' for directory in ('management', 'external')]
        paths += [self.root / 'runtime/state/daemon.lock']
        with ExitStack() as stack:
            for path in sorted(paths):
                private(path.parent, True)
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                stack.callback(os.close, fd); private(path)
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise RetirementError('original coordinator/runtime/worker still active') from None
            yield

    @contextmanager
    def database(self, path):
        private(path)
        db = sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row
        try: yield db
        finally: db.close()

    @staticmethod
    def offline_socket(path):
        path = Path(path)
        if path.resolve() != path.absolute(): raise RetirementError('runtime socket path contains a symlink')
        try: before = path.lstat()
        except FileNotFoundError: return None
        if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600):
            raise RetirementError('original runtime socket ownership/type differs')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            try: client.connect(str(path))
            except OSError as error:
                if error.errno != errno.ECONNREFUSED:
                    raise RetirementError('runtime listener absence is not verified') from error
            else: raise RetirementError('original runtime socket still accepts connections')
        after = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
        if identity(before) != identity(after): raise RetirementError('runtime socket changed during observation')
        return {'path': str(path), 'device': after.st_dev, 'inode': after.st_ino,
                'mode': stat.S_IMODE(after.st_mode), 'uid': after.st_uid, 'gid': after.st_gid,
                'listener_absence': 'ECONNREFUSED'}

    def snapshot(self):
        with self.database(self.root / 'coordinator/operations.sqlite3') as db:
            class View:
                lock = threading.RLock()
            view = View(); view.db = db
            rows = db.execute('SELECT lab FROM management_barriers').fetchall()
            if len(rows) != 1: raise RetirementError('one original gate lab required')
            lab = rows[0][0]; barrier = management_cleanup_check(view, lab)
            if barrier is None or barrier['phase'] != 'released' or len(barrier['targets']) != 1:
                raise RetirementError('complete released single-host gate required')
            if db.execute("SELECT 1 FROM operations WHERE phase NOT IN ('completed','cancelled','failed')").fetchone():
                raise RetirementError('coordinator workload recovery pending')
            if db.execute('SELECT 1 FROM initial_batches').fetchone() or db.execute('SELECT 1 FROM public_requests').fetchone():
                raise RetirementError('workload/public lifecycle footprint requires its own recovery')
        target = next(iter(barrier['targets'].values()))
        if target['target']['container_name'] is not None:
            raise RetirementError('original native runtime must be offline')
        runtime_socket = self.offline_socket(target['target']['socket_path'])
        with self.database(self.root / 'runtime/state/journal.sqlite3') as db:
            identity = db.execute('SELECT identity FROM journal_identity').fetchall()
            if len(identity) != 1 or identity[0][0] != target['journal_id']:
                raise RetirementError('original runtime journal changed')
            for table in ('nodes', 'resources', 'workload_generations'):
                if db.execute('SELECT 1 FROM ' + table).fetchone():
                    raise RetirementError('runtime workload footprint requires separate recovery')
            if db.execute("SELECT 1 FROM operations WHERE phase NOT IN ('completed','cancelled','failed')").fetchone():
                raise RetirementError('runtime execution outcome pending')
        hashes = {}; records = {}
        for kind in ('management', 'external', 'jump', 'dns', 'probes'):
            records[kind] = []
            for path in sorted((self.root / kind).glob('*.json')):
                row, mark = read(path); hashes[str(path)] = mark; records[kind].append(row)
        if any(len(records[k]) != 1 for k in ('management', 'external', 'jump', 'dns')):
            raise RetirementError('complete original management/helper journals required')
        management = records['management'][0]; external = records['external'][0]
        bundle = barrier['plan']['services']; receipt = barrier['services']['receipt']
        host = next(iter(barrier['targets']))
        if (management['plan']['lab'] != lab or management['plan']['generation'] != barrier['plan']['management_generation']
                or set(management['networks']) != set(barrier['plan']['hosts'][host]['segments'])
                or external['config'] != {('network' if k == 'name' else k): v for k, v in bundle['jumphost']['network'].items()}
                or external['id'] != receipt['external_network_id']):
            raise RetirementError('network birth journals differ from original coordinator')
        if external.get('phase') != 'active' or not re.fullmatch('[0-9a-f]{32}', external.get('nonce', '')):
            raise RetirementError('qualified original external birth required')
        for key, row in management['networks'].items():
            if row['expected'] != barrier['plan']['hosts'][host]['segments'][key]['network']:
                raise RetirementError('management network intent differs')
        dependencies = []
        for role, kind in (('jumphost', 'jump'), ('dns', 'dns')):
            row = records[kind][0]; cfg = bundle[role] if role == 'jumphost' else bundle['dns']['config']
            if row['config'] != cfg or any(row[k] != receipt[role][k] for k in ('container_id', 'nonce')):
                raise RetirementError('original helper birth differs')
            dependencies.append((row['container_id'], cfg['name']))
        expected = {}
        for field in ('packet_probes', 'dns_client_probes', 'probe_lifecycle'):
            stage = barrier.get(field, {})
            for request in stage.get('requests', []): expected[request['request_id']] = (request, stage['entries'][request['request_id']])
        stage = barrier.get('routing_probes', {})
        for pair in stage.get('pairs', []):
            for request in pair['requests']: expected[request['request_id']] = (request, stage['entries'][request['request_id']])
        if {r['request']['request_id'] for r in records['probes']} != set(expected):
            raise RetirementError('complete original probe footprint required')
        for row in records['probes']:
            request, entry = expected[row['request']['request_id']]
            if (row['request'] != request or row['phase'] != 'cleaned' or row.get('cleanup_verified') is not True
                    or row['container_id'] != entry['birth']['container_id']):
                raise RetirementError('original probe cleanup incomplete')
            dependencies.append((row['container_id'], 'dnlab-probe-' + digest(['management-probe-v1', request])[:24]))
        forbidden = set(management['resources']); aliases = set()
        for row in management['resources'].values():
            if row.get('identity', {}).get('ifalias'): aliases.add(row['identity']['ifalias'])
        for row in records['jump'] + records['dns'] + records['probes']:
            for endpoint in [row] + list(row.get('management_attachments', {}).values()):
                if endpoint.get('host', {}).get('ifname'): forbidden.add(endpoint['host']['ifname'])
                if endpoint.get('alias'): aliases.add(endpoint['alias'])
        return {'lab': lab, 'source_hashes': hashes, 'barrier_hash': digest(barrier),
                'runtime_id': target['journal_id'], 'runtime_socket': runtime_socket,
                'management': management, 'external': external,
                'dependencies': dependencies, 'forbidden': sorted(forbidden), 'aliases': sorted(aliases)}


class Retirement:
    def __init__(self, sources, output, expected_plugin_hash, *, docker=None, host_context=context, links=None, addresses=None, plugin=None, plugin_code=None, firewall=None):
        if not re.fullmatch('[0-9a-f]{64}', expected_plugin_hash): raise RetirementError('qualified plugin hash required')
        self.expected_plugin_hash = expected_plugin_hash
        self.plugin_code = plugin_code or (lambda: hashlib.sha256(Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py').read_bytes()).hexdigest())
        self.sources = sources; self.output = Path(output).absolute(); self.host_context = host_context
        self.docker = docker or Engine('/var/run/docker.sock')
        self.links = links or (lambda: json.loads(subprocess.run(
            ['ip', '-j', '-d', 'link', 'show'], capture_output=True, text=True, check=True, timeout=30).stdout))
        self.addresses = addresses or self.current_addresses
        self.plugin = plugin or (lambda: plugin_state('/var/lib/dnlab-vrf-plugin/state.json'))
        self.firewall = firewall

    @staticmethod
    def current_addresses(name):
        return json.loads(subprocess.run(['ip', '-j', 'address', 'show', 'dev', name], capture_output=True,
                                         text=True, check=True, timeout=30).stdout)

    @staticmethod
    def atomic(target, value):
        fd, path = tempfile.mkstemp(prefix='.retire-', dir=target.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
            os.replace(path, target); sync(target.parent)
        finally:
            if os.path.exists(path): os.unlink(path)

    def save(self, value):
        self.atomic(self.output, value)

    def observe(self, source, record):
        if self.plugin_code() != self.expected_plugin_hash or record and record.get('plugin_hash') != self.expected_plugin_hash:
            raise RetirementError('qualified plugin source changed')
        scope = self.host_context()
        old = source['management']['context']
        if (source['external']['context'] != old or scope == old or scope.get('boot_id') == old.get('boot_id')
                or record is not None and record['context'] != scope):
            raise RetirementError('explicit different-boot retirement context required')
        for identity, name in source['dependencies']:
            if self.docker.container(identity) is not None or self.docker.container(name) is not None:
                raise RetirementError('original helper/probe name or generation still present')
        links = self.links()
        if not isinstance(links, list) or len({v['ifname'] for v in links}) != len(links):
            raise RetirementError('kernel inventory incomplete')
        if any(v['ifname'] in source['forbidden'] or v.get('ifalias') in source['aliases'] for v in links):
            raise RetirementError('old kernel name or alias occupied; no adoption permitted')
        phases = record['resources'] if record else {}
        witnesses = {}; resources = {}
        worker = Worker(source['management']['plan'], directory=self.sources.root / 'management')
        rules = self.firewall(worker) if self.firewall else worker.firewall(source['management'])
        if set(rules) != {'iptables', 'ip6tables'} or any(rules.values()):
            raise RetirementError('old management firewall recovery still pending')
        for key, row in sorted(source['management']['networks'].items()):
            identity = row.get('id')
            if (not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity)
                    or row.get('phase') != 'active' or not re.fullmatch('[0-9a-f]{32}', row.get('nonce', ''))):
                raise RetirementError('complete original active network birth required')
            guard = NetworkGuard(worker, {key: row['expected']}, docker=self.docker, plugin=self.plugin)
            missing = phases.get(identity) in ('deleting', 'cleaned')
            value = guard.observe(row, missing=missing)
            if value is not None:
                if value['Containers'] or guard.plugin_check(row, value): raise RetirementError('management endpoints remain')
                for pool in self.plugin()['pools'].values():
                    if pool.get('tenant') == row['expected']['network']:
                        family = ipaddress.ip_network(pool['pool']).version
                        if set(pool['allocated']) - {row['expected']['ipv'+str(family)+'_gateway']}:
                            raise RetirementError('unqualified management IPAM allocations remain')
            resources[identity] = value
        external = source['external']; identity = external['id']
        ext = ExternalWorker(external['config'], directory=self.sources.root / 'external')
        value = self.docker.inspect(identity); named = self.docker.inspect(external['config']['network'])
        if named is not None and named['Id'] != identity: raise RetirementError('external network name was replaced')
        if (value is None) != (named is None): raise RetirementError('external name/ID disagree')
        bridge_name = external['config']['bridge']; bridge = next((v for v in links if v['ifname'] == bridge_name), None)
        if value is None:
            if phases.get(identity) not in ('deleting', 'cleaned') or bridge is not None:
                raise RetirementError('external absence or kernel teardown not qualified')
        else:
            wanted = ext.desired(external)
            if (any(value.get(k) != wanted[k] for k in ('Name','Driver','EnableIPv6','Internal','Attachable','Ingress','Options','Labels'))
                    or value.get('Scope') != 'local' or value.get('ConfigOnly', False) is not False
                    or value.get('Containers') != {}):
                raise RetirementError('external ownership/configuration/endpoints differ')
            ipam = deepcopy(value.get('IPAM'))
            if isinstance(ipam, dict) and (ipam.get('Options') is None or ipam.get('Options') == {}): ipam['Options'] = {}
            if ipam != wanted['IPAM']: raise RetirementError('external IPAM differs')
            if not bridge or bridge.get('linkinfo', {}).get('info_kind') != 'bridge': raise RetirementError('Docker external bridge missing')
            if any(v.get('master') in (bridge_name, bridge['ifindex']) for v in links):
                raise RetirementError('external bridge still has kernel attachments')
            addr = [(v.get('local'), v.get('prefixlen')) for item in self.addresses(bridge_name)
                    for v in item.get('addr_info', []) if v.get('family') == 'inet']
            if addr != [(external['config']['gateway'], ipaddress.ip_network(external['config']['subnet']).prefixlen)]:
                raise RetirementError('external bridge gateway differs')
            witnesses[identity] = signature(bridge)
        resources[identity] = value
        if len(resources) != len(source['management']['networks']) + 1:
            raise RetirementError('network identities overlap')
        inventory = self.docker.inventory()
        if sum(v.get('Name') == external['config']['network'] for v in inventory) != int(value is not None):
            raise RetirementError('external inventory changed')
        if any(v['Id'] != identity and (v.get('Options') or {}).get('com.docker.network.bridge.name') == bridge_name for v in inventory):
            raise RetirementError('external bridge reserved by another network')
        if record:
            if record['source'] != self.identity(source): raise RetirementError('original source changed')
            if (set(record['resources']) != set(resources)
                    or any(v not in ('planned', 'deleting', 'cleaned') for v in record['resources'].values())
                    or record.get('phase') not in ('pending', 'cleaned')):
                raise RetirementError('retirement journal resource state differs')
            for identity, witness in witnesses.items():
                if record['witnesses'].get(identity) != witness: raise RetirementError('current Docker bridge changed')
        if scope != self.host_context() or self.plugin_code() != self.expected_plugin_hash:
            raise RetirementError('current namespace or plugin changed during preflight')
        return resources, witnesses, scope

    @staticmethod
    def identity(source):
        return {k: source[k] for k in ('lab', 'source_hashes', 'barrier_hash', 'runtime_id', 'runtime_socket')}

    def run(self, request_id, *, apply=False):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', request_id): raise RetirementError('stable retirement request ID required')
        private(self.output.parent, True)
        with self.sources.locked():
            lock_path = self.sources.root / '.retirement.lock'
            lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                private(lock_path)
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise RetirementError('retirement already executing') from None
                # One durable operation per explicit output directory prevents
                # concurrent requests from claiming the same source networks.
                manifest = self.sources.root / '.retirement-owner.json'
                owner = {'request_id': request_id, 'output': str(self.output)}
                if manifest.exists():
                    if read(manifest)[0] != owner: raise RetirementError('retirement output already reserved')
                elif apply:
                    self.atomic(manifest, owner)
                source = self.sources.snapshot(); record = read(self.output)[0] if self.output.exists() else None
                if record and record['request_id'] != request_id: raise RetirementError('retirement request changed')
                resources, witnesses, scope = self.observe(source, record)
                if not apply: return {'phase': 'verified', 'network_ids': sorted(resources), 'mutations_performed': False}
                if record is None:
                    record = {'request_id': request_id, 'source': self.identity(source), 'context': scope,
                              'plugin_hash': self.expected_plugin_hash, 'witnesses': witnesses,
                              'phase': 'pending', 'resources': {k: 'planned' for k in resources}}
                    self.save(record)
                sync(self.output.parent)
                for identity in resources:
                    # Full preflight of every remaining resource before each
                    # delete, under the original worker/coordinator locks.
                    current, _, _ = self.observe(self.sources.snapshot(), record)
                    if current[identity] is not None:
                        record['resources'][identity] = 'deleting'; self.save(record)
                        current, _, _ = self.observe(self.sources.snapshot(), record)
                        if current[identity] is not None:
                            try: self.docker.delete(identity)
                            except Exception:
                                # No blind resend: only verified absence can
                                # establish success after an uncertain response.
                                after, _, _ = self.observe(self.sources.snapshot(), record)
                                if after[identity] is not None: raise
                    after, _, _ = self.observe(self.sources.snapshot(), record)
                    if after[identity] is not None: raise RetirementError('Docker network remains after delete')
                    record['resources'][identity] = 'cleaned'; self.save(record)
                self.observe(self.sources.snapshot(), record)
                record['phase'] = 'cleaned'; self.save(record)
                return {'phase': 'cleaned', 'network_ids': sorted(resources), 'cleanup_verified': True,
                        'original_birth_journals_preserved': True}
            finally: os.close(lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate-root', required=True); parser.add_argument('--output', required=True)
    parser.add_argument('--plugin-sha256', required=True)
    parser.add_argument('--request-id', required=True); parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print(json.dumps(Retirement(GateSources(args.gate_root), args.output, args.plugin_sha256).run(args.request_id, apply=args.apply)))
