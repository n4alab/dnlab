#!/usr/bin/env python3
"""Opt-in local VXLAN/TC gate; four isolated namespaces, no Docker or NOS."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.backend import Linux
from dnlab_runtime.journal import Journal
from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.vxlan import VxlanLinux, VxlanManager


class NamespaceLinux(Linux):
    def __init__(self, name):
        self.name = name
        self.commands = []
        self.inject_lost_redirect = False
        self.initial_context = self.network_identity()

    def network_identity(self):
        info = os.stat('/var/run/netns/' + self.name)
        boot = super().network_identity()['boot_id']
        return {'boot_id': boot, 'device': info.st_dev, 'inode': info.st_ino}

    def run(self, argv, **kwargs):
        self.commands.append(argv)
        from dnlab_runtime.manifest import Conflict
        fd = os.open('/var/run/netns/' + self.name, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (self.initial_context['device'], self.initial_context['inode']):
                raise Conflict('fixture namespace mount was replaced')
            inherited = kwargs.pop('pass_fds', ())
            result = super().run(['nsenter', f'--net=/proc/self/fd/{fd}', '--', *argv],
                                 pass_fds=(*inherited, fd), **kwargs)
        finally:
            os.close(fd)
        if self.inject_lost_redirect and argv[:3] == ['tc', 'filter', 'add'] and argv[4].startswith('rt-'):
            self.inject_lost_redirect = False
            raise RuntimeError('injected lost source-redirect response')
        return result


def command(argv, *, check=True):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(f'{argv!r}: rc={result.returncode}: {result.stderr}')
    return result


def ip(ns, *args):
    return command(['ip', '-n', ns, *args]).stdout


def ping(ns, destination, *, expected=True):
    result = command(['ip', 'netns', 'exec', ns, 'ping', '-n', '-I', 'eth0', '-c', '2', '-W', '1', '-s', '1372', destination], check=False)
    if (result.returncode == 0) != expected:
        raise RuntimeError(f'ICMP expectation failed: {result.stdout} {result.stderr}')
    return {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


RECEIVE = '''import json,socket,sys,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('eth0',0));s.settimeout(5)
print('ready',flush=True)
nonce=bytes.fromhex(sys.argv[1]);deadline=time.monotonic()+5
while time.monotonic()<deadline:
 frame=s.recv(2048)
 if frame[14:14+len(nonce)]==nonce:
  print(json.dumps({'destination':frame[:6].hex(),'ethertype':frame[12:14].hex(),'payload':frame[14:14+len(nonce)].hex()}),flush=True);sys.exit(0)
raise RuntimeError('frame not received')
'''
SEND = '''import socket,sys,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('eth0',0))
mac=bytes.fromhex(open('/sys/class/net/eth0/address').read().strip().replace(':',''))
frame=bytes.fromhex(sys.argv[1])+mac+bytes.fromhex(sys.argv[2])+bytes.fromhex(sys.argv[3])
for _ in range(3):s.send(frame);time.sleep(.05)
'''


def frame_probe(source, target, destination, ethertype):
    nonce = uuid.uuid4().hex
    receiver = subprocess.Popen(['ip', 'netns', 'exec', target, sys.executable, '-c', RECEIVE, nonce], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Receiver has a finite socket timeout; reading readiness precedes send.
        if receiver.stdout.readline().strip() != 'ready':
            raise RuntimeError('frame receiver not ready')
        command(['ip', 'netns', 'exec', source, sys.executable, '-c', SEND, destination, ethertype, nonce])
        out, err = receiver.communicate(timeout=7)
        if receiver.returncode:
            raise RuntimeError(f'frame receiver failed: {out} {err}')
        proof = json.loads(out)
        assert proof == {'destination': destination, 'ethertype': ethertype, 'payload': nonce}
        return proof
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.wait(timeout=5)


def run(*, crash_recovery=False, affinity=False, worker_image=None):
    root = Path(tempfile.mkdtemp(prefix='dnlab-vxlan-traffic-'))
    os.chmod(root, 0o700)
    token = uuid.uuid4().hex[:8]
    names = {key: f'drsp-{key}-{token}' for key in ('a', 'b', 'ga', 'gb')}
    created = []
    report = {'scope': 'single-host-isolated-namespace-underlay', 'namespaces': names,
              'cross_host_qualified': False, 'nos_qualified': False}
    journal = None
    try:
        baseline = command(['ip', 'netns', 'list']).stdout
        for name in names.values():
            assert name not in baseline
            command(['ip', 'netns', 'add', name])
            created.append(name)
            ip(name, 'link', 'set', 'lo', 'up')
        ip(names['a'], 'link', 'add', 'underlay0', 'type', 'veth', 'peer', 'name', 'underlay0', 'netns', names['b'])
        for side, address in [('a', '198.18.201.1/24'), ('b', '198.18.201.2/24')]:
            ip(names[side], 'address', 'add', address, 'dev', 'underlay0')
            ip(names[side], 'link', 'set', 'underlay0', 'up')
        journal = Journal(root / 'journal')
        executors, managers, identities, sources = {}, {}, {}, {}
        for side, guest, endpoint, address in [('a', 'ga', 'rt-0123456789ab', '198.19.100.1/24'), ('b', 'gb', 'rt-0123456789cd', '198.19.100.2/24')]:
            alias = 'dnlab-runtime:fixture-' + token + '-' + side
            ip(names[side], 'link', 'add', endpoint, 'alias', alias, 'mtu', '1450', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', names[guest])
            # On the qualified iproute2/kernel path, veth creation accepts alias
            # but does not retain it. This disposable fixture establishes it
            # explicitly and verifies the same peer identity before proceeding.
            before_alias = json.loads(ip(names[side], '-j', '-d', 'link', 'show', 'dev', endpoint))[0]
            ip(names[side], 'link', 'set', 'dev', endpoint, 'alias', alias)
            after_alias = json.loads(ip(names[side], '-j', '-d', 'link', 'show', 'dev', endpoint))[0]
            assert after_alias.get('ifalias') == alias
            assert all(before_alias.get(key) == after_alias.get(key)
                       for key in ('ifindex', 'address', 'link_index', 'link_netnsid'))
            report.setdefault('bootstrap', {})[side] = {'before_alias': before_alias, 'after_alias': after_alias}
            ip(names[side], 'link', 'set', endpoint, 'up')
            ip(names[guest], 'link', 'set', 'eth0', 'mtu', '1450', 'up')
            ip(names[guest], 'address', 'add', address, 'dev', 'eth0')
            executor = NamespaceLinux(names[side])
            executors[side] = executor
            linux = VxlanLinux(executor)
            managers[side] = VxlanManager(journal, linux)
            identities[side] = VxlanIdentity('fixture-' + token, 'cross-link', endpoint, 3011)
            sources[side] = next(x for x in linux.links() if x['ifname'] == endpoint)
        report['qualified_sources'] = sources
        (root / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        os.chmod(root / 'report.json', 0o600)
        def create(side):
            return managers[side].create(identities[side], source=sources[side], underlay='underlay0',
                local='198.18.201.1' if side == 'a' else '198.18.201.2',
                remote='198.18.201.2' if side == 'a' else '198.18.201.1', mtu=1450)
        for side in ('a', 'b'):
            create(side)
        before = {side: managers[side].row(identities[side].digest)['payload'] for side in ('a', 'b')}
        report['initial'] = before
        report['icmp'] = {'a_to_b': ping(names['ga'], '198.19.100.2'), 'b_to_a': ping(names['gb'], '198.19.100.1')}
        report['ethernet'] = {}
        for source, target in [('ga', 'gb'), ('gb', 'ga')]:
            for protocol, dest, ether in [('lldp', '0180c200000e', '88cc'), ('lacp', '0180c2000002', '8809')]:
                report['ethernet'][source + '-' + protocol] = frame_probe(names[source], names[target], dest, ether)
        for side in ('a', 'b'):
            count = len(executors[side].commands)
            create(side)
            # Read-only verification is allowed; no mutating command on retry.
            assert all('-j' in cmd for cmd in executors[side].commands[count:])
        managers['a'].delete(identities['a'])
        report['after_one_side_delete'] = ping(names['ga'], '198.19.100.2', expected=False)
        managers['b'].verify(identities['b'], before['b'])
        create('a')
        report['recreate'] = ping(names['ga'], '198.19.100.2')
        managers['a'].delete(identities['a'])
        executors['a'].inject_lost_redirect = True
        try:
            create('a')
        except RuntimeError as error:
            assert str(error) == 'injected lost source-redirect response'
        else:
            raise AssertionError('fault was not injected')
        assert managers['a'].row(identities['a'].digest)['phase'] == 'cleaned'
        assert not managers['a'].linux.filters(identities['a'].host_endpoint)
        managers['b'].verify(identities['b'], before['b'])
        report['lost_response_cleanup'] = True
        if affinity:
            from vxlan_affinity_probe import probe as affinity_probe
            affinity_probe(root, report, names, created, managers, identities, create, before['b'], ip, command, NamespaceLinux)
            create('a')
            report['after_affinity_icmp'] = ping(names['ga'], '198.19.100.2')
            managers['a'].delete(identities['a'])
        if crash_recovery:
            from vxlan_crash_probe import probe
            probe(root, report, names, journal, managers, identities, sources, before['b'], worker_image=worker_image)
            create('a')
            report['after_crash_recovery_icmp'] = ping(names['ga'], '198.19.100.2')
        for side in ('a', 'b'):
            managers[side].delete(identities[side])
            current = next(x for x in managers[side].linux.links() if x['ifname'] == identities[side].host_endpoint)
            from dnlab_runtime.vxlan import link_signature
            assert link_signature(current) == link_signature(sources[side])
            assert not managers[side].linux.filters(identities[side].host_endpoint)
            assert not any(x['kind'] in ('ingress', 'clsact') for x in managers[side].linux.qdiscs(identities[side].host_endpoint))
            assert identities[side].resolve(managers[side].linux.links()) is None
        report['owned_cleanup'] = True
        report['passed'] = True
    except Exception as error:
        report['passed'] = False
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        if journal:
            journal.close()
        cleanup = []
        for name in reversed(created):
            result = command(['ip', 'netns', 'delete', name], check=False)
            cleanup.append({'name': name, 'returncode': result.returncode, 'stderr': result.stderr})
        remaining = command(['ip', 'netns', 'list']).stdout
        report['cleanup'] = {'operations': cleanup, 'all_absent': all(name not in remaining for name in created)}
        (root / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        os.chmod(root / 'report.json', 0o600)
        print(json.dumps({'root': str(root), 'passed': report.get('passed'), 'error': report.get('error'), 'cleanup': report['cleanup']}))
    return 0 if report.get('passed') and report['cleanup']['all_absent'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--crash-recovery', action='store_true')
    parser.add_argument('--affinity', action='store_true')
    parser.add_argument('--worker-image')
    args = parser.parse_args()
    if args.worker_image and not args.crash_recovery:
        parser.error('--worker-image requires --crash-recovery')
    if not args.execute:
        print(json.dumps({'execute': False, 'scope': 'four isolated local namespaces', 'checks': ['ICMP MTU1450', 'LLDP/LACP frames both directions', 'idempotency', 'lost-response cleanup']}))
    else:
        sys.exit(run(crash_recovery=args.crash_recovery, affinity=args.affinity, worker_image=args.worker_image))
