#!/usr/bin/env python3
"""Isolated Unix HTTP/IPAM durability canary. Never registers a Docker plugin.

Creates only a private directory, a child provider process and a Unix socket.
The fault is injected at the real directory sync boundary in that child.
"""
import argparse
import hashlib
import http.client
import json
import multiprocessing
from pathlib import Path
import socket
import sys
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[2] / 'multinode'
sys.path.insert(0, str(SOURCE))
from dnlab_multinode import vrf_plugin as plugin


def provider(socket_path, state_path, fault_path):
    class Store(plugin.PluginStore):
        def _sync_directory(self):
            if Path(fault_path).exists():
                raise OSError('isolated directory fsync injection')
            super()._sync_directory()
    with plugin.ThreadingUnixHTTPServer(str(socket_path), plugin.VRFRequestHandler) as server:
        server.store = Store(state_path)
        server.ops = plugin.NetworkOps()
        server.serve_forever(poll_interval=0.05)


def post(socket_path, endpoint, payload):
    connection = http.client.HTTPConnection('localhost', timeout=3)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(3)
    connection.sock.connect(str(socket_path))
    try:
        connection.request('POST', endpoint, json.dumps(payload), {'Content-Type': 'application/json'})
        response = connection.getresponse()
        assert response.status == 200, response.status
        return json.loads(response.read())
    finally:
        connection.close()


def run(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    socket_path = directory / 'provider.sock'; state = directory / 'state.json'; fault = directory / 'fault'
    installed = Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
    before = hashlib.sha256(installed.read_bytes()).hexdigest() if installed.exists() else None
    child = None; checks = []
    def launch():
        process = multiprocessing.get_context('spawn').Process(target=provider, args=(socket_path, state, fault))
        process.start()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not process.is_alive(): raise RuntimeError('provider exited before readiness')
                try:
                    if post(socket_path, '/Plugin.Activate', {})['Implements']:
                        return process
                except (OSError, http.client.HTTPException):
                    time.sleep(0.025)
            raise TimeoutError('provider readiness')
        except BaseException:
            process.terminate(); process.join(5)
            raise
    def stop():
        nonlocal child
        if child is not None:
            child.terminate(); child.join(5)
            assert not child.is_alive()
            child = None
        socket_path.unlink(missing_ok=True)
    pool_request = dict(AddressSpace='dnlab-vrf-local', Pool='198.18.90.0/24', V6=False,
                        Options={'dnlab.tenant': 'isolated-provider-canary'})
    try:
        child = launch(); fault.write_text('injected')
        result = post(socket_path, '/IpamDriver.RequestPool', pool_request)
        assert 'Error' in result and 'fsync injection' in result['Error'], result
        committed = state.read_bytes(); checks.append('uncertain commit returns protocol error')
        other = dict(pool_request, Options={'dnlab.tenant': 'other-lab'})
        assert 'Error' in post(socket_path, '/IpamDriver.RequestPool', other)
        assert state.read_bytes() == committed
        checks.append('shared ledger blocks other lab mutation')
        stop(); child = launch()
        assert 'Error' in post(socket_path, '/IpamDriver.RequestPool', pool_request)
        assert state.read_bytes() == committed
        checks.append('fresh provider process cannot bypass failed durability barrier')
        fault.unlink()
        pool = post(socket_path, '/IpamDriver.RequestPool', pool_request)
        assert 'Error' not in pool and pool['PoolID'], pool
        assert len(json.loads(state.read_bytes())['pools']) == 1
        checks.append('automatic verified retry preserves original pool')
        address = {'PoolID': pool['PoolID'], 'Address': '198.18.90.2'}
        assert post(socket_path, '/IpamDriver.RequestAddress', address)['Address'] == '198.18.90.2/24'
        assert 'already allocated' in post(socket_path, '/IpamDriver.RequestAddress', address)['Error']
        checks.append('duplicate address remains conflict')
        assert post(socket_path, '/IpamDriver.ReleaseAddress', address) == {}
        assert post(socket_path, '/IpamDriver.ReleasePool', {'PoolID': pool['PoolID']}) == {}
        assert post(socket_path, '/IpamDriver.ReleasePool', {'PoolID': pool['PoolID']}) == {}
        assert json.loads(state.read_bytes()) == dict(version=2, pools={}, networks={}, endpoints={})
        checks.append('release and no-op retry leave empty durable ledger')
    finally:
        stop(); fault.unlink(missing_ok=True)
        after = hashlib.sha256(installed.read_bytes()).hexdigest() if installed.exists() else None
        assert after == before, 'installed plugin changed'
    report = dict(status='passed', checks=checks, socket_absent=not socket_path.exists(),
                  child_stopped=True, installed_provider_unchanged=True, installed_sha256=before,
                  source_sha256=hashlib.sha256(Path(plugin.__file__).read_bytes()).hexdigest(),
                  limits=['no power loss simulated', 'no Docker registration or kernel network mutations'])
    (directory / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    directory = args.directory or Path(tempfile.mkdtemp(prefix='dnlab-provider-parent-')) / 'canary'
    print(json.dumps(run(directory), indent=2))
