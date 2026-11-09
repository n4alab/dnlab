"""Deletion-only post-boot recovery; real journals and simulated Engine/plugin."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import json
import os
import socket
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from postboot_network_retirement import Retirement, RetirementError, GateSources, read
import postboot_network_retirement as module
from tests.test_management_network_host import fixture as management
from tests.test_jumphost_network_guard import CONFIG
from dnlab_multinode.services.jumphost_network_host import Worker as ExternalWorker
from dnlab_multinode.services.management_host import signature


@pytest.fixture
def world(management, tmp_path):
    host, worker, docker, guard = management
    guard.operate('ensure')
    old = worker.read(); root = tmp_path / 'source'; root.mkdir(mode=0o700)
    output_dir = tmp_path / 'retirement'; output_dir.mkdir(mode=0o700)
    ext = {'config': deepcopy(CONFIG), 'context': deepcopy(old['context']), 'id': 'a' * 64,
           'nonce': 'b' * 32, 'phase': 'active'}
    external = ExternalWorker(CONFIG, directory=root / 'external')
    value = external.desired(ext); value.pop('CheckDuplicate')
    value.update(Id=ext['id'], Scope='local', ConfigOnly=False, Containers={})
    docker.networks[ext['id']] = value
    links = [dict(ifname=CONFIG['bridge'], ifindex=100, address='02:42:00:00:00:02',
                  ifalias='', linkinfo={'info_kind': 'bridge'})]
    scope = {'boot_id': 'new-boot', 'device': 1, 'inode': 3}
    class Sources:
        def __init__(self):
            self.root = root
            self.value = {'lab': old['plan']['lab'], 'source_hashes': {'original': 'b' * 64},
                          'barrier_hash': 'c' * 64, 'runtime_id': 'd' * 32, 'runtime_socket': None,
                          'management': old, 'external': ext, 'dependencies': [('e' * 64, 'original-helper')],
                          'forbidden': sorted(old['resources']),
                          'aliases': [v['identity']['ifalias'] for v in old['resources'].values()]}
        @contextmanager
        def locked(self): yield
        def snapshot(self): return deepcopy(self.value)
    sources = Sources(); containers = {}
    docker.inventory = lambda: deepcopy(list(docker.networks.values()))
    docker.container = lambda name: deepcopy(containers.get(name))
    delete = docker.delete
    def remove(identity):
        try: delete(identity)
        finally:
            if identity == ext['id'] and identity not in docker.networks: links.clear()
    docker.delete = remove; docker.calls.clear()
    retirement = Retirement(sources, output_dir / 'operation.json', 'a' * 64, docker=docker, plugin_code=lambda: 'a' * 64,
                            host_context=lambda: deepcopy(scope), links=lambda: deepcopy(links),
                            addresses=lambda name: [{'addr_info': [{'family': 'inet', 'local': CONFIG['gateway'], 'prefixlen': 24}]}],
                            plugin=lambda: deepcopy(docker.plugin), firewall=lambda worker: {'iptables': [], 'ip6tables': []})
    return retirement, sources, docker, links, scope, containers, worker


def test_preflight_and_idempotent_retirement_preserve_original_journal(world):
    op, sources, docker, links, scope, containers, worker = world
    before = worker.path.read_bytes()
    assert op.run('retire')['mutations_performed'] is False
    assert not op.output.exists() and not docker.calls
    assert op.run('retire', apply=True)['cleanup_verified'] is True
    assert not docker.networks and not links
    assert worker.path.read_bytes() == before
    assert worker.load()['context']['boot_id'] != scope['boot_id']
    calls = deepcopy(docker.calls)
    assert op.run('retire', apply=True)['phase'] == 'cleaned' and docker.calls == calls
    assert all(action == 'delete' for action, payload in docker.calls)


@pytest.mark.parametrize('fault', ['management-driver', 'management-labels', 'management-ipam', 'endpoint',
                                  'allocation', 'foreign-kernel-name', 'renamed-alias', 'helper',
                                  'external-driver', 'external-labels', 'external-ipam', 'external-endpoint',
                                  'external-port', 'same-boot', 'other-bridge-owner'])
def test_complete_preflight_refuses_conflict_before_first_delete(world, fault):
    op, sources, docker, links, scope, containers, worker = world
    management = next(v for v in docker.networks.values() if v['Id'] != 'a' * 64)
    external = docker.networks['a' * 64]
    if fault == 'management-driver': management['Driver'] = 'bridge'
    elif fault == 'management-labels': management['Labels'] = {}
    elif fault == 'management-ipam': management['IPAM']['Config'][0]['Gateway'] = '10.1.0.99'
    elif fault == 'endpoint': management['Containers']['foreign'] = {}
    elif fault == 'allocation': next(iter(docker.plugin['pools'].values()))['allocated'] = ['10.1.0.2']
    elif fault == 'foreign-kernel-name': links.append({'ifname': sources.value['forbidden'][0]})
    elif fault == 'renamed-alias': links.append({'ifname': 'foreign', 'ifalias': sources.value['aliases'][0]})
    elif fault == 'helper': containers['original-helper'] = {'Id': 'foreign'}
    elif fault == 'external-driver': external['Driver'] = 'foreign'
    elif fault == 'external-labels': external['Labels'] = {}
    elif fault == 'external-ipam': external['IPAM']['Config'][0]['Subnet'] = '192.0.2.0/24'
    elif fault == 'external-endpoint': external['Containers']['foreign'] = {}
    elif fault == 'external-port': links.append({'ifname': 'foreign-port', 'master': 100})
    elif fault == 'same-boot': scope['boot_id'] = sources.value['management']['context']['boot_id']
    elif fault == 'other-bridge-owner':
        docker.networks['f' * 64] = {'Id': 'f' * 64, 'Name': 'foreign', 'Options': {'com.docker.network.bridge.name': CONFIG['bridge']}}
    before = worker.path.read_bytes()
    with pytest.raises(Exception): op.run('retire', apply=True)
    assert not docker.calls and worker.path.read_bytes() == before


def test_only_original_gateway_allocations_are_admissible(world):
    op, sources, docker, links, scope, containers, worker = world
    row = next(iter(sources.value['management']['networks'].values()))
    for pool in docker.plugin['pools'].values(): pool['allocated'] = [row['expected']['ipv6_gateway' if pool['v6'] else 'ipv4_gateway']]
    assert op.run('retire', apply=True)['phase'] == 'cleaned'


def test_remaining_old_firewall_rules_block_all_network_deletions(world):
    op, sources, docker, links, scope, containers, worker = world
    op.firewall = lambda current: {'iptables': current.rules(), 'ip6tables': []}
    with pytest.raises(RetirementError, match='firewall recovery'): op.run('retire', apply=True)
    assert not docker.calls


def test_failed_checkpoint_never_sends_delete_and_replay_uses_same_sources(world, monkeypatch):
    op, sources, docker, links, scope, containers, worker = world
    save = op.save
    monkeypatch.setattr(op, 'save', lambda _: (_ for _ in ()).throw(OSError('save failed')))
    with pytest.raises(OSError): op.run('retire', apply=True)
    assert not docker.calls
    monkeypatch.setattr(op, 'save', save)
    assert op.run('retire', apply=True)['phase'] == 'cleaned'


def test_lost_delete_reply_qualifies_absence_without_resending(world):
    op, sources, docker, links, scope, containers, worker = world
    docker.after = 'delete'
    assert op.run('retire', apply=True)['phase'] == 'cleaned'
    ids = [identity for action, identity in docker.calls]
    assert len(ids) == len(set(ids)) == 2


def test_crash_after_delete_before_checkpoint_recovers_without_second_delete(world, monkeypatch):
    op, sources, docker, links, scope, containers, worker = world
    save = op.save; failed = []
    def lost(value):
        if not failed and 'cleaned' in value['resources'].values():
            failed.append(True); raise OSError('crash before completion checkpoint')
        return save(value)
    monkeypatch.setattr(op, 'save', lost)
    with pytest.raises(OSError): op.run('retire', apply=True)
    assert 'deleting' in read(op.output)[0]['resources'].values()
    monkeypatch.setattr(op, 'save', save)
    assert op.run('retire', apply=True)['phase'] == 'cleaned'
    assert len(docker.calls) == len({identity for action, identity in docker.calls}) == 2


def test_uncertain_directory_sync_never_authorizes_delete_before_retry(world, monkeypatch):
    op, sources, docker, links, scope, containers, worker = world
    sync = module.sync
    def fail(directory):
        if directory == op.output.parent: raise OSError('directory sync failed')
        sync(directory)
    monkeypatch.setattr(module, 'sync', fail)
    with pytest.raises(OSError): op.run('retire', apply=True)
    assert not docker.calls
    monkeypatch.setattr(module, 'sync', sync)
    assert op.run('retire', apply=True)['phase'] == 'cleaned'


def test_unrelated_docker_plugin_and_kernel_resources_are_preserved(world):
    op, sources, docker, links, scope, containers, worker = world
    foreign = deepcopy(docker.networks['a' * 64]); foreign.update(Id='f' * 64, Name='unrelated')
    foreign['Options']['com.docker.network.bridge.name'] = 'br-unrelated'
    docker.networks[foreign['Id']] = foreign
    docker.plugin['networks'][foreign['Id']] = {'bridge': 'br-unrelated'}
    pool = {'tenant': 'unrelated', 'pool': '192.0.2.0/24', 'allocated': ['192.0.2.2']}
    docker.plugin['pools']['foreign'] = deepcopy(pool)
    # The fake Docker bridge removal removes only the original bridge.
    delete = docker.delete
    def keep_other(identity):
        others = [deepcopy(v) for v in links if v['ifname'] == 'br-unrelated']
        delete(identity)
        if identity == 'a' * 64: links.extend(others)
    docker.delete = keep_other
    foreign_link = {'ifname': 'br-unrelated', 'ifindex': 999, 'linkinfo': {'info_kind': 'bridge'}}
    links.append(deepcopy(foreign_link))
    assert op.run('retire', apply=True)['phase'] == 'cleaned'
    assert docker.networks == {foreign['Id']: foreign}
    assert docker.plugin['networks'] == {foreign['Id']: {'bridge': 'br-unrelated'}}
    assert docker.plugin['pools'] == {'foreign': pool}
    assert links == [foreign_link]


def test_delete_failure_preserves_pending_intent_until_explicit_retry(world):
    op, sources, docker, links, scope, containers, worker = world
    delete = docker.delete; attempted = []
    def fail(identity): attempted.append(identity); raise OSError('transport unknown')
    docker.delete = fail
    with pytest.raises(OSError): op.run('retire', apply=True)
    assert len(attempted) == 1 and len(docker.networks) == 2
    assert 'deleting' in read(op.output)[0]['resources'].values()
    docker.delete = delete
    assert op.run('retire', apply=True)['phase'] == 'cleaned'


def test_replacement_after_delete_is_preserved_and_never_retried(world):
    op, sources, docker, links, scope, containers, worker = world
    delete = docker.delete
    def replace(identity):
        previous = deepcopy(docker.networks[identity]); delete(identity)
        previous['Id'] = 'f' * 64; docker.networks['f' * 64] = previous
        raise OSError('lost reply and foreign replacement')
    docker.delete = replace
    with pytest.raises(Exception): op.run('retire', apply=True)
    count = len(docker.calls)
    with pytest.raises(Exception): op.run('retire', apply=True)
    assert 'f' * 64 in docker.networks and len(docker.calls) == count


@pytest.mark.parametrize('fault', ['source', 'boot', 'bridge', 'request', 'output', 'plugin'])
def test_pending_retirement_is_bound_to_sources_boot_bridge_and_request(world, fault):
    op, sources, docker, links, scope, containers, worker = world
    delete = docker.delete
    docker.delete = lambda _: (_ for _ in ()).throw(OSError('pending'))
    with pytest.raises(OSError): op.run('retire', apply=True)
    docker.delete = delete; before = deepcopy(docker.calls); request = 'retire'
    if fault == 'source': sources.value['source_hashes']['original'] = 'f' * 64
    elif fault == 'boot': scope['boot_id'] = 'another-boot'
    elif fault == 'bridge': links[0]['ifindex'] = 999
    elif fault == 'request': request = 'other'
    elif fault == 'plugin': op.expected_plugin_hash = 'f' * 64
    elif fault == 'output':
        new = op.output.parent / 'other'; new.mkdir(mode=0o700); op.output = new / 'operation.json'
    with pytest.raises(Exception): op.run(request, apply=True)
    assert docker.calls == before and len(docker.networks) == 2


def test_stale_private_socket_is_qualified_without_removal(tmp_path):
    path = tmp_path / 'runtime.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path)); os.chmod(path, 0o600)
    before = path.lstat()
    proof = GateSources.offline_socket(path)
    assert proof['listener_absence'] == 'ECONNREFUSED'
    assert proof['inode'] == before.st_ino and path.lstat().st_ino == before.st_ino


def test_live_socket_or_regular_file_never_proves_runtime_offline(tmp_path):
    path = tmp_path / 'runtime.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path)); os.chmod(path, 0o600); server.listen(1)
        with pytest.raises(RetirementError, match='still accepts'): GateSources.offline_socket(path)
    path.unlink(); path.write_text('foreign'); path.chmod(0o600)
    with pytest.raises(RetirementError, match='ownership/type'): GateSources.offline_socket(path)
