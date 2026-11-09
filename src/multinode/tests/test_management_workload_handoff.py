"""Compose real coordinator and runtime journals across the admission boundary.

Docker/kernel adapters are in memory; no host resources or workers are touched.
"""
from copy import deepcopy

import pytest

from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.services import management_barrier as coordinator
from dnlab_multinode.services.runtime_operations import OperationStore, RuntimeOperationError
from tests.test_runtime_initial_deploy import world, count
from dnlab_runtime import management_barrier as local
from dnlab_runtime.manifest import Conflict


def fence(world, monkeypatch):
    batch, store, clients, engines, members = world
    targets = {}
    for member in members:
        host = member['target']['host']
        engine = engines[host]
        monkeypatch.setattr(clients[host], 'management_barrier',
                            lambda lab, action, payload, e=engine: local.control(e, lab, action, payload),
                            raising=False)
        targets[host] = {'target': member['target'], 'journal_id': engine.journal.identity}
    driver = coordinator.Driver(store, batch.factory)
    plan = {'hosts': {host: {'segments': ['default', 'blue']} for host in targets}}
    driver.prepare('demo', 'networks', plan, targets)
    driver.acquire('demo', 'networks')
    driver.begin_provisioning('demo', 'networks')
    return driver, targets


def ready(plan, targets):
    # Service packet coverage has separate integration tests. Here this is the
    # qualified observer's attestation; the real two-level fences are exercised.
    return {'plan_fingerprint': coordinator.digest(plan),
            'hosts': {host: {'qualified': 'original-network-services'} for host in targets}}


def test_partial_release_and_coordinator_reopen_never_admit_a_partial_batch(world, monkeypatch):
    batch, store, clients, engines, members = world
    driver, targets = fence(world, monkeypatch)
    release = clients['master'].management_barrier

    def lost(lab, action, payload):
        result = release(lab, action, payload)
        if action == 'release':
            monkeypatch.setattr(clients['master'], 'management_barrier', release)
            raise TimeoutError('lost master release acknowledgement')
        return result

    monkeypatch.setattr(clients['master'], 'management_barrier', lost)
    with pytest.raises(TimeoutError):
        driver.release('demo', 'networks', ready)
    assert local.get(engines['master'].journal, 'demo')['phase'] == 'released'
    assert local.get(engines['worker'].journal, 'demo')['phase'] == 'applying'
    original = deepcopy(coordinator.get(store, 'demo'))
    fresh = OperationStore(store.directory)
    try:
        resumed = RuntimeInitialDeployment(fresh, batch.factory)
        with pytest.raises(Conflict, match='fences workload'):
            resumed.prepare('demo', 'deploy', members)
        # The released host alone would pass its local fence. The original
        # coordinator must still reject admission while the worker is held.
        with pytest.raises(RuntimeOperationError, match='fences coordinator'):
            resumed.prepare('demo', 'master-only', members[:1])
        assert count(clients) == 0
        assert fresh.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0] == 0
        assert fresh.db.execute('SELECT count(*) FROM operations').fetchone()[0] == 0

        def unavailable(*args):
            raise OSError('original network service no longer observable')

        recovery = coordinator.Driver(fresh, batch.factory)
        with pytest.raises(OSError):
            recovery.release('demo', 'networks', unavailable)
        assert coordinator.get(fresh, 'demo')['readiness'] == original['readiness']
        assert local.get(engines['worker'].journal, 'demo')['phase'] == 'applying'
        assert recovery.release('demo', 'networks', ready)['phase'] == 'released'
        resumed.prepare('demo', 'deploy', members)
        resumed.advance('demo', 'deploy')
        assert resumed.advance('demo', 'deploy')['phase'] == 'completed'
        assert set(resumed.bindings('demo', 'deploy')) == {'vd0', 'vd1'}
        assert count(clients) == 2
        assert coordinator.get(fresh, 'demo')['release_checks'] == {'master': 2, 'worker': 1}
    finally:
        fresh.close()


def test_lost_first_spawn_ack_then_reopen_and_cancel_stops_only_original_generation(world, monkeypatch):
    batch, store, clients, engines, members = world
    driver, targets = fence(world, monkeypatch)
    driver.release('demo', 'networks', ready)
    batch.prepare('demo', 'deploy', members)
    submit = clients['master'].submit_node

    def lost(request):
        submit(request)
        monkeypatch.setattr(clients['master'], 'submit_node', submit)
        raise TimeoutError('lost first spawn acknowledgement')

    monkeypatch.setattr(clients['master'], 'submit_node', lost)
    with pytest.raises(TimeoutError):
        batch.advance('demo', 'deploy')
    identity = engines['master'].backend.docker.inspect('drsp-vd0')['Id']
    assert not engines['worker'].backend.docker.containers
    fresh = OperationStore(store.directory)
    try:
        resumed = RuntimeInitialDeployment(fresh, batch.factory)
        resumed.cancel('demo', 'deploy')
        assert resumed.advance('demo', 'deploy')['phase'] == 'cancelled'
        assert count(clients) == 2  # Original start, followed by ordinary stop.
        assert all(not e.backend.docker.containers for e in engines.values())
        assert ('signal', 'SIGTERM') in engines['master'].backend.docker.calls
        assert all(('signal', 'SIGKILL') not in e.backend.docker.calls for e in engines.values())
        stopped = clients['master'].inspect_node('demo', 'vd0')
        assert stopped['workload']['container_id'] == identity
        assert stopped['committed_state'] == 'stopped' and stopped['container_state'] == 'absent'
        assert coordinator.get(fresh, 'demo')['phase'] == 'released'
        assert resumed.advance('demo', 'deploy')['phase'] == 'cancelled'
        assert count(clients) == 2
    finally:
        fresh.close()


def test_new_management_operation_refuses_after_first_batch_spawn(world, monkeypatch):
    batch, store, clients, engines, members = world
    driver, targets = fence(world, monkeypatch)
    driver.release('demo', 'networks', ready)
    batch.prepare('demo', 'deploy', members)
    batch.advance('demo', 'deploy')
    before = deepcopy(coordinator.get(store, 'demo'))
    with pytest.raises(RuntimeOperationError, match='operations concluded'):
        driver.prepare('demo', 'add-green', {'hosts': {host: {} for host in targets}}, targets)
    assert coordinator.get(store, 'demo') == before
    assert count(clients) == 1 and not engines['worker'].backend.docker.containers
    assert batch.advance('demo', 'deploy')['phase'] == 'completed'
    with pytest.raises(Conflict, match='lab cleanup still pending'):
        driver.prepare('demo', 'add-green', {'hosts': {host: {} for host in targets}}, targets)
    assert coordinator.get(store, 'demo') == before
    assert count(clients) == 2
