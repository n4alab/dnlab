"""Managed batches consume one immutable original network-service release.

Service readiness is a controlled observer here; packet/host qualification has
its own tests. The coordinator/runtime fences, compilation and journals are real.
"""
from copy import deepcopy
from dataclasses import replace
import yaml
import pytest

from tests.test_runtime_initial_deploy import world, count
from tests.test_native_lifecycle_parser import segmented, configure_segment_runtime
from tests.test_management_service_intent import inputs
from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.services import management_barrier as barrier
from dnlab_multinode.services.management_service_intent import compile_service_intent
from dnlab_multinode.services.config import parse_topology
from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.runtime_operations import RuntimeOperationError, OperationStore
from dnlab_multinode.models.schedule import SchedulePlan, HostAssignment
from dnlab_runtime import management_barrier as local
from dnlab_multinode.services import netsetup
from dnlab_multinode.services.mgmt_network import _expected_network
from dnlab_multinode.models.topology import MgmtConfig
from tests.test_management_prepare import Client as ManagementClient
from tests.test_management_host import plan as kernel_plan


@pytest.fixture
def managed(world, segmented, monkeypatch, request):
    batch, store, clients, engines, members = world
    setting = getattr(request, 'param', 'runtime-fixture')
    single_host = isinstance(setting, dict) and setting.get('single_host', False)
    container_name = setting['container_name'] if isinstance(setting, dict) else setting
    path, hosts, data, state, _ = segmented
    inventory = yaml.safe_load(hosts.read_text())
    inventory['infrastructure']['workers'] = {'worker': {'host': '192.0.2.2', 'ssh_user': 'root', 'ssh_key': '/fixture'}}
    hosts.write_text(yaml.safe_dump(inventory))
    if not single_host:
        data['topology']['nodes']['R2'] = {'kind': 'linux', 'image': 'sha256:' + 'a' * 64, 'management_network': 'default'}
    path.write_text(yaml.safe_dump(data))
    topo, model = resolve(parse_topology(path, hosts_file=hosts, native_management=True))
    topo, model, configs = inputs(topo, model)
    bundle = compile_service_intent(topo, model, configs)
    targets = {}
    metadata={'plans':{},'networks':{}};proofs={}
    placements = [('master', 'R1')] if single_host else [('master', 'R1'), ('worker', 'R2')]
    for host, node in placements:
        engine = engines[host]
        configure_segment_runtime(engine, model['networks'][topo.nodes[node].management_network])
        monkeypatch.setattr(clients[host], 'management_barrier',
                            lambda lab, action, payload, e=engine: local.control(e, lab, action, payload), raising=False)
        target = deepcopy(next(m['target'] for m in members if m['target']['host'] == host))
        target['container_name'] = container_name
        targets[host] = {'target': target, 'journal_id': engine.journal.identity}
        transport=ManagementClient(host,store.directory.parent/('management-'+host),[])
        clients[host].ssh=transport
        definitions={k:_expected_network(replace(topo,mgmt=MgmtConfig(**cfg)),host) for k,cfg in model['networks'].items()}
        kernel=kernel_plan();kernel.update(lab=topo.name,vrf=next(iter(definitions.values()))['vrf'])
        template=deepcopy(kernel['segments']['default']);kernel['segments']={}
        for index,(segment,expected) in enumerate(sorted(definitions.items())):
            kernel['segments'][segment]={**deepcopy(template),'bridge':expected['bridge'],'vxlan':'vm'+str(index),
                'vni':70001+index,'address':expected['ipv4_gateway']+'/'+expected['ipv4_subnet'].split('/')[1]}
        worker=transport.worker(kernel);worker.ensure()
        worker.network_factory(worker,definitions).operate('ensure')
        metadata['plans'][host]=kernel;metadata['networks'][host]=definitions
        proofs[host]={'kernel':netsetup.invoke(transport,'verify-ready',kernel),
                      'networks':netsetup.invoke(transport,'network-verify-ready',kernel,networks=definitions)}
        for expected in definitions.values():
            value=next(v for v in transport.docker.networks.values() if v['Name']==expected['network'])
            engine.backend.docker.networks[expected['network']]=deepcopy(value)
    driver = barrier.Driver(store, batch.factory)
    plan = {'hosts': {host: {} for host in targets}, 'services': bundle}
    driver.prepare('demo', 'management', plan, targets); driver.acquire('demo', 'management')
    driver.begin_provisioning('demo', 'management')
    with store.transaction():
        row = barrier.get(store, 'demo')
        row['services'] = {'phase': 'materialized', 'intent_fingerprint': bundle['fingerprint']}
        row['infrastructure']={'phase':'infrastructure-ready','snapshot':{'infrastructure':metadata},'proofs':proofs}
        barrier.put(store, 'demo', row)
    driver.release('demo', 'management', lambda p, t: {
        'plan_fingerprint': barrier.digest(p),
        'hosts': {h: {'scope': 'management-network-services-v1', 'controlled_observer': True} for h in t}})
    schedule = SchedulePlan(lab_name='demo', assignments={
        host: HostAssignment(host, 'fixture', [node]) for host, node in placements})
    options = {'targets': {host: row['target'] for host, row in targets.items()}}
    return world, topo, schedule, options


def prepare(managed):
    world, topo, schedule, options = managed
    return world[0].prepare_managed_topology(topo, schedule, 'deploy', 'management', **options)


@pytest.mark.parametrize('managed', [None, 'runtime-fixture'], indirect=True)
def test_managed_batch_binds_original_parent_and_reopens_without_replanning(managed):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    prepare(managed)
    saved = batch.get('demo', 'deploy', private=True)['payload']
    original = deepcopy(barrier.get(store, 'demo'))
    assert saved['management_parent']['operation_fingerprint'] == barrier.digest(original)
    assert saved['compilation']['management_plan'] == original['plan']['services']['management_plan']
    for member in saved['original']:
        host = member['target']['host']
        assert member['target'] == original['targets'][host]['target'] == options['targets'][host]
        assert store.get('demo', member['request']['request_id'], private=True)['target'] == member['target']
    assert batch.advance('demo', 'deploy')['phase'] == 'applying'
    fresh = OperationStore(store.directory)
    try:
        resumed = RuntimeInitialDeployment(fresh, batch.factory)
        assert resumed.prepare_managed_topology(topo, schedule, 'deploy', 'management', **options)['phase'] == 'applying'
        assert resumed.advance('demo', 'deploy')['phase'] == 'completed'
        assert set(resumed.bindings('demo', 'deploy')) == {'R1', 'R2'} and count(clients) == 2
        assert resumed.get('demo', 'deploy', private=True)['payload'] == saved
    finally: fresh.close()


@pytest.mark.parametrize('fault', ['missing', 'releasing', 'scope', 'ledger', 'target', 'generation'])
def test_invalid_management_parent_refused_without_workload_intents(managed, fault):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    row = barrier.get(store, 'demo'); key = 'management'
    if fault == 'missing': key = 'other'
    elif fault == 'releasing': row['phase'] = 'releasing'
    elif fault == 'scope':
        row['readiness']['hosts']['master']['scope'] = 'fixture-only'
        row['readiness_fingerprint'] = barrier.digest(row['readiness'])
        for receipt in row['released'].values(): receipt['readiness_fingerprint'] = row['readiness_fingerprint']
    elif fault == 'ledger': options['management_plan'] = {'foreign': True}
    elif fault == 'target': options['targets']['master']['socket_path'] = '/run/foreign.sock'
    elif fault == 'generation': options['lab_generation'] = 99
    with store.transaction(): barrier.put(store, 'demo', row)
    with pytest.raises(RuntimeOperationError):
        batch.prepare_managed_topology(topo, schedule, 'deploy', key, **options)
    assert count(clients) == 0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0] == 0
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0] == 0


def test_parent_change_during_last_preflight_rolls_back_all_children(managed, monkeypatch):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    plan = clients['worker'].plan_node
    def changed(request):
        result = plan(request)
        with store.transaction():
            row = barrier.get(store, 'demo'); row['unexpected_checkpoint'] = True; barrier.put(store, 'demo', row)
        return result
    monkeypatch.setattr(clients['worker'], 'plan_node', changed)
    with pytest.raises(RuntimeOperationError, match='parent changed'): prepare(managed)
    assert count(clients) == 0
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0] == 0


def test_partial_commit_does_not_continue_or_recover_under_another_parent(managed):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    prepare(managed); batch.advance('demo', 'deploy')
    original = deepcopy(barrier.get(store, 'demo')); changed = deepcopy(original); changed['unexpected_checkpoint'] = True
    with store.transaction(): barrier.put(store, 'demo', changed)
    with pytest.raises(RuntimeOperationError, match='parent changed'): batch.advance('demo', 'deploy')
    with pytest.raises(RuntimeOperationError, match='parent changed'): batch.recover('demo', 'deploy')
    assert count(clients) == 1 and not engines['worker'].backend.docker.containers
    assert batch.get('demo', 'deploy')['phase'] == 'recovery_required'
    with store.transaction(): barrier.put(store, 'demo', original)
    batch.recover('demo', 'deploy')
    assert batch.advance('demo', 'deploy')['phase'] == 'completed' and count(clients) == 2


def test_completed_batch_publication_refuses_replaced_parent(managed):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    prepare(managed); batch.advance('demo', 'deploy'); batch.advance('demo', 'deploy')
    with store.transaction():
        row = barrier.get(store, 'demo'); row['unexpected_checkpoint'] = True; barrier.put(store, 'demo', row)
    with pytest.raises(RuntimeOperationError, match='parent changed'): batch.bindings('demo', 'deploy')
    assert count(clients) == 2


def test_parent_binding_cannot_be_dropped_on_retry(managed):
    world, topo, schedule, options = managed
    prepare(managed)
    with pytest.raises(RuntimeOperationError, match='parent cannot be replaced'):
        world[0].prepare_topology(topo, schedule, 'deploy', management_plan=world[0].released_parent('demo', 'management')[1]['plan']['services']['management_plan'], **options)
    assert count(world[2]) == 0


def test_cancellation_retains_parent_and_ordinary_generation_qualified_stop(managed):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    prepare(managed); batch.advance('demo', 'deploy'); batch.cancel('demo', 'deploy')
    assert batch.advance('demo', 'deploy')['phase'] == 'cancelled'
    assert not engines['master'].backend.docker.containers and not engines['worker'].backend.docker.containers
    assert ('signal', 'SIGTERM') in engines['master'].backend.docker.calls
    assert all(('signal', 'SIGKILL') not in e.backend.docker.calls for e in engines.values())


@pytest.mark.parametrize('fault', ['unavailable', 'journal'])
def test_original_host_without_batch_workloads_is_reobserved_before_admission(managed, monkeypatch, fault):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    topo.nodes.pop('R2'); schedule.assignments.pop('worker'); options['targets'].pop('worker')
    def changed(**options):
        if fault == 'unavailable': raise OSError('original idle host unavailable')
        return {'journal_id': 'f' * 32}
    monkeypatch.setattr(clients['worker'], 'qualify_node', changed)
    with pytest.raises((RuntimeOperationError, OSError)):
        batch.prepare_managed_topology(topo, schedule, 'deploy', 'management', **options)
    assert count(clients) == 0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0] == 0
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0] == 0
