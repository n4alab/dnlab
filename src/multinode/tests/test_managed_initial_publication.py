"""Exercise the handoff from released management to durable public VD bindings.

The coordinator, compiler, runtime Engine and public store are real. Packet
readiness and Docker/Linux remain controlled by the managed fixture.
"""
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from tests.test_runtime_management_parent import managed
from tests.test_runtime_initial_deploy import world
from tests.test_native_lifecycle_parser import segmented
from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.controllers.runtime_publication import publish
from dnlab_multinode.models.schedule import SchedulePlan, HostAssignment
from dnlab_multinode.services import management_barrier as barrier, state as states
from dnlab_multinode.services.runtime_operations import OperationStore, RuntimeOperationError


def fixture_state(*args, **kwargs):
    tools = Path(__file__).resolve().parents[2]/'runtime/tools'
    if str(tools) not in sys.path: sys.path.insert(0, str(tools))
    from management_services_smoke import fixture_state as initialize
    return initialize(*args, **kwargs)


def test_fixture_checkpoints_original_placement_without_publishing_nodes(tmp_path):
    schedule = SchedulePlan(lab_name='fixture', vrf_table_id=49999, assignments={
        'master': HostAssignment('master', '192.0.2.1', ['R1']),
        'worker': HostAssignment('worker', '192.0.2.2', ['R2']),
        'idle': HostAssignment('idle', '192.0.2.3', [])})
    model = {'fixture': ['original']}
    value = fixture_state(tmp_path, schedule, management_plan=model,
                          publish_service_inventory=True, managed_initial_batch=True)
    assert value.node_runtime == {} and not value.dnlab_deployed
    assert value.vrf_table_id == schedule.vrf_table_id
    assert {host: (row.host, row.vd) for host, row in value.scheduling.items()} == {
        host: (row.host_ip, row.vd_names) for host, row in schedule.assignments.items()}
    states.save_state(value, tmp_path)
    loaded = states.load_state('fixture', tmp_path)
    assert loaded.to_dict() == value.to_dict()
    assert loaded.node_runtime == {} and not loaded.dnlab_deployed
    schedule.assignments['master'].vd_names.append('later')
    model['fixture'].append('later')
    assert value.scheduling['master'].vd == ['R1']
    assert value.management_plan == {'fixture': ['original']}


@pytest.mark.parametrize('with_http', [False, True])
def test_primitive_service_fixture_keeps_previous_inventory_contract(tmp_path, with_http):
    schedule = SchedulePlan(lab_name='fixture', assignments={
        'master': HostAssignment('master', '192.0.2.1', ['http-vd'])} if with_http else {})
    value = fixture_state(tmp_path, schedule, publish_service_inventory=True)
    assert value.scheduling == {} and value.node_runtime == {} and not value.dnlab_deployed


@pytest.fixture
def handoff(managed, tmp_path):
    world, topo, schedule, options = managed
    batch, store, clients, engines, members = world
    batch.prepare_managed_topology(topo, schedule, 'deploy', 'management', **options)
    while batch.advance('demo', 'deploy')['phase'] != 'completed': pass
    model = batch.get('demo', 'deploy', private=True)['payload']['compilation']['management_plan']
    value = fixture_state(tmp_path, schedule, management_plan=model, publish_service_inventory=True, managed_initial_batch=True)
    states.save_state(value, tmp_path)
    return managed, value, lambda: states.load_state('demo', tmp_path), lambda s: states.save_state(s, tmp_path)


@pytest.mark.parametrize('managed', [None, 'runtime-fixture'], indirect=True)
def test_reopened_managed_batch_publishes_only_original_bindings(handoff):
    (world, topo, schedule, options), value, load, checkpoint = handoff
    batch, store, clients, engines, members = world
    original_parent = deepcopy(barrier.get(store, 'demo'))
    original_payload = deepcopy(batch.get('demo', 'deploy', private=True)['payload'])
    fresh = OperationStore(store.directory)
    try:
        reopened = RuntimeInitialDeployment(fresh, batch.factory)
        result = publish(reopened, 'demo', 'deploy', load(), load, checkpoint)
        assert value.node_runtime == {} and not result.dnlab_deployed
        assert result.to_dict() == load().to_dict()
        assert result.mgmt_ip_reservations == value.mgmt_ip_reservations == {}
        assert result.management_plan == value.management_plan
        assert set(result.node_runtime) == set(topo.nodes)
        for node, runtime in result.node_runtime.items():
            assert runtime.host == schedule.host_for_vd(node)
            assert runtime.runtime_binding == reopened.bindings('demo', 'deploy')[node]
        snapshot = load().to_dict()
        assert publish(reopened, 'demo', 'deploy', load(), load, checkpoint).to_dict() == snapshot
        assert barrier.get(fresh, 'demo') == original_parent
        assert reopened.get('demo', 'deploy', private=True)['payload'] == original_payload
    finally: fresh.close()


def test_changed_management_parent_after_workload_commit_blocks_publication(handoff):
    (world, topo, schedule, options), value, load, checkpoint = handoff
    batch, store, clients, engines, members = world
    original = load().to_dict()
    parent = barrier.get(store, 'demo')
    parent['release_checks']['master'] += 1
    with store.transaction(): barrier.put(store, 'demo', parent)
    with pytest.raises(RuntimeOperationError, match='management parent changed'):
        publish(batch, 'demo', 'deploy', load(), load, checkpoint)
    assert load().to_dict() == original


@pytest.mark.parametrize('fault', ['missing-host', 'moved-node', 'duplicate-node'])
def test_changed_checkpointed_placement_blocks_publication(handoff, fault):
    (world, topo, schedule, options), value, load, checkpoint = handoff
    batch = world[0]
    changed = load()
    if fault == 'missing-host': del changed.scheduling['master']
    if fault == 'moved-node':
        changed.scheduling['master'].vd.remove('R1')
        changed.scheduling['worker'].vd.append('R1')
    if fault == 'duplicate-node': changed.scheduling['master'].vd.append('R2')
    checkpoint(changed)
    original = load().to_dict()
    with pytest.raises(RuntimeOperationError, match='placement'):
        publish(batch, 'demo', 'deploy', load(), load, checkpoint)
    assert load().to_dict() == original and load().node_runtime == {}


@pytest.mark.parametrize('committed', [False, True])
def test_publication_checkpoint_recovery_keeps_original_parent_and_births(handoff, committed):
    (world, topo, schedule, options), value, load, checkpoint = handoff
    batch, store, clients, engines, members = world
    births = deepcopy(batch.bindings('demo', 'deploy'))
    parent = deepcopy(barrier.get(store, 'demo'))
    def uncertain(candidate):
        if committed: checkpoint(candidate)
        raise OSError('publication acknowledgement uncertain')
    with pytest.raises(OSError): publish(batch, 'demo', 'deploy', load(), load, uncertain)
    assert bool(load().node_runtime) is committed
    recovered = publish(batch, 'demo', 'deploy', load(), load, checkpoint)
    assert {node: state.runtime_binding for node, state in recovered.node_runtime.items()} == births
    assert barrier.get(store, 'demo') == parent
    assert not recovered.dnlab_deployed


def http_fixture(managed, tmp_path, *, gate_context=None):
    tools = Path(__file__).resolve().parents[2]/'runtime/tools'
    if str(tools) not in sys.path: sys.path.insert(0, str(tools))
    from managed_http_workload_fixture import ManagedWorkload
    (batch, store, clients, engines, members), topo, schedule, options = managed
    topo = deepcopy(topo); schedule = deepcopy(schedule)
    topo.nodes = {'R1': topo.nodes['R1']}
    client = clients['master']; client.expected_journal_id = engines['master'].journal.identity
    node = topo.nodes['R1']; model = barrier.get(store, 'demo')['plan']['services']['management_plan']
    management = {'network': model['networks'][node.management_network]['network'],
                  'ipv4': node.mgmt_ipv4, 'ipv6': node.mgmt_ipv6, 'mac': node.mgmt_mac}
    fixture = ManagedWorkload(tmp_path, topo, schedule, 'R1', node.image, management,
                              options['targets']['master'], client, store, 'management', gate_context=gate_context)
    fixture.api = SimpleNamespace(inspect=lambda cid:next(
        (deepcopy(v) for v in engines['master'].backend.docker.containers.values() if v['Id']==cid),None))
    return fixture, topo, schedule, options, node, management


@pytest.mark.parametrize('managed', [{'single_host': True, 'container_name': None}], indirect=True)
def test_managed_http_gate_context_precedes_spawn_and_is_immutable(managed, tmp_path):
    context = dict(gate_id='gate', lab_id='demo', host_id='master', coordinator_id='only',
                   boot_id='synthetic', window_id='window', image_build_hold_sha256='f' * 64)
    fixture, topo, schedule, options, node, management = http_fixture(managed, tmp_path, gate_context=context)
    assert fixture.record['gate_context'] == context and fixture.record['phase'] == 'planned'
    assert not fixture.store.contains('demo', fixture.start['request_id'])
    before = fixture.path.read_bytes()
    from managed_http_workload_fixture import ManagedWorkload
    with pytest.raises(ValueError, match='original gate context'):
        ManagedWorkload(tmp_path, topo, schedule, 'R1', node.image, management,
            options['targets']['master'], fixture.runtime, fixture.store, 'management',
            gate_context={**context, 'window_id': 'foreign'})
    assert fixture.path.read_bytes() == before


@pytest.mark.parametrize('managed', [{'single_host': True, 'container_name': None}], indirect=True)
def test_managed_http_fixture_uses_compiled_request_without_primitive_adoption(managed, tmp_path):
    (batch, store, clients, engines, members), _, _, _ = managed
    fixture, topo, schedule, options, node, management = http_fixture(managed, tmp_path)
    from managed_http_workload_fixture import ManagedWorkload
    client = clients['master']
    assert not store.contains('demo', fixture.start['request_id'])
    fixture.drive(fixture.start)
    payload = fixture.batch.get('demo', fixture.key, private=True)['payload']
    assert payload['original'] == [{'request': fixture.start, 'target': options['targets']['master']}]
    assert payload['management_parent'] == fixture.record['admission']['parent']
    assert fixture.start['spec']['container_name'] != 'drsp-http-' + fixture.record['nonce'][:12]
    replay = ManagedWorkload(tmp_path, topo, schedule, 'R1', node.image, management,
                             options['targets']['master'], client, store, 'management')
    assert replay.drive(replay.start)['phase'] == 'completed'
    assert len(clients['master'].calls) > 0
    assert sum(call[0] == 'submit' for call in clients['master'].calls) == 1
    fixture.cleanup()
    assert fixture.record['cleanup_verified']
    assert client.inspect_node('demo', 'R1')['container_state'] == 'absent'


@pytest.mark.parametrize('managed', [{'single_host': True, 'container_name': None}], indirect=True)
def test_managed_http_fixture_cancels_prepared_batch_without_spawning(managed, tmp_path):
    fixture, topo, schedule, options, node, management = http_fixture(managed, tmp_path)
    fixture.batch.prepare_managed_topology(topo, schedule, fixture.key, 'management', **fixture.options)
    fixture.cleanup()
    assert fixture.batch.get('demo', fixture.key)['phase'] == 'cancelled'
    assert fixture.record['cleanup_verified']
    assert fixture.record['cancelled_absence']['committed_state'] == 'absent'
    fixture.cleanup()
    assert fixture.record['cleanup_verified']
    assert not any(call[0] == 'submit' for call in managed[0][2]['master'].calls)


@pytest.mark.parametrize('fault', ['container', 'pending', 'journal', 'request', 'node', 'lab', 'revision',
                                  'birth', 'incomplete', 'mutation', 'affected', 'plan_revision', 'unavailable'])
@pytest.mark.parametrize('managed', [{'single_host': True, 'container_name': None}], indirect=True)
def test_cancelled_fixture_requires_complete_original_absence_observation(managed, tmp_path, monkeypatch, fault):
    fixture, topo, schedule, options, node, management = http_fixture(managed, tmp_path)
    fixture.batch.prepare_managed_topology(topo, schedule, fixture.key, 'management', **fixture.options)
    fixture.cleanup()
    assert fixture.record['cleanup_verified']
    client = managed[0][2]['master']; original = client.plan_node
    def changed(request):
        if fault == 'unavailable': raise OSError('observation unavailable')
        result = deepcopy(original(request)); view = result['node_preflight']
        if fault == 'container': view.update(container_state='running', container_id='foreign')
        if fault == 'pending': view['pending_operation_id'] = 'foreign'
        if fault == 'journal': view['journal_id'] = 'f'*32
        if fault == 'request': view['request_fingerprint'] = 'f'*64
        if fault == 'node': view['node_id'] = 'foreign'
        if fault == 'lab': view['lab_id'] = 'foreign'
        if fault == 'revision': view['revision'] = 1
        if fault == 'birth': view['workload_phase'] = 'creating'
        if fault == 'incomplete': del view['container_id']
        if fault == 'mutation': result['mutations_performed'] = True
        if fault == 'affected': result['affected_nodes'] = ['foreign']
        if fault == 'plan_revision': result['expected_revision'] = 1
        return result
    monkeypatch.setattr(client, 'plan_node', changed)
    with pytest.raises((RuntimeError, OSError)):
        fixture.cleanup()
    assert fixture.record['phase'] == 'cleanup_pending' and not fixture.record['cleanup_verified']
    assert fixture.batch.get('demo', fixture.key)['phase'] == 'cancelled'
    assert not any(call[0] == 'submit' for call in client.calls)


@pytest.mark.parametrize('managed', [{'single_host': True, 'container_name': None}], indirect=True)
def test_managed_http_fixture_refuses_changed_parent_before_admission(managed, tmp_path):
    fixture, topo, schedule, options, node, management = http_fixture(managed, tmp_path)
    store = managed[0][1]
    parent = barrier.get(store, 'demo'); parent['release_checks']['master'] += 1
    with store.transaction(): barrier.put(store, 'demo', parent)
    with pytest.raises(RuntimeError, match='original parent differs'): fixture.drive(fixture.start)
    assert not store.contains('demo', fixture.start['request_id'])


def test_managed_http_fixture_refuses_multi_host_parent_without_saved_intent(managed, tmp_path):
    with pytest.raises(RuntimeError, match='single-host original management parent'):
        http_fixture(managed, tmp_path)
    assert not (tmp_path/'managed-http-workload.json').exists()
