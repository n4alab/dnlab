"""Initial bindings enter public state only after complete qualified observation."""
from copy import deepcopy

import pytest

from dnlab_multinode.controllers.runtime_publication import publish
from dnlab_multinode.models.state import DeploymentState, HostScheduleState, NodeRuntimeState
from dnlab_multinode.services import state as state_service
from dnlab_multinode.services.runtime_operations import RuntimeOperationError, digest
from tests.test_runtime_initial_deploy import world, count


@pytest.fixture
def publication(world, tmp_path):
    batch, store, clients, engines, members = world
    compiled = {'members': deepcopy(members), 'links': [], 'image_resolutions': {},
                'webui_wishlist': {}, 'webui_allocations': {}}
    compiled['fingerprint'] = digest(compiled)
    batch.prepare('demo', 'deploy', members, compilation=compiled)
    batch.advance('demo', 'deploy'); batch.advance('demo', 'deploy')
    state = DeploymentState(lab_name='demo', topology_file='fixture.yml', runtime_mode='custom', dnlab_deployed=False)
    state.scheduling = {m['target']['host']: HostScheduleState(host='fixture', topology_file='', vd=[m['request']['node_id']]) for m in members}
    state_service.save_state(state, tmp_path)
    load = lambda: state_service.load_state('demo', tmp_path)
    save = lambda value: state_service.save_state(value, tmp_path)
    return world, state, load, save


def test_publishes_original_generation_once_without_finalizing_deploy(publication):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    original = deepcopy(state)
    result = publish(batch, 'demo', 'deploy', state, load, save)
    assert state == original and state.node_runtime == {}
    assert not result.dnlab_deployed and not load().dnlab_deployed
    assert set(result.node_runtime) == {'vd0', 'vd1'} and count(clients) == 2
    for member in batch.members('demo', 'deploy'):
        runtime = result.node_runtime[member['node']]
        assert runtime.runtime_binding == batch.binding(member)
        assert runtime.host == member['target']['host']
    assert publish(batch, 'demo', 'deploy', load(), load, save) == result
    assert count(clients) == 2


def test_last_generation_replaced_does_not_publish_first_node(publication):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    engines['worker'].backend.docker.containers['drsp-vd1']['Id'] = 'foreign'
    before = load().to_dict()
    with pytest.raises(Exception):
        publish(batch, 'demo', 'deploy', state, load, save)
    assert load().to_dict() == before and state.node_runtime == {}
    assert count(clients) == 2


@pytest.mark.parametrize('fault', ['lab', 'backend', 'teardown', 'placement', 'duplicate-placement', 'foreign-node', 'retired-node'])
def test_unqualified_public_context_rejected_without_write(publication, fault):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    before = load().to_dict()
    if fault == 'lab': state.lab_name = 'other'
    elif fault == 'backend': state.runtime_mode = 'per-vd'
    elif fault == 'teardown': state.teardown_requested = True
    elif fault == 'placement': state.scheduling['master'].vd.clear()
    elif fault == 'duplicate-placement': state.scheduling['worker'].vd.append('vd0')
    elif fault == 'foreign-node': state.node_runtime['foreign'] = NodeRuntimeState(node='foreign')
    elif fault == 'retired-node': state.retired_native_nodes['vd0'] = NodeRuntimeState(node='vd0')
    with pytest.raises(RuntimeOperationError):
        publish(batch, 'demo', 'deploy', state, load, save)
    assert load().to_dict() == before and count(clients) == 2


@pytest.mark.parametrize('committed', [False, True])
def test_checkpoint_failure_preserves_generations_and_can_retry_observed_state(publication, committed):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    births = {node: client.inspect_node('demo', node)['workload'] for node, client in zip(('vd0', 'vd1'), clients.values())}
    def failed(value):
        if committed: save(value)
        raise OSError('checkpoint acknowledgement uncertain')
    with pytest.raises(OSError): publish(batch, 'demo', 'deploy', state, load, failed)
    assert state.node_runtime == {} and bool(load().node_runtime) is committed
    result = publish(batch, 'demo', 'deploy', load(), load, save)
    assert set(result.node_runtime) == {'vd0', 'vd1'} and count(clients) == 2
    for node, client in zip(('vd0', 'vd1'), clients.values()):
        assert client.inspect_node('demo', node)['workload'] == births[node]


def test_stale_state_or_closure_during_observation_cannot_be_overwritten(publication, monkeypatch):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    bindings = batch.bindings
    def changed(*args):
        result = bindings(*args)
        fresh = load(); fresh.teardown_requested = True; save(fresh)
        return result
    monkeypatch.setattr(batch, 'bindings', changed)
    with pytest.raises(RuntimeOperationError, match='changed before initial publication'):
        publish(batch, 'demo', 'deploy', state, load, save)
    assert load().teardown_requested and load().node_runtime == {}


def test_replay_does_not_replace_an_existing_public_binding(publication):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    result = publish(batch, 'demo', 'deploy', state, load, save)
    result.node_runtime['vd1'].runtime_binding['container_id'] = 'foreign'
    save(result)
    before = load().to_dict()
    with pytest.raises(RuntimeOperationError, match='differs from original initial generation'):
        publish(batch, 'demo', 'deploy', load(), load, save)
    assert load().to_dict() == before and count(clients) == 2
