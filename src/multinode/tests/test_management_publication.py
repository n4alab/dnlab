"""Publish original helpers without allocating, replacing or inferring readiness."""
from copy import deepcopy
import pytest

from dnlab_multinode.controllers.management_publication import publish
from dnlab_multinode.services import management_service_runtime as services, management_barrier as barrier
from dnlab_multinode.services import state as state_service
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_management_service_readiness import qualified
from tests.test_management_prepare import setup


@pytest.fixture
def released(qualified, tmp_path):
    context, calls, fault = qualified
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save = context
    controller.release_network_services('probe', 'demo', state, clients)
    state.dnlab_deployed = False
    state_service.save_state(state, tmp_path)
    load = lambda: state_service.load_state('demo', tmp_path)
    checkpoint = lambda value: state_service.save_state(value, tmp_path)
    return context, load, checkpoint


def invoke(released, checkpoint=None, clients=None):
    context, load, save = released
    topo,state,ips,original_clients,runtimes,targets,store,controller,schedule,registry,events,oldsave = context
    return publish(controller, 'probe', 'demo', load(), original_clients if clients is None else clients,
                   load, checkpoint or save)


def test_original_service_inventory_published_after_release_and_replay_is_readonly(released, monkeypatch):
    context, load, save = released
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,oldsave = context
    original = deepcopy(barrier.get(store, 'demo')); calls = []
    previous = services.invoke
    def observed(client, bundle, action):
        assert action == 'observe'
        calls.append(action); return previous(client, bundle, action)
    monkeypatch.setattr(services, 'invoke', observed)
    result = invoke(released)
    jump = original['plan']['services']['jumphost']; dns = original['plan']['services']['dns']['config']
    assert result.jumphost.generation == jump['generation']
    assert result.jumphost.password == jump['env']['JUMPHOST_PASSWORD']
    assert result.jumphost.ssh_port == jump['port'] and result.jumphost.ssh_bind_ip == jump['bind_ip']
    assert result.dns.container == dns['name'] and result.dns.generation == dns['generation']
    assert result.dns.hosts_file.endswith('-' + original['services']['receipt']['dns']['nonce'] + '/hosts')
    assert not result.dnlab_deployed and result.node_runtime == {}
    assert state.jumphost is None and state.dns is None
    assert invoke(released).to_dict() == result.to_dict()
    assert calls == ['observe'] * 4 and barrier.get(store, 'demo') == original


@pytest.mark.parametrize('field', ['jumphost', 'dns', 'management_networks', 'external_network_id', 'mutations_performed'])
def test_replacement_or_incomplete_observation_never_writes_public_inventory(released, monkeypatch, field):
    context, load, save = released
    before = load().to_dict(); previous = services.invoke
    def changed(client, bundle, action):
        value = deepcopy(previous(client, bundle, action))
        if field in ('jumphost', 'dns'): value[field]['container_id'] = 'f' * 64
        elif field == 'management_networks': value[field]['blue'] = 'f' * 64
        elif field == 'mutations_performed': value[field] = True
        else: value[field] = 'f' * 64
        return value
    monkeypatch.setattr(services, 'invoke', changed)
    with pytest.raises(RuntimeOperationError, match='generations differ'): invoke(released)
    assert load().to_dict() == before


@pytest.mark.parametrize('committed', [False, True])
def test_uncertain_publication_checkpoint_retries_same_original_services(released, committed):
    context, load, save = released
    store = context[6]; original = deepcopy(barrier.get(store, 'demo'))
    def fail(value):
        if committed: save(value)
        raise OSError('checkpoint acknowledgement uncertain')
    with pytest.raises(OSError): invoke(released, checkpoint=fail)
    assert (load().jumphost is not None) is committed
    result = invoke(released)
    assert result.jumphost and result.dns
    assert barrier.get(store, 'demo') == original


def test_existing_public_service_generation_not_overwritten(released):
    context, load, save = released
    result = invoke(released); result.jumphost.generation = 'f' * 32; save(result)
    before = load().to_dict()
    with pytest.raises(RuntimeOperationError, match='public service differs'): invoke(released)
    assert load().to_dict() == before


def test_incomplete_host_roster_refused_before_service_inspection(released, monkeypatch):
    def forbidden(*args): raise AssertionError('no remote inspection')
    monkeypatch.setattr(services, 'invoke', forbidden)
    with pytest.raises(RuntimeOperationError, match='released management context'): invoke(released, clients={})


def test_unreleased_context_never_publishes_service_descriptors(released, monkeypatch):
    context, load, save = released
    store = context[6]; row = barrier.get(store, 'demo'); row['phase'] = 'provisioning'
    with store.transaction(): barrier.put(store, 'demo', row)
    monkeypatch.setattr(services, 'invoke', lambda *a: pytest.fail('no remote inspection'))
    with pytest.raises(RuntimeOperationError, match='released management context'): invoke(released)
    assert load().jumphost is None and load().dns is None


def test_teardown_recorded_during_observation_is_not_overwritten(released, monkeypatch):
    context, load, save = released
    previous = services.invoke; count = []
    def changed(client, bundle, action):
        value = previous(client, bundle, action); count.append(action)
        if len(count) == 2:
            current = load(); current.teardown_requested = True; save(current)
        return value
    monkeypatch.setattr(services, 'invoke', changed)
    with pytest.raises(RuntimeOperationError, match='deployment changed'): invoke(released)
    assert load().teardown_requested and load().jumphost is None


@pytest.mark.parametrize('fault', ['closure', 'intent'])
def test_original_intent_and_closure_rechecked_after_service_observation(released, monkeypatch, fault):
    context, load, save = released
    store = context[6]; previous = services.invoke; calls = []
    def changed(client, bundle, action):
        value = previous(client, bundle, action); calls.append(action)
        if len(calls) == 2:
            with store.transaction():
                if fault == 'closure':
                    from dnlab_multinode.services.runtime_lab_closure import put
                    put(store, 'demo', {'generation': 1, 'phase': 'closing', 'allowed': {}})
                else:
                    row = barrier.get(store, 'demo'); row['publication_conflict'] = True
                    barrier.put(store, 'demo', row)
        return value
    monkeypatch.setattr(services, 'invoke', changed)
    with pytest.raises(RuntimeOperationError, match='closing or closed|operation changed'): invoke(released)
    assert load().jumphost is None and load().dns is None
