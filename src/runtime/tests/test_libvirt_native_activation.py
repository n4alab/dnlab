"""Exercise native assembly with an inert systemd stream and real journals."""

from contextlib import contextmanager
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_activation_controller import controller
from test_libvirt_service_observer import service, install, request_profile
from tools import libvirt_native_activation as native


@pytest.fixture
def assembly(controller, monkeypatch):
    previous, reference, _, state, _ = controller
    source = previous.source
    observations = []
    initial = []

    class Signals:
        owner = ':1.42'

        def subscribe(self):
            observations.append('subscribed')

        def drain(self):
            return []

    @contextmanager
    def open_stream(root, inventory, requests, *, read_context):
        from tools.libvirt_systemd_events import SystemdActivationStream

        assert read_context() == inventory['context']
        assert [request['nonce'] for request in requests] == [item['nonce'] for item in reference['items'][1:]]
        stream = SystemdActivationStream(Signals(), requests, pin_process=forbidden)
        try:
            yield stream, None
        finally:
            stream.continuous = False
            observations.append('closed')

    def forbidden(*args, **kwargs):
        pytest.fail('native process, socket or command used during synthetic assembly')

    monkeypatch.setattr(native, 'open_activation_stream', open_stream)
    monkeypatch.setattr(native, 'InitialSessionState', lambda root, installation: initial.append)
    monkeypatch.setattr(native.ActivationProcessRunner, 'arm', forbidden)
    monkeypatch.setattr(native.BusStartProcessRunner, 'arm', forbidden)

    def open_session(**overrides):
        reload_profile = dict(python=dict(path='/synthetic/python', sha256='a' * 64),
                              worker=dict(path='/synthetic/reload.py', sha256='b' * 64))
        start_profile = deepcopy(reload_profile)
        start_profile['worker'] = dict(path='/synthetic/start.py', sha256='c' * 64)
        bus_inventory = dict(context=source['context'], status='collected', passes=2, library_present=True,
                             proof=dict(library=dict(object=dict(sha256='d' * 64))))
        kwargs = dict(root=None, operation=reference['id'], window=previous.window, binary=previous.binary,
                      reload_profile=reload_profile, start_profile=start_profile, sources_sha256='e' * 64,
                      bus_inventory=bus_inventory, read_context=lambda: deepcopy(source['context']),
                      source_reader=previous.source_reader, resources=previous.resources,
                      inventory=previous.inventory, virsh=dict(path='/usr/bin/virsh', sha256='f' * 64),
                      files=None, unit_query=forbidden)
        return native.open_native_activation(previous.journal, source, **(kwargs | overrides))

    return open_session, observations, state, initial


def test_binds_original_requests_before_any_command(assembly):
    open_session, observations, state, initial = assembly
    with open_session() as (driver, reference):
        assert observations == ['subscribed']
        assert state['calls'] == []
        assert initial and all(receipts['dnlab-libvirtd.service'] is None for receipts in initial)
        references = driver._monitors(reference)
        for item in reference['items'][1:]:
            request = driver.monitor_request(reference, item)
            assert references[item['spec']['unit']]['request_sha256'] == fingerprint(request)
            assert driver.commands.inspect_intent(item, reference['id']) is None
            command = driver.command_builder(driver.source, item, reference['id'], driver.binary)
            assert command['transport']['kind'] == 'dbus-start-v1'
        assert driver.recover_original(reference) == reference
    assert observations == ['subscribed', 'closed']
    with pytest.raises(Conflict):
        driver.apply_original(reference)
    assert state['calls'] == []


def test_refuses_new_subscription_for_bound_intent(assembly):
    open_session, observations, _, _ = assembly
    with open_session():
        pass
    with pytest.raises(Conflict, match='supervisor cannot be replaced'), open_session():
        pytest.fail('replacement supervisor was opened')
    assert observations == ['subscribed', 'closed']


def test_partial_registration_preserves_original_supervisor_binding(assembly, monkeypatch):
    open_session, observations, _, _ = assembly
    register = native.ActivationEventMonitor.register

    def interrupt(monitor, request, subscription):
        if request['spec']['role'] == 'virtlockd':
            raise OSError('interrupted after first monitor registration')
        return register(monitor, request, subscription)

    with monkeypatch.context() as patch:
        patch.setattr(native.ActivationEventMonitor, 'register', interrupt)
        with pytest.raises(OSError, match='after first monitor'), open_session():
            pytest.fail('incomplete registration was accepted')
    with pytest.raises(Conflict, match='supervisor cannot be replaced'), open_session():
        pytest.fail('partial registration was replaced')
    assert observations == ['subscribed', 'closed']


def test_context_mismatch_does_not_subscribe(assembly):
    open_session, observations, _, _ = assembly
    with pytest.raises(Conflict, match='activation context differs'), open_session(read_context=lambda: {}):
        pytest.fail('foreign context was accepted')
    assert observations == []


def test_preexisting_state_stops_before_subscription(assembly, monkeypatch):
    open_session, observations, state, _ = assembly

    def reject(receipts):
        assert receipts['dnlab-libvirtd.service'] is None
        raise Conflict('pre-existing libvirt state')

    monkeypatch.setattr(native, 'InitialSessionState', lambda root, installation: reject)
    with pytest.raises(Conflict, match='pre-existing libvirt state'), open_session():
        pytest.fail('pre-existing driver state was accepted')
    assert observations == [] and state['calls'] == []


def test_explicit_successor_dispatch_precedes_monitor_subscription(assembly, monkeypatch):
    from tools import libvirt_postboot_state
    from dnlab_runtime.libvirt_activation import SessionActivation
    open_session, observations, state, _ = assembly
    called = []
    admission = {'synthetic':'dispatch-only'}
    original_read = SessionActivation.read
    def read(driver, operation):
        return {'synthetic':'predecessor'} if operation == 'completed-original' else original_read(driver, operation)
    def successor(controller, predecessor_id, *, state_admission):
        assert observations == []
        assert state_admission == admission
        called.append(predecessor_id)
        # Dispatch-only fixture: lineage validation is covered by the real
        # successor coordinator tests, while this assembly has a prepared row.
        return controller.driver.read(controller.operation)
    def forbidden(*args):pytest.fail('initial preparation used for a successor')
    monkeypatch.setattr(native.ActivationController, 'prepare_successor', successor)
    monkeypatch.setattr(native.ActivationController, 'prepare', forbidden)
    monkeypatch.setattr(SessionActivation, 'read', read)
    monkeypatch.setattr(libvirt_postboot_state, 'PostBootEmptyState',
                        lambda root, source, predecessor, approved: lambda receipts: None)
    with open_session(predecessor_id='completed-original', state_admission=admission):
        assert called == ['completed-original'] and observations == ['subscribed']
    assert state['calls'] == [] and observations == ['subscribed', 'closed']
