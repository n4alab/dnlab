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

    return open_session, observations, state


def test_binds_original_requests_before_any_command(assembly):
    open_session, observations, state = assembly
    with open_session() as (driver, reference):
        assert observations == ['subscribed']
        assert state['calls'] == []
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
    open_session, observations, _ = assembly
    with open_session():
        pass
    with pytest.raises(Conflict, match='supervisor cannot be replaced'), open_session():
        pytest.fail('replacement supervisor was opened')
    assert observations == ['subscribed', 'closed']


def test_partial_registration_preserves_original_supervisor_binding(assembly, monkeypatch):
    open_session, observations, _ = assembly
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
    open_session, observations, _ = assembly
    with pytest.raises(Conflict, match='activation context differs'), open_session(read_context=lambda: {}):
        pytest.fail('foreign context was accepted')
    assert observations == []
