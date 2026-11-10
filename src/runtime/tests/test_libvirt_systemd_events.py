"""Systemd wire-signal fixtures and the real activation event monitor."""

from collections import deque
from copy import deepcopy
import ctypes as C

import pytest

from dnlab_runtime.libvirt_activation_events import ActivationEventMonitor
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_activation_acknowledgements import acknowledgements
from test_libvirt_service_observer import service, install, request_profile
from tools.libvirt_systemd_events import (
    BROKER, BROKER_PATH, MANAGER, MANAGER_INTERFACE, MANAGER_PATH, PROPERTIES, UNIT_PATHS,
    SignalABI, SystemdActivationStream, SystemdSignals,
)


class Message:
    def __init__(self, sender, path, interface, member, signature, values):
        self.headers = [value.encode() for value in (sender, path, interface, member, signature)]
        self.containers = [deque(values)]
        self.buffer = None

    def sd_bus_message_get_sender(self, _):
        return self.headers[0]

    def sd_bus_message_get_path(self, _):
        return self.headers[1]

    def sd_bus_message_get_interface(self, _):
        return self.headers[2]

    def sd_bus_message_get_member(self, _):
        return self.headers[3]

    def sd_bus_message_get_signature(self, *_):
        return self.headers[4]

    def sd_bus_message_read_basic(self, _, kind, output):
        if not self.containers[-1]:
            return 0
        wire_kind, value = self.containers[-1].popleft()
        assert wire_kind == kind
        output._obj.value = value.encode() if isinstance(value, str) else value
        return 1

    def sd_bus_message_enter_container(self, _, kind, signature):
        if not self.containers[-1]:
            return 0
        wire_kind, wire_signature, values = self.containers[-1].popleft()
        assert (wire_kind, wire_signature) == (kind, signature)
        self.containers.append(deque(values))
        return 1

    def sd_bus_message_exit_container(self, _):
        assert not self.containers.pop()
        return 1

    def sd_bus_message_skip(self, _, signature):
        assert self.containers[-1].popleft()[0] == signature
        return 1

    def sd_bus_message_read_array(self, _, kind, pointer, length):
        wire_kind, value = self.containers[-1].popleft()
        assert wire_kind == kind
        self.buffer = C.create_string_buffer(value)
        pointer._obj.value = C.addressof(self.buffer)
        length._obj.value = len(value)
        return 1


def decode(message, owner=':1.42'):
    abi = object.__new__(SignalABI)
    abi.library = message
    return abi.decode(C.c_void_p(256), owner)


UNIT = 'dnlab-virtlogd.service'
JOB = MANAGER_PATH + '/job/12'


@pytest.mark.parametrize('sender,number,expected', [
    (':1.42', 12, dict(kind='job-removed', unit=UNIT, job_path=JOB, result='done')),
    (':1.13', 12, None),
    (':1.42', 13, 'error'),
])
def test_job_wire_sender_and_job_number(sender, number, expected):
    message = Message(sender, MANAGER_PATH, MANAGER_INTERFACE, 'JobRemoved', 'uoss',
                      [(b'u', number), (b'o', JOB), (b's', UNIT), (b's', 'done')])
    if expected == 'error':
        with pytest.raises(Conflict, match='number and path'):
            decode(message)
    else:
        assert decode(message) == expected


def properties(interface, name, signature, data, *, invalidated=()):
    path = next(path for path, unit in UNIT_PATHS.items() if unit == UNIT)
    values = [
        (b's', MANAGER + '.' + interface),
        (b'a', b'{sv}', [(b'e', b'sv', [(b's', name), (b'v', signature, [data])])]),
        (b'a', b's', [(b's', key) for key in invalidated]),
    ]
    return Message(':1.42', path, PROPERTIES, 'PropertiesChanged', 'sa{sv}as', values)


def test_property_wire_decodes_first_generation_and_rejects_invalidation():
    inv = bytes.fromhex('a1' * 16)
    assert decode(properties('Unit', 'InvocationID', b'ay', (b'y', inv))) == {
        'kind': 'property', 'unit': UNIT, 'invocation_id': inv.hex(),
    }
    assert decode(properties('Service', 'MainPID', b'u', (b'u', 321))) == {
        'kind': 'property', 'unit': UNIT, 'pid': 321,
    }
    with pytest.raises(Conflict, match='invalidated'):
        decode(properties('Service', 'MainPID', b'u', (b'u', 321), invalidated=['MainPID']))


def test_manager_owner_change_terminates_original_stream():
    message = Message(BROKER, BROKER_PATH, BROKER, 'NameOwnerChanged', 'sss',
                      [(b's', MANAGER), (b's', ':1.42'), (b's', ':1.43')])
    with pytest.raises(Conflict, match='owner changed'):
        decode(message)


def test_broker_matches_are_installed_before_subscribe_and_never_retried():
    class ABI:
        def __init__(self):
            self.calls = []

        def _remaining(self, _):
            return 100_000

        def _call(self, _, destination, path, interface, method, arguments, output, timeout):
            self.calls.append((destination, method, arguments))
            assert output == '' and 0 < timeout <= 5_000_000
            return dict(sender=destination, call_serial=3, reply_serial=3, body=[])

        def connected(self, _, name):
            return name == ':1.43'

    abi = ABI()
    signals = SystemdSignals(abi, object(), dict(manager_owner=':1.42', unique_name=':1.43'))
    signals.subscribe()
    assert [row[:2] for row in abi.calls] == [(BROKER, 'AddMatch')] * 3 + [(':1.42', 'Subscribe')]
    with pytest.raises(Conflict, match='already attempted'):
        signals.subscribe()
    assert len(abi.calls) == 4


@pytest.mark.parametrize('order', ['job-first', 'properties-first', 'foreign-job'])
def test_wire_events_feed_activation_monitor_without_late_generation_adoption(acknowledgements, order):
    ledger, item, _, state, complete, _ = acknowledgements
    request, _ = ledger._request(item, 'activation')
    row = state['witness']['service']
    unit = request['spec']['unit']
    queued = []
    pins = {}

    class Signals:
        owner = ':1.42'

        def subscribe(self):
            pass

        def drain(self):
            result = queued[:]
            queued.clear()
            return result

    class Processes:
        def verify(self, reference, request, subscription):
            return pins.get(reference['token']) == reference

    def pin(request, subscription, pid, invocation):
        reference = dict(kind='original-service-process-v1', token='1' * 32,
                         request_sha256=fingerprint(request), subscription_sha256=fingerprint(subscription),
                         invocation_id=invocation, pid=pid, start_ticks=row['process']['start_ticks'],
                         boot_id=request['context']['boot_id'],
                         namespaces_sha256=fingerprint(request['context']['namespaces']))
        assert not pins
        pins[reference['token']] = deepcopy(reference)
        return reference

    stream = SystemdActivationStream(Signals(), [request], pin_process=pin)
    monitor = ActivationEventMonitor(
        ledger.journal, binary=ledger.binary, activation_reader=ledger.activation_reader,
        command_intent=ledger.command_intent, command_reader=ledger.command_reader, stream=stream,
        processes=Processes(), correlate=lambda request, subscription, event: event['job_path'] == JOB,
        observe=lambda request, invocation: row,
    )
    original = monitor.register(request, stream.subscription(unit))
    ledger.monitor = monitor
    ledger.prepare(item, 'activation', original)
    complete()
    job_new = dict(kind='job-new', unit=unit, job_path=JOB)
    job_removed = dict(kind='job-removed', unit=unit, job_path=JOB, result='done')
    generation = [
        dict(kind='property', unit=unit, invocation_id=row['unit']['invocation_id']),
        dict(kind='property', unit=unit, pid=row['process']['pid']),
    ]
    if order == 'job-first':
        queued.extend([job_new, *generation, job_removed])
    else:
        queued.extend(generation)
        with pytest.raises(Conflict, match='evidence pending'):
            monitor.read_original(original, request)
        assert len(pins) == 1
        assert [event['kind'] for event in stream.read(stream.subscription(unit), after=0, limit=8)['events']] == [
            'invocation',
        ]
        if order == 'foreign-job':
            job_new['job_path'] = MANAGER_PATH + '/job/13'
            queued.append(job_new)
            with pytest.raises(Conflict, match='not correlated'):
                ledger.qualify(item, 'activation')
            saved, _, _ = monitor._read(original, request)
            assert saved['phase'] == 'pending' and saved['proof'] is None
            return
        queued.extend([job_new, job_removed])
    receipt = ledger.qualify(item, 'activation')
    assert ledger.original_receipt(item, 'activation') == receipt
    assert len(pins) == 1
    queued.append(dict(kind='property', unit=unit, pid=row['process']['pid'] + 1))
    with pytest.raises(Conflict, match='generation changed'):
        ledger.original_receipt(item, 'activation')
    assert stream.continuous is False
