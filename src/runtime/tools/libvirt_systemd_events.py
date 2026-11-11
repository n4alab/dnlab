"""Observe original systemd job and process signals on an owned sd-bus connection."""

from contextlib import contextmanager
from copy import deepcopy
import ctypes as C
from time import monotonic
import uuid

from dnlab_runtime.libvirt_activation_bus import UNITS
from dnlab_runtime.manifest import Conflict, fingerprint
from tools.libvirt_bus_connection import BROKER, MANAGER, TIMEOUT, ConnectionABI, open_proven_bus, unique_name
from tools.libvirt_service_process import open_service_process_pins
from tools.libvirt_systemd_bus import require, success

MANAGER_PATH = '/org/freedesktop/systemd1'
MANAGER_INTERFACE = MANAGER + '.Manager'
PROPERTIES = 'org.freedesktop.DBus.Properties'
BROKER_PATH = '/org/freedesktop/DBus'
UNIT_PATH = MANAGER_PATH + '/unit/'
UNIT_PATHS = {
    UNIT_PATH + ''.join(char if char.isalnum() else f'_{ord(char):02x}' for char in unit): unit
    for unit in UNITS
}
MAX_BATCH = 512
MAX_HISTORY = 256


class SignalABI(ConnectionABI):
    def __init__(self, library):
        super().__init__(library)
        pointer, string = C.c_void_p, C.c_char_p
        signatures = {
            'sd_bus_message_get_path': ([pointer], string),
            'sd_bus_message_get_interface': ([pointer], string),
            'sd_bus_message_get_member': ([pointer], string),
            'sd_bus_message_enter_container': ([pointer, C.c_char, string], C.c_int),
            'sd_bus_message_exit_container': ([pointer], C.c_int),
            'sd_bus_message_skip': ([pointer, string], C.c_int),
            'sd_bus_message_read_array': (
                [pointer, C.c_char, C.POINTER(pointer), C.POINTER(C.c_size_t)], C.c_int),
        }
        for name, (arguments, result) in signatures.items():
            call = getattr(library, name)
            call.argtypes = arguments
            call.restype = result

    def _basic(self, message, code, *, optional=False):
        output = C.c_uint32() if code == b'u' else C.c_char_p()
        result = success(self.library.sd_bus_message_read_basic(message, code, C.byref(output)),
                         'sd_bus_message_read_basic')
        if not result and optional:
            return None
        require(result > 0 and output.value is not None, 'required systemd signal field missing')
        if code == b'u':
            return output.value
        require(len(output.value) <= 256, 'systemd signal field exceeds bound')
        return output.value.decode('ascii')

    def _enter(self, message, kind, fields):
        return success(self.library.sd_bus_message_enter_container(message, kind, fields),
                       'sd_bus_message_enter_container')

    def _exit(self, message):
        success(self.library.sd_bus_message_exit_container(message), 'sd_bus_message_exit_container')

    def _properties(self, message, unit):
        interface = self._basic(message, b's')
        if interface == MANAGER + '.Unit':
            field, key, signature = 'InvocationID', 'invocation_id', b'ay'
        elif interface == MANAGER + '.Service':
            field, key, signature = 'MainPID', 'pid', b'u'
        else:
            return None
        result = None
        require(self._enter(message, b'a', b'{sv}') > 0, 'systemd changed properties missing')
        while self._enter(message, b'e', b'sv'):
            name = self._basic(message, b's')
            if name == field:
                require(result is None and self._enter(message, b'v', signature) > 0,
                        'duplicate or malformed systemd generation property')
                if signature == b'u':
                    result = self._basic(message, b'u')
                else:
                    pointer, size = C.c_void_p(), C.c_size_t()
                    require(success(self.library.sd_bus_message_read_array(
                        message, b'y', C.byref(pointer), C.byref(size)),
                        'sd_bus_message_read_array') > 0 and size.value == 16 and pointer.value,
                        'systemd InvocationID must contain 16 bytes')
                    result = C.string_at(pointer, size.value).hex()
                self._exit(message)
            else:
                success(self.library.sd_bus_message_skip(message, b'v'), 'sd_bus_message_skip')
            self._exit(message)
        self._exit(message)
        require(self._enter(message, b'a', b's') > 0, 'systemd invalidated properties missing')
        while (name := self._basic(message, b's', optional=True)) is not None:
            require(name != field, 'systemd generation property invalidated')
        self._exit(message)
        return None if result is None else dict(kind='property', unit=unit, **{key: result})

    def decode(self, message, owner):
        library = self.library
        sender = library.sd_bus_message_get_sender(message)
        path = library.sd_bus_message_get_path(message)
        interface = library.sd_bus_message_get_interface(message)
        member = library.sd_bus_message_get_member(message)
        if (sender, path, interface, member) == (
                BROKER.encode(), BROKER_PATH.encode(), BROKER.encode(), b'NameOwnerChanged'):
            require(library.sd_bus_message_get_signature(message, 1) == b'sss', 'malformed owner change signal')
            if self._basic(message, b's') == MANAGER:
                raise Conflict('systemd manager owner changed on the subscribed connection')
            return None
        if sender != owner.encode('ascii'):
            return None
        if path == MANAGER_PATH.encode() and interface == MANAGER_INTERFACE.encode():
            if member not in (b'JobNew', b'JobRemoved'):
                return None
            removed = member == b'JobRemoved'
            require(library.sd_bus_message_get_signature(message, 1) == (b'uoss' if removed else b'uos'),
                    'malformed systemd job signal')
            number = self._basic(message, b'u')
            job = self._basic(message, b'o')
            unit = self._basic(message, b's')
            if unit not in UNITS:
                return None
            require(number > 0 and job == f'{MANAGER_PATH}/job/{number}', 'systemd job number and path differ')
            event = dict(kind='job-removed' if removed else 'job-new', unit=unit, job_path=job)
            if removed:
                event['result'] = self._basic(message, b's')
            return event
        if path is not None and interface == PROPERTIES.encode() and member == b'PropertiesChanged':
            unit = UNIT_PATHS.get(path.decode('ascii'))
            if unit is not None:
                require(library.sd_bus_message_get_signature(message, 1) == b'sa{sv}as',
                        'malformed systemd properties signal')
                return self._properties(message, unit)
        return None


class SystemdSignals:
    """Install broker matches on a dedicated connection whose owner closes it."""

    def __init__(self, abi, handle, identity):
        self.abi, self.handle = abi, handle
        self.owner = identity['manager_owner']
        self.client = identity['unique_name']
        self.started = False
        self.continuous = False
        require(unique_name(self.owner) and unique_name(self.client) and self.owner != self.client,
                'verified unique systemd owner and client required')

    def _call(self, destination, path, interface, method, arguments, deadline):
        reply = self.abi._call(self.handle, destination, path, interface, method, arguments, '',
                               self.abi._remaining(deadline))
        require(reply['sender'] == destination and 0 < reply['call_serial'] == reply['reply_serial'],
                'systemd subscription reply does not match its request')

    def subscribe(self):
        require(not self.started, 'original systemd subscription already attempted')
        self.started = True
        deadline = monotonic() + TIMEOUT
        matches = [
            f"type='signal',sender='{BROKER}',path='{BROKER_PATH}',interface='{BROKER}',"
            f"member='NameOwnerChanged',arg0='{MANAGER}'",
        ]
        for unit in UNITS:
            for member in ('JobNew', 'JobRemoved'):
                matches.append(f"type='signal',sender='{self.owner}',path='{MANAGER_PATH}',"
                               f"interface='{MANAGER_INTERFACE}',member='{member}',arg2='{unit}'")
        for path in UNIT_PATHS:
            matches.append(f"type='signal',sender='{self.owner}',path='{path}',"
                           f"interface='{PROPERTIES}',member='PropertiesChanged'")
        for match in matches:
            self._call(BROKER, BROKER_PATH, BROKER, 'AddMatch', [match], deadline)
        self._call(self.owner, MANAGER_PATH, MANAGER_INTERFACE, 'Subscribe', [], deadline)
        require(self.abi.connected(self.handle, self.client), 'subscribed system bus connection lost')
        self.continuous = True

    def drain(self):
        require(self.continuous, 'original systemd signal connection unavailable')
        library = self.abi.library
        events = []
        try:
            for _ in range(MAX_BATCH):
                message = C.c_void_p()
                try:
                    processed = success(library.sd_bus_process(self.handle, C.byref(message)), 'sd_bus_process')
                    if message.value is not None:
                        event = self.abi.decode(message, self.owner)
                        if event is not None:
                            events.append(event)
                    if not processed:
                        require(self.abi.connected(self.handle, self.client), 'systemd signal connection lost')
                        return events
                finally:
                    if message.value is not None:
                        library.sd_bus_message_unref(message)
            raise Conflict('systemd signal drain exceeded its batch bound')
        except Exception:
            self.continuous = False
            raise

    def verify_worker_connection(self, reference, connection):
        """Resolve the worker's unique name on the original subscribed bus."""
        if (not self.continuous or connection['manager_owner'] != self.owner
                or connection['unique_name'] == self.client
                or not self.abi.connected(self.handle, self.client)):
            return False
        deadline = monotonic() + TIMEOUT
        query = self.abi._broker_query
        owner = query(self.handle, 'GetNameOwner', MANAGER, 's', deadline)
        pid = query(self.handle, 'GetConnectionUnixProcessID', connection['unique_name'], 'u', deadline)
        uid = query(self.handle, 'GetConnectionUnixUser', connection['unique_name'], 'u', deadline)
        return (owner == self.owner and pid == reference['process_record']['pid'] and uid == 0
                and self.abi.connected(self.handle, self.client))


class SystemdActivationStream:
    """Convert wire signals to the activation monitor's replayable event batches."""

    def __init__(self, signals, requests, *, pin_process):
        require(callable(pin_process), 'original service process pin provider required')
        self.signals, self.pin_process = signals, pin_process
        self.records = {}
        self.continuous = True
        for request in requests:
            unit = request['spec']['unit']
            require(unit in UNITS and unit not in self.records, 'one original request per dedicated unit required')
            subscription = dict(token=uuid.uuid4().hex, request_sha256=fingerprint(request),
                                context_sha256=fingerprint(request['context']), manager_owner=signals.owner, barrier=0)
            self.records[unit] = dict(request=deepcopy(request), subscription=subscription,
                                      events=[], invocation_id=None, pid=None)
        self.signals.subscribe()
        self._pump()
        require(not any(record['events'] or record['pid'] is not None or record['invocation_id'] is not None
                        for record in self.records.values()),
                'systemd activation events already present at subscription')

    def subscription(self, unit):
        return deepcopy(self.records[unit]['subscription'])

    def _append(self, record, event):
        require(len(record['events']) < MAX_HISTORY, 'systemd activation event history exhausted')
        record['events'].append(dict(event, sequence=len(record['events']) + 1))

    def _property(self, record, event):
        key = 'pid' if 'pid' in event else 'invocation_id'
        value = event[key]
        previous = record[key]
        empty = value in (0, '0' * 32)
        if previous is not None:
            require(value == previous, 'original systemd service generation changed')
            return
        if empty:
            return
        record[key] = value
        if record['pid'] is not None and record['invocation_id'] is not None:
            reference = self.pin_process(deepcopy(record['request']), deepcopy(record['subscription']),
                                         record['pid'], record['invocation_id'])
            self._append(record, dict(kind='invocation', unit=event['unit'], pid=record['pid'],
                                      invocation_id=record['invocation_id'], process_reference=reference))

    def _pump(self):
        require(self.continuous, 'original systemd activation stream unavailable')
        try:
            for event in self.signals.drain():
                record = self.records.get(event['unit'])
                if record is None:
                    continue
                if event['kind'] == 'property':
                    self._property(record, event)
                else:
                    self._append(record, event)
        except Exception:
            self.continuous = False
            raise

    def verify(self, subscription, request):
        record = self.records.get(request['spec']['unit'])
        if record is None or record['request'] != request or record['subscription'] != subscription:
            return False
        self._pump()
        return True

    def read(self, subscription, *, after, limit):
        matching = [record for record in self.records.values() if record['subscription'] == subscription]
        require(len(matching) == 1 and type(after) is int and type(limit) is int
                and 0 <= after and 0 < limit <= MAX_HISTORY, 'original systemd event cursor required')
        self._pump()
        events = matching[0]['events']
        require(after <= len(events), 'systemd event cursor exceeds retained history')
        batch = deepcopy(events[after:after + limit])
        return dict(subscription_sha256=fingerprint(subscription), after=after, through=after + len(batch),
                    continuous=True, events=batch)


@contextmanager
def open_activation_stream(root, inventory, requests, *, read_context):
    """Keep the sole original subscription live for all three activation steps."""
    requests = tuple(requests)
    require({request['spec']['unit'] for request in requests} == set(UNITS)
            and all(request['context'] == inventory['context'] for request in requests),
            'dedicated activation stream and inventory contexts must agree')
    with (open_service_process_pins(inventory['context'], read_context=read_context) as processes,
          open_proven_bus(root, inventory, read_context=read_context) as (abi, handle, identity)):
        signals = SystemdSignals(SignalABI(abi.library), handle, identity)
        stream = SystemdActivationStream(signals, requests, pin_process=processes.pin)
        try:
            yield stream, processes
            stream._pump()
        finally:
            stream.continuous = False
            signals.continuous = False
