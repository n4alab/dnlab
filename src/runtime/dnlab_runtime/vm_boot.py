"""Initial VM boot with paused CPUs, durable process proof and event activation.

Mandatory providers must qualify the original event source and newly created
QEMU incarnation. No defaults open libvirt or discover/adopt a running domain.
Start, source registration and CPU resume are never blindly repeated after an
uncertain response. Retirement and ordinary shutdown are separate operations.
"""
from copy import deepcopy
import re
import uuid

from .backend_reservations import available
from .manifest import Conflict, fingerprint
from .qemu_process import validate_process_record
from .vm_template import fields, require

PHASES = {'prepared', 'arming_requested', 'armed', 'start_requested', 'paused',
          'activation_requested', 'monitored_paused', 'resume_requested', 'running'}


class VMBootDriver:
    def __init__(self, definitions, *, source, capture_started, observer):
        require(all(callable(getattr(source, name, None)) for name in ('arm', 'activate', 'verify'))
                and callable(capture_started) and callable(observer), 'qualified VM boot providers required')
        self.definitions, self.journal = definitions, definitions.journal
        self.source, self.capture_started, self.observer = source, capture_started, observer

    def _boot(self, value):
        boot = value['boot']
        fields(boot, ('phase', 'source_id', 'definition_sha256', 'source_ack', 'reference', 'process_record',
                      'activation_ack', 'error_type', 'recovery_required'), 'VM boot journal')
        require(boot['phase'] in PHASES and isinstance(boot['source_id'], str)
                and re.fullmatch(r'[0-9a-f]{32}', boot['source_id'])
                and boot['definition_sha256'] == fingerprint([value['request_fingerprint'], value['ack']])
                and type(boot['recovery_required']) is bool, 'original VM boot intent differs')
        if boot['phase'] in ('paused', 'activation_requested', 'monitored_paused', 'resume_requested', 'running'):
            self._process_record(value, boot['reference'], boot['process_record'])
        else:
            require(boot['reference'] is None and boot['process_record'] is None, 'unexpected early VM process receipt')
        return boot

    def _process_record(self, value, reference, record):
        record = validate_process_record(record)
        require(record['birth'] == value['birth'] and reference['birth'] == value['birth']
                and fingerprint(record['process']) == reference['process_sha256']
                and record['uid'] == self.definitions.session.profile['uid']
                and record['gid'] == self.definitions.session.profile['gid'], 'original VM process record differs')
        return record

    def _observer(self, value):
        boot = self._boot(value)
        return self.observer(deepcopy(boot['reference']), deepcopy(boot['process_record']))

    def _check(self, value, *, resources=True):
        self.definitions._fence(value)
        available(self.journal, value['birth']['lab_id'], value['birth']['node_id'], 'libvirt', vm_birth=value['birth'])
        self.definitions._session(value)
        if resources:self.definitions._resources(value)

    def _domain(self, value):
        domain = self.definitions.connection.lookupByUUIDString(value['birth']['uuid'])
        if domain.UUIDString() != value['birth']['uuid']:raise Conflict('original boot domain UUID differs')
        return domain

    def _inactive(self, value):
        domain = self._domain(value)
        if self.definitions._ack(value, domain) != value['ack']:raise Conflict('original boot definition differs')
        if domain.hasManagedSaveImage(0) != 0:raise Conflict('managed save requires explicit handling before boot')
        return domain

    def prepare(self, operation_id):
        with self.journal.execution_lock:
            value = self.definitions.read(operation_id)
            self._check(value)
            if 'boot' in value:
                self._boot(value)
                return value
            require(value['phase'] == 'defined' and value['ack'] is not None, 'qualified definition required before boot')
            self._inactive(value)
            with self.journal.transaction():
                current = self.definitions.read(operation_id)
                self.definitions._fence(current)
                if fingerprint(current) != fingerprint(value):raise Conflict('definition changed before boot intent')
                value['boot'] = {'phase': 'prepared', 'source_id': uuid.uuid4().hex,
                    'definition_sha256': fingerprint([value['request_fingerprint'], value['ack']]),
                    'source_ack': None, 'reference': None, 'process_record': None, 'activation_ack': None,
                    'error_type': '', 'recovery_required': False}
                self.definitions._save(operation_id, value)
            return self.definitions.read(operation_id)

    def _advance(self, operation_id, before, after, **updates):
        with self.journal.transaction():
            value = self.definitions.read(operation_id); boot = self._boot(value)
            self.definitions._fence(value)
            if boot['phase'] != before:raise Conflict('VM boot checkpoint changed')
            for key, new in updates.items():
                require(key in ('source_ack', 'reference', 'process_record', 'activation_ack'), 'invalid VM boot receipt')
                if boot[key] is not None and boot[key] != new:raise Conflict('original VM boot receipt cannot change')
                boot[key] = deepcopy(new)
            boot.update(phase=after, error_type='', recovery_required=False)
            self._boot(value)
            self.definitions._save(operation_id, value)
        return value

    def _source_ack(self, value):
        boot = self._boot(value); ack = boot['source_ack']
        fields(ack, ('source_id', 'collector_id', 'request_fingerprint', 'birth_sha256', 'ready'), 'boot source acknowledgement')
        require(ack['source_id'] == boot['source_id'] and isinstance(ack['collector_id'], str)
                and re.fullmatch(r'[0-9a-f]{32}', ack['collector_id'])
                and ack['request_fingerprint'] == value['request_fingerprint']
                and ack['birth_sha256'] == fingerprint(value['birth']) and ack['ready'] is True,
                'original event source acknowledgement differs')
        require(self.source.verify(deepcopy(ack)) is True, 'original event source is not qualified')

    def _activation(self, value):
        self._source_ack(value); boot = self._boot(value); ack = boot['activation_ack']
        expected = {'source_id': boot['source_id'], 'collector_id': boot['source_ack']['collector_id'],
                    'reference_sha256': fingerprint(boot['reference']),
                    'process_record_sha256': fingerprint(boot['process_record']), 'active': True}
        require(ack == expected and self.source.verify(deepcopy(ack)) is True, 'original event activation differs')

    def _instance(self, value, state):
        self._check(value); self._activation(value)
        self._observer(value)(value['birth'])
        domain = self._domain(value)
        require(domain.state(0)[0] == state, 'VM CPU state differs from original boot stage')
        self.definitions._fence(value)
        return domain

    def _error(self, operation_id, error):
        # Persist uncertainty even when the lab fence now blocks mutations.
        with self.journal.transaction():
            value = self.definitions.read(operation_id); boot = self._boot(value)
            if boot['phase'] != 'running':
                boot.update(error_type=type(error).__name__, recovery_required=True)
                self.definitions._save(operation_id, value)

    def apply(self, operation_id):
        with self.journal.execution_lock:
            self.prepare(operation_id)
            try:
                while True:
                    value = self.definitions.read(operation_id); boot = self._boot(value); stage = boot['phase']
                    self._check(value)
                    if stage == 'prepared':
                        self._inactive(value)
                        value = self._advance(operation_id, stage, 'arming_requested')
                        self._check(value); self._inactive(value)
                        ack = self.source.arm(deepcopy(value))
                        candidate = deepcopy(value); candidate['boot']['source_ack'] = ack
                        self._source_ack(candidate)
                        self._advance(operation_id, 'arming_requested', 'armed', source_ack=ack)
                    elif stage == 'armed':
                        self._source_ack(value); self._inactive(value)
                        value = self._advance(operation_id, stage, 'start_requested')
                        self._check(value); self._source_ack(value); domain = self._inactive(value)
                        require(domain.createWithFlags(1) == 0, 'paused VM start did not complete')
                        require(domain.state(0)[0] == 3, 'new VM did not start with CPUs paused')
                        receipt = self.capture_started(deepcopy(value), domain)
                        fields(receipt, ('reference', 'process_record'), 'original paused creation receipt')
                        reference, record = receipt['reference'], receipt['process_record']
                        self._process_record(value, reference, record)
                        require(reference['birth'] == value['birth'] and reference['uri'] == self.definitions.session.profile['uri']
                                and reference['persistent_sha256'] == value['ack']['persistent_sha256'], 'original paused creation proof differs')
                        self.observer(deepcopy(reference), deepcopy(record))(value['birth'])
                        self._source_ack(value)
                        require(domain.state(0)[0] == 3, 'guest CPUs ran before durable proof')
                        self._advance(operation_id, 'start_requested', 'paused', reference=reference, process_record=record)
                    elif stage == 'paused':
                        self._source_ack(value)
                        self._observer(value)(value['birth'])
                        require(self._domain(value).state(0)[0] == 3, 'VM is not paused before event activation')
                        value = self._advance(operation_id, stage, 'activation_requested')
                        self._check(value); self._source_ack(value)
                        ack = self.source.activate(deepcopy(value))
                        candidate = deepcopy(value); candidate['boot']['activation_ack'] = ack
                        self._activation(candidate)
                        self._advance(operation_id, 'activation_requested', 'monitored_paused', activation_ack=ack)
                    elif stage == 'monitored_paused':
                        self._instance(value, 3)
                        value = self._advance(operation_id, stage, 'resume_requested')
                        domain = self._instance(value, 3)
                        require(domain.resume() == 0, 'guest CPU resume did not complete')
                        self._instance(value, 1)
                        self._advance(operation_id, 'resume_requested', 'running')
                    elif stage in ('running', 'resume_requested'):
                        # A lost resume response is recoverable in read-only
                        # mode once the same proven incarnation is running.
                        self._instance(value, 1)
                        if stage == 'resume_requested':value = self._advance(operation_id, stage, 'running')
                        return value
                    else:
                        raise Conflict('uncertain VM boot stage requires qualified recovery; action is not repeated')
            except Exception as error:
                self._error(operation_id, error)
                raise
