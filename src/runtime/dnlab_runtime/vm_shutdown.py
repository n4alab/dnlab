"""Distinct guest-shutdown and explicit hypervisor-stop operations.

Guest shutdown requires a qualified NOS capability. Explicit Stop VD requires
its separate approved policy and never certifies guest shutdown or guest flush.
Neither operation retries uncertain requests, escalates to SIGKILL, retires
resources or renews a lost witness. Exit publication and final readonly resource
checks share one journal transaction.
"""
from copy import deepcopy
import json
import re

from .manifest import Conflict, canonical, fingerprint
from .qemu_process import validate_process_record
from .vm_shutdown_observation import VMShutdownObservation, VMStopObservation
from .vm_template import digest, fields, require


def _capability(value, original, method='acpi'):
    if method == 'libvirt-sigterm':
        fields(value,('method','template_sha256','policy_sha256','explicit'),'explicit hypervisor stop policy')
        require(value['method'] == method and value['explicit'] is True
                and value['template_sha256'] == original['birth']['template_sha256']
                and digest(value['policy_sha256']), 'explicit original SIGTERM-only stop policy required')
        return
    require(method == 'acpi', 'unknown VM exit operation method')
    fields(value,('method','template_sha256','qualification_sha256','qualified'),'qualified VM shutdown capability')
    require(value['method'] == 'acpi' and value['qualified'] is True
            and value['template_sha256'] == original['birth']['template_sha256']
            and digest(value['qualification_sha256']), 'qualified original template ACPI shutdown required')


def _read(journal, operation):
    row = journal.db.execute('SELECT * FROM vm_shutdown_intents WHERE id=?',(operation,)).fetchone()
    if row is None:raise Conflict('original VM shutdown intent missing')
    value = json.loads(row['payload'])
    fields(value,('id','definition_id','birth','original','original_sha256','capability',
                  'witness','phase','request_ack','proof','error_type'), 'VM shutdown intent')
    original = value['original'];reference = value['witness']
    method = value['capability'].get('method')
    observation = VMShutdownObservation if method == 'acpi' else VMStopObservation
    record = validate_process_record(original['boot']['process_record'])
    require(value['id'] == operation and fingerprint(value) == row['fingerprint']
            and value['definition_id'] == row['definition_id'] == value['birth']['creator_operation_id']
            and value['birth'] == original['birth'] and value['original_sha256'] == fingerprint(original)
            and row['boot_source_id'] == original['boot']['source_id']
            and original['boot']['phase'] in observation.BOOT_PHASES
            and record['birth'] == value['birth']
            and value['phase'] in ('prepared','requested','completed'), 'original VM shutdown lineage differs')
    _capability(value['capability'],original,method)
    fields(reference,('kind','id','birth','process_record_sha256'),'original VM shutdown witness')
    require(reference['kind'] == 'original-qemu-exit-witness-v1'
            and isinstance(reference['id'],str) and re.fullmatch('[0-9a-f]{32}',reference['id'])
            and reference['birth'] == value['birth']
            and reference['process_record_sha256'] == fingerprint(original['boot']['process_record']),
            'original shutdown pidfd witness differs')
    ack = value['request_ack']
    require((ack is None or (type(ack) is dict and set(ack) == {'return_code'}
                            and type(ack['return_code']) is int and ack['return_code'] == 0))
            and (value['phase'] != 'prepared' or value['request_ack'] is None), 'original ACPI acknowledgement differs')
    if value['phase'] == 'completed':
        expected = dict(kind=observation.KIND,birth=deepcopy(value['birth']),
            definition_sha256=original['request_fingerprint'],
            exit=dict(reference=reference,process=original['boot']['process_record']['process'],exited=True),
            inactive_ack=original['ack'],reason=observation.REASON, **observation.EXTRA)
        require(fingerprint(value['proof']) == fingerprint(expected), 'original ordinary VM shutdown receipt differs')
    else:require(value['proof'] is None, 'unexpected early VM shutdown completion')
    return value


def stopped_proof(definitions, original, *, required=True):
    """Reobserve an already committed exit; never acquire another pidfd."""
    journal = definitions.journal
    table = journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vm_shutdown_intents'").fetchone()
    row = None if table is None else journal.db.execute(
        'SELECT id FROM vm_shutdown_intents WHERE definition_id=? AND boot_source_id=?',
        (original['birth']['creator_operation_id'],original.get('boot',{}).get('source_id'))).fetchone()
    value = None if row is None else _read(journal,row['id'])
    if value is None or value['phase'] != 'completed':
        if required:raise Conflict('original VM writer absence needs verified shutdown')
        return None
    current = definitions.read(value['definition_id'])
    retirement = None
    if current.get('retirement') is not None:
        from .vm_definition_retirement import stopped_retirement_lineage
        retirement = stopped_retirement_lineage(definitions,current,original,value)
    else:
        require(current == original == value['original'],
                'completed VM shutdown belongs to another generation')
    original = value['original']
    definitions._session(original)
    try:domain = definitions.connection.lookupByUUIDString(original['birth']['uuid'])
    except Exception as error:
        code = getattr(error,'get_error_code',None)
        require(retirement is not None and retirement['phase'] in ('undefine_requested','retired')
                and callable(code) and code() == definitions.missing,
                'stopped VM absence requires original undefine intent')
        try:definitions.connection.lookupByName(original['ack']['name'])
        except Exception as name_error:
            name_code = getattr(name_error,'get_error_code',None)
            require(callable(name_code) and name_code() == definitions.missing,
                    'retired VM name absence is not qualified')
        else:raise Conflict('retired VM name is occupied')
        return deepcopy(value['proof'])
    require(retirement is None or retirement['phase'] != 'retired',
            'retired VM definition reappeared')
    observation = VMShutdownObservation if value['capability']['method'] == 'acpi' else VMStopObservation
    require(observation._ordinary_state(domain)
            and definitions._ack(original,domain) == original['ack'], 'original stopped VM definition changed')
    return deepcopy(value['proof'])


class VMShutdownDriver:
    METHOD = 'acpi'
    OBSERVATION = VMShutdownObservation
    REQUEST_ERROR = 'original ACPI shutdown request did not complete'
    def __init__(self, boot, *, capability):
        require(callable(capability), 'qualified readonly template shutdown provider required')
        self.boot,self.definitions,self.journal = boot,boot.definitions,boot.journal
        self.capability = capability
        self.observe_exit = self.OBSERVATION(boot)
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_shutdown_intents '
                '(id TEXT PRIMARY KEY,definition_id TEXT NOT NULL,boot_source_id TEXT NOT NULL,'
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL,UNIQUE(definition_id,boot_source_id))')

    def read(self, operation):
        value = _read(self.journal,operation)
        require(value['capability']['method'] == self.METHOD, 'original VM exit operation method differs; no fallback')
        return value

    def _request(self, domain):return domain.shutdownFlags(1)

    def _write(self, value):
        self.journal.db.execute('UPDATE vm_shutdown_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    def _source(self, value):
        original = self.definitions.read(value['definition_id'])
        require(original == value['original'], 'original VM changed during shutdown')
        self.definitions._fence(original);self.definitions._session(original)
        capability = self.capability(deepcopy(original))
        require(fingerprint(capability) == fingerprint(value['capability']), 'original shutdown qualification changed')
        _capability(capability,original,self.METHOD)
        return original

    @staticmethod
    def _witness(value, witness):
        require(witness is not None and witness.reference() == value['witness'],
                'original held shutdown pidfd required; no reacquisition')

    def _live(self, value, witness):
        original = self._source(value);self._witness(value,witness)
        require(witness.verify_live() == original['boot']['process_record']['process'],
                'original live shutdown process differs')
        return self.boot._instance(original,1)

    def prepare(self, operation, definition_id, witness=None):
        require(isinstance(operation,str) and re.fullmatch('[0-9a-f]{32}',operation),
                'explicit VM shutdown operation ID required')
        with self.journal.execution_lock:
            prior = self.journal.db.execute('SELECT 1 FROM vm_shutdown_intents WHERE id=?',(operation,)).fetchone()
            if prior:
                value = self.read(operation)
                require(value['definition_id'] == definition_id, 'shutdown request ID belongs to another VM')
                self._source(value)
                return value
            original = self.definitions.read(definition_id)
            require(self.boot._boot(original)['phase'] in self.OBSERVATION.BOOT_PHASES and witness is not None,
                    'original running boot and held pidfd required before shutdown')
            held = self.journal.db.execute('SELECT id FROM vm_shutdown_intents WHERE definition_id=? AND boot_source_id=?',
                (definition_id,original['boot']['source_id'])).fetchone()
            if held is not None:raise Conflict('original boot already has a shutdown intent; no replacement')
            capability = self.capability(deepcopy(original));_capability(capability,original,self.METHOD)
            value = dict(id=operation,definition_id=definition_id,birth=deepcopy(original['birth']),
                original=deepcopy(original),original_sha256=fingerprint(original),capability=deepcopy(capability),
                witness=witness.reference(),phase='prepared',request_ack=None,proof=None,error_type='')
            self._live(value,witness)
            with self.journal.transaction():
                self._source(value);self._witness(value,witness);witness.verify_live()
                self.journal.db.execute('INSERT INTO vm_shutdown_intents VALUES(?,?,?,?,?)',
                    (operation,definition_id,original['boot']['source_id'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def _complete(self, value, witness):
        original = self._source(value);self._witness(value,witness)
        proof = self.observe_exit(original,witness)
        if proof is None:return self.read(value['id'])
        before_publication = getattr(self.boot,'_before_exit_publication',None)
        if before_publication is not None:before_publication(deepcopy(original))
        with self.journal.transaction():
            current = self.read(value['id']);self._source(current);self._witness(current,witness)
            require(current['phase'] == 'requested', 'original shutdown checkpoint changed')
            require(self.observe_exit(original,witness) == proof, 'original shutdown changed before publication')
            current.update(phase='completed',proof=proof,error_type='');self._write(current)
            # Readers see the candidate completed proof in the same transaction.
            # A changed overlay, TAP or foreign writer rolls back publication.
            self.definitions._resources(original)
            require(self.observe_exit(original,witness) == proof, 'original shutdown changed during resource verification')
            self._source(current)
        return self.read(value['id'])

    def apply(self, operation, witness=None):
        with self.journal.execution_lock:
            value = self.read(operation)
            try:
                if value['phase'] == 'completed':
                    original = self._source(value);stopped_proof(self.definitions,original)
                    self.definitions._resources(original)
                    return value
                if value['phase'] == 'prepared':
                    self._live(value,witness)
                    with self.journal.transaction():
                        current = self.read(operation);self._source(current)
                        require(current['phase'] == 'prepared', 'original shutdown request checkpoint changed')
                        current['phase'] = 'requested';self._write(current)
                    value = self.read(operation)
                    domain = self._live(value,witness)
                    require(self._request(domain) == 0, self.REQUEST_ERROR)
                    with self.journal.transaction():
                        current = self.read(operation)
                        require(current['phase'] == 'requested', 'original shutdown acknowledgement checkpoint changed')
                        current['request_ack'] = {'return_code':0};self._write(current)
                    value = self.read(operation)
                # Requested includes a lost reply: only observe, never resend.
                return self._complete(value,witness)
            except Exception as error:
                try:
                    with self.journal.transaction():
                        current = self.read(operation)
                        if current['phase'] != 'completed':
                            current['error_type'] = type(error).__name__;self._write(current)
                except Exception as recording_error:
                    error.add_note('shutdown diagnostic persistence also failed: '+str(recording_error))
                raise


class VMStopDriver(VMShutdownDriver):
    """Explicit approved Stop VD, separate from the NOS ACPI capability.

    The policy is authorization, not a claim of prior guest qualification.
    Only VIR_DOMAIN_DESTROY_GRACEFUL (1) is sent once. No flag-zero fallback,
    SIGKILL, disk wipe or retry of an uncertain request is permitted.
    """
    METHOD = 'libvirt-sigterm'
    OBSERVATION = VMStopObservation
    REQUEST_ERROR = 'original explicit Stop VD request did not complete'

    def _request(self, domain):return domain.destroyFlags(1)

    def _live(self, value, witness):
        original = self._source(value);self._witness(value,witness)
        require(witness.verify_live() == original['boot']['process_record']['process'],
                'original live stop process differs')
        self.boot._check(original);self.boot._activation(original)
        self.boot._observer(original)(original['birth'])
        handoff = getattr(self.boot,'handoff',None)
        if handoff is not None:handoff.acquire(value['definition_id'])
        domain = self.boot._domain(original)
        require(domain.state(0)[0] in (1,3), 'original VM must be running or monitored paused before explicit stop')
        self.boot._check(original);self.boot._activation(original)
        require(witness.verify_live() == original['boot']['process_record']['process'],
                'original stop process changed before request')
        return domain
