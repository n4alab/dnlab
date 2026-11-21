"""One ordinary ACPI request, followed by original pidfd/domain observation.

Capability qualification is mandatory and supplied by the trusted template
registry. This module does not qualify an NOS by assertion, wait indefinitely,
force exit, retire resources or renew a lost witness. Publication uses the same
journal transaction as the final readonly resource checks.
"""
from copy import deepcopy
import json
import re

from .manifest import Conflict, canonical, fingerprint
from .qemu_process import validate_process_record
from .vm_shutdown_observation import VMShutdownObservation
from .vm_template import digest, fields, require


def _capability(value, original):
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
    record = validate_process_record(original['boot']['process_record'])
    require(value['id'] == operation and fingerprint(value) == row['fingerprint']
            and value['definition_id'] == row['definition_id'] == value['birth']['creator_operation_id']
            and value['birth'] == original['birth'] and value['original_sha256'] == fingerprint(original)
            and row['boot_source_id'] == original['boot']['source_id']
            and original['boot']['phase'] == 'running'
            and record['birth'] == value['birth']
            and value['phase'] in ('prepared','requested','completed'), 'original VM shutdown lineage differs')
    _capability(value['capability'],original)
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
        expected = dict(kind='ordinary-qemu-shutdown-v1',birth=deepcopy(value['birth']),
            definition_sha256=original['request_fingerprint'],
            exit=dict(reference=reference,process=original['boot']['process_record']['process'],exited=True),
            inactive_ack=original['ack'],reason='guest-shutdown')
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
    require(definitions.read(value['definition_id']) == original == value['original'],
            'completed VM shutdown belongs to another generation')
    definitions._session(original)
    domain = definitions.connection.lookupByUUIDString(original['birth']['uuid'])
    require(VMShutdownObservation._ordinary_state(domain)
            and definitions._ack(original,domain) == original['ack'], 'original stopped VM definition changed')
    return deepcopy(value['proof'])


class VMShutdownDriver:
    def __init__(self, boot, *, capability):
        require(callable(capability), 'qualified readonly template shutdown provider required')
        self.boot,self.definitions,self.journal = boot,boot.definitions,boot.journal
        self.capability = capability
        self.observe_exit = VMShutdownObservation(boot)
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_shutdown_intents '
                '(id TEXT PRIMARY KEY,definition_id TEXT NOT NULL,boot_source_id TEXT NOT NULL,'
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL,UNIQUE(definition_id,boot_source_id))')

    def read(self, operation):return _read(self.journal,operation)

    def _write(self, value):
        self.journal.db.execute('UPDATE vm_shutdown_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    def _source(self, value):
        original = self.definitions.read(value['definition_id'])
        require(original == value['original'], 'original VM changed during shutdown')
        self.definitions._fence(original);self.definitions._session(original)
        capability = self.capability(deepcopy(original))
        require(fingerprint(capability) == fingerprint(value['capability']), 'original shutdown qualification changed')
        _capability(capability,original)
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
            require(self.boot._boot(original)['phase'] == 'running' and witness is not None,
                    'original running boot and held pidfd required before shutdown')
            held = self.journal.db.execute('SELECT id FROM vm_shutdown_intents WHERE definition_id=? AND boot_source_id=?',
                (definition_id,original['boot']['source_id'])).fetchone()
            if held is not None:raise Conflict('original boot already has a shutdown intent; no replacement')
            capability = self.capability(deepcopy(original));_capability(capability,original)
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
                    require(domain.shutdownFlags(1) == 0, 'original ACPI shutdown request did not complete')
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
