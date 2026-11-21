"""Coordinate original overlays after acknowledged definition retirement.

Historical storage/definition receipts remain held. TAP/directory observation is
an explicit provider, independent of the retired storage set. No restart, wipe,
domain mutation or reservation release is performed here.
"""
from copy import deepcopy
import json

from .backend_reservations import available, verify_tap_reservations
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_definition_retirement import UnstartedDefinitionRetirement
from .vm_overlay_retirement import OverlayRetirement
from .vm_storage import VMStorage
from .vm_template import fields, require, template_digest


class VMStorageRetirement:
    def __init__(self, storage, retirement, *, window, preflight):
        require(isinstance(storage,VMStorage) and isinstance(retirement,UnstartedDefinitionRetirement)
                and retirement.definitions is storage.definitions and callable(preflight),
                'original storage, definition retirement and remaining-resource observer required')
        self.storage,self.retirement,self.preflight = storage,retirement,preflight
        self.definitions,self.journal = storage.definitions,storage.journal
        self.files = OverlayRetirement(storage.files,window=window,preflight=self._overlay_preflight)
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_storage_retirements '
                '(id TEXT PRIMARY KEY,definition_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_storage_retirements WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original VM storage retirement missing')
        value = json.loads(row['payload'])
        fields(value,('id','birth','definition','storage','retirement','window_sha256','phase','proof'),
               'original VM storage retirement')
        require(fingerprint(value) == row['fingerprint'] and value['id'] == row['id'] == operation
                and row['definition_id'] == value['birth']['creator_operation_id'] == value['storage']['id']
                and value['birth'] == value['definition']['birth'] == value['storage']['birth'] == value['retirement']['birth']
                and value['phase'] in ('prepared','removing','removed')
                and value['window_sha256'] == self.files.window.sha256,
                'original VM storage retirement lineage differs')
        expected = self._proof(value) if value['phase'] == 'removed' else None
        require(fingerprint(value['proof']) == fingerprint(expected), 'original storage absence receipt differs')
        return value

    @staticmethod
    def _proof(value):
        return dict(storage_sha256=fingerprint(value['storage']),retirement_sha256=fingerprint(value['retirement']),
                    overlay_nonces=[item['nonce'] for item in value['storage']['items']],all_overlays_removed=True)

    def _write(self, value):
        self.journal.db.execute('UPDATE vm_storage_retirements SET payload=?,fingerprint=? WHERE id=?',
                                (canonical(value),fingerprint(value),value['id']))

    def _source(self, value):
        require(self.files.files is self.storage.files and self.storage.definitions is self.definitions
                and self.retirement.definitions is self.definitions
                and self.files.journal is self.storage.journal is self.journal,
                'original VM storage retirement controllers changed')
        original = value['retirement'];current = self.definitions.read(value['storage']['id'])
        require(self.retirement.read(original['id']) == original and original['phase'] == 'retired',
                'completed original definition retirement required')
        expected = deepcopy(original['definition'])
        expected.update(phase='retired',retirement=dict(id=original['id'],definition_sha256=original['definition_sha256']))
        require(current == value['definition'] == expected and self.storage.read(value['storage']['id']) == value['storage']
                and value['storage']['phase'] == 'ready', 'original retired VM storage changed')
        self.definitions._session(current);self.definitions._fence(current)
        available(self.journal,current['birth']['lab_id'],current['birth']['node_id'],'libvirt',vm_birth=current['birth'])
        verify_tap_reservations(self.journal,current['birth'],current['xml'])
        ack = original['definition']['creation_ack']
        self.definitions._absent(self.definitions.connection.lookupByUUIDString,ack['uuid'])
        self.definitions._absent(self.definitions.connection.lookupByName,ack['name'])
        require(self.storage._writer_state(value['storage']) == [], 'VM storage retirement requires no writers')
        require(self.storage.assets(deepcopy(value['storage'])) == dict(
            template_sha256=template_digest(value['storage']['template']),assets_verified=True),
            'original immutable VM assets changed during retirement')
        expected_resources = dict(definition_sha256=current['request_fingerprint'],
            retirement_sha256=fingerprint(original),endpoints_verified=True,directory_verified=True)
        require(fingerprint(self.preflight(deepcopy(value))) == fingerprint(expected_resources),
                'complete remaining VM endpoint/directory preflight required')
        for item in value['storage']['items']:
            self.files.window.verify(self.files._key(item),value['storage']['id'],value['window_sha256'])
        require(self.definitions.read(value['storage']['id']) == current, 'VM owner changed during retirement preflight')
        self.definitions._fence(current)

    def _set(self, value):
        operation = value['storage']['id'];items = value['storage']['items']
        rows = self.journal.db.execute('SELECT nonce FROM vm_overlay_retirements WHERE operation_id=?',(operation,)).fetchall()
        require({row['nonce'] for row in rows} <= {item['nonce'] for item in items},
                'unexpected overlay retirement outside original VM disk set')
        for item in items:
            if any(row['nonce'] == item['nonce'] for row in rows):
                child = self.files.read(item,operation)
                require(child['definition_retirement_sha256'] == fingerprint(value['retirement']),
                        'overlay retirement belongs to another definition retirement')
                self.files._layout(child)
                if value['phase'] == 'removed':require(child['phase'] == 'removed', 'incomplete original storage removal')
            else:
                require(value['phase'] != 'removed' and self.storage.files.observe(item,operation) == item['proof'],
                        'original overlay missing before retirement intent')

    def _check(self, value):
        self._source(value);self._set(value);self._source(value)

    def _overlay_preflight(self, child):
        row = self.journal.db.execute('SELECT id FROM vm_storage_retirements WHERE definition_id=?',
                                      (child['operation_id'],)).fetchone()
        require(row is not None, 'original whole-set VM retirement required before overlay mutation')
        value = self.read(row['id'])
        require(child['item'] in value['storage']['items'] and child['definition_retirement_sha256'] == fingerprint(value['retirement']),
                'original storage retirement child differs')
        self._check(value)
        return dict(operation_id=child['operation_id'],spec_sha256=fingerprint(child['item']['spec']),
            definition_retirement_sha256=fingerprint(value['retirement']),domain_absent_verified=True,
            writers_absent=True,resources_verified=True)

    def prepare(self, operation, definition_id, retirement_id):
        identifier(operation,'storage retirement operation_id')
        with self.journal.execution_lock:
            row = self.journal.db.execute('SELECT id FROM vm_storage_retirements WHERE id=? OR definition_id=?',
                                          (operation,definition_id)).fetchone()
            if row is not None:
                value = self.read(row['id'])
                require(value['id'] == operation and value['storage']['id'] == definition_id
                        and value['retirement']['id'] == retirement_id,'original storage retirement request differs')
                self._check(value);return value
            storage = self.storage.read(definition_id)
            value = dict(id=operation,birth=deepcopy(storage['birth']),definition=self.definitions.read(definition_id),
                storage=storage,retirement=self.retirement.read(retirement_id),window_sha256=self.files.window.sha256,
                phase='prepared',proof=None)
            self._check(value)
            with self.journal.transaction():
                self._check(value)
                self.journal.db.execute('INSERT INTO vm_storage_retirements VALUES(?,?,?,?)',
                    (operation,definition_id,canonical(value),fingerprint(value)))
            return self.read(operation)

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);self._check(value)
            if value['phase'] == 'removed':return value
            if value['phase'] == 'prepared':
                with self.journal.transaction():
                    value['phase'] = 'removing';self._write(value);self._check(value)
            for item in value['storage']['items']:
                self._check(value)
                self.files.prepare(item,value['storage']['id'],definition_retirement_sha256=fingerprint(value['retirement']))
                self.files.apply(item,value['storage']['id'])
            with self.journal.transaction():
                value.update(phase='removed',proof=self._proof(value));self._write(value);self._check(value)
            return self.read(operation)
