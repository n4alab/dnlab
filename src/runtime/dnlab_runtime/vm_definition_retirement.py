"""Definition-only retirement of an acknowledged VM that has never booted.

No shutdown, disk/TAP deletion or reservation release is performed. Original
resources and journal history stay held for their separately qualified cleanup.
Undefine is sent at most once; uncertain presence stays pending without resend.
"""
from copy import deepcopy
import json
from xml.etree import ElementTree as ET

from .libvirt_observer import xml_fingerprint
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_definition import creation_acknowledgement
from .vm_template import require


class UnstartedDefinitionRetirement:
    def __init__(self, definitions, *, preflight):
        require(callable(preflight), 'complete never-started retirement preflight required')
        self.definitions, self.journal, self.preflight = definitions, definitions.journal, preflight
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_definition_retirements '
                '(id TEXT PRIMARY KEY,definition_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM vm_definition_retirements WHERE id=?', (operation,)).fetchone()
        if row is None:raise Conflict('original VM definition retirement missing')
        value = json.loads(row['payload'])
        if (fingerprint(value) != row['fingerprint'] or value['id'] != operation
                or value['definition']['birth']['creator_operation_id'] != row['definition_id']
                or value['birth'] != value['definition']['birth']
                or value['definition_sha256'] != fingerprint(value['definition'])
                or value['phase'] not in ('prepared','undefine_requested','retired')
                or 'boot' in value['definition'] or value['definition'].get('retirement') is not None):
            raise Conflict('original never-started retirement differs')
        creation_acknowledgement(value['definition'])
        if value['call_ack'] not in (None, {'return_code':0}):raise Conflict('original undefine response differs')
        if value['phase'] == 'prepared' and value['call_ack'] is not None:
            raise Conflict('unexpected early undefine response')
        if value['phase'] == 'retired':
            expected = dict(definition_sha256=value['definition_sha256'],
                creation_sha256=fingerprint(value['definition']['creation_ack']), domain_absent_verified=True,
                never_started=True, undefine_response=value['call_ack'])
            if value['proof'] != expected:raise Conflict('original definition absence receipt differs')
        elif value['proof'] is not None:raise Conflict('unexpected early definition absence receipt')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_definition_retirements SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value), fingerprint(value), value['id']))

    def _source(self, value, *, held=True):
        original = value['definition']
        current = self.definitions.read(original['birth']['creator_operation_id'])
        expected = deepcopy(original)
        if held:
            expected['phase'] = 'retired' if value['phase'] == 'retired' else 'retirement_requested'
            expected['retirement'] = dict(id=value['id'],definition_sha256=value['definition_sha256'])
        if current != expected:raise Conflict('original never-started definition changed')
        if 'boot' in current:raise Conflict('boot history requires qualified VM shutdown before retirement')
        from .backend_reservations import available
        available(self.journal,current['birth']['lab_id'],current['birth']['node_id'],'libvirt',vm_birth=current['birth'])
        self.definitions._session(current)
        # This initial path deliberately retains the original open lab epoch.
        # Closing-lab teardown and previously booted domains need their own
        # verified exit/cleanup operation; no fence is bypassed here.
        self.definitions._resources(current)
        observed = self.preflight(deepcopy(current))
        require(observed == dict(definition_sha256=value['definition_sha256'],
            session_sha256=original['session_sha256'], never_started=True,
            writers_absent=True, resources_unchanged=True), 'complete never-started cleanup preflight differs')
        return current

    def _missing(self, error):
        code = getattr(error, 'get_error_code', None)
        return callable(code) and code() == self.definitions.missing

    def _absent(self, connection, ack):
        for lookup, key in ((connection.lookupByUUIDString, ack['uuid']), (connection.lookupByName, ack['name'])):
            try:lookup(key)
            except Exception as error:
                if not self._missing(error):raise Conflict('original definition absence is not qualified') from error
            else:raise Conflict('original definition UUID or name is occupied')

    def _domain(self, value, *, held=True, absence=False):
        self._source(value, held=held)
        original = value['definition']; ack = creation_acknowledgement(original)
        connection = self.definitions.connection
        try:domain = connection.lookupByUUIDString(ack['uuid'])
        except Exception as error:
            if not absence or not self._missing(error):raise Conflict('original definition absence is not qualified') from error
            try:connection.lookupByName(ack['name'])
            except Exception as name_error:
                if not self._missing(name_error):raise Conflict('original definition name absence is not qualified') from name_error
            else:raise Conflict('original definition name now belongs to another domain')
            self._source(value, held=held)
            self._absent(connection, ack)
            return None
        if (domain.UUIDString() != ack['uuid'] or domain.name() != ack['name']
                or domain.isPersistent() != 1 or domain.isActive() != 0
                or xml_fingerprint(domain.XMLDesc(2), original['birth']) != ack['persistent_sha256']):
            raise Conflict('original inactive definition generation differs')
        if (domain.autostart() != 0 or domain.hasManagedSaveImage(0) != 0
                or domain.snapshotNum(0) != 0 or domain.checkpointCount() != 0
                or ET.fromstring(ack['xml']).find('os/nvram') is not None):
            raise Conflict('unstarted definition has autostart or retained VM state')
        if (domain.UUIDString() != ack['uuid'] or domain.isActive() != 0
                or xml_fingerprint(domain.XMLDesc(2), original['birth']) != ack['persistent_sha256']):
            raise Conflict('definition changed during never-started observation')
        self._source(value, held=held)
        if (domain.UUIDString() != ack['uuid'] or domain.name() != ack['name']
                or domain.isActive() != 0 or domain.isPersistent() != 1
                or xml_fingerprint(domain.XMLDesc(2), original['birth']) != ack['persistent_sha256']
                or domain.autostart() != 0 or domain.hasManagedSaveImage(0) != 0
                or domain.snapshotNum(0) != 0 or domain.checkpointCount() != 0):
            raise Conflict('definition changed after cleanup resource preflight')
        return domain

    def prepare(self, operation, definition_id):
        identifier(operation, 'definition retirement operation_id')
        with self.journal.execution_lock:
            row = self.journal.db.execute('SELECT id FROM vm_definition_retirements WHERE id=? OR definition_id=?',
                (operation, definition_id)).fetchone()
            if row is not None:
                value = self.read(row['id'])
                if value['id'] != operation or value['definition']['birth']['creator_operation_id'] != definition_id:
                    raise Conflict('original definition retirement request differs')
                self._domain(value, absence=value['phase'] != 'prepared')
                return value
            original = self.definitions.read(definition_id)
            if ('boot' in original or original.get('retirement') is not None
                    or original['phase'] not in ('defined','define_requested','recovery_required')):
                raise Conflict('only an original acknowledged never-started definition can retire')
            creation_acknowledgement(original)
            value = dict(id=operation,birth=deepcopy(original['birth']),definition=original,definition_sha256=fingerprint(original),
                         phase='prepared',call_ack=None,proof=None)
            self._domain(value, held=False)
            with self.journal.transaction():
                self._source(value, held=False)
                self.journal.db.execute('INSERT INTO vm_definition_retirements VALUES(?,?,?,?)',
                    (operation, definition_id, canonical(value), fingerprint(value)))
                current = deepcopy(original)
                current.update(phase='retirement_requested',retirement=dict(id=operation,definition_sha256=value['definition_sha256']))
                self.definitions._save(definition_id, current)
            return self.read(operation)

    def _finish(self, value):
        if self._domain(value, absence=True) is not None:
            raise Conflict('uncertain undefine left original domain present; no resend')
        proof = dict(definition_sha256=value['definition_sha256'],
            creation_sha256=fingerprint(value['definition']['creation_ack']), domain_absent_verified=True,
            never_started=True, undefine_response=value['call_ack'])
        with self.journal.transaction():
            current = self._source(value)
            if self._domain(value, absence=True) is not None:raise Conflict('original definition reappeared before retirement commit')
            current['phase'] = 'retired'
            self.definitions._save(current['birth']['creator_operation_id'], current)
            value.update(phase='retired',proof=proof)
            self._save(value)
            if self._domain(value, absence=True) is not None:raise Conflict('original definition reappeared during retirement commit')
        return self.read(value['id'])

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'retired':
                if self._domain(value, absence=True) is not None:raise Conflict('retired definition reappeared')
                return value
            if value['phase'] == 'undefine_requested':return self._finish(value)
            self._domain(value)
            with self.journal.transaction():
                self._source(value)
                value['phase'] = 'undefine_requested';self._save(value)
            domain = self._domain(value)
            result = domain.undefineFlags(0)
            require(type(result) is int and result == 0, 'original undefine response uncertain; recover without resend')
            value['call_ack'] = {'return_code':0}
            with self.journal.transaction():self._save(value)
            return self._finish(value)
