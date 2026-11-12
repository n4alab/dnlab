"""One-shot persistent definition intent; no VM start or automatic redefinition.

Only an exclusive dedicated session writer may use this driver. Definition
normalization must already be qualified: an unexpected libvirt rewrite keeps
the original domain and journal in recovery, without boot or cleanup.
"""
import json
from xml.etree import ElementTree as ET

from .libvirt_observer import xml_fingerprint
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_events import validate_birth
from .vm_template import require


def request_part(value):
    return {key: value[key] for key in ('request_id', 'birth', 'xml', 'session_sha256', 'lab_generation')}


class VMDefinitionDriver:
    def __init__(self, journal, connection, session, preflight, *, no_domain_code):
        require(callable(preflight) and type(no_domain_code) is int and no_domain_code > 0,
                'qualified VM preflight and structured missing-domain code required')
        self.journal, self.connection, self.session = journal, connection, session
        self.preflight, self.missing = preflight, no_domain_code
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_definition_intents (id TEXT PRIMARY KEY,lab TEXT NOT NULL,node TEXT NOT NULL,request_id TEXT NOT NULL,domain_uuid TEXT NOT NULL UNIQUE,domain_name TEXT NOT NULL UNIQUE,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,UNIQUE(lab,request_id),UNIQUE(lab,node))')

    def read(self, operation_id):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM vm_definition_intents WHERE id=?', (operation_id,)).fetchone()
        if row is None:raise Conflict('original VM definition intent missing')
        value = json.loads(row['payload'])
        if type(value.get('lab_generation')) is not int or value['lab_generation'] < 1:
            raise Conflict('original VM lab generation missing or invalid; recovery required')
        if fingerprint(value) != row['fingerprint'] or fingerprint(request_part(value)) != value['request_fingerprint']:
            raise Conflict('VM definition intent integrity differs')
        birth = value['birth']; validate_birth(birth)
        if (birth['creator_operation_id'] != row['id'] or birth['lab_id'] != row['lab']
                or birth['node_id'] != row['node'] or birth['uuid'] != row['domain_uuid']
                or value['request_id'] != row['request_id'] or ET.fromstring(value['xml']).findtext('name') != row['domain_name']):
            raise Conflict('VM definition owner differs')
        return value

    def _save(self, operation_id, value):
        self.journal.db.execute('UPDATE vm_definition_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value), fingerprint(value), operation_id))

    def prepare(self, request_id, birth, xml, *, lab_generation=1):
        identifier(request_id, 'request_id'); validate_birth(birth)
        require(type(lab_generation) is int and lab_generation > 0, 'positive original lab generation required')
        xml_fingerprint(xml, birth)
        name = ET.fromstring(xml).findtext('name'); identifier(name, 'domain name')
        require(birth['host_id'] == self.session.profile['host_id'], 'VM definition session host differs')
        self._fence({'birth': birth, 'request_id': request_id, 'lab_generation': lab_generation})
        part = {'request_id': request_id, 'birth': birth, 'xml': xml,
                'session_sha256': fingerprint(self.session.proof()), 'lab_generation': lab_generation}
        value = json.loads(canonical({**part, 'request_fingerprint': fingerprint(part), 'phase': 'prepared', 'ack': None, 'error_type': ''}))
        with self.journal.transaction():
            self._fence(value)
            prior = self.journal.db.execute('SELECT id FROM vm_definition_intents WHERE lab=? AND request_id=?',
                (birth['lab_id'], request_id)).fetchone()
            if prior:
                saved = self.read(prior['id'])
                if saved['request_fingerprint'] != value['request_fingerprint']:raise Conflict('VM request_id content differs')
                from .backend_reservations import available
                available(self.journal,birth['lab_id'],birth['node_id'],'libvirt',vm_birth=birth)
                return saved
            from .backend_reservations import available
            available(self.journal,birth['lab_id'],birth['node_id'],'libvirt',vm_birth=birth)
            current = self.journal.node(birth['lab_id'], birth['node_id'])
            if current and current['state'] != 'stopped':raise Conflict('node already owns a workload')
            held = self.journal.db.execute('SELECT 1 FROM vm_definition_intents WHERE (lab=? AND node=?) OR domain_uuid=? OR domain_name=?',
                (birth['lab_id'], birth['node_id'], birth['uuid'], name)).fetchone()
            if held:raise Conflict('VM definition identity already reserved')
            from .backend_reservations import tap_keys, storage_keys
            keys = tap_keys(xml) | storage_keys(xml)
            for key in sorted(keys):
                if self.journal.db.execute('SELECT 1 FROM resources WHERE key=?', (key,)).fetchone():
                    raise Conflict(f'resource reserved: {key}')
            for key in sorted(keys):
                self.journal.db.execute('INSERT INTO resources VALUES(?,?,?,?)',
                    (key, birth['lab_id'], birth['node_id'], birth['creator_operation_id']))
            self.journal.db.execute('INSERT INTO vm_definition_intents VALUES(?,?,?,?,?,?,?,?)',
                (birth['creator_operation_id'], birth['lab_id'], birth['node_id'], request_id, birth['uuid'], name,
                 canonical(value), fingerprint(value)))
        return self.read(birth['creator_operation_id'])

    def _fence(self, value):
        from .lab_closure import check
        # This is a definition/start mutation, never a qualified teardown
        # child. The original lab epoch is distinct from VM birth generation.
        check(self.journal, {'lab_id': value['birth']['lab_id'], 'node_id': value['birth']['node_id'],
            'request_id': value['request_id'], 'action': 'vm-define', 'lab_generation': value['lab_generation']})

    def _session(self, value):
        self.session.verify(value['session_sha256'])
        if self.connection.getURI() != self.session.profile['uri']:raise Conflict('dedicated session URI differs')

    def _absent(self, lookup, key):
        try:
            lookup(key)
        except Exception as error:
            code = getattr(error, 'get_error_code', None)
            if callable(code) and code() == self.missing:return
            raise Conflict('domain absence is not qualified') from error
        raise Conflict('domain UUID or name already present; no replacement allowed')

    def _preflight(self, value):
        self._fence(value)
        self._session(value)
        self._absent(self.connection.lookupByUUIDString, value['birth']['uuid'])
        self._absent(self.connection.lookupByName, ET.fromstring(value['xml']).findtext('name'))
        self._resources(value)

    def _resources(self, value):
        from .backend_reservations import verify_tap_reservations
        with self.journal.lock:
            verify_tap_reservations(self.journal, value['birth'], value['xml'])
        receipt = self.preflight(json.loads(canonical(value)))
        require(receipt == {'request_fingerprint': value['request_fingerprint'],
            'session_sha256': value['session_sha256'], 'assets_verified': True,
            'overlays_verified': True, 'endpoints_verified': True}, 'complete qualified VM preflight required')
        self._fence(value)

    def _ack(self, value, domain):
        name = ET.fromstring(value['xml']).findtext('name')
        if (domain.UUIDString() != value['birth']['uuid'] or domain.name() != name
                or domain.isPersistent() != 1 or domain.isActive() != 0):
            raise Conflict('original inactive VM definition differs')
        actual = xml_fingerprint(domain.XMLDesc(2), value['birth'])
        if actual != xml_fingerprint(value['xml'], value['birth']):
            raise Conflict('libvirt definition normalization is not qualified')
        return {'uuid': value['birth']['uuid'], 'name': name, 'persistent_sha256': actual,
                'session_sha256': value['session_sha256']}

    def apply(self, operation_id):
        with self.journal.execution_lock:
            value = self.read(operation_id)
            self._fence(value)
            from .backend_reservations import available
            available(self.journal,value['birth']['lab_id'],value['birth']['node_id'],'libvirt',vm_birth=value['birth'])
            self._session(value)
            if value['phase'] == 'defined':
                actual = self._ack(value, self.connection.lookupByUUIDString(value['birth']['uuid']))
                if actual != value['ack']:raise Conflict('original VM definition acknowledgement differs')
                self._fence(value)
                return value
            if value['phase'] != 'prepared':raise Conflict('uncertain VM definition requires recovery; define is not repeated')
            self._preflight(value)
            value['phase'] = 'define_requested'
            with self.journal.transaction():
                self._fence(value)
                self._save(operation_id, value)
            try:
                # Recheck after the durable write and before the only define.
                self._preflight(value)
                domain = self.connection.defineXMLFlags(value['xml'], 1)
                ack = self._ack(value, domain)
                self._session(value)
                self._fence(value)
            except Exception as error:
                value.update(phase='recovery_required', error_type=type(error).__name__)
                with self.journal.transaction():self._save(operation_id, value)
                raise
            # A failure to confirm this commit must not overwrite an already
            # committed acknowledgement or cause another hypervisor define.
            value.update(phase='defined', ack=ack)
            with self.journal.transaction():
                self._fence(value)
                self._save(operation_id, value)
            return self.read(operation_id)
