"""Release the complete original TAP set after qualified domain retirement.

The creator actor and devices must still exist. Persistent birth/ifindex/name
claims remain held; this does not adopt interfaces or release node reservations.
Storage/directory verification is explicit and independent of live TAP presence.
"""
from copy import deepcopy
import json

from .backend_reservations import available, verify_tap_reservations
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_definition_retirement import UnstartedDefinitionRetirement
from .vm_tap_local import LocalTapEndpoints
from .vm_tap_retention import ownership, request_part, signature
from .vm_taps import VMTaps
from .vm_template import fields, require


class VMTapRetirement:
    def __init__(self, taps, retirement, *, preflight):
        require(isinstance(taps,VMTaps) and isinstance(taps.endpoints,LocalTapEndpoints)
                and isinstance(retirement,UnstartedDefinitionRetirement)
                and taps.definitions is retirement.definitions and callable(preflight),
                'original TAP actor, definition retirement and remaining-resource observer required')
        self.taps,self.retirement,self.preflight = taps,retirement,preflight
        self.endpoints,self.definitions,self.journal = taps.endpoints,taps.definitions,taps.journal
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_retirements '
                '(id TEXT PRIMARY KEY,definition_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_tap_retirements WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original VM TAP retirement missing')
        value = json.loads(row['payload'])
        fields(value,('id','birth','definition','tap_set','retirement','actor','items','phase','proof'),'VM TAP retirement')
        require(fingerprint(value) == row['fingerprint'] and value['id'] == row['id'] == operation
                and row['definition_id'] == value['tap_set']['id'] == value['birth']['creator_operation_id']
                and value['birth'] == value['definition']['birth'] == value['retirement']['birth'] == value['tap_set']['birth']
                and value['phase'] in ('prepared','removing','removed')
                and [item['nonce'] for item in value['items']] == [item['spec']['tap']['nonce'] for item in value['tap_set']['items']],
                'original VM TAP retirement lineage differs')
        for item in value['items']:
            fields(item,('nonce','creator','phase','proof'),'VM TAP retirement child')
            require(item['phase'] in ('prepared','releasing','close_requested','absent')
                    and (item['phase'] == 'absent') == (item['proof'] is not None), 'original TAP retirement step differs')
        expected = self._proof(value) if value['phase'] == 'removed' else None
        require(fingerprint(value['proof']) == fingerprint(expected), 'original VM TAP absence receipt differs')
        return value

    @staticmethod
    def _proof(value):
        return dict(tap_set_sha256=fingerprint(value['tap_set']),retirement_sha256=fingerprint(value['retirement']),
                    absence_sha256=[fingerprint(item['proof']) for item in value['items']],all_taps_absent=True)

    def _write(self, value):
        self.journal.db.execute('UPDATE vm_tap_retirements SET payload=?,fingerprint=? WHERE id=?',
                                (canonical(value),fingerprint(value),value['id']))

    def _source(self, value, *, held=True):
        if held:require(self.read(value['id']) == value, 'original TAP retirement changed')
        require(self.taps.endpoints is self.endpoints and self.taps.definitions is self.definitions
                and self.retirement.definitions is self.definitions and self.endpoints.journal is self.journal,
                'original TAP retirement controllers changed')
        original = value['retirement'];operation = value['tap_set']['id']
        require(self.retirement.read(original['id']) == original and original['phase'] == 'retired',
                'completed original definition retirement required before TAP release')
        expected = deepcopy(original['definition'])
        expected.update(phase='retired',retirement=dict(id=original['id'],definition_sha256=original['definition_sha256']))
        require(self.definitions.read(operation) == value['definition'] == expected
                and self.taps.read(operation) == value['tap_set'] and value['tap_set']['phase'] == 'retained'
                and self.taps.read_context() == value['tap_set']['context']
                and self.endpoints._actor(operation) == value['actor'], 'original retired TAP owner or context changed')
        self.definitions._fence(expected);self.definitions._session(expected)
        available(self.journal,expected['birth']['lab_id'],expected['birth']['node_id'],'libvirt',vm_birth=expected['birth'])
        verify_tap_reservations(self.journal,expected['birth'],expected['xml'])
        claims = {(row['ifindex'],row['interface_name']) for row in self.journal.db.execute(
            'SELECT ifindex,interface_name FROM vm_tap_ifindices WHERE operation_id=?',(operation,))}
        require(claims == {(item['spec']['tap']['ifindex'],item['spec']['tap']['name']) for item in value['tap_set']['items']},
                'original TAP ifindex reservations changed during retirement')
        ack = original['definition']['creation_ack']
        self.definitions._absent(self.definitions.connection.lookupByUUIDString,ack['uuid'])
        self.definitions._absent(self.definitions.connection.lookupByName,ack['name'])
        require(self.taps._writers(value['tap_set'],expected) == [], 'TAP retirement requires qualified writer absence')
        require(fingerprint(self.preflight(deepcopy(value))) == fingerprint(dict(
            definition_sha256=expected['request_fingerprint'],retirement_sha256=fingerprint(original),
            storage_verified=True,directory_verified=True)), 'complete remaining storage/directory preflight required')
        self.definitions._fence(expected);self.definitions._session(expected)
        require(self.definitions.read(operation) == expected, 'VM changed during TAP retirement preflight')

    def _lease(self, value, item, child):
        operation = value['tap_set']['id']
        require(self.endpoints._source(item,operation) == child['creator'], 'original TAP creator changed during retirement')
        def preflight(retained):
            require(request_part(retained) == request_part(item['proof']['retention']),
                    'retirement cannot replace original TAP lease')
            self._check(value)
            return dict(request_sha256=retained['request_sha256'],lease_token=retained['lease_token'],
                original_birth_sha256=fingerprint(retained['birth']),resources_verified=True,guest_writers_absent=True)
        return self.endpoints.retirement_lease(item,operation,preflight=preflight)

    def _layout(self, value):
        for item,child in zip(value['tap_set']['items'],value['items']):
            lease = self._lease(value,item,child);retained = lease.read(child['nonce'])
            expected = deepcopy(item['proof']['retention'])
            expected.update(phase=retained['phase'],proof=retained['proof'])
            require(retained == expected and retained['phase'] in ('retained','release_requested','released','absent'),
                    'original TAP release lineage changed')
            allowed = dict(prepared=('retained',),releasing=('retained','release_requested','released'),
                           close_requested=('released','absent'),absent=('absent',))
            require(retained['phase'] in allowed[child['phase']], 'original TAP release chronology differs')
            device = lease.device
            if device._fd is None:
                require(child['phase'] in ('close_requested','absent') and retained['phase'] in ('released','absent')
                        and not device._links(), 'original TAP closure or name/index absence is unqualified')
            else:
                require(retained['phase'] != 'absent', 'original absent TAP descriptor reappeared')
                proof = device.capture();owners = ownership(proof)
                permitted = [1,0] if retained['phase'] == 'release_requested' else [0 if retained['phase'] == 'released' else 1]
                require(signature(proof) == signature(retained['birth'])
                        and owners[:2] == [retained['uid'],retained['gid']] and owners[2] in permitted,
                        'original retained TAP kernel identity changed')
            if child['phase'] == 'absent':require(child['proof'] == retained, 'original TAP absence receipt changed')

    def _check(self, value, *, held=True):
        self._source(value,held=held);self._layout(value);self._source(value,held=held)
        if value['phase'] == 'removed':require(all(item['phase'] == 'absent' for item in value['items']), 'incomplete TAP removal')

    def prepare(self, operation, definition_id, retirement_id):
        identifier(operation,'TAP retirement operation_id')
        with self.journal.execution_lock:
            row = self.journal.db.execute('SELECT id FROM vm_tap_retirements WHERE id=? OR definition_id=?',
                                          (operation,definition_id)).fetchone()
            if row is not None:
                value = self.read(row['id'])
                require(value['id'] == operation and value['tap_set']['id'] == definition_id
                        and value['retirement']['id'] == retirement_id, 'original TAP retirement request differs')
                self._check(value);return value
            taps = self.taps.read(definition_id)
            value = dict(id=operation,birth=deepcopy(taps['birth']),definition=self.definitions.read(definition_id),
                tap_set=taps,retirement=self.retirement.read(retirement_id),actor=self.endpoints._actor(definition_id),
                items=[dict(nonce=item['spec']['tap']['nonce'],creator=self.endpoints._source(item,definition_id),
                            phase='prepared',proof=None) for item in taps['items']],phase='prepared',proof=None)
            self._check(value,held=False)
            with self.journal.transaction():
                self._check(value,held=False)
                self.journal.db.execute('INSERT INTO vm_tap_retirements VALUES(?,?,?,?)',
                    (operation,definition_id,canonical(value),fingerprint(value)))
            return self.read(operation)

    def _advance(self, value, child=None, **changes):
        with self.journal.transaction():
            self._check(value)
            (value if child is None else child).update(**changes)
            self._write(value);self._check(value)

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);self._check(value)
            if value['phase'] == 'removed':return value
            if value['phase'] == 'prepared':self._advance(value,phase='removing')
            for item,child in zip(value['tap_set']['items'],value['items']):
                self._check(value)
                if child['phase'] == 'absent':continue
                lease = self._lease(value,item,child)
                if child['phase'] == 'prepared':self._advance(value,child,phase='releasing')
                if child['phase'] == 'releasing':
                    lease.release(child['nonce'])
                    self._advance(value,child,phase='close_requested')
                self._check(value)
                if lease.device._fd is not None:lease.device.close()
                proof = lease.confirm_absent(child['nonce'])
                self._advance(value,child,phase='absent',proof=proof)
            self._advance(value,phase='removed',proof=self._proof(value))
            return self.read(operation)
