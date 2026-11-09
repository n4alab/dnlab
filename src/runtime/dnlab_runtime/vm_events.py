"""Durable VM event reduction using the runtime's existing local journal.

The observation provider must verify the original domain/configuration and
QEMU process; events alone do not prove ownership or a user's intent. This
module never starts, stops, resets or reconnects to a hypervisor. A disconnected
or inconsistent stream remains in recovery until an explicit qualified recovery
path is implemented; reopening the journal cannot silently renew it.
"""
import json
import re
import uuid

from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_template import digest, fields, require
from .workload_identity import WorkloadReference


def validate_birth(value):
    fields(value, ('uuid', 'lab_id', 'node_id', 'host_id', 'generation', 'creator_operation_id', 'nonce', 'template_sha256'), 'VM event birth')
    WorkloadReference('libvirt', 'vm', value['uuid'])
    for key in ('lab_id', 'node_id', 'host_id'):identifier(value[key], key)
    require(type(value['generation']) is int and value['generation'] > 0 and digest(value['template_sha256'])
            and all(isinstance(value[k], str) and re.fullmatch(r'[0-9a-f]{32}', value[k])
                    for k in ('creator_operation_id', 'nonce')), 'invalid VM event birth')


def validate_observation(value, birth):
    fields(value, ('birth', 'config_sha256', 'process'), 'VM observation')
    require(value['birth'] == birth and digest(value['config_sha256']), 'VM observation owner differs')
    process = value['process']
    if process is not None:
        fields(process, ('boot_id', 'pid', 'start_ticks', 'executable_sha256'), 'QEMU process')
        require(isinstance(process['boot_id'], str) and process['boot_id']
                and type(process['pid']) is int and process['pid'] > 0
                and type(process['start_ticks']) is int and process['start_ticks'] > 0
                and digest(process['executable_sha256']), 'invalid QEMU process observation')


class VMEventTracker:
    def __init__(self, journal, observe):
        self.journal, self.observe = journal, observe
        # Never recover this token from the journal: a new collector cannot
        # claim continuous observation of a previous connection's events.
        self.monitor_id = uuid.uuid4().hex
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_event_streams (id TEXT PRIMARY KEY,domain_uuid TEXT NOT NULL UNIQUE,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_events (stream_id TEXT NOT NULL,sequence INTEGER NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,PRIMARY KEY(stream_id,sequence))')

    def read(self, stream_id):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT payload,fingerprint FROM vm_event_streams WHERE id=?', (stream_id,)).fetchone()
        if row is None:raise Conflict('original VM event stream missing')
        value = json.loads(row['payload'])
        if fingerprint(value) != row['fingerprint']:raise Conflict('VM event stream integrity differs')
        return value

    def _save(self, stream_id, value):
        self.journal.db.execute('UPDATE vm_event_streams SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value), fingerprint(value), stream_id))

    def begin(self, stream_id, birth):
        require(isinstance(stream_id, str) and re.fullmatch(r'[0-9a-f]{32}', stream_id), 'original event source token required')
        validate_birth(birth)
        with self.journal.transaction():
            row = self.journal.db.execute('SELECT id FROM vm_event_streams WHERE domain_uuid=?', (birth['uuid'],)).fetchone()
            if row:
                if row['id'] != stream_id:raise Conflict('VM event source cannot be implicitly replaced')
                saved = self.read(stream_id)
                if saved['birth'] != birth or saved['phase'] != 'active':raise Conflict('VM event stream requires qualified recovery')
                if saved['monitor_id'] != self.monitor_id:raise Conflict('VM collector continuity requires qualified recovery')
                observed = self.observe(birth)
                validate_observation(observed, birth)
                if observed != saved['original']:raise Conflict('VM event source generation changed')
                return saved
            observed = self.observe(birth)
            validate_observation(observed, birth)
            require(observed['process'] is not None, 'running original QEMU process required')
            value = {'birth': birth, 'original': observed, 'monitor_id': self.monitor_id, 'phase': 'active', 'last_sequence': 0,
                     'reboot_count': 0, 'guest_readiness': 'unknown', 'reason': ''}
            self.journal.db.execute('INSERT INTO vm_event_streams VALUES(?,?,?,?)',
                (stream_id, birth['uuid'], canonical(value), fingerprint(value)))
            return self.read(stream_id)

    def record(self, stream_id, sequence, kind):
        require(type(sequence) is int and sequence > 0
                and kind in ('reboot', 'crash', 'stopped', 'started', 'connection-lost'), 'invalid VM event')
        event = {'sequence': sequence, 'kind': kind}
        with self.journal.transaction():
            value = self.read(stream_id)
            if value['monitor_id'] != self.monitor_id:
                raise Conflict('VM collector continuity requires qualified recovery')
            prior = self.journal.db.execute('SELECT payload,fingerprint FROM vm_events WHERE stream_id=? AND sequence=?',
                (stream_id, sequence)).fetchone()
            if prior:
                previous = json.loads(prior['payload'])
                if fingerprint(previous) != prior['fingerprint'] or previous['event'] != event:
                    raise Conflict('VM event sequence reused with different content')
                return previous
            reason = ''
            observed = None
            if value['phase'] != 'active':reason = 'original stream is not active'
            elif sequence != value['last_sequence'] + 1:reason = 'event sequence gap or reordering'
            elif kind == 'connection-lost':reason = 'hypervisor connection lost; history incomplete'
            else:
                try:
                    observed = self.observe(value['birth'])
                    validate_observation(observed, value['birth'])
                    original = value['original']
                    if observed['config_sha256'] != original['config_sha256']:reason = 'VM configuration changed'
                    elif kind == 'reboot' and observed['process'] != original['process']:reason = 'QEMU incarnation changed or exited'
                except Exception as error:
                    reason = 'VM re-observation failed (' + type(error).__name__ + ')'
            if reason:
                value.update(phase='recovery_required', reason=reason)
            elif kind == 'reboot':
                value['reboot_count'] += 1
            else:
                # A lifecycle notification is not proof of graceful NOS stop
                # or authorization to adopt a newly started process.
                value.update(phase='recovery_required', reason='lifecycle event needs qualified operation: ' + kind)
            value['guest_readiness'] = 'unknown'
            value['last_sequence'] = max(sequence, value['last_sequence'])
            result = {'event': event, 'observed': observed, 'state': value}
            self.journal.db.execute('INSERT INTO vm_events VALUES(?,?,?,?)',
                (stream_id, sequence, canonical(result), fingerprint(result)))
            self._save(stream_id, value)
            return json.loads(canonical(result))
