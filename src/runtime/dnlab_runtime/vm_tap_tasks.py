"""Opt-in TAP stages executed by the existing sequential runtime worker.

No scheduler, process launcher or automatic recovery is introduced. Queued
commands reference an already qualified original runtime process. Uncertain
attempts are parked; recovery explicitly reuses that same actor/descriptor set.
"""
from copy import deepcopy
import json

from .libvirt_account_commands import reference_proof
from .manifest import Busy, Conflict, canonical, fingerprint
from .vm_tap_local import LocalTapEndpoints, worker_command
from .vm_template import digest, fields, require

PHASES=('queued','applying','completed','recovery_required')


class TapTasks:
    def __init__(self, taps):
        require(isinstance(taps.endpoints,LocalTapEndpoints), 'original-process TAP provider required')
        self.taps,self.endpoints,self.journal=taps,taps.endpoints,taps.journal
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_tasks '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,phase TEXT NOT NULL, '
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation):
        with self.journal.lock:return self._read(operation)

    def _read(self, operation):
        row=self.journal.db.execute('SELECT * FROM vm_tap_tasks WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original VM TAP task missing')
        value=json.loads(row['payload']);original=self.taps.read(operation)
        fields(value,('id','birth','command_sha256','reference','phase','result_sha256','error_type','error'),'VM TAP task')
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=operation or row['phase']!=value['phase']
                or row['domain_uuid']!=value['birth']['uuid'] or value['birth']!=original['birth']
                or value['command_sha256']!=fingerprint(worker_command(original)) or value['phase'] not in PHASES):
            raise Conflict('original VM TAP task lineage differs')
        reference_proof(value['reference'],worker_command(original))
        require(isinstance(value['error_type'],str) and len(value['error_type'])<=128
            and isinstance(value['error'],str) and len(value['error'])<=1024, 'bounded original TAP task failure required')
        if value['phase']=='completed':require(digest(value['result_sha256']), 'original TAP completion receipt required')
        else:require(value['result_sha256'] is None, 'unexpected early TAP completion receipt')
        if value['phase']!='recovery_required':
            require(value['error_type']==value['error']=='', 'unexpected TAP task failure metadata')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_tap_tasks SET phase=?,payload=?,fingerprint=? WHERE id=?',
            (value['phase'],canonical(value),fingerprint(value),value['id']))

    def _check(self, value, *, held=True):
        if held and self.read(value['id'])!=value:raise Conflict('original TAP task changed')
        original=self.taps.read(value['id'])
        if (value['birth']!=original['birth'] or value['command_sha256']!=fingerprint(worker_command(original))
                or self.endpoints._actor(value['id'])['reference']!=value['reference']):
            raise Conflict('original TAP task actor or command changed')
        self.taps._check(original,mutate=original['phase']!='retained')
        for item in original['items']:
            if item['phase']=='create_requested':self.endpoints._source(item,value['id'])
        if self.endpoints._actor(value['id'])['reference']!=value['reference']:
            raise Conflict('original TAP task actor changed during preflight')
        if held and self.read(value['id'])!=value:raise Conflict('original TAP task changed during preflight')

    def submit(self, operation, reference, *, max_pending=128):
        require(type(max_pending) is int and max_pending>0, 'positive VM TAP task limit required')
        with self.journal.execution_lock:
            original=self.taps.read(operation);reference_proof(reference,worker_command(original))
            if self.journal.db.execute('SELECT 1 FROM vm_tap_tasks WHERE id=?',(operation,)).fetchone():
                value=self.read(operation)
                if value['reference']!=reference:raise Conflict('original TAP task reference cannot change')
                return value
            require(original['phase']=='prepared', 'VM TAP task must precede allocation')
            active=self.journal.db.execute("SELECT count(*) FROM vm_tap_tasks WHERE phase!='completed'").fetchone()[0]
            if active>=max_pending:raise Busy('VM TAP task limit reached')
            # Bind the actor once before the task can become visible to the
            # worker. A lost submit response can only reuse this same binding.
            self.endpoints.bind(operation,reference)
            value=dict(id=operation,birth=deepcopy(original['birth']),command_sha256=fingerprint(worker_command(original)),
                reference=deepcopy(reference),phase='queued',result_sha256=None,error_type='',error='')
            with self.journal.transaction():
                self._check(value,held=False)
                self.journal.db.execute('INSERT INTO vm_tap_tasks VALUES(?,?,?,?,?)',
                    (operation,value['birth']['uuid'],value['phase'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def pending(self):
        with self.journal.lock:
            return [self.read(row['id'])['id'] for row in self.journal.db.execute(
                "SELECT id FROM vm_tap_tasks WHERE phase='queued' ORDER BY rowid")]

    def execute(self, operation):
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase']=='completed':return value  # historical operation receipt, not workload readiness
            if value['phase']!='queued':raise Conflict('TAP task requires explicit original-attempt recovery')
            try:
                with self.journal.transaction():
                    self._check(value)
                    if self.read(operation)!=value:raise Conflict('TAP task changed before execution')
                    value['phase']='applying';self._save(value)
                self._check(value)
                result=self.taps.apply(operation)
                if result['phase']!='retained' or self.taps.observe(operation)!=result:
                    raise Conflict('original complete TAP retention not verified')
                with self.journal.transaction():
                    self._check(value)
                    if self.read(operation)!=value:raise Conflict('TAP task changed before completion')
                    value.update(phase='completed',result_sha256=fingerprint(result));self._save(value)
                return self.read(operation)
            except Exception as error:
                current=self.read(operation)
                immutable=('id','birth','command_sha256','reference')
                if any(current[key]!=value[key] for key in immutable):
                    raise Conflict('original TAP task changed; failure metadata not overwritten') from error
                if current['phase']=='completed':
                    if value['phase']!='completed' or current['result_sha256']!=value['result_sha256']:
                        raise Conflict('unexpected TAP completion; original task preserved') from error
                    return current  # committed completion with a lost caller response
                before=deepcopy(current)
                current.update(phase='recovery_required',error_type=type(error).__name__[:128],error=str(error)[:1024])
                with self.journal.transaction():
                    if self.read(operation)!=before:raise Conflict('TAP failure task changed before recording')
                    self._save(current)
                return self.read(operation)

    def recover(self, operation):
        """Requeue the original command explicitly; never bind a new actor."""
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase'] in ('queued','completed'):return value
            self._check(value)
            with self.journal.transaction():
                self._check(value)
                if self.read(operation)!=value:raise Conflict('original TAP recovery task changed')
                value.update(phase='queued',error_type='',error='');self._save(value)
            return self.read(operation)
