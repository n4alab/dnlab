"""Durable candidate staging only; never replaces or reloads an installed unit.

The complete inactive-session preflight remains mandatory and injected. Both
source and candidate use the existing filesystem birth observer. Interrupted
creation requires explicit durability recovery of the original birth.
"""
from copy import deepcopy
import json

from .libvirt_configuration import compile_revision
from .manifest import Conflict, canonical, fingerprint


class ConfigurationStaging:
    def __init__(self, journal, files, *, window, preflight=None, readonly=False):
        if not readonly and not callable(preflight):raise Conflict('complete configuration preflight required')
        self.journal,self.files,self.window,self.preflight=journal,files,window,preflight
        self.readonly=readonly
        if readonly:return
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_configuration_staging '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @staticmethod
    def item(value):
        spec=deepcopy(value['plan']['target_spec'])
        spec.update(path=value['staging'],key='file:'+value['staging'])
        return dict(spec=spec,nonce=value['nonce'])

    def _check(self,value,*,require_window=True):
        if self.readonly:raise Conflict('readonly configuration staging')
        if (value['plan']!=compile_revision(value['installation'])
                or value['source_sha256']!=fingerprint(value['installation'])
                or value['phase'] not in ('prepared','replace_requested')
                or self.window.sha256!=value['window_sha256']
                or self.window.receipt['context']!=value['installation']['context']):
            raise Conflict('original configuration staging binding differs')
        nonce=value['nonce']
        if (not isinstance(nonce,str) or len(nonce)!=32
                or any(c not in '0123456789abcdef' for c in nonce)
                or value['staging']!='/etc/systemd/system/.dnlab-libvirtd.'+nonce+'.candidate'):
            raise Conflict('original configuration staging path differs')
        target=dict(spec=value['plan']['target_spec'])
        if require_window:self.window.verify(target,value['id'],value['window_sha256'])
        expected=dict(revision_sha256=fingerprint(value),source_proof=value['plan']['source_item']['proof'])
        if self.preflight(deepcopy(value))!=expected:
            raise Conflict('complete inactive configuration staging preflight differs')
        source=self.files.observe(value['plan']['source_item'],value['installation']['id'])
        if source!=value['plan']['source_item']['proof']:
            raise Conflict('original installed unit differs before staging')
        if require_window:self.window.verify(target,value['id'],value['window_sha256'])

    def _read(self,value):
        row=self.journal.db.execute('SELECT * FROM libvirt_configuration_staging WHERE id=?',(value['id'],)).fetchone()
        if row is None:return None
        record=json.loads(row['payload'])
        if (fingerprint(record)!=row['fingerprint'] or record['revision']!=value
                or record['item']!=self.item(value)
                or record['phase'] not in ('stage_requested','staged')
                or record['phase']=='stage_requested' and record['proof'] is not None):
            raise Conflict('original staging intent differs')
        return record

    def _save(self,record):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_configuration_staging SET payload=?,fingerprint=? WHERE id=?',
                (canonical(record),fingerprint(record),record['revision']['id']))

    def observe(self,value):
        with self.journal.execution_lock:
            self._check(value,require_window=False)
            record=self._read(value)
            if record is None:return None
            if record['phase']!='staged':raise Conflict('configuration staging pending; explicit recovery required')
            proof=self.files.observe(record['item'],value['id'])
            if proof is None or proof!=record['proof']:raise Conflict('original staged candidate differs')
            return deepcopy(proof)

    def stage(self,value):
        with self.journal.execution_lock:
            self._check(value)
            record=self._read(value)
            if record is not None:return self.observe(value)
            item=self.item(value)
            if self.files.observe(item,value['id']) is not None:raise Conflict('staging target already occupied')
            record=dict(revision=deepcopy(value),item=item,phase='stage_requested',proof=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_configuration_staging VALUES(?,?,?)',
                    (value['id'],canonical(record),fingerprint(record)))
            self._check(value)
            proof=self.files.create(item,value['id'])
            self._check(value)
            if self.files.observe(item,value['id'])!=proof:raise Conflict('candidate birth not independently observed')
            record.update(phase='staged',proof=proof)
            self._save(record)
            return self.observe(value)

    def recover(self,value):
        with self.journal.execution_lock:
            self._check(value)
            record=self._read(value)
            if record is None:raise Conflict('original staging intent missing; no create on recovery')
            if record['phase']=='staged':return self.observe(value)
            # The filesystem adapter refuses recovery without its original FD birth.
            proof=self.files.recover(record['item'],value['id'])
            self._check(value)
            if self.files.observe(record['item'],value['id'])!=proof:
                raise Conflict('recovered candidate birth not independently observed')
            record.update(phase='staged',proof=proof)
            self._save(record)
            return self.observe(value)
