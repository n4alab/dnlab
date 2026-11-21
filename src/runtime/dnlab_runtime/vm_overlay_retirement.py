"""Local overlay removal under an explicit exclusive administrative window.

The trusted preflight must prove completed definition retirement, absence of all
writers and the complete remaining resource set. This lower adapter never
infers domain absence or authorizes itself from an absent filename. Original
births remain unchanged; uncertain rename/unlink are never repeated.
"""
from copy import deepcopy
import json
import os
from pathlib import PurePosixPath

from .libvirt_configuration_swap import NOREPLACE, rename_siblings
from .libvirt_provisioning import ProvisioningWindow
from .manifest import Conflict, canonical, fingerprint
from .vm_overlay_files import OverlayFiles
from .vm_template import digest, fields, require


class OverlayRetirement:
    def __init__(self, files, *, window, preflight):
        require(isinstance(files,OverlayFiles) and not files.readonly
                and isinstance(window,ProvisioningWindow) and callable(preflight),
                'original writable overlay adapter, exclusive window and retirement preflight required')
        self.files,self.journal,self.window,self.preflight = files,files.journal,window,preflight
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_overlay_retirements '
                '(operation_id TEXT NOT NULL,nonce TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(operation_id,nonce))')

    def _key(self, item):return dict(spec=dict(key='file:'+item['spec']['path']))

    def _check(self, value):
        require(self.files._load(value['item'],value['operation_id']) == value['original'],
                'original overlay birth changed during retirement')
        self.window.verify(self._key(value['item']),value['operation_id'],value['window_sha256'])
        expected = dict(operation_id=value['operation_id'],spec_sha256=fingerprint(value['item']['spec']),
            definition_retirement_sha256=value['definition_retirement_sha256'],
            domain_absent_verified=True,writers_absent=True,resources_verified=True)
        require(fingerprint(self.preflight(deepcopy(value))) == fingerprint(expected),
                'complete original overlay retirement preflight differs')
        self.window.verify(self._key(value['item']),value['operation_id'],value['window_sha256'])

    def read(self, item, operation):
        row = self.journal.db.execute('SELECT * FROM vm_overlay_retirements WHERE operation_id=? AND nonce=?',
                                      (operation,item['nonce'])).fetchone()
        if row is None:raise Conflict('original overlay retirement intent missing')
        value = json.loads(row['payload'])
        fields(value,('operation_id','item','original','definition_retirement_sha256','window_sha256',
                      'quarantine','phase','proof'),'original overlay retirement')
        require(value['operation_id'] == row['operation_id'] == operation and value['item'] == item
                and fingerprint(value) == row['fingerprint'] and digest(value['definition_retirement_sha256'])
                and value['original']['phase'] == 'ready' and item['proof'] == value['original']['proof']
                and value['window_sha256'] == self.window.sha256
                and value['quarantine'] == self._quarantine(value)
                and value['phase'] in ('prepared','rename_requested','quarantined','unlink_requested','removed'),
                'original overlay retirement lineage differs')
        expected = self._proof(value) if value['phase'] == 'removed' else None
        require(fingerprint(value['proof']) == fingerprint(expected), 'original overlay removal proof differs')
        return value

    @staticmethod
    def _quarantine(value):
        return '.dnlab-retired-'+fingerprint(dict(operation_id=value['operation_id'],item=value['item'],
            definition_retirement_sha256=value['definition_retirement_sha256']))

    @staticmethod
    def _proof(value):
        return dict(original_sha256=fingerprint(value['original']),
            definition_retirement_sha256=value['definition_retirement_sha256'],
            original_path_absent=True,quarantine_absent=True,directory_synced=True)

    def _save(self, value):
        with self.journal.transaction():self._write(value)

    def _write(self, value):
        self.journal.db.execute('UPDATE vm_overlay_retirements SET payload=?,fingerprint=? '
            'WHERE operation_id=? AND nonce=?',(canonical(value),fingerprint(value),value['operation_id'],value['item']['nonce']))

    @staticmethod
    def _exists(parent, name):
        try:os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return False
        return True

    def _verify(self, parent, value, name):
        item = deepcopy(value['item'])
        item['spec']['path'] = str(PurePosixPath(self.files.root)/name)
        with self.files._file(parent,item,value['original']) as fd:
            self.files._chain(fd,value['item']['spec'],allow_dirty=False)
            self._check(value)

    def prepare(self, item, operation, *, definition_retirement_sha256):
        require(digest(definition_retirement_sha256) and item['phase'] == 'ready',
                'completed definition retirement and original ready overlay required')
        with self.journal.execution_lock,self.files._root() as parent:
            row = self.journal.db.execute('SELECT 1 FROM vm_overlay_retirements WHERE operation_id=? AND nonce=?',
                                          (operation,item['nonce'])).fetchone()
            if row is not None:
                value = self.read(item,operation)
                require(value['definition_retirement_sha256'] == definition_retirement_sha256,
                        'original overlay retirement request changed')
                self._check(value);return value
            original = self.files._load(item,operation)
            require(original is not None and original['phase'] == 'ready' and original['proof'] == item['proof'],
                    'original durable overlay birth required before retirement')
            value = dict(operation_id=operation,item=deepcopy(item),original=original,
                definition_retirement_sha256=definition_retirement_sha256,window_sha256=self.window.sha256,
                quarantine='',phase='prepared',proof=None)
            value['quarantine'] = self._quarantine(value)
            self._check(value)
            require(not self._exists(parent,value['quarantine']), 'overlay retirement quarantine occupied')
            self._verify(parent,value,self.files._leaf(item))
            with self.journal.transaction():
                self._check(value)
                self.journal.db.execute('INSERT INTO vm_overlay_retirements VALUES(?,?,?,?)',
                    (operation,item['nonce'],canonical(value),fingerprint(value)))
            return self.read(item,operation)

    def apply(self, item, operation):
        with self.journal.execution_lock,self.files._root() as parent:
            value = self.read(item,operation);self._check(value)
            leaf = self.files._leaf(item);quarantine = value['quarantine']
            if value['phase'] == 'prepared':
                self._verify(parent,value,leaf)
                require(not self._exists(parent,quarantine), 'overlay retirement quarantine occupied')
                value['phase'] = 'rename_requested';self._save(value)
                self._verify(parent,value,leaf)
                rename_siblings(parent,leaf,quarantine,NOREPLACE)
            if value['phase'] == 'rename_requested':
                require(not self._exists(parent,leaf), 'overlay rename uncertain; no resend')
                self._verify(parent,value,quarantine)
                os.fsync(parent)
                value['phase'] = 'quarantined';self._save(value)
            if value['phase'] == 'quarantined':
                require(not self._exists(parent,leaf), 'original overlay path reoccupied')
                self._verify(parent,value,quarantine)
                value['phase'] = 'unlink_requested';self._save(value)
                self._verify(parent,value,quarantine)
                require(not self._exists(parent,leaf), 'original overlay path reoccupied before unlink')
                os.unlink(quarantine,dir_fd=parent)
            # An uncertain unlink is observed, never repeated. Directory fsync
            # is safely repeatable, and is required before completion publication.
            require(not self._exists(parent,leaf) and not self._exists(parent,quarantine),
                    'overlay removal uncertain or path reoccupied; no resend')
            self._check(value);os.fsync(parent);self._check(value)
            if value['phase'] != 'removed':
                with self.journal.transaction():
                    value.update(phase='removed',proof=self._proof(value));self._write(value)
                    self._check(value)
                    require(not self._exists(parent,leaf) and not self._exists(parent,quarantine),
                            'overlay path reappeared during removal commit')
            require(not self._exists(parent,leaf) and not self._exists(parent,quarantine),
                    'overlay path reappeared during removal commit')
            return self.read(item,operation)
