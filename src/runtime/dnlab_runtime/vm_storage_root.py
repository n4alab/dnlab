"""One tracked administrative root for local VM instance directories.

The root is shared infrastructure, never removed with an individual VD. Existing
parents are dependencies; an existing target without its original birth is a
conflict. The directory adapter owns mkdir, identity, marker and fsync recovery.
This module creates no VM, overlay, account or service and has no delete path.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath
import uuid

from .libvirt_install_dependencies import InstallationDirectoryDependencies
from .libvirt_install_files import InstallationFiles
from .libvirt_postboot import context as validate_context
from .libvirt_provisioning import ProvisioningWindow
from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_overlay_files import directory_identity, local_filesystem
from .vm_template import digest, fields, require


def parent_spec(path):
    absolute(path)
    parent = str(PurePosixPath(path).parent)
    require(parent != '/', 'explicit non-root storage parent required')
    return dict(key='directory:'+parent, kind='directory', path=parent,
                uid=0, gid=0, mode=0o755)


class LocalStorageParent:
    """Readonly parent/ancestor and ext4 checks through the existing adapters."""
    def __init__(self, files):
        require(isinstance(files, InstallationFiles), 'original directory adapter required')
        self.files, self.root = files, files.root

    def __call__(self, spec):
        reader = InstallationDirectoryDependencies(self.root, [spec])
        original = reader(spec)
        # _parent only opens ancestors; the final component is never accessed.
        with self.files._parent(spec['path']+'/.dnlab-storage-parent') as (fd, _):
            identity = dict(directory_identity(fd), kind='directory')
            require(identity == original['identity'], 'original storage parent changed')
            local_filesystem(fd)
            require(reader(spec) == original, 'storage parent ancestry changed')
        return dict(directory=original, filesystem='ext4')


class VMStorageRoot:
    def __init__(self, journal, *, files, parent_reader, context, read_context,
                 window=None, readonly=False):
        validate_context(context)
        require(type(readonly) is bool and files.journal is journal
                and getattr(parent_reader, 'root', None) == files.root
                and all(callable(fn) for fn in (parent_reader, read_context))
                and all(callable(getattr(files, name, None)) for name in
                        ('observe', 'create', 'recover', 'directory_requested'))
                and (window is None or isinstance(window, ProvisioningWindow)),
                'original storage-root journal, context and directory providers required')
        self.journal, self.files, self.parent_reader = journal, files, parent_reader
        self.context, self.read_context = deepcopy(context), read_context
        self.context_sha256, self.files_root = fingerprint(context), files.root
        self.window, self.readonly = window, readonly
        if readonly:
            require(journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='vm_storage_roots'").fetchone() is not None,
                'original VM storage-root journal required')
        else:
            with journal.transaction():
                journal.db.execute('CREATE TABLE IF NOT EXISTS vm_storage_roots '
                    '(id TEXT PRIMARY KEY,host_id TEXT NOT NULL,path TEXT NOT NULL,payload TEXT NOT NULL,'
                    'fingerprint TEXT NOT NULL,UNIQUE(host_id,path))')

    @staticmethod
    def _item(value):
        return dict(spec=deepcopy(value['spec']), nonce=value['nonce'])

    @staticmethod
    def _parent(value):
        fields(value, ('directory', 'filesystem'), 'local storage parent')
        require(value['filesystem'] == 'ext4', 'only qualified local ext4 storage is enabled')
        proof = value['directory']
        fields(proof, ('dependency', 'path', 'identity', 'ancestors'), 'storage parent dependency')
        require(proof['dependency'] == 'existing_directory', 'original parent dependency required')
        return value

    @staticmethod
    def _proof(value, proof):
        fields(proof, ('intent_id', 'nonce', 'spec_sha256', 'identity'), 'storage-root birth')
        identity = proof['identity']
        fields(identity, ('device', 'inode', 'uid', 'gid', 'mode', 'kind'), 'storage-root identity')
        require(proof['intent_id'] == value['id'] and proof['nonce'] == value['nonce']
                and proof['spec_sha256'] == fingerprint(value['spec'])
                and all(type(identity[k]) is int and identity[k] >= 0 for k in
                        ('device', 'inode', 'uid', 'gid', 'mode'))
                and identity['inode'] > 0 and identity['kind'] == 'directory'
                and (identity['uid'], identity['gid'], identity['mode']) == (0, 0, 0o755),
                'original durable root:root0755 storage directory required')
        return deepcopy(proof)

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_storage_roots WHERE id=?', (operation,)).fetchone()
        if row is None:
            raise Conflict('original VM storage-root intent missing')
        value = json.loads(row['payload'])
        fields(value, ('id', 'context', 'spec', 'parent', 'nonce', 'window_sha256', 'phase', 'proof'),
               'storage-root intent')
        validate_context(value['context'])
        spec = value['spec']; parent = parent_spec(spec['path'])
        require(value['id'] == operation == row['id'] and fingerprint(value) == row['fingerprint']
                and value['context']['host_id'] == row['host_id'] and spec['path'] == row['path']
                and spec == dict(key='directory:'+row['path'], kind='directory', path=row['path'],
                                 uid=0, gid=0, mode=0o755)
                and digest(value['window_sha256']) and type(value['nonce']) is str
                and len(value['nonce']) == 32 and all(c in '0123456789abcdef' for c in value['nonce'])
                and value['phase'] in ('prepared', 'creating', 'ready')
                and self._parent(value['parent'])['directory']['path'] == parent['path'],
                'original storage-root journal differs')
        if value['phase'] == 'ready':
            self._proof(value, value['proof'])
        else:
            require(value['proof'] is None, 'unexpected early storage-root birth')
        return value

    def _save(self, value):
        require(not self.readonly, 'readonly storage-root observer cannot save')
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_storage_roots SET payload=?,fingerprint=? WHERE id=?',
                                   (canonical(value), fingerprint(value), value['id']))

    def _check(self, value, *, mutating):
        require(fingerprint(self.context) == self.context_sha256
                and self.files.journal is self.journal and self.files.root == self.files_root
                and self.parent_reader.root == self.files_root
                and self.read_context() == self.context
                and value['context']['host_id'] == self.context['host_id'],
                'original storage-root host/current context differs')
        parent = parent_spec(value['spec']['path'])
        require(self.parent_reader(parent) == value['parent'], 'original storage parent replaced or changed')
        if mutating:
            require(not self.readonly and self.window is not None
                    and value['context'] == self.context
                    and self.window.receipt['context'] == self.context
                    and fingerprint(self.window.receipt) == value['window_sha256'],
                    'original storage-root creator context and window required')
            self.window.verify(self._item(value), value['id'], value['window_sha256'])
        if value['phase'] != 'creating':
            actual = self.files.observe(self._item(value), value['id'])
            require(actual == value['proof'], 'storage-root target occupied, missing or replaced')
        require(self.parent_reader(parent) == value['parent'] and self.read_context() == self.context,
                'storage-root parent or context changed during observation')

    def prepare(self, operation, path, parent):
        require(not self.readonly and self.window is not None, 'explicit storage-root provisioning required')
        identifier(operation, 'storage-root operation'); absolute(path); parent_spec(path)
        parent = deepcopy(self._parent(parent))
        request = dict(id=operation, context=deepcopy(self.context),
            spec=dict(key='directory:'+path, kind='directory', path=path, uid=0, gid=0, mode=0o755),
            parent=parent, window_sha256=self.window.sha256)
        with self.journal.execution_lock:
            if self.journal.db.execute('SELECT 1 FROM vm_storage_roots WHERE id=?', (operation,)).fetchone():
                value = self.read(operation)
                require(all(value[key] == item for key, item in request.items()),
                        'storage-root retry inputs differ; no replacement')
                self._check(value, mutating=False)
                return value
            require(self.journal.db.execute('SELECT 1 FROM vm_storage_roots WHERE host_id=? AND path=?',
                    (self.context['host_id'], path)).fetchone() is None, 'storage-root path already reserved')
            value = dict(request, nonce=uuid.uuid4().hex, phase='prepared', proof=None)
            self._check(value, mutating=True)
            with self.journal.transaction():
                self._check(value, mutating=True)
                self.journal.db.execute('INSERT INTO vm_storage_roots VALUES(?,?,?,?,?)',
                    (operation, self.context['host_id'], path, canonical(value), fingerprint(value)))
            return self.read(operation)

    def observe(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            require(value['phase'] == 'ready', 'storage-root creation pending; explicit recovery required')
            self._check(value, mutating=False)
            return value

    def identity(self, operation):
        return {key:item for key,item in self.observe(operation)['proof']['identity'].items() if key != 'kind'}

    def _file_window(self, operation):
        def current():
            self._check(self.read(operation), mutating=True)
            return self.window.observe()
        return ProvisioningWindow(self.window.receipt, current)

    def _run(self, operation, *, recover):
        require(not self.readonly, 'readonly storage-root observer cannot mutate')
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'ready':
                return self.observe(operation)
            if recover and value['phase'] == 'prepared':
                raise Conflict('no original storage-root creation requested')
            if value['phase'] == 'creating' and not recover:
                raise Conflict('original storage-root creation requires explicit recovery')
            self._check(value, mutating=True)
            create = value['phase'] == 'prepared'
            if create:
                value['phase'] = 'creating'; self._save(value)
                self._check(value, mutating=True)
            if not create:
                requested = self.files.directory_requested(self._item(value), operation)
                require(type(requested) is bool, 'original directory request state required')
                if not requested:
                    require(self.files.observe(self._item(value), operation) is None,
                            'unrequested storage-root target occupied; no adoption')
                    create = True
            self._check(value, mutating=True)
            action = self.files.create if create else self.files.recover
            proof = self._proof(value, action(self._item(value), operation, window=self._file_window(operation)))
            self._check(value, mutating=True)
            require(self.files.observe(self._item(value), operation) == proof,
                    'original storage-root durability not independently observed')
            value.update(phase='ready', proof=proof); self._save(value)
            return self.observe(operation)

    def apply(self, operation):
        return self._run(operation, recover=False)

    def recover(self, operation):
        return self._run(operation, recover=True)
