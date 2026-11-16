"""Tracked immutable template assets inside an already qualified directory.

No directories, domains or workers are created here. The caller supplies the
complete import preflight and owns the exclusive provisioning window. Recovery
can resume only a recorded inode with its original marker and source bytes;
missing births, foreign files and corrupt prefixes are never rewritten.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import PurePosixPath
import stat
import uuid

from .libvirt_account_runner import open_resource
from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_bundle import metadata
from .vm_template import digest

MARKER = 'user.dnlab.vm-template'
CHUNK = 1024 * 1024


def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


class TemplateAssetFiles:
    def __init__(self, journal, *, root, parent_identity, preflight, readonly=False):
        absolute(root)
        if not callable(preflight) or type(readonly) is not bool:
            raise Conflict('explicit template import preflight and observer mode required')
        self.journal, self.root = journal, root
        self.parent, self.preflight = deepcopy(parent_identity), preflight
        self.readonly = readonly
        if (set(self.parent) != {'device', 'inode', 'uid', 'gid', 'mode'}
                or any(type(value) is not int or value < 0 for value in self.parent.values())
                or self.parent['inode'] == 0
                or self.parent['uid'] != 0 or self.parent['gid'] != 0
                or self.parent['mode'] != 0o755):
            raise Conflict('qualified root-owned traversable template parent required')
        if readonly:
            if journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='vm_template_asset_files'").fetchone() is None:
                raise Conflict('original template asset journal missing')
        else:
            with journal.transaction():
                journal.db.execute('CREATE TABLE IF NOT EXISTS vm_template_asset_files '
                    '(id TEXT PRIMARY KEY,path TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @contextmanager
    def _parent(self):
        descriptors = []
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            descriptors.append(fd)
            for part in PurePosixPath(self.root).parts[1:]:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                descriptors.append(fd)
            if identity(os.fstat(fd)) != self.parent:
                raise Conflict('original template parent differs')
            yield fd
            if identity(os.fstat(fd)) != self.parent or identity(os.stat(self.root, follow_symlinks=False)) != self.parent:
                raise Conflict('template parent changed')
        finally:
            for fd in reversed(descriptors):os.close(fd)

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_template_asset_files WHERE id=?', (operation,)).fetchone()
        if row is None:raise Conflict('original template asset intent missing')
        value = json.loads(row['payload'])
        request = value['request']
        if (fingerprint(value) != row['fingerprint'] or request['id'] != row['id']
                or request['destination'] != row['path'] or request['parent'] != self.parent
                or value['phase'] not in ('prepared', 'create_requested', 'copying', 'sealing', 'ready')
                or (value['phase'] in ('prepared', 'create_requested')) != (value['file'] is None)
                or (value['phase'] == 'ready') != (value['proof'] is not None)):
            raise Conflict('original template asset intent differs')
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_template_asset_files SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value), fingerprint(value), value['request']['id']))

    def _guard(self, value):
        request = value['request']
        def source_identity():
            if value['phase'] in ('prepared', 'create_requested', 'copying') and 'source_metadata' in value:
                with open_resource(request['source']) as fd:
                    if list(metadata(os.fstat(fd))) != value['source_metadata']:
                        raise Conflict('original template source identity changed')
        def destination_identity():
            with self._parent() as parent:
                if value['file'] is not None:
                    with self._file(parent, value, writable=False):pass
                else:
                    try:os.stat(PurePosixPath(request['destination']).name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:pass
                    else:raise Conflict('template destination occupied; no adoption')
        source_identity()
        destination_identity()
        if self.preflight(deepcopy(request)) != dict(request_sha256=fingerprint(request),
                exclusive_writer=True, source_verified=True):
            raise Conflict('complete exclusive template import preflight differs')
        source_identity()
        destination_identity()

    def prepare(self, operation, *, source, destination, sha256, size):
        if self.readonly:raise Conflict('readonly template observer')
        identifier(operation, 'template import');absolute(source);absolute(destination)
        if (str(PurePosixPath(destination).parent) != self.root or destination == source
                or not digest(sha256) or type(size) is not int or size <= 0):
            raise Conflict('explicit immutable template asset request required')
        request = dict(id=operation, source=source, destination=destination,
                       sha256=sha256, size=size, parent=self.parent)
        with self.journal.execution_lock:
            prior = self.journal.db.execute('SELECT id FROM vm_template_asset_files WHERE id=?', (operation,)).fetchone()
            if prior:
                saved = self.read(operation)
                if saved['request'] != request:raise Conflict('template import request changed')
                return saved
            value = dict(request=request, phase='prepared', nonce=uuid.uuid4().hex, file=None, proof=None)
            self._guard(value)
            with self._parent() as parent, open_resource(source) as fd:
                before = metadata(os.fstat(fd)); hashed = hashlib.sha256(); total = 0
                if before[5] != size:raise Conflict('original template source size differs')
                while block := os.read(fd, CHUNK):
                    if total + len(block) > size:raise Conflict('template source grew')
                    hashed.update(block); total += len(block)
                if total != size or hashed.hexdigest() != sha256 or metadata(os.fstat(fd)) != before:
                    raise Conflict('original template source content differs')
                try:os.stat(PurePosixPath(destination).name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise Conflict('template destination occupied; no adoption')
                value['source_metadata'] = list(before)
                self._guard(value)
                with self.journal.transaction():
                    self.journal.db.execute('INSERT INTO vm_template_asset_files VALUES(?,?,?,?)',
                        (operation, destination, canonical(value), fingerprint(value)))
            return self.read(operation)

    def _marker(self, value):
        return fingerprint(dict(request=value['request'], nonce=value['nonce'])).encode()

    @contextmanager
    def _file(self, parent, value, *, writable):
        leaf = PurePosixPath(value['request']['destination']).name
        pin = os.open(leaf, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            def check(info):
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != 0 or info.st_gid != 0
                        or {k:identity(info)[k] for k in ('device', 'inode')} != value['file']
                        or stat.S_IMODE(info.st_mode) not in ((0o600,) if value['phase'] == 'copying' else (0o600, 0o444))):
                    raise Conflict('original template asset inode or metadata differs')
            check(os.fstat(pin))
            fd = os.open('/proc/self/fd/' + str(pin),
                         (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                check(os.fstat(fd))
                if os.getxattr(fd, MARKER) != self._marker(value):raise Conflict('original template asset marker differs')
                yield fd
                check(os.fstat(fd));check(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                if os.getxattr(fd, MARKER) != self._marker(value):raise Conflict('template asset marker changed')
            finally:os.close(fd)
        finally:os.close(pin)

    def _contents(self, value, fd, *, extend):
        request = value['request']; length = os.fstat(fd).st_size
        if length > request['size']:raise Conflict('template copy exceeds original size')
        if not extend and length != request['size']:raise Conflict('original template copy incomplete')
        os.lseek(fd, 0, os.SEEK_SET)
        with open_resource(request['source']) as source:
            if list(metadata(os.fstat(source))) != value['source_metadata']:
                raise Conflict('original template source identity changed')
            remaining = length; hashed = hashlib.sha256(); total = 0
            while block := os.read(source, CHUNK):
                if total + len(block) > request['size']:raise Conflict('template source grew during copy')
                prefix = min(remaining, len(block))
                if prefix and os.read(fd, prefix) != block[:prefix]:
                    raise Conflict('original template copy prefix differs')
                remaining -= prefix
                if extend and prefix < len(block):
                    self._guard(value)
                    pending = memoryview(block)[prefix:]
                    while pending:
                        count = os.write(fd, pending)
                        if count <= 0:raise OSError('template copy made no progress')
                        pending = pending[count:]
                hashed.update(block);total += len(block)
            if (remaining or total != request['size'] or hashed.hexdigest() != request['sha256']
                    or list(metadata(os.fstat(source))) != value['source_metadata']):
                raise Conflict('original template source changed during copy')

    @staticmethod
    def _hash(value, fd):
        os.lseek(fd, 0, os.SEEK_SET);before = metadata(os.fstat(fd))
        hashed = hashlib.sha256();total = 0
        if before[5] != value['request']['size']:raise Conflict('original template copy incomplete')
        while block := os.read(fd, CHUNK):
            total += len(block)
            if total > value['request']['size']:raise Conflict('template copy grew during verification')
            hashed.update(block)
        if (total != value['request']['size'] or hashed.hexdigest() != value['request']['sha256']
                or metadata(os.fstat(fd)) != before):
            raise Conflict('original immutable template content differs')

    def _finish(self, value, parent, fd):
        self._guard(value)
        self._hash(value, fd)
        os.fchmod(fd, 0o444);os.fsync(fd);os.fsync(parent)
        self._guard(value)
        named = os.stat(PurePosixPath(value['request']['destination']).name, dir_fd=parent, follow_symlinks=False)
        if (metadata(named) != metadata(os.fstat(fd)) or named.st_uid != 0 or named.st_gid != 0
                or named.st_nlink != 1 or os.getxattr(fd, MARKER) != self._marker(value)):
            raise Conflict('original template copy changed before confirmation')
        proof = dict(request_sha256=fingerprint(value['request']), identity=identity(os.fstat(fd)),
                     sha256=value['request']['sha256'], size=value['request']['size'])
        value.update(phase='ready', proof=proof);self._save(value)
        return proof

    def apply(self, operation):
        if self.readonly:raise Conflict('readonly template observer')
        if (os.geteuid(), os.getegid()) != (0, 0):raise Conflict('root:root template installer required')
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'ready':return self.observe(operation)
            if value['phase'] != 'prepared':raise Conflict('template copy pending; explicit recovery required')
            self._guard(value)
            value['phase'] = 'create_requested';self._save(value)
            with self._parent() as parent:
                self._guard(value)
                leaf = PurePosixPath(value['request']['destination']).name
                fd = os.open(leaf, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                try:
                    value.update(file={k:identity(os.fstat(fd))[k] for k in ('device', 'inode')}, phase='copying')
                    self._save(value)
                    os.setxattr(fd, MARKER, self._marker(value), flags=os.XATTR_CREATE)
                    self._contents(value, fd, extend=True)
                    value['phase'] = 'sealing';self._save(value)
                    return self._finish(value, parent, fd)
                finally:os.close(fd)

    def recover(self, operation):
        if self.readonly:raise Conflict('readonly template observer')
        if (os.geteuid(), os.getegid()) != (0, 0):raise Conflict('root:root template installer required')
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'ready':return self.observe(operation)
            if value['phase'] not in ('copying', 'sealing'):
                raise Conflict('original template file birth missing; no create on recovery')
            self._guard(value)
            with self._parent() as parent, self._file(parent, value, writable=value['phase'] == 'copying') as fd:
                if value['phase'] == 'copying':self._contents(value, fd, extend=True)
                else:self._hash(value, fd)
                value['phase'] = 'sealing';self._save(value)
                return self._finish(value, parent, fd)

    def observe(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] != 'ready':raise Conflict('original template asset durability pending')
            self._guard(value)
            with self._parent() as parent, self._file(parent, value, writable=False) as fd:
                if stat.S_IMODE(os.fstat(fd).st_mode) != 0o444:raise Conflict('immutable template asset mode changed')
                self._hash(value, fd)
                proof = dict(request_sha256=fingerprint(value['request']), identity=identity(os.fstat(fd)),
                             sha256=value['request']['sha256'], size=value['request']['size'])
                if proof != value['proof']:raise Conflict('original template asset proof differs')
                return proof
