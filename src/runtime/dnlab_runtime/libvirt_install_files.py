"""Tracked installation files/directories; no account or service commands.

A root override is used only by filesystem tests. Production callers still need
qualified context/prerequisite checks and the account adapter before enabling
installation. Interrupted births without their nonce remain conflicts.
"""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import PurePosixPath
import stat

from .manifest import Conflict, canonical, fingerprint

MARKER = 'user.dnlab.libvirt-install'


class InstallationFiles:
    def __init__(self, root='/', *, journal, readonly=False):
        if type(readonly) is not bool:raise Conflict('explicit filesystem observer mode required')
        self.root, self.journal, self.readonly = root, journal, readonly
        if readonly:
            if journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='libvirt_install_file_births'").fetchone() is None:
                raise Conflict('original installation file birth journal missing')
            return
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_install_file_births '
                '(operation_id TEXT NOT NULL,nonce TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(operation_id,nonce))')

    def _birth(self, item, operation_id):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM libvirt_install_file_births WHERE operation_id=? AND nonce=?',
                (operation_id, item['nonce'])).fetchone()
        if row is None:return None
        value = json.loads(row['payload'])
        if (fingerprint(value) != row['fingerprint']
                or value['binding'] != self._marker(item, operation_id).decode()
                or value['phase'] not in ('birth_pending', 'durability_pending', 'durability_confirmed')):
            raise Conflict('original installation file birth differs')
        return value

    def _save_birth(self, item, operation_id, value):
        if self.readonly:raise Conflict('readonly installation file observer cannot save birth')
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_install_file_births SET payload=?,fingerprint=? '
                'WHERE operation_id=? AND nonce=?',
                (canonical(value), fingerprint(value), operation_id, item['nonce']))

    @staticmethod
    def _kernel_id(fd):
        info = os.fstat(fd)
        return dict(device=info.st_dev, inode=info.st_ino)

    def _qualified(self, item, operation_id, parent, name, birth):
        if self._kernel_id(parent) != birth['parent']:
            raise Conflict('original installation parent directory differs')
        receipt = self._observe(item, operation_id, parent, name)
        if {key: receipt['identity'][key] for key in ('device', 'inode')} != birth['file']:
            raise Conflict('original installation file replaced')
        # Rewalk the visible path as well as checking the pinned parent FD.
        with self._parent(item['spec']['path']) as (visible, _):
            if self._kernel_id(visible) != birth['parent']:
                raise Conflict('installation parent path replaced')
        return receipt

    @contextmanager
    def _parent(self, path):
        parts = PurePosixPath(path).parts
        if not isinstance(path, str) or not path.startswith('/') or '..' in parts or len(parts) < 2:
            raise Conflict('absolute installation path required')
        descriptors = []
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            descriptors.append(fd)
            for name in parts[1:-1]:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                descriptors.append(fd)
            yield fd, parts[-1]
        finally:
            for fd in reversed(descriptors):os.close(fd)

    def _marker(self, item, operation_id):
        return canonical(dict(intent_id=operation_id, nonce=item['nonce'],
                              spec_sha256=fingerprint(item['spec']))).encode()

    def _identity(self, fd, spec):
        info = os.fstat(fd)
        directory = spec['kind'] == 'directory'
        if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or info.st_uid != spec['uid'] or info.st_gid != spec['gid']
                or stat.S_IMODE(info.st_mode) != spec['mode']
                or not directory and info.st_nlink != 1):
            raise Conflict('installation file metadata differs')
        result = dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                      gid=info.st_gid, mode=stat.S_IMODE(info.st_mode), kind=spec['kind'])
        if not directory:
            # Bounded by the original generated configuration, never an arbitrary read.
            expected = spec['content'].encode()
            os.lseek(fd, 0, os.SEEK_SET)
            content = b''
            while len(content) <= len(expected):
                chunk = os.read(fd, min(65536, len(expected) + 1 - len(content)))
                if not chunk:break
                content += chunk
            if content != expected or hashlib.sha256(content).hexdigest() != spec['sha256']:
                raise Conflict('installation file content differs')
            result['sha256'] = spec['sha256']
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_uid,
                after.st_gid, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Conflict('installation file changed during observation')
        return result

    def _observe(self, item, operation_id, parent, name):
        spec = item['spec']
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if spec['kind'] == 'directory':flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=parent)
        try:
            if os.getxattr(fd, MARKER) != self._marker(item, operation_id):
                raise Conflict('installation file birth marker differs')
            identity = self._identity(fd, spec)
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (linked.st_dev, linked.st_ino) != (identity['device'], identity['inode']):
                raise Conflict('installation file replaced during observation')
            if os.getxattr(fd, MARKER) != self._marker(item, operation_id):
                raise Conflict('installation file birth marker changed')
            return dict(intent_id=operation_id, nonce=item['nonce'],
                        spec_sha256=fingerprint(spec), identity=identity)
        finally:os.close(fd)

    def observe(self, item, operation_id):
        if item['spec']['kind'] not in ('file', 'directory'):raise Conflict('filesystem target kind required')
        with self.journal.execution_lock:
            birth = self._birth(item, operation_id)
            try:
                with self._parent(item['spec']['path']) as (parent, name):
                    if birth is None:
                        try:os.stat(name, dir_fd=parent, follow_symlinks=False)
                        except FileNotFoundError:return None
                        raise Conflict('original installation file birth missing')
                    if birth['phase'] != 'durability_confirmed':
                        raise Conflict('installation file durability pending; explicit recovery required')
                    receipt = self._qualified(item, operation_id, parent, name, birth)
                    if receipt != birth['proof']:raise Conflict('confirmed installation file proof differs')
                    return receipt
            except FileNotFoundError:
                if birth is not None:raise Conflict('original installation file missing') from None
                return None
            except OSError as error:
                raise Conflict('installation filesystem observation is not qualified') from error

    def observe_relocated(self, item, operation_id, destination):
        """Read the same durable birth at an explicit sibling path; never adopt.

        The caller must bind the relocation to its own transition journal. This
        returns the original proof/marker, not a new birth for the destination.
        """
        original=PurePosixPath(item['spec']['path'])
        moved=PurePosixPath(destination)
        if (item['spec']['kind']!='file' or not isinstance(destination,str)
                or str(moved)!=destination or moved.parent!=original.parent
                or '..' in moved.parts):
            raise Conflict('explicit sibling file relocation required')
        with self.journal.execution_lock:
            birth=self._birth(item,operation_id)
            if birth is None or birth['phase']!='durability_confirmed':
                raise Conflict('original durable relocation birth required')
            try:
                with self._parent(destination) as (parent,name):
                    proof=self._qualified(item,operation_id,parent,name,birth)
                    if proof!=birth['proof']:raise Conflict('original relocated file differs')
                    return proof
            except OSError as error:
                raise Conflict('original relocated file is not qualified') from error

    def recover(self, item, operation_id, *, window=None):
        """Reconfirm durability of the exact original file, never create or rewrite."""
        if self.readonly:raise Conflict('readonly installation file observer cannot recover')
        with self.journal.execution_lock:
            birth = self._birth(item, operation_id)
            if birth is None or birth['file'] is None:
                raise Conflict('original installation file birth missing; no adoption permitted')
            if item['spec']['kind']=='directory':
                if window is None:raise Conflict('original provisioning window required for directory recovery')
                window.verify(item,operation_id,birth['window_sha256'])
            with self._parent(item['spec']['path']) as (parent, name):
                self._qualified(item, operation_id, parent, name, birth)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
                try:
                    if self._kernel_id(fd) != birth['file']:
                        raise Conflict('original installation file replaced before durability recovery')
                    self._identity(fd, item['spec'])
                    if os.getxattr(fd, MARKER) != self._marker(item, operation_id):
                        raise Conflict('original installation file marker differs')
                    os.fsync(fd)
                    os.fsync(parent)
                    receipt = self._qualified(item, operation_id, parent, name, birth)
                    if item['spec']['kind']=='directory':
                        window.verify(item,operation_id,birth['window_sha256'])
                    birth.update(phase='durability_confirmed', proof=receipt)
                    self._save_birth(item, operation_id, birth)
                    return self.observe(item, operation_id)
                finally:os.close(fd)

    def create(self, item, operation_id, *, window=None):
        if self.readonly:raise Conflict('readonly installation file observer cannot create')
        spec = item['spec']
        if spec['kind'] not in ('file', 'directory'):raise Conflict('filesystem target kind required')
        if spec['kind']=='directory' and window is None:
            raise Conflict('directory birth requires a separately qualified provisioning window')
        # Directory mkdir/open requires the agreed exclusive administration window.
        # A crash before its original FD identity is saved cannot be adopted.
        # No cleanup on failure: the installer retains create_requested.
        with self.journal.execution_lock, self._parent(spec['path']) as (parent, name):
            if self._birth(item, operation_id) is not None:
                raise Conflict('original installation file birth held; use durability recovery')
            birth = None
            if spec['kind']=='directory':
                window.verify(item,operation_id)
                birth = dict(binding=self._marker(item,operation_id).decode(),file=None,
                    parent=self._kernel_id(parent),phase='birth_pending',proof=None,
                    window_sha256=window.sha256)
                with self.journal.transaction():
                    self.journal.db.execute('INSERT INTO libvirt_install_file_births VALUES(?,?,?,?)',
                        (operation_id,item['nonce'],canonical(birth),fingerprint(birth)))
                window.verify(item,operation_id,birth['window_sha256'])
                os.mkdir(name,0o700,dir_fd=parent)
                window.verify(item,operation_id,birth['window_sha256'])
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            else:
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
            try:
                if birth is None:
                    birth = dict(binding=self._marker(item, operation_id).decode(),
                        file=self._kernel_id(fd), parent=self._kernel_id(parent),
                        phase='durability_pending', proof=None)
                    with self.journal.transaction():
                        self.journal.db.execute('INSERT INTO libvirt_install_file_births VALUES(?,?,?,?)',
                            (operation_id, item['nonce'], canonical(birth), fingerprint(birth)))
                else:
                    window.verify(item,operation_id,birth['window_sha256'])
                    birth.update(file=self._kernel_id(fd),phase='durability_pending')
                    self._save_birth(item,operation_id,birth)
                    window.verify(item,operation_id,birth['window_sha256'])
                os.setxattr(fd, MARKER, self._marker(item, operation_id), flags=os.XATTR_CREATE)
                if spec['kind'] == 'file':
                    content = memoryview(spec['content'].encode())
                    while content:
                        written = os.write(fd, content)
                        if written <= 0:raise OSError(errno.EIO, 'installation write made no progress')
                        content = content[written:]
                if (os.fstat(fd).st_uid, os.fstat(fd).st_gid) != (spec['uid'], spec['gid']):
                    os.fchown(fd, spec['uid'], spec['gid'])
                os.fchmod(fd, spec['mode'])
                self._identity(fd, spec)
                os.fsync(fd)
                os.fsync(parent)
                receipt = self._qualified(item, operation_id, parent, name, birth)
                if spec['kind']=='directory':window.verify(item,operation_id,birth['window_sha256'])
                birth.update(phase='durability_confirmed', proof=receipt)
                self._save_birth(item, operation_id, birth)
                return self.observe(item, operation_id)
            finally:os.close(fd)
