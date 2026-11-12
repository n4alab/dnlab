"""Original local overlay births, durability and formatter recovery.

Parents are supplied with qualified identities; this adapter creates no dirs.
Only ext4 is enabled in the first native profile. Base files are immutable by
hash and readonly mode. Pending births/commands are never adopted from names.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .libvirt_account_commands import reference_proof
from .libvirt_account_runner import open_resource
from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint, identifier
from .qcow2_header import inspect_header
from .qemu_process import validate_process_record
from .vm_bundle import metadata
from .vm_overlay_worker import MARKER, command_plan, file_identity, validate_command
from .vm_template import digest, fields, require


def directory_identity(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode), 'original overlay parent directory required')
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def local_filesystem(fd):
    ids = [line.split(':', 1)[1].strip() for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines()
           if line.startswith('mnt_id:')]
    require(len(ids) == 1 and ids[0].isdecimal(), 'original overlay mount ID required')
    rows = [line.split(' - ', 1) for line in Path('/proc/self/mountinfo').read_text().splitlines()
            if line.split(' ', 1)[0] == ids[0]]
    require(len(rows) == 1 and len(rows[0]) == 2 and rows[0][1].split()[0] == 'ext4',
            'only the explicit local ext4 overlay profile is enabled')


class OverlayFiles:
    def __init__(self, journal, *, root, parent_identity, binary, runner_factory, preflight, readonly=False):
        absolute(root)
        require(callable(runner_factory) and callable(preflight), 'original formatter and preflight providers required')
        require(type(readonly) is bool, 'explicit VM overlay observer mode required')
        self.readonly = readonly
        self.journal, self.root, self.parent_identity = journal, root, deepcopy(parent_identity)
        self.binary, self.runner_factory, self.preflight = deepcopy(binary), runner_factory, preflight
        self.runners, self.base_cache = {}, {}
        if readonly:
            require(journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vm_overlay_files'").fetchone() is not None,
                    'original overlay birth journal required for readonly observation')
            return
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_overlay_files '
                '(operation_id TEXT NOT NULL,nonce TEXT NOT NULL,path TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,'
                'fingerprint TEXT NOT NULL,PRIMARY KEY(operation_id,nonce))')

    @contextmanager
    def _walk_root(self):
        with ExitStack() as stack:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            for part in PurePosixPath(self.root).parts[1:]:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                stack.callback(os.close, fd)
            yield fd

    @contextmanager
    def _root(self):
        with self._walk_root() as fd:
            require(directory_identity(fd) == self.parent_identity and not self.parent_identity['mode'] & 0o022,
                    'original qualified overlay parent changed')
            local_filesystem(fd)
            yield fd
            require(directory_identity(fd) == self.parent_identity, 'overlay parent changed during operation')
            local_filesystem(fd)
            with self._walk_root() as visible:
                require(directory_identity(visible) == self.parent_identity, 'overlay parent path replaced')

    def _leaf(self, item):
        path = PurePosixPath(absolute(item['spec']['path']))
        require(str(path.parent) == self.root, 'overlay must be a direct child of its qualified parent')
        return path.name

    @staticmethod
    def _request(item, operation):
        spec = item['spec']
        fields(spec, ('id', 'path', 'base_path', 'base_sha256', 'base_format', 'uid', 'gid', 'mode'), 'VM overlay specification')
        identifier(spec['id'], 'VM disk ID');absolute(spec['path']);absolute(spec['base_path'])
        require(isinstance(operation, str) and re.fullmatch('[0-9a-f]{32}', operation)
                and isinstance(item['nonce'], str) and re.fullmatch('[0-9a-f]{32}', item['nonce'])
                and digest(spec['base_sha256']) and spec['base_format'] in ('raw', 'qcow2')
                and all(type(spec[key]) is int and 0 < spec[key] < 2**31 for key in ('uid', 'gid'))
                and spec['mode'] == 0o600 and spec['path'] != spec['base_path'], 'qualified original VM overlay request required')
        return dict(operation_id=operation, nonce=item['nonce'], spec=deepcopy(item['spec']))

    def _load(self, item, operation):
        request = self._request(item, operation)
        row = self.journal.db.execute('SELECT * FROM vm_overlay_files WHERE operation_id=? AND nonce=?',
                                      (operation, item['nonce'])).fetchone()
        if row is None:return None
        value = json.loads(row['payload'])
        if (fingerprint(value) != row['fingerprint'] or value['request'] != request
                or row['path'] != item['spec']['path'] or value['parent'] != self.parent_identity
                or value['phase'] not in ('create_requested', 'initializing', 'file_ready', 'arming_requested',
                                           'armed', 'release_requested', 'formatted', 'ready')):
            raise Conflict('original overlay birth journal differs')
        expected = {
            'create_requested': (False, False, False, False, False),
            'initializing': (True, False, False, False, False),
            'file_ready': (True, False, False, False, False),
            'arming_requested': (True, True, False, False, False),
            'armed': (True, True, True, False, False),
            'release_requested': (True, True, True, False, False),
            'formatted': (True, True, True, True, False),
            'ready': (True, True, True, True, True),
        }[value['phase']]
        if tuple(value[key] is not None for key in ('file', 'command', 'reference', 'outcome', 'proof')) != expected:
            raise Conflict('original overlay stage/proofs are inconsistent')
        if value['file'] is not None:
            fields(value['file'], ('device', 'inode', 'uid', 'gid', 'mode'), 'original overlay birth inode')
            require(all(type(part) is int and part >= 0 for part in value['file'].values())
                    and value['file']['inode'] > 0, 'original overlay birth inode malformed')
        command, reference, outcome = value['command'], value['reference'], value['outcome']
        if command is not None:
            validate_command(command)
            if (command['request_sha256'] != fingerprint(value['request'])
                    or command['target']['identity'] != self._expected(value)
                    or command['target']['base_path'] != item['spec']['base_path']
                    or command['target']['base_format'] != item['spec']['base_format']):
                raise Conflict('original overlay format command differs')
        if reference is not None:reference_proof(reference, command)
        if outcome is not None:
            fields(outcome, ('reference', 'exit_code', 'stdout', 'stderr'), 'original formatter outcome')
            if (outcome['reference'] != reference or type(outcome['exit_code']) is not int or outcome['exit_code'] != 0
                    or outcome['stdout'] != '' or outcome['stderr'] != ''):
                raise Conflict('original successful overlay formatter outcome differs')
        if value['phase'] == 'ready' and (outcome is None or value['proof'] != self._proof(value)):
            raise Conflict('original completed overlay proof differs')
        return value

    def _save(self, value):
        request = value['request']
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_overlay_files SET payload=?,fingerprint=? WHERE operation_id=? AND nonce=?',
                (canonical(value), fingerprint(value), request['operation_id'], request['nonce']))

    @staticmethod
    def _expected(value):
        require(value['file'] is not None, 'original overlay inode was not recorded; no adoption')
        return dict(device=value['file']['device'], inode=value['file']['inode'],
                    **{key:value['request']['spec'][key] for key in ('uid', 'gid', 'mode')})

    def _guard(self, item, operation, *, mutating):
        writers = self.preflight(deepcopy(item), operation, mutating=mutating)
        require(type(writers) is list and len(writers) <= 1 and (not mutating or not writers),
                'original overlay preflight requires exclusive qualified writer state')
        if writers:
            writer = validate_process_record(writers[0])
            require(writer['birth']['creator_operation_id'] == operation
                    and writer['uid'] == item['spec']['uid'] and writer['gid'] == item['spec']['gid'],
                    'overlay writer is not the original VM')
        return writers

    def _base(self, spec):
        with open_resource(spec['base_path']) as fd:
            before = metadata(os.fstat(fd))
            require(before[3] == 0 and before[5] > 0 and not before[2] & 0o222, 'root-owned readonly immutable VM base required')
            key = (spec['base_path'], before, spec['base_sha256'], spec['base_format'])
            if key not in self.base_cache:
                hashed = hashlib.sha256()
                while True:
                    block = os.read(fd, 1024 * 1024)
                    if not block:break
                    hashed.update(block)
                require(hashed.hexdigest() == spec['base_sha256'], 'original VM base content differs')
                if spec['base_format'] == 'qcow2':
                    info = inspect_header(fd)
                    require(info['backing_path'] is None, 'standalone VM base required')
                    size = info['virtual_size']
                else:
                    require(spec['base_format'] == 'raw', 'explicit VM base format required')
                    size = before[5]
                require(metadata(os.fstat(fd)) == before, 'VM base changed during verification')
                if len(self.base_cache) >= 32:self.base_cache.clear()
                self.base_cache[key] = size
            return self.base_cache[key]

    @contextmanager
    def _inode(self, parent, item, value, *, writable=False, initializing=False):
        # O_PATH qualifies type and original inode before opening for data IO;
        # a foreign device/FIFO at the old name must never be activated.
        try:path_fd = os.open(self._leaf(item), os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:raise Conflict('original VM overlay missing; explicit wipe required') from None
        try:
            allowed = (value['file'], self._expected(value)) if initializing else (self._expected(value),)
            require(file_identity(os.fstat(path_fd)) in allowed, 'original overlay inode differs')
            flags = os.O_RDWR if writable else os.O_RDONLY
            fd = os.open(f'/proc/self/fd/{path_fd}', flags | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                require(file_identity(os.fstat(fd)) in allowed
                        and file_identity(os.stat(self._leaf(item), dir_fd=parent, follow_symlinks=False)) in allowed,
                        'original overlay path/inode changed')
                yield fd
                require(file_identity(os.fstat(fd)) in allowed
                        and file_identity(os.stat(self._leaf(item), dir_fd=parent, follow_symlinks=False)) in allowed,
                        'original overlay path/inode changed')
            finally:os.close(fd)
        finally:os.close(path_fd)

    @contextmanager
    def _file(self, parent, item, value, *, writable=False):
        with self._inode(parent, item, value, writable=writable) as fd:
            require(os.getxattr(fd, MARKER) == fingerprint(value['request']).encode('ascii'),
                    'original overlay marker differs')
            yield fd
            require(os.getxattr(fd, MARKER) == fingerprint(value['request']).encode('ascii'),
                    'original overlay marker changed')

    def _chain(self, fd, spec, *, allow_dirty):
        base_size = self._base(spec)
        info = inspect_header(fd, allow_dirty=allow_dirty)
        require(info['backing_path'] == spec['base_path'] and info['backing_format'] == spec['base_format']
                and info['virtual_size'] == base_size, 'original VM overlay backing/size differs')

    @staticmethod
    def _proof(value):
        request = value['request']
        require(value['reference'] is not None and value['outcome'] is not None, 'original formatter completion required')
        return dict(operation_id=request['operation_id'], nonce=request['nonce'], spec_sha256=fingerprint(request['spec']),
                    identity=OverlayFiles._expected(value), creation=dict(request_sha256=fingerprint(request),
                    worker_reference_sha256=fingerprint(value['reference']), exit_code=0))

    def observe(self, item, operation):
        with self.journal.execution_lock, self._root() as parent:
            value = self._load(item, operation)
            if value is None:
                try:os.stat(self._leaf(item), dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:return None
                raise Conflict('overlay path occupied without original birth; no adoption')
            if value['phase'] != 'ready':raise Conflict('original overlay requires durability/formatter recovery')
            before = self._guard(item, operation, mutating=False)
            with self._file(parent, item, value) as fd:
                self._chain(fd, item['spec'], allow_dirty=bool(before))
                if self._guard(item, operation, mutating=False) != before:raise Conflict('overlay writer changed during observation')
            return deepcopy(value['proof'])

    def create(self, item, operation):
        require(not self.readonly, 'readonly overlay observer cannot create')
        require(item['phase'] == 'create_requested', 'durable overlay creation intent required')
        with self.journal.execution_lock, self._root() as parent:
            require(self._load(item, operation) is None, 'original overlay birth already held; recover only')
            self._guard(item, operation, mutating=True);self._base(item['spec'])
            try:os.stat(self._leaf(item), dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise Conflict('overlay path occupied without original birth; no adoption')
            value = dict(request=self._request(item, operation), parent=deepcopy(self.parent_identity),
                         phase='create_requested', file=None, command=None, reference=None, outcome=None, proof=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO vm_overlay_files VALUES(?,?,?,?,?)',
                    (operation, item['nonce'], item['spec']['path'], canonical(value), fingerprint(value)))
            self._guard(item, operation, mutating=True)
            fd = os.open(self._leaf(item), os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
            try:
                value.update(file=file_identity(os.fstat(fd)), phase='initializing');self._save(value)
            finally:os.close(fd)
        return self.recover(item, operation)

    def recover(self, item, operation):
        require(not self.readonly, 'readonly overlay observer cannot recover')
        with self.journal.execution_lock, self._root() as parent:
            value = self._load(item, operation)
            require(value is not None, 'original overlay birth required; create is not repeated')
            if value['phase'] == 'ready':return self.observe(item, operation)
            self._guard(item, operation, mutating=True);self._base(item['spec'])
            require(value['file'] is not None, 'original overlay inode was not recorded; no adoption')
            if value['phase'] == 'initializing':
                with self._inode(parent, item, value, writable=True, initializing=True) as fd:
                    actual = file_identity(os.fstat(fd))
                    require(actual in (value['file'], self._expected(value)) and os.fstat(fd).st_size == 0,
                            'original empty overlay birth changed')
                    try:marker = os.getxattr(fd, MARKER)
                    except OSError as error:
                        if error.errno != errno.ENODATA:raise
                        marker = None
                    require(marker in (None, fingerprint(value['request']).encode('ascii')), 'foreign overlay marker')
                    self._guard(item, operation, mutating=True)
                    os.fchown(fd, item['spec']['uid'], item['spec']['gid']);os.fchmod(fd, item['spec']['mode'])
                    if marker is None:os.setxattr(fd, MARKER, fingerprint(value['request']).encode('ascii'), flags=os.XATTR_CREATE)
                    os.fsync(fd);os.fsync(parent)
                value['phase'] = 'file_ready';self._save(value)
            with self._file(parent, item, value, writable=True) as fd:
                self._guard(item, operation, mutating=True)
                if value['phase'] != 'formatted':
                    key = fingerprint(value['request'])
                    if key not in self.runners:self.runners[key] = self.runner_factory()
                    runner = self.runners[key]
                if value['phase'] == 'file_ready':
                    value.update(command=command_plan(value['request'], self.binary, fd, self._expected(value)), phase='arming_requested')
                    self._save(value);self._guard(item, operation, mutating=True)
                    value.update(reference=runner.arm(value['command']), phase='armed');self._save(value)
                if value['phase'] == 'arming_requested':
                    value['reference'] = runner.original_reference(value['command'])
                    require(value['reference'] is not None, 'original formatter reference unavailable; no second arm')
                    value['phase'] = 'armed';self._save(value)
                if value['phase'] == 'armed':
                    self._guard(item, operation, mutating=True)
                    value['phase'] = 'release_requested';self._save(value)
                    self._guard(item, operation, mutating=True)
                    runner.release(value['reference'])
                if value['phase'] == 'release_requested':
                    # A lost caller response before release is distinguishable
                    # from an uncertain send by the original runner's journal.
                    if runner._read(value['reference'])['phase'] == 'armed':
                        self._guard(item, operation, mutating=True)
                        runner.release(value['reference'])
                    outcome = runner.outcome(value['reference'])
                    require(outcome is not None and type(outcome['exit_code']) is int and outcome['exit_code'] == 0
                            and outcome['stdout'] == '' and outcome['stderr'] == '',
                            'original successful formatter completion required; no resend')
                    value.update(outcome=outcome, phase='formatted');self._save(value)
                self._guard(item, operation, mutating=True)
                self._chain(fd, item['spec'], allow_dirty=False)
                os.fsync(fd);os.fsync(parent)
                value.update(proof=self._proof(value), phase='ready');self._save(value)
            return self.observe(item, operation)
