"""Read one quiet original resource journal without SQLite sidecar creation.

Initial acquisition validates the caller's original resource digest; it does not
claim a journal birth from a pathname. Retain the returned binding for later
acquisitions. The shared workload lock permits concurrent readers and excludes
ordinary writers. A pending WAL, replacement or failed validation is a conflict.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import threading
from types import SimpleNamespace

from .manifest import Conflict


def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def stamp(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
        'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


@contextmanager
def readonly_resource_journal(directory, *, journal_identity, resource_sha256,
                              verify, validate, expected_binding=None):
    """validate(view) must freshly verify the original resource and return its hash.

    The lease.check() callback rechecks file paths, source/context and resource
    proof before use. No creation, recovery, checkpoint or mutable journal API
    is exposed. The caller owns durable storage of the initial receipt.
    """
    directory = os.fspath(directory)
    if (not isinstance(directory, str) or not directory.startswith('/')
            or str(PurePosixPath(directory)) != directory or '..' in PurePosixPath(directory).parts
            or not isinstance(journal_identity, str) or re.fullmatch('[0-9a-f]{32}', journal_identity) is None
            or not isinstance(resource_sha256, str) or re.fullmatch('[0-9a-f]{64}', resource_sha256) is None
            or not all(callable(fn) for fn in (verify, validate))):
        raise Conflict('explicit original resource journal and digest required')
    active = False
    with ExitStack() as stack:
        verify()
        parent = os.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        stack.callback(os.close, parent)
        for part in PurePosixPath(directory).parts[1:]:
            parent = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, parent)
        original_dir = identity(os.fstat(parent))
        if original_dir['uid'] != os.geteuid() or original_dir['mode'] != 0o700:
            raise Conflict('private original resource journal directory required')
        descriptors = {}
        for name in ('workload.lock', 'journal.sqlite3'):
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, fd); info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or name == 'journal.sqlite3' and not 0 < info.st_size <= 16*1024*1024):
                raise Conflict('original resource journal file metadata differs')
            descriptors[name] = (fd, stamp(info), identity(info))
            if name == 'workload.lock':
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH|fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Conflict('original resource journal writer is active') from None

        def files():
            verify()
            if (identity(os.fstat(parent)) != original_dir
                    or identity(os.stat(directory, follow_symlinks=False)) != original_dir):
                raise Conflict('original resource journal directory replaced')
            for name, (fd, original, _) in descriptors.items():
                if (stamp(os.fstat(fd)) != original
                        or stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original):
                    raise Conflict('original resource journal file changed or replaced')
            for name in ('journal.sqlite3-wal', 'journal.sqlite3-shm', 'journal.sqlite3-journal'):
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise Conflict('original resource journal has pending SQLite state')

        files()
        database_fd = descriptors['journal.sqlite3'][0]
        database_sha256 = hashlib.sha256(os.pread(database_fd, 16*1024*1024+1, 0)).hexdigest()
        receipt = dict(kind='readonly-resource-journal-v1', directory=directory,
            journal_identity=journal_identity, directory_identity=original_dir,
            database_identity=descriptors['journal.sqlite3'][2], lock_identity=descriptors['workload.lock'][2],
            database_sha256=database_sha256, resource_sha256=resource_sha256)
        if expected_binding is not None and expected_binding != receipt:
            raise Conflict('original resource journal binding changed')
        files()
        uri = (Path('/proc/self/fd')/str(database_fd)).as_uri()+'?mode=ro&immutable=1'
        database = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False)
        stack.callback(database.close); database.row_factory = sqlite3.Row
        database.execute('PRAGMA query_only=ON')
        lock = threading.RLock()
        view = SimpleNamespace(db=database, identity=journal_identity, lock=lock,
                               execution_lock=lock, management_execution_lock=lock)
        active = True

        def check():
            if not active:
                raise Conflict('original readonly resource journal lease is closed')
            with lock:
                files()
                row = database.execute('SELECT identity FROM journal_identity WHERE singleton=1').fetchone()
                if view.identity != journal_identity or row is None or row['identity'] != journal_identity:
                    raise Conflict('original resource journal logical identity differs')
                if validate(view) != resource_sha256:
                    raise Conflict('original resource proof differs')
                files()
                return deepcopy(receipt)

        check()
        lease = SimpleNamespace(journal=view, receipt=deepcopy(receipt), check=check)
        try:
            yield lease
        finally:
            try:
                check()
            finally:
                active = False
