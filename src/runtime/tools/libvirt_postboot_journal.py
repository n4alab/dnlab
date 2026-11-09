"""Open an existing installation journal for a metadata-only post-boot prepare.

The caller supplies a rechecked administrative window and durably retains the
returned physical binding before any writable connection. Resume requires that
same binding, not the pre-prepare hash of a database already changed by prepare.
No missing journal, identity or original installation is initialized here.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import threading

from dnlab_runtime.execution import execution_gate
from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.manifest import Conflict,fingerprint


def file_identity(info):
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode))


class ExistingJournal:
    """The journal protocol used by post-boot components, without schema setup."""
    def __init__(self,database,identity,gate,check):
        self.db,self.identity,self.execution_lock,self.check=database,identity,gate,check
        self.lock=threading.RLock()

    @contextmanager
    def transaction(self):
        with self.execution_lock,self.lock:
            self.check();self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.check();self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK');raise


@contextmanager
def open_postboot_journal(directory,installation,*,identity,initial_sha256,retain,verify,original_binding=None):
    directory=Path(directory)
    if (not directory.is_absolute() or '..' in directory.parts or not callable(retain) or not callable(verify)
            or not isinstance(identity,str) or len(identity)!=32
            or not isinstance(initial_sha256,str) or len(initial_sha256)!=64):
        raise Conflict('explicit original post-boot journal inputs required')
    descriptors=[];db=None
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);descriptors.append(parent)
        for part in directory.parts[1:]:
            parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            descriptors.append(parent)
        root_identity=file_identity(os.fstat(parent))
        if root_identity['uid']!=os.getuid() or root_identity['mode']!=0o700:
            raise Conflict('original private journal directory metadata differs')
        fd=os.open('journal.sqlite3',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        descriptors.append(fd);info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>16*1024*1024):
            raise Conflict('original journal database metadata differs')
        binding=dict(kind='postboot-original-journal-v1',directory=str(directory),
            directory_identity=root_identity,database_identity=file_identity(info),
            journal_identity=identity,source_sha256=fingerprint(installation),initial_sha256=initial_sha256)

        def check():
            verify()
            if (file_identity(os.stat(directory,follow_symlinks=False))!=root_identity
                    or file_identity(os.fstat(parent))!=root_identity
                    or file_identity(os.stat('journal.sqlite3',dir_fd=parent,follow_symlinks=False))!=binding['database_identity']
                    or file_identity(os.fstat(fd))!=binding['database_identity']):
                raise Conflict('original post-boot journal path replaced or changed')

        with execution_gate(directory) as gate:
            check()
            if original_binding is None:
                for name in ('journal.sqlite3-wal','journal.sqlite3-journal'):
                    try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                    except FileNotFoundError:continue
                    raise Conflict('initial original journal has pending database state')
                digest=hashlib.sha256()
                with os.fdopen(os.dup(fd),'rb') as stream:
                    for block in iter(lambda:stream.read(65536),b''):digest.update(block)
                if digest.hexdigest()!=initial_sha256:raise Conflict('initial original journal hash differs')
            elif original_binding!=binding:
                raise Conflict('original post-boot journal resume binding differs')
            check()
            # mode=rw cannot create an absent database. No schema/PRAGMA writes
            # precede the original logical identity/source checks.
            uri=Path('/proc/self/fd')/str(parent)/'journal.sqlite3'
            db=sqlite3.connect(uri.as_uri()+'?mode=rw',uri=True,isolation_level=None)
            db.row_factory=sqlite3.Row
            row=db.execute('SELECT identity FROM journal_identity WHERE singleton=1').fetchone()
            if row is None or row['identity']!=identity:raise Conflict('original journal logical identity differs')
            journal=ExistingJournal(db,identity,gate,check)
            source=SessionInstaller(journal,None,readonly=True)
            if source.read(installation['id'])!=installation:raise Conflict('original journal installation differs')
            check()
            if original_binding is None:retain(deepcopy(binding))
            check()
            db.execute('PRAGMA synchronous=FULL')
            yield journal,deepcopy(binding)
            check()
    finally:
        if db is not None:db.close()
        for fd in reversed(descriptors):os.close(fd)
