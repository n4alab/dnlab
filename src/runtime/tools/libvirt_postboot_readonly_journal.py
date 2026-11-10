"""Read the retained original journal without creating locks or SQLite sidecars.

Requires a quiet original execution lock and no pending database state. This is
an observation, never a new post-boot binding or permission to reuse resources.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import threading
from types import SimpleNamespace

from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.manifest import Conflict,fingerprint
from tools.libvirt_postboot_journal import file_identity


def stamp(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
        info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


@contextmanager
def readonly_bound_journal(directory,installation,*,binding,verify):
    directory=Path(directory);descriptors=[];database=None
    if (not directory.is_absolute() or '..' in directory.parts or not callable(verify)
            or binding.get('kind')!='postboot-original-journal-v1' or binding.get('directory')!=str(directory)
            or binding.get('source_sha256')!=fingerprint(installation)):
        raise Conflict('original readonly journal binding required')
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);descriptors.append(parent)
        for part in directory.parts[1:]:
            parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            descriptors.append(parent)
        if file_identity(os.fstat(parent))!=binding['directory_identity']:
            raise Conflict('original readonly journal directory differs')
        for name in ('workload.lock','journal.sqlite3'):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);descriptors.append(fd)
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
                raise Conflict('original readonly journal file metadata differs')
            if name=='workload.lock':
                lock_fd=fd;lock_identity=file_identity(info)
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise Conflict('original journal execution is active') from None
            else:
                db_fd=fd;initial=stamp(info)
                if file_identity(info)!=binding['database_identity'] or info.st_size>16*1024*1024:
                    raise Conflict('original readonly journal database differs')
        def check():
            verify()
            if (file_identity(os.stat(directory,follow_symlinks=False))!=binding['directory_identity']
                    or file_identity(os.fstat(parent))!=binding['directory_identity']
                    or file_identity(os.stat('workload.lock',dir_fd=parent,follow_symlinks=False))!=lock_identity
                    or file_identity(os.fstat(lock_fd))!=lock_identity
                    or stamp(os.stat('journal.sqlite3',dir_fd=parent,follow_symlinks=False))!=initial
                    or stamp(os.fstat(db_fd))!=initial):
                raise Conflict('original readonly journal changed during observation')
            for name in ('journal.sqlite3-wal','journal.sqlite3-shm','journal.sqlite3-journal'):
                try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:continue
                raise Conflict('original readonly journal has pending database state')
        check()
        # Hash the bounded pinned file for diagnostics, not an obsolete baseline.
        digest=hashlib.sha256(os.pread(db_fd,16*1024*1024+1,0)).hexdigest()
        uri=(Path('/proc/self/fd')/str(parent)/'journal.sqlite3').as_uri()
        database=sqlite3.connect(uri+'?mode=ro&immutable=1',uri=True,isolation_level=None)
        database.row_factory=sqlite3.Row;database.execute('PRAGMA query_only=ON')
        journal=SimpleNamespace(db=database,identity=binding['journal_identity'],lock=threading.RLock(),execution_lock=threading.RLock())
        row=database.execute('SELECT identity FROM journal_identity WHERE singleton=1').fetchone()
        if row is None or row['identity']!=binding['journal_identity']:
            raise Conflict('original readonly journal logical identity differs')
        if SessionInstaller(journal,None,readonly=True).read(installation['id'])!=installation:
            raise Conflict('original readonly installation differs')
        check()
        yield journal,dict(binding=binding,database_sha256=digest,readonly=True)
        check()
    finally:
        if database is not None:database.close()
        for fd in reversed(descriptors):os.close(fd)
