"""Fence the existing gate journal and read its pending WAL without side effects.

Opening the original SQLite database is deliberately excluded. A coherent raw
copy under the original execution lock supplies read-only material for the
lineage validator. The caller persists that binding before any later write.
"""
from contextlib import ExitStack
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

from dnlab_runtime.vm_template import require

DIRECTORY=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
FILES=('journal.sqlite3','journal.sqlite3-wal')


def identity(info):
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))


def stamp(info):
    return identity(info)|dict(size=info.st_size,links=info.st_nlink,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)


class OriginalGateFence:
    def __init__(self, directory, binding):
        self.directory=Path(directory);self.binding=deepcopy(binding);self.stack=ExitStack()
        self.parent=self.lock=None;self.baseline=None;self.database=None
        require(self.directory.is_absolute() and '..' not in self.directory.parts
                and set(binding)=={'directory','workload.lock',*FILES}, 'original gate physical binding required')

    def __enter__(self):
        try:
            self.parent=os.open('/',DIRECTORY);self.stack.callback(os.close,self.parent)
            for part in self.directory.parts[1:]:
                self.parent=os.open(part,DIRECTORY,dir_fd=self.parent);self.stack.callback(os.close,self.parent)
            self.lock=os.open('workload.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
            self.stack.callback(os.close,self.lock)
            require(identity(os.fstat(self.lock))==self.binding['workload.lock']
                    and stat.S_ISREG(os.fstat(self.lock).st_mode) and os.fstat(self.lock).st_nlink==1,
                    'original gate execution lock differs')
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.check();return self
        except BaseException:
            self.stack.close();self.parent=self.lock=None;raise

    def check(self):
        require(self.parent is not None and self.lock is not None, 'original gate fence is not held')
        require(identity(os.fstat(self.parent))==self.binding['directory']
                and identity(os.stat(self.directory,follow_symlinks=False))==self.binding['directory']
                and identity(os.fstat(self.lock))==self.binding['workload.lock'],
                'original gate fence directory or descriptor replaced')
        for name in ('workload.lock',*FILES):
            info=os.stat(name,dir_fd=self.parent,follow_symlinks=False)
            require(identity(info)==self.binding[name] and stat.S_ISREG(info.st_mode)
                    and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,
                    'original gate file binding differs: '+name)
        require(self.binding['directory']['uid']==0 and not self.binding['directory']['mode']&0o022,
                'original gate root-controlled directory required')

    def _raw(self):
        self.check();rows={};content={};total=0
        for name in FILES:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
            try:
                before=stamp(os.fstat(fd));limit=64*1024*1024-total
                require(before['size']<=limit, 'bounded original journal copy required')
                data=os.pread(fd,limit+1,0);total+=len(data)
                require(len(data)==before['size'] and total<=64*1024*1024
                        and stamp(os.fstat(fd))==before
                        and stamp(os.stat(name,dir_fd=self.parent,follow_symlinks=False))==before,
                        'original gate journal changed during raw read')
                rows[name]=dict(metadata=before,sha256=hashlib.sha256(data).hexdigest());content[name]=data
            finally:os.close(fd)
        self.check();return rows,content

    def snapshot(self, destination):
        """Create a new private snapshot; never copy or touch the original SHM."""
        require(self.database is None, 'original gate snapshot already captured')
        rows,content=self._raw();again,other=self._raw()
        require(rows==again and content==other, 'original gate WAL copy is not coherent')
        destination=Path(destination);destination.mkdir(mode=0o700)
        for name,data in content.items():
            fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(os.dup(fd),'wb') as out:out.write(data);out.flush()
                os.fsync(fd)
            finally:os.close(fd)
        parent=os.open(destination,DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
        self.verify_raw(rows)
        self.database=sqlite3.connect((destination/'journal.sqlite3').as_uri()+'?mode=ro',uri=True,isolation_level=None)
        self.database.row_factory=sqlite3.Row;self.database.execute('PRAGMA query_only=ON')
        self.baseline=rows
        return self.database,deepcopy(rows)

    def verify_raw(self, expected=None):
        require(expected is not None or self.baseline is not None, 'original gate raw baseline missing')
        rows,_=self._raw()
        require(rows==(self.baseline if expected is None else expected), 'original gate journal changed after binding')

    def __exit__(self,*args):
        try:
            if self.database is not None:self.database.close()
        finally:
            self.stack.close();self.parent=self.lock=None
