"""Bind one administrative metadata write to the original physical journal.

The caller freezes the request, original proof and native observer. A durable
write binding is acknowledged before opening the existing DB writable. A
checkpointed DB without WAL is accepted only to read an exact committed receipt;
it never authorizes another write or creation of a replacement WAL.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import require
from image_build_admin_fence import OriginalGateFence, identity, stamp
from image_build_unreleased_retirement import (
    _observation, completed_unreleased, retire_unreleased, unreleased_state,
)


class CheckpointedRetirementFence(OriginalGateFence):
    """Same DB/directory/lock identities, WAL absent; completed SELECT only."""
    def check(self):
        require(self.parent is not None and self.lock is not None, 'original completed gate fence not held')
        require(identity(os.fstat(self.parent))==self.binding['directory']
                and identity(os.stat(self.directory,follow_symlinks=False))==self.binding['directory']
                and self.binding['directory']['uid']==0 and not self.binding['directory']['mode']&0o022,
                'original completed gate directory differs')
        for name in ('workload.lock','journal.sqlite3'):
            info=os.stat(name,dir_fd=self.parent,follow_symlinks=False)
            require(identity(info)==self.binding[name] and stat.S_ISREG(info.st_mode)
                    and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,
                    'original completed gate file differs: '+name)
        require(identity(os.fstat(self.lock))==self.binding['workload.lock'], 'original completed gate lock differs')
        try:os.stat('journal.sqlite3-wal',dir_fd=self.parent,follow_symlinks=False)
        except FileNotFoundError:return
        require(False, 'WAL present; checkpointed receipt reader cannot adopt it')

    def _raw(self):
        self.check();name='journal.sqlite3'
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
        try:
            before=stamp(os.fstat(fd));require(before['size']<=64*1024*1024, 'bounded completed database required')
            raw=os.pread(fd,64*1024*1024+1,0)
            require(len(raw)==before['size'] and stamp(os.fstat(fd))==before
                    and stamp(os.stat(name,dir_fd=self.parent,follow_symlinks=False))==before,
                    'completed database changed during read')
        finally:os.close(fd)
        self.check()
        return {name:dict(metadata=before,sha256=hashlib.sha256(raw).hexdigest())},{name:raw}


def _writer(fence):
    require(type(fence) is OriginalGateFence, 'only the original existing WAL permits a metadata writer')
    fence.check()
    uri=(Path('/proc/self/fd')/str(fence.parent)/'journal.sqlite3').as_uri()+'?mode=rw'
    db=sqlite3.connect(uri,uri=True,isolation_level=None)
    try:
        db.row_factory=sqlite3.Row;db.execute('PRAGMA synchronous=FULL');fence.check()
        return db
    except BaseException:
        db.close();raise


def execute_unreleased(fence, request, original, *, arguments, snapshot, observe, persist):
    """Operate only under a held fence; callbacks are explicit and mandatory.

    persist(name, value) must fsync file and directory and return fingerprint(value).
    Each invocation uses a new private report directory, with the same immutable
    request on recovery. No original Journal constructor, service command or
    retry loop is involved.
    """
    request=deepcopy(request);original=deepcopy(original);arguments=deepcopy(arguments)
    require(type(fence) in (OriginalGateFence,CheckpointedRetirementFence)
            and callable(observe) and callable(persist), 'original fence and qualified explicit providers required')
    wanted=_observation(request,original)
    def check():
        require(canonical(observe())==canonical(wanted), 'original administrative observation differs')
        fence.check()
    def save(name,value):
        require(persist(name,deepcopy(value))==fingerprint(value), 'durable administrative report not acknowledged')
    copied,raw=fence.snapshot(snapshot)
    table=copied.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='image_build_administrative_retirements'").fetchone()
    if table and copied.execute('SELECT 1 FROM image_build_administrative_retirements LIMIT 1').fetchone():
        require(unreleased_state(copied,**arguments,claim_present=False)==original,
                'original committed retirement history differs')
        check();receipt=completed_unreleased(copied,request,**arguments);check();fence.verify_raw(raw)
        save('retirement.json',dict(receipt=receipt,already_committed=True))
        return receipt
    require(type(fence) is OriginalGateFence,
            'WAL absent without committed retirement; preserve pending, no new writer')
    require(unreleased_state(copied,**arguments)==original, 'original unreleased write history differs')
    check()
    save('write-binding.json',dict(request=request,original_sha256=fingerprint(original),
        physical=fence.binding,raw=raw,journal_identity=original['journal_identity']))
    check();fence.verify_raw(raw)
    db=_writer(fence)
    try:
        require(unreleased_state(db,**arguments)==original, 'writable original journal identity/history differs')
        receipt=retire_unreleased(db,request,**arguments,observe=observe)
        require(completed_unreleased(db,request,**arguments)==receipt, 'original retirement commit differs')
        fence.check();save('retirement.json',dict(receipt=receipt,already_committed=False))
        return receipt
    finally:db.close()
