"""Real temporary SQLite WAL and kernel lock; no installed journal access."""
from copy import deepcopy
import fcntl
import os
import sqlite3

import pytest

from dnlab_runtime.vm_template import TemplateError
from image_build_admin_fence import OriginalGateFence, identity


@pytest.fixture
def source(tmp_path):
    path=tmp_path/'original';path.mkdir(mode=0o700)
    lock=path/'workload.lock';lock.touch(mode=0o600)
    db=sqlite3.connect(path/'journal.sqlite3',isolation_level=None)
    db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE example (value TEXT)')
    db.execute("INSERT INTO example VALUES('original')")
    for name in ('journal.sqlite3','journal.sqlite3-wal'):os.chmod(path/name,0o600)
    binding={name:identity((path/name).stat()) for name in ('workload.lock','journal.sqlite3','journal.sqlite3-wal')}
    binding['directory']=identity(path.stat())
    yield path,binding,db
    db.close()


def test_pending_wal_read_does_not_change_original_files(source,tmp_path):
    path,binding,_=source
    before={p.name:(p.stat(),p.read_bytes()) for p in path.iterdir()}
    with OriginalGateFence(path,binding) as fence:
        copy,proof=fence.snapshot(tmp_path/'snapshot')
        assert copy.execute('SELECT value FROM example').fetchone()[0]=='original'
        with pytest.raises(sqlite3.OperationalError):copy.execute("INSERT INTO example VALUES('forbidden')")
        fence.verify_raw(proof)
        fd=os.open(path/'workload.lock',os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)
    assert set(p.name for p in path.iterdir())==set(before)
    for name,(info,content) in before.items():
        assert (path/name).read_bytes()==content
        after=(path/name).stat()
        assert (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def test_active_original_execution_refuses_without_snapshot(source,tmp_path):
    path,binding,_=source;fd=os.open(path/'workload.lock',os.O_RDONLY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            with OriginalGateFence(path,binding):raise AssertionError('must not enter')
    finally:os.close(fd)
    assert not (tmp_path/'snapshot').exists()


def test_source_change_after_snapshot_is_refused(source,tmp_path):
    path,binding,db=source
    with OriginalGateFence(path,binding) as fence:
        fence.snapshot(tmp_path/'snapshot');db.execute("INSERT INTO example VALUES('changed')")
        with pytest.raises(TemplateError,match='changed after binding'):fence.verify_raw()


@pytest.mark.parametrize('name',['directory','workload.lock','journal.sqlite3','journal.sqlite3-wal'])
def test_foreign_physical_binding_refuses_without_initializing_files(source,name):
    path,binding,_=source;wrong=deepcopy(binding);wrong[name]['inode']+=1
    with pytest.raises(TemplateError):
        with OriginalGateFence(path,wrong):raise AssertionError('must not enter')


def test_missing_lock_is_not_created(source):
    path,binding,_=source;(path/'workload.lock').unlink()
    with pytest.raises(FileNotFoundError):
        with OriginalGateFence(path,binding):raise AssertionError('must not enter')
    assert not (path/'workload.lock').exists()
