"""Quiet journal leases on exclusively owned test files, without host resources."""
from copy import deepcopy
import fcntl
import json
import os
import sqlite3
from types import SimpleNamespace

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.readonly_resource_journal import readonly_resource_journal


@pytest.fixture
def source(tmp_path):
    directory = tmp_path/'journal'; journal = Journal(directory)
    proof = dict(kind='synthetic-root', nonce='a'*32, inode=12345)
    with journal.execution_lock, journal.transaction():
        journal.db.execute('CREATE TABLE original_resource (id TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        journal.db.execute('INSERT INTO original_resource VALUES(?,?)', ('root', canonical(proof)))
    original_id = journal.identity; journal.close()
    state = dict(context=True, validations=0)
    def verify():
        if not state['context']:raise Conflict('synthetic current context changed')
    def validate(view):
        state['validations'] += 1
        row = view.db.execute('SELECT payload FROM original_resource WHERE id=?', ('root',)).fetchone()
        if row is None or json.loads(row[0]) != proof:raise Conflict('original synthetic resource differs')
        return fingerprint(proof)
    def open_reader(**kwargs):
        options = dict(journal_identity=original_id, resource_sha256=fingerprint(proof),
                       verify=verify, validate=validate)
        options.update(kwargs)
        return readonly_resource_journal(directory, **options)
    return SimpleNamespace(directory=directory, open=open_reader, state=state, identity=original_id,
                           proof=proof, validate=validate)


def test_readonly_query_leaves_files_and_bytes_unchanged_and_expires_lease(source):
    e = source; names = sorted(p.name for p in e.directory.iterdir())
    raw = (e.directory/'journal.sqlite3').read_bytes()
    with e.open() as lease:
        assert lease.journal.db.execute('PRAGMA query_only').fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            lease.journal.db.execute('DELETE FROM original_resource')
        binding = lease.check()
        assert binding['journal_identity'] == e.identity and binding['resource_sha256'] == fingerprint(e.proof)
        lease.receipt['resource_sha256'] = 'f'*64
        assert lease.check() == binding
    with pytest.raises(Conflict, match='lease is closed'):lease.check()
    assert sorted(p.name for p in e.directory.iterdir()) == names
    assert (e.directory/'journal.sqlite3').read_bytes() == raw
    with e.open(expected_binding=binding) as reopened:
        assert reopened.check() == binding


def test_shared_readers_exclude_an_ordinary_writer(source):
    e = source
    with e.open() as first, e.open() as second:
        assert first.check() == second.check()
        fd = os.open(e.directory/'workload.lock', os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)


def test_active_writer_is_rejected_before_sqlite_open(source, monkeypatch):
    e = source; fd = os.open(e.directory/'workload.lock', os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        monkeypatch.setattr('dnlab_runtime.readonly_resource_journal.sqlite3.connect',
                            lambda *args, **kwargs:pytest.fail('SQLite opened during writer activity'))
        with pytest.raises(Conflict, match='writer is active'):
            with e.open():pytest.fail('active writer admitted')
    finally:os.close(fd)


@pytest.mark.parametrize('sidecar', ['journal.sqlite3-wal', 'journal.sqlite3-shm', 'journal.sqlite3-journal'])
def test_pending_sqlite_state_is_not_ignored_or_recovered(source, monkeypatch, sidecar):
    e = source; pending = e.directory/sidecar; pending.write_bytes(b'preserve uncertain state')
    monkeypatch.setattr('dnlab_runtime.readonly_resource_journal.sqlite3.connect',
                        lambda *args, **kwargs:pytest.fail('SQLite opened with pending state'))
    with pytest.raises(Conflict, match='pending SQLite'):
        with e.open():pytest.fail('pending state admitted')
    assert pending.read_bytes() == b'preserve uncertain state'


@pytest.mark.parametrize('name', ['journal.sqlite3', 'workload.lock'])
def test_replacement_during_lease_is_rejected_without_touching_either_file(source, name):
    e = source; path = e.directory/name; raw = path.read_bytes(); backup = path.with_name(name+'.original')
    with pytest.raises(Conflict, match='changed or replaced'):
        with e.open() as lease:
            path.rename(backup); path.write_bytes(raw); path.chmod(0o600)
            lease.check()
    assert path.read_bytes() == backup.read_bytes() == raw


def test_directory_replacement_cannot_redirect_the_pinned_database(source):
    e = source; old = e.directory.with_name('original-journal')
    with pytest.raises(Conflict, match='directory replaced'):
        with e.open() as lease:
            e.directory.rename(old); e.directory.mkdir(mode=0o700)
            lease.check()
    assert (old/'journal.sqlite3').is_file() and list(e.directory.iterdir()) == []


def test_a_changed_persisted_binding_is_rejected_before_sqlite(source, monkeypatch):
    e = source
    with e.open() as lease:binding = deepcopy(lease.receipt)
    binding['database_identity']['inode'] += 1
    monkeypatch.setattr('dnlab_runtime.readonly_resource_journal.sqlite3.connect',
                        lambda *args, **kwargs:pytest.fail('SQLite opened with changed binding'))
    with pytest.raises(Conflict, match='binding changed'):
        with e.open(expected_binding=binding):pytest.fail('changed binding admitted')


def test_logical_identity_and_original_resource_are_required(source):
    e = source
    with pytest.raises(Conflict, match='logical identity'):
        with e.open(journal_identity='0'*32):pytest.fail('foreign journal admitted')
    assert e.state['validations'] == 0
    with pytest.raises(Conflict, match='resource proof differs'):
        with e.open(validate=lambda view:'f'*64):pytest.fail('foreign resource admitted')


def test_context_failure_on_exception_still_closes_the_database(source):
    e = source; retained = []
    with pytest.raises(Conflict, match='current context changed') as error:
        with e.open() as lease:
            retained.append(lease.journal.db); e.state['context'] = False
            raise OSError('original synthetic body error')
    assert isinstance(error.value.__context__, OSError)
    with pytest.raises(sqlite3.ProgrammingError):retained[0].execute('SELECT 1')


def test_failed_resource_validation_releases_pins_and_sqlite(source, monkeypatch):
    e = source; descriptors = []; connections = []; original = os.open
    def opened(*args, **kwargs):
        fd = original(*args, **kwargs); descriptors.append(fd); return fd
    def failed(view):
        connections.append(view.db); raise Conflict('original resource rejected')
    monkeypatch.setattr('dnlab_runtime.readonly_resource_journal.os.open', opened)
    with pytest.raises(Conflict, match='resource rejected'):
        with e.open(validate=failed):pytest.fail('invalid resource admitted')
    for fd in descriptors:
        with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError):connections[0].execute('SELECT 1')
