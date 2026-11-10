"""Readonly binding checks on private temporary SQLite; no native installation."""
from copy import deepcopy
import sqlite3

import pytest

from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_journal import open_postboot_journal
from tools.libvirt_postboot_readonly_journal import readonly_bound_journal
from test_libvirt_postboot_journal import original,install,request_profile


@pytest.fixture
def bound(original):
    arguments,path,_,_=original
    with open_postboot_journal(**arguments) as (journal,binding):
        with journal.transaction():journal.db.execute('CREATE TABLE later_metadata (value TEXT)')
    return arguments,path,binding


def test_reads_current_metadata_without_initial_hash_or_writes(bound):
    args,path,binding=bound;raw=path.read_bytes();names=set(p.name for p in path.parent.iterdir())
    with readonly_bound_journal(args['directory'],args['installation'],binding=binding,verify=lambda:None) as (journal,receipt):
        assert journal.db.execute('SELECT count(*) FROM later_metadata').fetchone()[0]==0
        assert receipt['readonly'] is True and receipt['database_sha256']!=binding['initial_sha256']
        with pytest.raises(sqlite3.OperationalError,match='readonly'):
            journal.db.execute('CREATE TABLE forbidden (value TEXT)')
    assert path.read_bytes()==raw and set(p.name for p in path.parent.iterdir())==names


@pytest.mark.parametrize('sidecar',['-wal','-shm','-journal'])
def test_pending_database_state_preserved_and_refused(bound,sidecar):
    args,path,binding=bound;pending=path.with_name(path.name+sidecar);pending.write_bytes(b'synthetic')
    raw=path.read_bytes()
    with pytest.raises(Conflict,match='pending database state'):
        with readonly_bound_journal(args['directory'],args['installation'],binding=binding,verify=lambda:None):
            pytest.fail('pending journal opened')
    assert pending.read_bytes()==b'synthetic' and path.read_bytes()==raw


def test_database_replacement_not_adopted(bound):
    args,path,binding=bound;replacement=path.with_name('replacement')
    replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);replacement.replace(path)
    with pytest.raises(Conflict,match='database differs'):
        with readonly_bound_journal(args['directory'],args['installation'],binding=binding,verify=lambda:None):
            pytest.fail('replacement opened')


def test_changes_during_read_refused(bound):
    args,path,binding=bound
    with pytest.raises(Conflict,match='changed during observation'):
        with readonly_bound_journal(args['directory'],args['installation'],binding=binding,verify=lambda:None):
            path.touch()


def test_foreign_source_rejected_without_creating_files(bound):
    args,path,binding=bound;source=deepcopy(args['installation']);source['phase']='foreign'
    raw=path.read_bytes()
    with pytest.raises(Conflict,match='binding required'):
        with readonly_bound_journal(args['directory'],source,binding=binding,verify=lambda:None):
            pytest.fail('foreign source opened')
    assert path.read_bytes()==raw
