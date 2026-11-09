"""Verifier I/O remains read-only, including SQLite and Docker inventory."""
import os
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tools'))
from verify_jumphost_lifecycle_gate import database,inventory,exited


def test_closed_database_is_read_without_creating_sidecars(tmp_path):
    path=tmp_path/'journal.sqlite3'
    connection=sqlite3.connect(path);connection.execute('CREATE TABLE facts (value TEXT)')
    connection.execute("INSERT INTO facts VALUES('original')");connection.commit();connection.close()
    before={p.name:p.read_bytes() for p in tmp_path.iterdir()}
    assert database(path,('facts',))=={'facts':[{'value':'original'}]}
    assert {p.name:p.read_bytes() for p in tmp_path.iterdir()}==before


def test_nonempty_wal_cannot_be_silently_ignored(tmp_path):
    path=tmp_path/'journal.sqlite3';path.write_bytes(b'not used')
    wal=tmp_path/'journal.sqlite3-wal';wal.write_bytes(b'uncheckpointed')
    with pytest.raises(ValueError,match='checkpointed'):database(path,('facts',))
    assert wal.read_bytes()==b'uncheckpointed'


def test_missing_database_is_not_created(tmp_path):
    path=tmp_path/'missing.sqlite3'
    with pytest.raises(sqlite3.OperationalError):database(path,('facts',))
    assert not list(tmp_path.iterdir())


def test_global_inventory_contains_original_ids_state_and_network_configuration():
    calls=[]
    container={'Id':'a'*64,'Name':'original','Image':'sha256:'+'b'*64,
               'State':{'Pid':42,'StartedAt':'original','Running':True},'RestartCount':0}
    network={key:key for key in ('Name','Driver','IPAM','Options','Labels','Containers')}
    class API:
        def request(self,method,path):
            assert method=='GET';calls.append(path)
            if path=='/containers/json?all=1':return [{'Id':container['Id']}]
            if path=='/networks':return [{'Id':'c'*64}]
            if path.startswith('/containers/'):return container
            return network
    result=inventory(API())
    assert result['containers'][container['Id']]['state']==container['State']
    assert result['networks']['c'*64]==network and len(calls)==4


def test_original_process_must_have_exited_or_changed_generation():
    start=(Path('/proc/self/stat')).read_text().rsplit(')',1)[1].split()[19]
    assert not exited({'pid':os.getpid(),'start':start})
    assert exited({'pid':os.getpid(),'start':'0'})
