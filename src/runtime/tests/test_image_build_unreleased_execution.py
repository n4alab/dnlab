"""Physical bindings on synthetic journals; Docker/proc observations simulated."""
from copy import deepcopy
import os
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))

from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_admin_fence import OriginalGateFence, identity
import image_build_unreleased_execution as execution
from image_build_unreleased_retirement import unreleased_state
from test_image_build_unreleased_retirement import unreleased
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def physical(unreleased,tmp_path):
    hold,_,_,args,original,request,observed=unreleased
    root=tmp_path/'original';root.mkdir(mode=0o700)
    db=sqlite3.connect(root/'journal.sqlite3',isolation_level=None);db.row_factory=sqlite3.Row
    hold.journal.db.backup(db);db.execute('PRAGMA journal_mode=WAL')
    db.execute('UPDATE metadata SET version=version')
    (root/'workload.lock').touch(mode=0o600)
    for name in ('journal.sqlite3','journal.sqlite3-wal'):os.chmod(root/name,0o600)
    binding={name:identity((root if name=='directory' else root/name).stat())
             for name in ('directory','workload.lock','journal.sqlite3','journal.sqlite3-wal')}
    assert unreleased_state(db,**args)==original
    try:yield root,binding,db,args,original,request,observed
    finally:db.close()


def test_write_binding_is_acknowledged_before_original_writer_opens(physical,tmp_path,monkeypatch):
    root,binding,db,args,original,request,observed=physical;saved={};open_writer=execution._writer
    def persist(name,value):saved[name]=deepcopy(value);return fingerprint(value)
    def writer(fence):
        assert list(saved)==['write-binding.json']
        assert saved['write-binding.json']['journal_identity']==original['journal_identity']
        return open_writer(fence)
    monkeypatch.setattr(execution,'_writer',writer)
    with OriginalGateFence(root,binding) as fence:
        receipt=execution.execute_unreleased(fence,request,original,arguments=args,snapshot=tmp_path/'snapshot',
            observe=lambda:deepcopy(observed),persist=persist)
    assert receipt['claim_released'] is True and saved['retirement.json']['already_committed'] is False
    assert unreleased_state(db,**args,claim_present=False)==original


def test_lost_report_after_commit_recovers_checkpointed_receipt_without_writer(physical,tmp_path,monkeypatch):
    root,binding,db,args,original,request,observed=physical
    def lost(name,value):
        if name=='retirement.json':raise OSError('lost receipt report')
        return fingerprint(value)
    with OriginalGateFence(root,binding) as fence:
        with pytest.raises(OSError,match='lost receipt report'):
            execution.execute_unreleased(fence,request,original,arguments=args,snapshot=tmp_path/'snapshot-first',
                observe=lambda:deepcopy(observed),persist=lost)
    db.close();assert not (root/'journal.sqlite3-wal').exists()
    before={p.name:p.read_bytes() for p in root.iterdir()}
    monkeypatch.setattr(execution,'_writer',lambda fence:pytest.fail('completed recovery must not open a writer'))
    saved={}
    def persist(name,value):saved[name]=deepcopy(value);return fingerprint(value)
    with execution.CheckpointedRetirementFence(root,binding) as fence:
        receipt=execution.execute_unreleased(fence,request,original,arguments=args,snapshot=tmp_path/'snapshot-recovery',
            observe=lambda:deepcopy(observed),persist=persist)
    assert receipt['claim_released'] is True and saved['retirement.json']['already_committed'] is True
    assert list(saved)==['retirement.json']
    assert {p.name:p.read_bytes() for p in root.iterdir()}==before


def test_missing_wal_without_committed_receipt_preserves_pending(physical,tmp_path,monkeypatch):
    root,binding,db,args,original,request,observed=physical;db.close()
    before={p.name:p.read_bytes() for p in root.iterdir()};saved=[]
    monkeypatch.setattr(execution,'_writer',lambda fence:pytest.fail('no replacement WAL allowed'))
    with execution.CheckpointedRetirementFence(root,binding) as fence:
        with pytest.raises(TemplateError,match='WAL absent without committed retirement'):
            execution.execute_unreleased(fence,request,original,arguments=args,snapshot=tmp_path/'snapshot',
                observe=lambda:deepcopy(observed),persist=lambda *args:saved.append(args))
    assert saved==[] and {p.name:p.read_bytes() for p in root.iterdir()}==before


@pytest.mark.parametrize('fault',['raise','unacknowledged'])
def test_uncertain_binding_durability_never_opens_writer(physical,tmp_path,monkeypatch,fault):
    root,binding,db,args,original,request,observed=physical
    def persist(name,value):
        if fault=='raise':raise OSError('fsync failed')
        return None
    monkeypatch.setattr(execution,'_writer',lambda fence:pytest.fail('binding not durable'))
    with OriginalGateFence(root,binding) as fence:
        with pytest.raises((OSError,TemplateError)):
            execution.execute_unreleased(fence,request,original,arguments=args,snapshot=tmp_path/'snapshot',
                observe=lambda:deepcopy(observed),persist=persist)
    assert unreleased_state(db,**args)==original


def test_changed_observation_after_durable_binding_does_not_open_writer(physical,tmp_path,monkeypatch):
    root,binding,db,args,original,request,observed=physical;calls=[]
    def observe():
        proof=deepcopy(observed);calls.append(True)
        if len(calls)==2:proof['owner_absent']=False
        return proof
    monkeypatch.setattr(execution,'_writer',lambda fence:pytest.fail('observation changed after binding'))
    with OriginalGateFence(root,binding) as fence:
        with pytest.raises(TemplateError,match='observation differs'):
            execution.execute_unreleased(fence,request,original,arguments=args,snapshot=tmp_path/'snapshot',
                observe=observe,persist=lambda name,value:fingerprint(value))
    assert unreleased_state(db,**args)==original


def test_checkpointed_reader_rejects_even_an_existing_original_wal(physical,tmp_path):
    root,binding,*_=physical
    with pytest.raises(TemplateError,match='WAL present'):
        with execution.CheckpointedRetirementFence(root,binding):pytest.fail('must not adopt WAL')
