"""New-cycle metadata prepare with retained physical binding, temp SQLite only."""
import hashlib
import json
from pathlib import Path

import pytest

from tools import libvirt_postboot_prepare_host as entry
from tools.libvirt_postboot_journal import open_postboot_journal
from test_libvirt_postboot_prepare_host import native_recipe,assembly,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def bound_recipe(native_recipe):
    recipe,output,database,commands,files,proofs=native_recipe
    original=json.loads((recipe/'journal-reference.json').read_text())
    installed=json.loads((recipe/'installed.json').read_text());retained=[]
    with open_postboot_journal(original['directory'],installed,identity=original['identity'],
            initial_sha256=original['database_sha256'],retain=retained.append,verify=lambda:None) as (journal,binding):
        with journal.transaction():journal.db.execute('CREATE TABLE previous_boot_metadata (value TEXT)')
    assert hashlib.sha256(database.read_bytes()).hexdigest()!=original['database_sha256']
    (recipe/'journal-binding.json').write_text(json.dumps(binding))
    receipt=json.loads((recipe/'receipt.json').read_text())
    receipt['input_sha256']['journal-binding.json']=hashlib.sha256((recipe/'journal-binding.json').read_bytes()).hexdigest()
    (recipe/'receipt.json').write_text(json.dumps(receipt))
    return recipe,output,database,commands,files,proofs,binding


def test_retained_binding_allows_new_metadata_cycle_without_old_hash(bound_recipe):
    recipe,output,_,commands,files,_,binding=bound_recipe
    assert entry.run(recipe)==0
    assert json.loads((output/'journal-binding.json').read_text())==binding
    reference=(output/'prepared-reference.json').read_bytes()
    assert entry.run(recipe,resume_output=output)==0
    assert (output/'prepared-reference.json').read_bytes()==reference and len(commands)==2 and files.calls==[]


def test_foreign_binding_refused_without_metadata_schema_or_allocation(bound_recipe):
    recipe,output,database,_,files,_,binding=bound_recipe
    raw=database.read_bytes();binding['database_identity']['inode']+=1
    (recipe/'journal-binding.json').write_text(json.dumps(binding))
    receipt=json.loads((recipe/'receipt.json').read_text())
    receipt['input_sha256']['journal-binding.json']=hashlib.sha256((recipe/'journal-binding.json').read_bytes()).hexdigest()
    (recipe/'receipt.json').write_text(json.dumps(receipt))
    assert entry.run(recipe)==1 and database.read_bytes()==raw and files.calls==[]
    assert not (output/'prepared-reference.json').exists()


def test_lost_response_resumes_original_bound_cycle(bound_recipe,monkeypatch):
    from tools.libvirt_postboot_prepare import PrepareDelivery
    recipe,output,_,_,files,_,binding=bound_recipe;prepare=PrepareDelivery.prepare
    def lost(self,**kwargs):prepare(self,**kwargs);raise OSError('synthetic bound prepare response lost')
    monkeypatch.setattr(PrepareDelivery,'prepare',lost)
    assert entry.run(recipe)==1
    original=(output/'prepared-reference.json').read_bytes()
    monkeypatch.setattr(PrepareDelivery,'prepare',prepare)
    assert entry.run(recipe,resume_output=output)==0
    assert (output/'prepared-reference.json').read_bytes()==original
    assert json.loads((output/'journal-binding.json').read_text())==binding and files.calls==[]


def test_frozen_completed_revision_conflict_stops_before_prepare(bound_recipe):
    recipe,output,database,commands,files,_,_=bound_recipe
    raw=database.read_bytes()
    (recipe/'completed-revision.json').write_text('{}')
    receipt=json.loads((recipe/'receipt.json').read_text())
    receipt['input_sha256']['completed-revision.json']=hashlib.sha256((recipe/'completed-revision.json').read_bytes()).hexdigest()
    (recipe/'receipt.json').write_text(json.dumps(receipt))
    assert entry.run(recipe)==1 and database.read_bytes()==raw and commands==[] and files.calls==[]
    result=json.loads(next(output.glob('result-*.json')).read_text())
    assert 'explicit completed revision recipe input' in result['error']['message']
