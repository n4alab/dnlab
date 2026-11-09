"""Inert adapter contract checks; existing helper guards remain authoritative."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tools'))
import retirement_infrastructure as module
from dnlab_multinode.services.runtime_operations import RuntimeOperationError


@pytest.mark.parametrize('role',['relay','jumphost','dns'])
def test_helper_owner_uses_original_guard_and_retains_birth_on_cleanup(role,monkeypatch):
    record={'phase':'active','config':{'generation':'a'*32,'name':'original'},
        'container_id':'b'*64,'nonce':'c'*32,'image':{'Id':'d'*64},'context':{'boot':'original'}}
    owner=module.HelperOwner(role,'lab',object(),record);calls=[]
    def guard(*args,**kwargs):
        action=args[3] if role=='relay' else args[2];calls.append((action,args,kwargs))
        if action=='delete':record['phase']='cleaned'
        return deepcopy(record)
    monkeypatch.setattr(owner.module,'_guard',guard)
    pin=owner.identity();owner.cleanup(pin);owner.verify_cleaned(pin)
    assert [c[0] for c in calls]==['preflight-delete','preflight-delete','delete','verify-cleaned']
    assert all('ensure' not in c[0] for c in calls)
    if role=='relay':assert all(c[2]=={'generation':'a'*32} for c in calls)
    else:
        expected={'generation':'a'*32}
        if role=='jumphost':expected['container']='original'
        assert all(c[1][3]==expected for c in calls)


@pytest.mark.parametrize('role',['relay','jumphost','dns'])
def test_substituted_helper_is_preserved(role,monkeypatch):
    record={'phase':'active','config':{'generation':'a'*32,'name':'original'},'container_id':'b'*64,'nonce':'c'*32}
    owner=module.HelperOwner(role,'lab',object(),record);calls=[]
    def guard(*args,**kwargs):
        action=args[3] if role=='relay' else args[2];calls.append(action)
        return {**deepcopy(record),'container_id':'f'*64}
    monkeypatch.setattr(owner.module,'_guard',guard)
    with pytest.raises(RuntimeOperationError,match='generation changed'):owner.cleanup(owner.pin)
    assert calls==['preflight-delete']


def test_fixture_with_cli_journals_cannot_bypass_cli_qualification(tmp_path):
    (tmp_path/'cli-before-connect-exec.json').write_text('{}')
    with pytest.raises(RuntimeOperationError,match='CLI execution requires'):
        module.owners(tmp_path,'lab',None,None,None,None)


def test_fixture_refuses_global_installed_journal_paths(tmp_path):
    with pytest.raises(RuntimeOperationError,match='journal directory binding required'):
        module.owners(tmp_path,'lab',None,None,None,None)
