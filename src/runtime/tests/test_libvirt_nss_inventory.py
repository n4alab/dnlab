"""Only injected synthetic NSS rows; no host pwd/grp queries or commands."""
from copy import deepcopy
import sys

import pytest

from dnlab_runtime.manifest import Conflict,fingerprint
from tools import libvirt_nss_inventory as module


def fake(database,key):
    if key in ('root',0):
        value=dict(name='root',gid=0)
        if database=='passwd':value['uid']=0
        return value
    return None


def test_two_targeted_observations_do_not_claim_complete_nss_absence():
    calls=[]
    def query(database,key):calls.append((database,key));return fake(database,key)
    result=module.collect('dnlab-libvirt',1001,1002,query=query)
    assert result['qualified'] is False and result['candidate_reported_absent'] is True
    assert len(calls)==16 and calls[:8]==calls[8:]
    assert result['observation_sha256']==fingerprint(result['observed'])
    assert 'provider' in result['limitations'][1]


@pytest.mark.parametrize('database,key,row',[
    ('passwd','dnlab-libvirt',dict(name='dnlab-libvirt',uid=2000,gid=2001)),
    ('passwd',1001,dict(name='other',uid=1001,gid=2001)),
    ('group','dnlab-libvirt',dict(name='dnlab-libvirt',gid=2001)),
    ('group',1002,dict(name='other',gid=1002)),
])
def test_name_or_numeric_collision_is_recorded_without_adoption(database,key,row):
    original=deepcopy(row)
    def query(db,value):return row if (db,value)==(database,key) else fake(db,value)
    result=module.collect('dnlab-libvirt',1001,1002,query=query)
    assert result['candidate_reported_absent'] is False and result['qualified'] is False
    assert row==original


@pytest.mark.parametrize('fault',['wrong_id','wrong_name','malformed','missing_root','error','change'])
def test_incomplete_ambiguous_or_changed_queries_are_not_accepted(fault):
    calls=[]
    def query(database,key):
        calls.append((database,key))
        if fault=='error':raise OSError('synthetic provider error')
        if database=='passwd' and key=='root':
            if fault=='missing_root':return None
            if fault=='malformed':return dict(name='root',uid=True,gid=0)
            if fault=='wrong_name':return dict(name='foreign',uid=0,gid=0)
        if database=='passwd' and key==1001:
            if fault=='wrong_id':return dict(name='foreign',uid=1003,gid=1002)
            if fault=='change' and len(calls)>8:return dict(name='foreign',uid=1001,gid=1002)
        return fake(database,key)
    with pytest.raises(Conflict):module.collect('dnlab-libvirt',1001,1002,query=query)


def test_host_query_requires_explicit_switch(monkeypatch):
    monkeypatch.setattr(sys,'argv',['inventory'])
    monkeypatch.setattr(module,'host_query',lambda *args:pytest.fail('host query not authorized'))
    with pytest.raises(SystemExit) as error:module.main()
    assert error.value.code==2
