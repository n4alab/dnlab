"""Historical unit binding only; current resource observations are synthetic."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_unit_prepare import PostBootUnitPrepare
from tools.libvirt_unit_postboot_collection import UnitPostBootCollection
from tools import libvirt_unit_postboot_collect_host as entry
from test_libvirt_postboot_unit_prepare import unit_prepare,directories,wiring,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def collection(unit_prepare):
    built,source,window,_,_,_,_,_=unit_prepare
    reference=PostBootUnitPrepare(built,effective_source=source,window=window).prepare()
    result={'context':{'boot_id':'synthetic-new-boot'},'pending_volatile':['synthetic-run-path'],'qualified':False}
    calls=[]
    def collect():calls.append(True);return deepcopy(result)
    reader=SimpleNamespace(collect=collect)
    arguments=dict(reference=reference,effective_source=source,directory_reference=built.reference)
    value=UnitPostBootCollection(reader,built.session.journal,**arguments)
    return value,arguments,calls,reader


def test_keeps_old_reference_without_qualifying_new_boot(collection):
    value,arguments,calls,_=collection;before=value.journal.db.total_changes
    observed=value.collect()
    assert observed['historical_unit_reference']==arguments['reference'] and calls==[True]
    assert observed['qualified'] is False and observed['unit_apply_permitted'] is False
    assert observed['pending_volatile']==['synthetic-run-path']
    assert value.journal.db.total_changes==before


def test_foreign_reference_refused_before_resource_collection(collection):
    value,_,calls,_=collection;value.reference['nonce']='0'*32
    with pytest.raises(Conflict,match='observation changed'):value.collect()
    assert calls==[]


def test_changed_reference_during_collection_refused(collection):
    value,_,calls,reader=collection
    def changed():
        calls.append(True);value.reference['nonce']='0'*32;return {'qualified':False}
    reader.collect=changed
    with pytest.raises(Conflict,match='observation changed'):value.collect()
    assert calls==[True]


def test_foreign_directory_lineage_refused(collection):
    value,arguments,_,reader=collection
    arguments=deepcopy(arguments);arguments['directory_reference']['recovery']['id']='foreign'
    with pytest.raises(Conflict,match='lineage differs'):
        UnitPostBootCollection(reader,value.journal,**arguments)


def test_explicit_collect_flag_before_host_access(monkeypatch,tmp_path):
    monkeypatch.setattr(entry,'run',lambda *a:pytest.fail('collection without flag'))
    with pytest.raises(SystemExit) as error:entry.main(['--recipe',str(tmp_path)])
    assert error.value.code==2
