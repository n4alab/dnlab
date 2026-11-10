"""Scoped unit files use private temporary paths; other resources simulated."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import UNIT
from dnlab_runtime.libvirt_configuration_adapter import ConfigurationFileAdapter
from dnlab_runtime.libvirt_configuration_swap import EXCHANGE,NOREPLACE
from dnlab_runtime.libvirt_current_session import CurrentConfigurationSession
from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_unit_prepare import PostBootUnitPrepare
from tools.libvirt_postboot_unit_revision import PreparedUnitFiles,PostBootUnitRevision
from test_libvirt_configuration_adapter import configured
from test_libvirt_postboot_unit_prepare import unit_prepare,directories,wiring,boot_parent,installed_packages,install,request_profile


def scoped(configured):
    driver,adapter,reference,root=configured
    files=PreparedUnitFiles(str(root),journal=driver.journal,reference=reference)
    replacement=ConfigurationFileAdapter(files,window=driver.window,preflight=adapter.preflight)
    driver.adapter=replacement
    return driver,replacement,reference,root


def test_scoped_unit_candidate_and_exchange_preserve_original_backup(configured):
    driver,adapter,reference,root=scoped(configured)
    source=(root/UNIT.lstrip('/')).read_bytes()
    effective=driver.apply(reference['id'])
    assert 'Requisite=' in (root/UNIT.lstrip('/')).read_text()
    assert (root/reference['backup'].lstrip('/')).read_bytes()==source
    assert driver.apply(reference['id'])==effective
    assert adapter.files.request['id']==reference['id']


def test_lost_exchange_response_recovers_original_without_repeating_exchange(configured,monkeypatch):
    driver,adapter,reference,_=scoped(configured);rename=adapter.swap._rename;calls=[]
    def lost(*args):
        calls.append(args[-1]);rename(*args)
        if args[-1]==EXCHANGE:raise OSError('synthetic lost exchange response')
    monkeypatch.setattr(adapter.swap,'_rename',lost)
    with pytest.raises(OSError,match='lost exchange'):driver.apply(reference['id'])
    assert driver.recover(reference['id'])==driver.effective(reference['id'])
    assert calls==[EXCHANGE,NOREPLACE]


def test_file_capability_refuses_other_births_and_relocation_paths(configured):
    _,adapter,reference,root=scoped(configured);files=adapter.files
    candidate=deepcopy(files.candidate);candidate['nonce']='0'*32
    with pytest.raises(Conflict,match='candidate mutation'):files.create(candidate,reference['id'])
    with pytest.raises(Conflict,match='candidate mutation'):files.recover(files.candidate,'foreign')
    with pytest.raises(Conflict,match='relocation'):
        files.observe_relocated(reference['plan']['source_item'],reference['installation']['id'],'/etc/foreign')
    assert not (root/reference['staging'].lstrip('/')).exists()


def test_current_revision_separates_file_capability_without_preparing_again(unit_prepare,monkeypatch):
    directories,source,window,_,_,_,_,_=unit_prepare
    reference=PostBootUnitPrepare(directories,effective_source=source,window=window).prepare()
    monkeypatch.setattr(CurrentConfigurationSession,'prepare',lambda *a:pytest.fail('unit apply entry cannot prepare'))
    before=directories.session.journal.db.total_changes
    revision=PostBootUnitRevision(directories,effective_source=source,window=window,unit_reference=reference)
    assert revision.revision.adapter.files is revision.files and revision.files is not directories.files
    assert revision.revision.preflight.files.view.files is directories.files
    assert directories.session.journal.db.total_changes==before
    with pytest.raises(Conflict,match='directory mutation'):
        directories.files.create(revision.files.candidate,reference['id'])


def test_foreign_revision_reference_is_refused_before_file_capability(unit_prepare):
    directories,source,window,_,parent,files,_,_=unit_prepare
    reference=PostBootUnitPrepare(directories,effective_source=source,window=window).prepare()
    reference['nonce']='0'*32;calls=list(files.calls)
    with pytest.raises(Conflict):PostBootUnitRevision(directories,effective_source=source,window=window,unit_reference=reference)
    assert files.calls==calls and list(parent.iterdir())==[]


def test_active_service_blocks_unit_replacement_before_staging(unit_prepare):
    directories,source,window,_,parent,files,observed,_=unit_prepare
    reference=PostBootUnitPrepare(directories,effective_source=source,window=window).prepare()
    revision=PostBootUnitRevision(directories,effective_source=source,window=window,unit_reference=reference)
    calls=list(files.calls)
    next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    with pytest.raises(Conflict):revision.apply_original()
    assert files.calls==calls and list(parent.iterdir())==[]
