"""Composed post-boot workflow; synthetic observers, directories and journal."""
from contextlib import contextmanager
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict
from test_libvirt_install import install,request_profile
from test_libvirt_package_policy import installed_packages
from test_libvirt_run_parent import boot_parent,PinnedDirectories


@pytest.fixture
def assembly(boot_parent):
    driver,original,current,observed,installer,_,parent=boot_parent
    agreement=dict(operation_id='assembled-directories',context=deepcopy(current),
        targets=list(observed['volatile']),nonce='4'*32)
    live=deepcopy(agreement);window=ProvisioningWindow(agreement,lambda:deepcopy(live))
    files=PinnedDirectories(driver.journal,observed,parent['identity']);observations=[]
    def observe(value):
        observations.append(1)
        return deepcopy(observed)
    arguments=dict(journal=driver.journal,installation=original,current=current,
        qualification_id='assembled-qualification',recovery_id='assembled-directories',run_parent=parent,
        source_reader=installer.read,observer=observe,account_history=driver.account_history,
        files=files,window=window,journal_identity=driver.journal.identity)
    session=PostBootRecoverySession(**arguments)
    return session,arguments,observed,files,live,installer,observations


def test_constructor_does_not_observe_and_prepare_never_creates_directories(assembly):
    session,_,_,files,_,installer,observations=assembly
    assert observations==[] and files.calls==[]
    source=installer.read(session.original['id']);reference=session.prepare()
    assert files.calls==[] and reference['recovery']['phase']=='prepared'
    assert session.qualification.read(session.qualification_id)['phase']=='persistent_qualified'
    assert observations and installer.read(source['id'])==source
    before=session.journal.db.total_changes
    assert session.prepare()==reference and session.journal.db.total_changes==before


def test_apply_uses_original_reference_once_and_effective_never_claims_daemon_ready(assembly):
    session,_,_,files,live,installer,_=assembly
    reference=session.prepare();result=session.apply_original(reference)
    assert result['daemon_ready'] is False and len(files.calls)==2
    source=installer.read(session.original['id'])
    effective=session.effective(reference)
    assert effective['scope']=='session-directories-only' and effective['daemon_ready'] is False
    assert effective['source']['prerequisites']['os_parents']['/run']['device']==58
    assert source['prerequisites']['os_parents']['/run']['device']==57
    live['nonce']='8'*32
    assert session.apply_original(reference)==result
    assert session.effective(reference)==effective and len(files.calls)==2


def test_lost_directory_response_recovers_same_births_after_reopening(assembly):
    session,arguments,_,files,_,_,_=assembly;reference=session.prepare();files.lose_after=True
    with pytest.raises(OSError,match='lost after'):session.apply_original(reference)
    pending=session.recovery.read(session.recovery_id)
    assert pending['items'][0]['phase']=='create_requested' and len(files.calls)==1
    reopened=PostBootRecoverySession(**arguments)
    reopened.recover_original(reference)
    assert len(files.calls)==2 and len(set(files.calls))==2
    assert reopened.recovery.read(reopened.recovery_id)['items'][0]['nonce']==reference['recovery']['items'][0]['nonce']


def test_uncertain_absence_is_preserved_without_repeat_or_implicit_apply(assembly):
    session,_,_,files,_,_,_=assembly;reference=session.prepare()
    with pytest.raises(Conflict,match='pending recovery'):session.recover_original(reference)
    assert files.calls==[]
    files.lose_before=True
    with pytest.raises(OSError,match='lost before'):session.apply_original(reference)
    for action in (session.apply_original,session.recover_original):
        with pytest.raises(Conflict):action(reference)
    assert len(files.calls)==1 and session.recovery.read(session.recovery_id)['phase']=='applying'


@pytest.mark.parametrize('fault',['parent','package','source','window'])
def test_changed_preconditions_block_first_directory_write(assembly,fault):
    session,_,observed,files,live,installer,_=assembly;reference=session.prepare()
    if fault=='parent':observed['prerequisites']['os_parents']['/run']['device']+=1
    elif fault=='package':next(iter(observed['prerequisites']['packages'].values()))['Version']='changed'
    elif fault=='window':live['nonce']='1'*32
    else:
        original=installer.read(session.original['id']);original['prerequisites']['binaries']['libvirtd']['sha256']='2'*64
        with installer.journal.transaction():installer._save(original)
    with pytest.raises(Conflict):session.apply_original(reference)
    assert files.calls==[]


@pytest.mark.parametrize('fault',['journal','context','qualification','nonce','spec'])
def test_foreign_prepared_reference_never_reaches_apply(assembly,fault):
    session,_,_,files,_,_,_=assembly;reference=session.prepare();changed=deepcopy(reference)
    if fault=='journal':changed['journal_identity']='foreign'
    elif fault=='context':changed['context']['boot_id']='foreign'
    elif fault=='qualification':changed['qualification_sha256']='0'*64
    elif fault=='nonce':changed['recovery']['items'][0]['nonce']='0'*32
    else:changed['recovery']['items'][0]['spec']['path']='/foreign'
    before=session.journal.db.total_changes
    with pytest.raises(Conflict):session.apply_original(changed)
    assert files.calls==[] and session.journal.db.total_changes==before


def test_prepare_recovers_qualified_metadata_without_new_nonces(assembly,monkeypatch):
    session,_,_,files,_,_,_=assembly;prepare=session.recovery.prepare
    monkeypatch.setattr(session.recovery,'prepare',lambda *args: (_ for _ in ()).throw(OSError('synthetic prepare interruption')))
    with pytest.raises(OSError,match='prepare interruption'):session.prepare()
    qualified=session.qualification.read(session.qualification_id)
    assert qualified['phase']=='persistent_qualified' and files.calls==[]
    monkeypatch.setattr(session.recovery,'prepare',prepare)
    reference=session.prepare()
    assert session.qualification.read(session.qualification_id)==qualified
    assert reference['qualification_sha256'] and files.calls==[]


def test_lost_prepare_commit_response_reuses_original_metadata(assembly,monkeypatch):
    session,_,_,files,_,_,_=assembly;transaction=session.journal.transaction;lost=[]
    @contextmanager
    def commit():
        with transaction():yield
        row=session.journal.db.execute('SELECT id FROM libvirt_volatile_recoveries WHERE id=?',(session.recovery_id,)).fetchone()
        if row and not lost:
            lost.append(True)
            raise OSError('synthetic lost prepared commit response')
    monkeypatch.setattr(session.journal,'transaction',commit)
    with pytest.raises(OSError,match='lost prepared commit'):session.prepare()
    original=session.recovery.read(session.recovery_id)
    monkeypatch.setattr(session.journal,'transaction',transaction)
    reference=session.prepare()
    assert reference['recovery']==original and files.calls==[]
