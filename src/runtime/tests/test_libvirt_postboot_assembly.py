"""Prepare wiring with synthetic leaf observers; no NSS/systemctl/host reads."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_run_parent import bind_run_parent
from dnlab_runtime.manifest import Conflict
from tools import libvirt_postboot_assembly as module
from test_libvirt_postboot_session import assembly,boot_parent,installed_packages,install,request_profile


def test_prepare_only_capability_blocks_both_directory_mutators(assembly):
    _,arguments,_,files,_,_,_=assembly;files.readonly=True
    session=PostBootRecoverySession(**arguments,prepare_only=True)
    reference=session.prepare();before=session.journal.db.total_changes
    for method in (session.apply_original,session.recover_original):
        with pytest.raises(Conflict,match='metadata-only'):method(reference)
    assert session.journal.db.total_changes==before and files.calls==[]


@pytest.fixture
def wiring(boot_parent,monkeypatch):
    driver,original,current,observed,installer,_,parent=boot_parent
    for role in ('groupadd','useradd'):
        entry=dict(sha256='a'*64)
        original['prerequisites']['account_inputs']['usr/sbin/'+role]=entry
        observed['prerequisites']['account_inputs']['usr/sbin/'+role]=deepcopy(entry)
    with installer.journal.transaction():
        installer._save(original)
        installer.journal.db.execute('CREATE TABLE libvirt_install_file_births '
            '(operation_id TEXT,nonce TEXT,payload TEXT,fingerprint TEXT)')
    parent=bind_run_parent(original,current,parent['identity'])
    calls=[];snapshots=[]
    class Snapshot:
        def __init__(self,*args,**kwargs):snapshots.append((args,kwargs))
        def __call__(self):
            calls.append('snapshot')
            return dict(context=deepcopy(current),prerequisites=deepcopy(observed['prerequisites']))
    monkeypatch.setattr(module,'InstallationSnapshot',Snapshot)
    def identity(self,request):
        calls.append('identity');return deepcopy(request['expected'])
    monkeypatch.setattr(module.LocalAccountIdentity,'__call__',identity)
    def history(self,item):
        calls.append('history');return driver.account_history(item)
    monkeypatch.setattr(module.HistoricalAccountCreation,'__call__',history)
    monkeypatch.setattr(module.InstallationFiles,'observe',lambda self,item,operation:deepcopy(item['proof']))
    monkeypatch.setattr(module.PostBootObserver,'_volatile',lambda self,item,entry:dict(state='absent'))
    def forbidden(*args,**kwargs):pytest.fail('real query or resource mutation reached')
    monkeypatch.setattr(module.InstallationFiles,'create',forbidden)
    monkeypatch.setattr(module.InstallationFiles,'recover',forbidden)
    agreement=dict(operation_id='readonly-assembly-directories',context=deepcopy(current),
        targets=list(observed['volatile']),nonce='5'*32)
    arguments=dict(journal=installer.journal,installation=original,current=current,
        qualification_id='readonly-assembly-qualification',recovery_id=agreement['operation_id'],run_parent=parent,
        window=ProvisioningWindow(agreement,lambda:deepcopy(agreement)),expected_packages={'synthetic':'1'},
        approved_account_inputs={'synthetic':True},worker_profile={'synthetic':True},query=forbidden,nss_query=forbidden)
    return arguments,calls,snapshots,observed,installer


def test_assembly_has_no_live_reads_and_prepare_uses_all_readonly_bindings(wiring):
    arguments,calls,snapshots,_,installer=wiring
    built=module.PostBootPrepareAssembly(**arguments)
    assert calls==[] and built.files.readonly is True and built.session.prepare_only is True
    assert built.history.journal is built.files.journal is arguments['journal']
    assert built.history.binaries['useradd']['path']=='/usr/sbin/useradd'
    assert snapshots[0][0][2:]==(arguments['expected_packages'],arguments['approved_account_inputs'])
    assert built.diagnostics==dict(observer=None,activity=[])
    reference=built.session.prepare()
    assert set(calls)=={'snapshot','identity','history'}
    assert built.observer.diagnostics['status']=='collected'
    assert installer.read(arguments['installation']['id'])==arguments['installation']
    with pytest.raises(Conflict,match='metadata-only'):built.session.apply_original(reference)


def test_assembly_refuses_changed_original_before_constructing_observers(wiring):
    arguments,calls,snapshots,_,_=wiring
    arguments['installation']=deepcopy(arguments['installation']);arguments['installation']['phase']='foreign'
    before=arguments['journal'].db.total_changes
    with pytest.raises(Conflict,match='assembly installation differs'):module.PostBootPrepareAssembly(**arguments)
    assert calls==[] and snapshots==[] and arguments['journal'].db.total_changes==before


def test_service_conflict_is_not_hidden_by_assembly(wiring):
    arguments,_,_,observed,_=wiring
    built=module.PostBootPrepareAssembly(**arguments)
    next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    with pytest.raises(Conflict):built.session.prepare()
    assert built.session.qualification.read(arguments['qualification_id'])['phase']=='prepared'
