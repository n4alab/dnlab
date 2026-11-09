"""Temporary complete session; NSS and account workers remain simulated.

Ownership of temporary directories requires mapped UID1001/GID1002. No actual
account tool, daemon, host inventory, libvirt client or service query is run.
"""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import UNIT
from dnlab_runtime.libvirt_configuration_session import ConfigurationSession
from dnlab_runtime.libvirt_configuration_swap import EXCHANGE,NOREPLACE
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict
from test_libvirt_install_session import session
from test_libvirt_install_snapshot import snapshot,fixture,request_profile


@pytest.fixture
def configured(session,monkeypatch):
    provisioning,worker,root,write,old_current,provider=session
    provisioning.prepare();original=provisioning.apply()
    # The original account operations are completed before revision construction.
    # No worker execution or old active provisioning window is available now.
    old_current['nonce']='f'*32
    monkeypatch.setattr(worker,'arm',lambda *a:pytest.fail('revision cannot arm an account worker'))
    monkeypatch.setattr(worker,'release',lambda *a:pytest.fail('revision cannot release an account worker'))
    receipt=dict(operation_id='policy-revision',context=deepcopy(original['context']),targets=['file:'+UNIT],nonce='d'*32)
    current=deepcopy(receipt);window=ProvisioningWindow(receipt,lambda:deepcopy(current))
    before=dict(content=(root/UNIT.lstrip('/')).read_text(),inode=(root/UNIT.lstrip('/')).stat().st_ino)
    return provisioning,worker,root,write,original,window,current,before


def assemble(configured,**kwargs):
    provisioning,_,_,_,original,window,_,_=configured
    return ConfigurationSession(provisioning,kwargs.get('reference',original),window=kwargs.get('window',window),
        journal_identity=kwargs.get('journal_identity',provisioning.installer.journal.identity))


def test_construction_and_prepare_do_not_change_installed_files_or_run_workers(configured,monkeypatch):
    provisioning,worker,root,_,original,_,_,before=configured
    snapshot=provisioning.adapter.snapshot
    monkeypatch.setattr(provisioning.adapter,'snapshot',lambda:pytest.fail('construction cannot observe host'))
    revision=assemble(configured)
    monkeypatch.setattr(provisioning.adapter,'snapshot',snapshot)
    value=revision.prepare()
    assert value['phase']=='prepared' and revision.prepare()==value
    assert (root/UNIT.lstrip('/')).read_text()==before['content']
    assert (root/UNIT.lstrip('/')).stat().st_ino==before['inode']
    assert worker.calls==['groupadd','useradd'] and provisioning.installer.read(original['id'])==original


def test_apply_reopens_original_installation_and_revision_without_account_execution(configured):
    provisioning,worker,root,_,original,_,_,before=configured
    revision=assemble(configured);prepared=revision.prepare()
    effective=revision.apply_original(prepared)
    assert 'Requisite=' in (root/UNIT.lstrip('/')).read_text()
    assert (root/prepared['backup'].lstrip('/')).stat().st_ino==before['inode']
    reopened=assemble(configured)
    assert reopened.effective()==effective and reopened.apply_original(prepared)==effective
    assert worker.calls==['groupadd','useradd'] and provisioning.installer.read(original['id'])==original


@pytest.mark.parametrize('boundary',[EXCHANGE,NOREPLACE])
def test_recovery_reuses_original_reference_and_transition(configured,monkeypatch,boundary):
    revision=assemble(configured);prepared=revision.prepare();rename=revision.adapter.swap._rename;calls=[]
    def lost(*args):
        calls.append(args[-1]);rename(*args)
        if args[-1]==boundary:raise OSError('synthetic lost rename reply')
    monkeypatch.setattr(revision.adapter.swap,'_rename',lost)
    with pytest.raises(OSError):revision.apply_original(prepared)
    result=revision.recover_original(prepared)
    assert result==revision.effective() and calls==[EXCHANGE,NOREPLACE]


@pytest.mark.parametrize('fault',['journal','source','window'])
def test_wrong_binding_refused_without_mutations(configured,fault):
    provisioning,worker,root,_,original,window,_,before=configured
    kwargs={}
    if fault=='journal':kwargs['journal_identity']='0'*32
    elif fault=='source':
        changed=deepcopy(original);changed['items'][0]['nonce']='f'*32;kwargs['reference']=changed
    else:
        receipt=deepcopy(window.receipt);receipt['targets'].append('file:/foreign')
        kwargs['window']=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    with pytest.raises(Conflict):assemble(configured,**kwargs)
    assert (root/UNIT.lstrip('/')).stat().st_ino==before['inode']
    assert worker.calls==['groupadd','useradd']


def test_prepared_reference_substitution_and_changed_host_prerequisite_are_refused(configured):
    _,worker,root,write,_,_,_,before=configured
    revision=assemble(configured);prepared=revision.prepare()
    wrong=deepcopy(prepared);wrong['nonce']='f'*32
    with pytest.raises(Conflict,match='binding'):revision.apply_original(wrong)
    write('etc/default/useradd','foreign preserved config')
    with pytest.raises(Conflict):revision.apply_original(prepared)
    assert (root/UNIT.lstrip('/')).stat().st_ino==before['inode']
    assert worker.calls==['groupadd','useradd']


def test_original_source_rechecked_after_revision_checkpoint(configured,monkeypatch):
    provisioning,worker,root,_,original,_,_,before=configured
    revision=assemble(configured);prepared=revision.prepare();save=revision.driver._save
    def changed(value):
        save(value)
        if value['phase']=='replace_requested':
            source=deepcopy(original);source['context']['boot_id']='synthetic changed journal context'
            provisioning.installer._save(source)
    monkeypatch.setattr(revision.driver,'_save',changed)
    with pytest.raises(Conflict,match='installation changed'):revision.apply_original(prepared)
    assert revision.driver.read(prepared['id'])['phase']=='replace_requested'
    assert (root/UNIT.lstrip('/')).stat().st_ino==before['inode']
    assert not (root/prepared['backup'].lstrip('/')).exists()
    assert worker.calls==['groupadd','useradd']
