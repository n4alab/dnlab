"""Revision through actual temporary files; other session resources simulated."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT
from dnlab_runtime.libvirt_configuration_adapter import ConfigurationFileAdapter
from dnlab_runtime.libvirt_configuration_swap import EXCHANGE,NOREPLACE
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict
from tools.libvirt_service_units import observe_service_files
from test_libvirt_install import install,request_profile


@pytest.fixture
def configured(install,tmp_path):
    installer,_,prepared,_=install
    installation=installer.apply(prepared['id'])
    root=tmp_path/'root';(root/'etc/systemd/system').mkdir(parents=True)
    files=InstallationFiles(str(root),journal=installer.journal)
    for item in installation['items']:
        if item['spec']['kind']=='file':
            (root/item['spec']['path'].lstrip('/')).parent.mkdir(parents=True,exist_ok=True)
            item['proof']=files.create(item,installation['id'])
    receipt=dict(operation_id='policy-revision',context=deepcopy(installation['context']),targets=['file:'+UNIT],nonce='e'*32)
    window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    def preflight(value):
        for item in value['installation']['items']:
            if item['spec']['kind']=='file' and item['spec']['path']!=UNIT:
                if files.observe(item,installation['id'])!=item['proof']:
                    raise Conflict('synthetic remaining-file preflight differs')
        return dict(context=deepcopy(value['installation']['context']),source_sha256=value['source_sha256'],
            unchanged_sha256=value['plan']['unchanged_sha256'],services_inactive=True)
    adapter=ConfigurationFileAdapter(files,window=window,preflight=preflight)
    driver=ConfigurationRevision(installer.journal,adapter,window=window)
    value=driver.prepare('policy-revision',installation)
    return driver,adapter,value,root


def test_revision_apply_reopens_and_resolves_effective_original_birth(configured):
    driver,adapter,value,root=configured
    before=deepcopy(value['installation'])
    result=driver.apply(value['id'])
    original=driver.read(value['id'])
    assert original['installation']==before and original['phase']=='completed'
    assert driver.apply(value['id'])==result
    unit=next(item for item in result['items'] if item['spec'].get('path')==UNIT)
    assert adapter.observe_revised_file(unit,value['id'],original)==unit['proof']
    assert (root/value['backup'].lstrip('/')).stat().st_ino==value['plan']['source_item']['proof']['identity']['inode']
    reopened=ConfigurationFileAdapter(adapter.files,window=adapter.window,preflight=adapter.preflight)
    replay=ConfigurationRevision(driver.journal,reopened,window=driver.window)
    assert replay.effective(value['id'])==result
    class EffectiveFiles:
        def observe(self,item,creator):
            if creator==value['id']:return reopened.observe_revised_file(item,creator,original)
            return reopened.files.observe(item,creator)
    assert len(observe_service_files(EffectiveFiles(),result))==7


@pytest.mark.parametrize('boundary',[EXCHANGE,NOREPLACE])
def test_lost_rename_response_recovers_same_outer_intent(configured,monkeypatch,boundary):
    driver,adapter,value,_=configured;rename=adapter.swap._rename;calls=[]
    def lost(*args):
        flags=args[-1];calls.append(flags);rename(*args)
        if flags==boundary:raise OSError('synthetic lost rename reply')
    monkeypatch.setattr(adapter.swap,'_rename',lost)
    with pytest.raises(OSError):driver.apply(value['id'])
    assert driver.read(value['id'])['phase']=='replace_requested'
    with pytest.raises(Conflict,match='no repeat'):driver.apply(value['id'])
    result=driver.recover(value['id'])
    assert result==driver.effective(value['id'])
    assert calls==[EXCHANGE,NOREPLACE]


def test_lost_candidate_reply_uses_original_birth_without_another_create(configured,monkeypatch):
    driver,adapter,value,_=configured;create=adapter.files.create;calls=[]
    def lost(*args,**kwargs):
        calls.append(1);create(*args,**kwargs);raise OSError('synthetic lost candidate reply')
    monkeypatch.setattr(adapter.files,'create',lost)
    with pytest.raises(OSError):driver.apply(value['id'])
    assert driver.recover(value['id'])==driver.effective(value['id'])
    assert len(calls)==1


def test_recovery_without_candidate_birth_never_creates(configured,monkeypatch):
    driver,adapter,value,root=configured
    monkeypatch.setattr(adapter.files,'create',lambda *args,**kwargs:(_ for _ in ()).throw(OSError('synthetic before create')))
    with pytest.raises(OSError):driver.apply(value['id'])
    with pytest.raises(Conflict,match='birth missing'):driver.recover(value['id'])
    current=driver.read(value['id'])
    assert current['phase']=='replace_requested'
    assert (root/UNIT.lstrip('/')).read_text()==value['plan']['source_item']['spec']['content']
    assert not (root/current['backup'].lstrip('/')).exists()


def test_changed_full_preflight_prevents_recovery_mutations(configured,monkeypatch):
    driver,adapter,value,root=configured
    monkeypatch.setattr(adapter,'preflight',lambda value:{})
    with pytest.raises(Conflict,match='preflight'):driver.apply(value['id'])
    with pytest.raises(Conflict):driver.recover(value['id'])
    assert driver.read(value['id'])['phase']=='prepared'
    assert not (root/value['staging'].lstrip('/')).exists()


def test_effective_file_rejects_wrong_creator_and_changed_spec(configured):
    driver,adapter,value,_=configured
    result=driver.apply(value['id']);current=driver.read(value['id'])
    unit=next(item for item in result['items'] if item['spec'].get('path')==UNIT)
    with pytest.raises(Conflict,match='creator'):adapter.observe_revised_file(unit,'foreign',current)
    changed=deepcopy(unit);changed['spec']['mode']=0o600
    with pytest.raises(Conflict,match='specification'):adapter.observe_revised_file(changed,value['id'],current)


def test_closed_window_rejects_pending_recovery(configured,monkeypatch):
    driver,adapter,value,root=configured
    def lost(current):raise OSError('synthetic interrupted before staging')
    monkeypatch.setattr(adapter,'replace',lost)
    with pytest.raises(OSError):driver.apply(value['id'])
    monkeypatch.setattr(adapter.window,'observe',lambda:{})
    with pytest.raises(Conflict,match='window'):driver.recover(value['id'])
    assert not (root/value['staging'].lstrip('/')).exists()


def test_outer_commit_loss_reuses_original_completed_transition(configured,monkeypatch):
    driver,adapter,value,_=configured;save=driver._save;renames=[];rename=adapter.swap._rename
    def counted(*args):
        renames.append(args[-1]);return rename(*args)
    def lost(current):
        if current['phase']=='completed':raise OSError('synthetic outer completion commit loss')
        return save(current)
    monkeypatch.setattr(adapter.swap,'_rename',counted)
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError,match='outer completion'):driver.apply(value['id'])
    assert driver.read(value['id'])['phase']=='replace_requested'
    monkeypatch.setattr(driver,'_save',save)
    assert driver.apply(value['id'])==driver.effective(value['id'])
    assert renames==[EXCHANGE,NOREPLACE]


def test_other_installed_file_changed_after_staging_blocks_exchange(configured,monkeypatch):
    driver,adapter,value,root=configured;stage=adapter.staging.stage
    other=next(item for item in value['installation']['items'] if item['spec']['kind']=='file' and item['spec']['path']!=UNIT)
    def changed(current):
        proof=stage(current)
        (root/other['spec']['path'].lstrip('/')).write_text('foreign preserve')
        return proof
    monkeypatch.setattr(adapter.staging,'stage',changed)
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert adapter.swap._read(adapter.request(driver.read(value['id']))) is None
    assert (root/UNIT.lstrip('/')).read_text()==value['plan']['source_item']['spec']['content']
    assert (root/other['spec']['path'].lstrip('/')).read_text()=='foreign preserve'
