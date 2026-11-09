"""Policy revision coordination with synthetic replacements; no host file writes."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT,compile_revision
from dnlab_runtime.libvirt_activation import SessionActivation
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_activation import Services
from test_libvirt_install import install,request_profile
from tools.libvirt_service_units import observe_service_files


class Replacement:
    def __init__(self):self.receipt=None;self.calls=0;self.lost=False;self.before=False;self.conflict=False
    def observe(self,value):
        if self.conflict:raise Conflict('synthetic inactive-service or resource preflight conflict')
        return dict(context=deepcopy(value['installation']['context']),source_sha256=value['source_sha256'],
            unchanged_sha256=value['plan']['unchanged_sha256'],receipt=deepcopy(self.receipt))
    def replace(self,value):
        self.calls+=1
        if self.before:raise OSError('lost before original replacement completion')
        source=value['plan']['source_item']['proof']
        self.receipt=dict(operation_id=value['id'],nonce=value['nonce'],source_proof=deepcopy(source),
            backup=dict(path=value['backup'],identity=deepcopy(source['identity'])),
            replacement=dict(intent_id=value['id'],nonce=value['nonce'],spec_sha256=fingerprint(value['plan']['target_spec']),
                identity={'synthetic_new_inode':999}))
        if self.lost:raise OSError('lost after original replacement completion')
        return deepcopy(self.receipt)


@pytest.fixture
def revision(install):
    installer,_,prepared,_=install
    original=installer.apply(prepared['id'])
    adapter=Replacement()
    receipt=dict(operation_id='policy-revision',context=deepcopy(original['context']),targets=['file:'+UNIT],nonce='e'*32)
    window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    driver=ConfigurationRevision(installer.journal,adapter,window=window)
    value=driver.prepare('policy-revision',original)
    return driver,adapter,value,installer,original


def test_effective_configuration_preserves_base_and_carries_original_creators(revision):
    driver,adapter,value,installer,original=revision
    assert adapter.calls==0
    effective=driver.apply(value['id'])
    assert effective['profile']['activation_policy']=='requisite-after-v1'
    assert installer.read(original['id'])==original
    changed=[item for item in effective['items'] if item['spec'].get('path')==UNIT][0]
    assert changed['proof']['intent_id']==value['id'] and changed['nonce']==value['nonce']
    assert effective['configuration_revision']['source_sha256']==fingerprint(original)
    assert driver.apply(value['id'])==effective and adapter.calls==1
    activation=SessionActivation(driver.journal,Services())
    activated=activation.prepare('activation',effective)
    assert activation.apply(activated['id'])['phase']=='ready_empty'
    assert installer.read(original['id'])==original


def test_lost_response_recovers_same_revision_without_second_replacement(revision):
    driver,adapter,value,_,_=revision;adapter.lost=True
    with pytest.raises(OSError):driver.apply(value['id'])
    assert driver.read(value['id'])['phase']=='replace_requested'
    assert driver.apply(value['id'])['configuration_revision']['operation_id']==value['id']
    assert adapter.calls==1


def test_uncertain_absence_cannot_repeat_or_project_revision(revision):
    driver,adapter,value,_,_=revision;adapter.before=True
    with pytest.raises(OSError):driver.apply(value['id'])
    with pytest.raises(Conflict,match='no repeat'):driver.apply(value['id'])
    with pytest.raises(Conflict,match='pending'):driver.effective(value['id'])
    assert adapter.calls==1


def test_preflight_conflict_after_checkpoint_prevents_replacement(revision,monkeypatch):
    driver,adapter,value,_,_=revision;save=driver._save
    def changed(current):
        save(current)
        if current['phase']=='replace_requested':adapter.conflict=True
    monkeypatch.setattr(driver,'_save',changed)
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert adapter.calls==0
    assert driver.read(value['id'])['phase']=='replace_requested'


def test_changed_window_after_checkpoint_cannot_replace(revision,monkeypatch):
    driver,adapter,value,_,_=revision;save=driver._save
    def changed(current):
        save(current)
        if current['phase']=='replace_requested':monkeypatch.setattr(driver.window,'observe',lambda:{})
    monkeypatch.setattr(driver,'_save',changed)
    with pytest.raises(Conflict,match='window'):driver.apply(value['id'])
    assert adapter.calls==0


def test_completed_projection_is_readonly_after_window_closes(revision,monkeypatch):
    driver,adapter,value,_,_=revision
    effective=driver.apply(value['id'])
    monkeypatch.setattr(driver.window,'observe',lambda:{})
    before=driver.journal.db.total_changes
    assert driver.effective(value['id'])==effective and driver.apply(value['id'])==effective
    assert driver.journal.db.total_changes==before and adapter.calls==1


def test_replacement_or_backup_substitution_cannot_be_adopted(revision):
    driver,adapter,value,_,_=revision
    driver.apply(value['id'])
    adapter.receipt['backup']['identity']={'foreign':'preserve'}
    with pytest.raises(Conflict):driver.effective(value['id'])
    assert adapter.calls==1


def test_revision_rejects_changes_beyond_selected_policy(revision):
    driver,adapter,value,_,original=revision
    changed=deepcopy(original);changed['request']['session']['uid']=2000
    with pytest.raises(Conflict):compile_revision(changed)
    with pytest.raises(Conflict,match='original configuration revision request differs'):
        driver.prepare('other-revision',original)
    assert adapter.calls==0


def test_effective_file_observation_uses_each_original_creator(revision):
    driver,_,value,_,_=revision
    effective=driver.apply(value['id']);calls=[]
    class Files:
        def observe(self,item,creator):
            calls.append((item['spec']['path'],creator))
            assert creator==item['proof']['intent_id']
            return deepcopy(item['proof'])
    proofs=observe_service_files(Files(),effective)
    assert len(proofs)==7
    assert dict(calls)[UNIT]==value['id']
    assert all(creator==effective['id'] for path,creator in calls if path!=UNIT)
    foreign=deepcopy(effective)
    unit=next(item for item in foreign['items'] if item['spec'].get('path')==UNIT)
    unit['proof']['intent_id']='foreign-creator'
    calls.clear()
    with pytest.raises(Conflict,match='creator'):observe_service_files(Files(),foreign)
    assert UNIT not in dict(calls)
