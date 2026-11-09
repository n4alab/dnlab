"""Synthetic post-boot recovery; native adapter case uses temporary dirs only."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_install import proof
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_volatile_recovery import VolatileDirectories
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_postboot import postboot
from test_libvirt_install import install,request_profile


class Directories:
    def __init__(self,journal,observed):
        self.journal,self.observed=journal,observed;self.resources={};self.calls=[]
        self.lose_after=False;self.lose_before=False;self.fail_sync=False;self.pending=set()
    def observe(self,item,operation):
        key=item['spec']['key']
        if key in self.pending:raise Conflict('directory durability pending')
        current=self.resources.get(key)
        return None if current is None else proof(deepcopy(current),item,operation)
    def _birth(self,item,operation):
        current=self.resources.get(item['spec']['key'])
        if current is None:return None
        proof(current,item,operation)
        return dict(file=deepcopy(current['identity']))
    def create(self,item,operation,*,window):
        window.verify(item,operation);key=item['spec']['key'];self.calls.append(key)
        assert key not in self.resources
        if self.lose_before:
            self.lose_before=False;raise OSError('synthetic lost before creation')
        current=dict(intent_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
            identity={'new_synthetic_directory':len(self.calls)})
        self.resources[key]=deepcopy(current);self.observed['volatile'][key]={'state':'present_unqualified'}
        if self.fail_sync:
            self.fail_sync=False;self.pending.add(key);raise OSError('synthetic fsync failure')
        if self.lose_after:
            self.lose_after=False;raise OSError('synthetic lost after creation')
        return current
    def recover(self,item,operation,*,window):
        window.verify(item,operation)
        if self._birth(item,operation) is None:raise Conflict('original directory birth missing')
        self.pending.discard(item['spec']['key'])
        return self.observe(item,operation)


@pytest.fixture
def recovery(postboot):
    qualifier,value,installer,_,observed,_=postboot
    receipt=qualifier.qualify_persistent(value['id'])
    frozen=qualifier.read(value['id'])
    agreement=dict(operation_id='volatile-recovery',context=deepcopy(value['context']),targets=value['plan']['volatile'],nonce='d'*32)
    current=deepcopy(agreement);window=ProvisioningWindow(agreement,lambda:deepcopy(current))
    files=Directories(qualifier.journal,observed)
    controller=VolatileDirectories(qualifier,files,window=window)
    return controller,value,installer,observed,current,receipt,frozen


def test_current_boot_directories_have_new_births_and_preserve_historical_source(recovery):
    controller,value,installer,_,current,receipt,frozen=recovery
    prepared=controller.prepare('volatile-recovery',value['id'])
    assert controller.files.calls==[] and prepared['phase']=='prepared'
    result=controller.apply(prepared['id'])
    assert result['scope']=='session-directories-only' and result['daemon_ready'] is False
    assert len(result['directories'])==2 and controller.files.calls==value['plan']['volatile']
    assert all(p['intent_id']==prepared['id'] for p in result['directories'].values())
    assert controller.qualification.read(value['id'])==frozen
    assert installer.read(value['installation']['id'])==value['installation']
    with pytest.raises(Conflict,match='volatile'):controller.qualification.require_revision_ready(value['id'])
    current['nonce']='e'*32
    before=controller.journal.db.total_changes
    assert controller.observe(prepared['id'])==result and controller.apply(prepared['id'])==result
    assert controller.journal.db.total_changes==before


def test_lost_create_reply_uses_only_original_new_boot_birth(recovery):
    controller,value,_,_,_,_,_=recovery
    prepared=controller.prepare('volatile-recovery',value['id']);controller.files.lose_after=True
    with pytest.raises(OSError):controller.apply(prepared['id'])
    assert controller.read(prepared['id'])['phase']=='applying'
    assert controller.apply(prepared['id'])==controller.observe(prepared['id'])
    assert controller.files.calls==value['plan']['volatile']


def test_uncertain_absence_never_repeats_creation_or_adopts_a_directory(recovery):
    controller,value,_,_,_,_,_=recovery
    prepared=controller.prepare('volatile-recovery',value['id']);controller.files.lose_before=True
    with pytest.raises(OSError):controller.apply(prepared['id'])
    with pytest.raises(Conflict,match='not repeated'):controller.apply(prepared['id'])
    with pytest.raises(Conflict,match='birth required'):controller.recover(prepared['id'])
    assert controller.files.calls==[value['plan']['volatile'][0]]


def test_directory_durability_requires_explicit_original_recovery(recovery):
    controller,value,_,_,_,_,_=recovery
    prepared=controller.prepare('volatile-recovery',value['id']);controller.files.fail_sync=True
    with pytest.raises(OSError,match='fsync'):controller.apply(prepared['id'])
    with pytest.raises(Conflict,match='durability'):controller.apply(prepared['id'])
    assert controller.recover(prepared['id'])==controller.observe(prepared['id'])
    assert controller.files.calls==value['plan']['volatile']


def test_last_foreign_target_blocks_every_creation(recovery):
    controller,value,_,observed,_,_,_=recovery;key=value['plan']['volatile'][-1]
    controller.files.resources[key]={'foreign':'preserve'};observed['volatile'][key]={'state':'present_unqualified'}
    with pytest.raises(Conflict):controller.prepare('volatile-recovery',value['id'])
    assert controller.files.calls==[] and controller.files.resources[key]=={'foreign':'preserve'}


@pytest.mark.parametrize('fault',['boot','late-target','window'])
def test_checkpoint_preflight_blocks_allocation_on_change(recovery,monkeypatch,fault):
    controller,value,_,observed,window,_,_=recovery
    prepared=controller.prepare('volatile-recovery',value['id']);save=controller._save;injected=[]
    def changed(current):
        save(current)
        if current['phase']=='applying' and not injected:
            injected.append(1)
            if fault=='boot':observed['context']['boot_id']='third-synthetic-boot'
            elif fault=='late-target':
                key=value['plan']['volatile'][-1]
                controller.files.resources[key]={'foreign':'preserve'};observed['volatile'][key]={'state':'present_unqualified'}
            else:window['nonce']='e'*32
    monkeypatch.setattr(controller,'_save',changed)
    with pytest.raises(Conflict):controller.apply(prepared['id'])
    assert injected==[1] and controller.files.calls==[]
    assert controller.read(prepared['id'])['phase']=='applying'


def test_changed_persistent_resource_preserves_first_directory_and_pending_state(recovery,monkeypatch):
    controller,value,_,observed,_,_,_=recovery
    prepared=controller.prepare('volatile-recovery',value['id']);save=controller._save
    def changed(current):
        save(current)
        if current['items'][0]['phase']=='created':observed['persistent'][next(iter(observed['persistent']))]={'foreign':'preserve'}
    monkeypatch.setattr(controller,'_save',changed)
    with pytest.raises(Conflict):controller.apply(prepared['id'])
    assert controller.files.calls==[value['plan']['volatile'][0]]
    assert len(controller.files.resources)==1 and controller.read(prepared['id'])['phase']=='applying'


def test_recovery_cannot_start_a_prepared_operation(recovery):
    controller,value,_,_,_,_,_=recovery
    prepared=controller.prepare('volatile-recovery',value['id'])
    with pytest.raises(Conflict,match='no implicit apply'):controller.recover(prepared['id'])
    assert controller.files.calls==[]


def test_native_directory_births_on_private_temporary_root(recovery,tmp_path):
    # Requires mapped fixture UID/GID for fchown; no account command is executed.
    controller,value,_,observed,_,_,_=recovery
    root=tmp_path/'native-root';(root/'run').mkdir(parents=True)
    files=InstallationFiles(str(root),journal=controller.journal)
    controller=VolatileDirectories(controller.qualification,files,window=controller.window)
    original_observer=controller.qualification.observer
    def current(request):
        result=original_observer(request)
        for item in value['installation']['items']:
            if item['spec']['key'] in value['plan']['volatile']:
                path=root/item['spec']['path'].lstrip('/')
                result['volatile'][item['spec']['key']]={'state':'present_unqualified' if path.exists() else 'absent'}
        return result
    controller.qualification.observer=current
    prepared=controller.prepare('volatile-recovery',value['id'])
    result=controller.apply(prepared['id'])
    assert len(result['directories'])==2 and controller.observe(prepared['id'])==result
    for item in controller.read(prepared['id'])['items']:
        assert files.observe(item,prepared['id'])==item['proof']
        assert item['proof']['identity']['inode']==(root/item['spec']['path'].lstrip('/')).stat().st_ino
    assert not list(root.rglob('*.sock'))
