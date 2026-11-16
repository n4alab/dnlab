"""Complete synthetic bundle imports; no vendor disks, QEMU or services."""
from copy import deepcopy
import hashlib
import json
import os
import shutil

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import template_digest
from dnlab_runtime.vm_template_files import TemplateAssetFiles, identity
from dnlab_runtime.vm_template_install import TemplateBundleInstall, bundle_plan
from test_vm_bundle import bundle, template


@pytest.fixture
def imported(bundle,tmp_path):
    source,template,data = bundle
    store = tmp_path/'store';store.mkdir(mode=0o755);store.chmod(0o755)
    raw = (source/'manifest.json').read_bytes()
    manifest = dict(sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
    plan = bundle_plan(str(store),str(source),template,manifest)
    agreement = dict(operation_id='import-template',context=dict(host_id='synthetic',boot_id='synthetic-boot'),
                     targets=[item['key'] for item in plan],nonce='a'*32)
    state = dict(active=True)
    window = ProvisioningWindow(agreement,lambda:deepcopy(agreement) if state['active'] else {})
    journal = Journal(tmp_path/'journal')
    def preflight(request):return dict(request_sha256=fingerprint(request),exclusive_writer=True)
    def make(**options):
        return TemplateBundleInstall(journal,root=str(store),parent_identity=identity(store.stat()),
                                     window=window,preflight=preflight,**options)
    driver = make()
    request = dict(source=str(source),template_sha256=template_digest(template))
    yield driver,source,store,template,data,state,request,make
    journal.close()


def test_complete_bundle_is_published_only_with_all_original_members(imported):
    driver,source,store,template,data,state,request,make = imported
    reference = driver.prepare('import-template',**request)
    assert driver.prepare('import-template',**request) == reference
    with pytest.raises(Conflict,match='publication missing'):driver.observe('import-template')
    result = driver.apply('import-template');target = store/template_digest(template)
    assert result['directory'] == str(target) and result['bundle']['template'] == template
    assert (target/'disks/base.qcow2').read_bytes() == data
    assert (target/'manifest.json').read_bytes() == (source/'manifest.json').read_bytes()
    assert all(item['phase'] == 'created' for item in driver.read('import-template')['items'])
    assert all(path.stat().st_mode & 0o777 == (0o755 if path.is_dir() else 0o444)
               for path in [target,*target.rglob('*')])
    shutil.rmtree(source);state['active'] = False
    assert make(readonly=True).observe('import-template') == result
    assert driver.apply('import-template') == result
    with pytest.raises(Conflict,match='readonly'):make(readonly=True).recover('import-template')


def test_source_change_rejects_before_any_directory_creation(imported):
    driver,source,store,_,_,_,request,_ = imported
    driver.prepare('import-template',**request)
    (source/'disks/base.qcow2').write_bytes(b'changed')
    with pytest.raises(Conflict,match='source bundle member changed'):driver.apply('import-template')
    assert list(store.iterdir()) == []
    assert driver.read('import-template')['phase'] == 'prepared'


def test_foreign_bundle_cannot_be_adopted_even_with_matching_content(imported):
    driver,source,store,template,_,_,request,_ = imported
    target = store/template_digest(template);shutil.copytree(source,target)
    before = (target/'manifest.json').read_bytes()
    with pytest.raises(Conflict,match='foreign or unrecorded'):driver.prepare('import-template',**request)
    assert (target/'manifest.json').read_bytes() == before
    assert driver.journal.db.execute('SELECT count(*) FROM vm_template_bundle_imports').fetchone()[0] == 0


def test_foreign_late_member_blocks_before_the_first_asset_copy(imported,monkeypatch):
    driver,_,store,template,_,_,request,_ = imported
    driver.prepare('import-template',**request);save = driver._save
    target = store/template_digest(template)
    def inject(value):
        save(value)
        directories = [item for item in value['items'] if item['spec']['kind'] == 'directory']
        if all(item['phase'] == 'created' for item in directories) and not (target/'manifest.json').exists():
            (target/'manifest.json').write_bytes(b'foreign manifest')
    monkeypatch.setattr(driver,'_save',inject)
    with pytest.raises(Conflict,match='foreign template asset'):driver.apply('import-template')
    assert (target/'manifest.json').read_bytes() == b'foreign manifest'
    assert not (target/'disks/base.qcow2').exists()


def test_lost_asset_reply_reuses_same_completed_child_and_inode(imported,monkeypatch):
    driver,_,store,template,_,_,request,make = imported
    driver.prepare('import-template',**request);apply = TemplateAssetFiles.apply;calls = []
    def lost(self,operation):
        result = apply(self,operation);calls.append(operation)
        if len(calls) == 1:raise OSError('lost asset reply')
        return result
    monkeypatch.setattr(TemplateAssetFiles,'apply',lost)
    with pytest.raises(OSError,match='lost asset reply'):driver.apply('import-template')
    target = store/template_digest(template)/'disks/base.qcow2';inode = target.stat().st_ino
    with pytest.raises(Conflict,match='explicit recovery'):driver.apply('import-template')
    result = make().recover('import-template')
    assert result == driver.observe('import-template') and target.stat().st_ino == inode
    assert len(calls) == len(set(calls)) == 2  # Base and manifest; base is not copied twice.


def test_partial_original_asset_can_resume_through_complete_bundle_preflight(imported,monkeypatch):
    import dnlab_runtime.vm_template_files as files
    driver,_,store,template,data,_,request,make = imported
    driver.prepare('import-template',**request)
    target = store/template_digest(template)/'disks/base.qcow2';write = os.write;lost = []
    def partial(fd,content):
        if os.readlink('/proc/self/fd/'+str(fd)) == str(target) and not lost:
            lost.append(True);write(fd,content[:5]);raise OSError('interrupted template write')
        return write(fd,content)
    with monkeypatch.context() as patch:
        patch.setattr(files.os,'write',partial)
        with pytest.raises(OSError,match='interrupted template write'):driver.apply('import-template')
    assert target.read_bytes() == data[:5]
    inode = target.stat().st_ino
    assert make().recover('import-template')['template_sha256'] == template_digest(template)
    assert target.read_bytes() == data and target.stat().st_ino == inode


def test_directory_durability_recovery_keeps_original_birth(imported,monkeypatch):
    import dnlab_runtime.libvirt_install_files as files
    driver,_,store,template,_,_,request,make = imported
    driver.prepare('import-template',**request)
    target = store/template_digest(template);sync = os.fsync;lost = []
    def uncertain(fd):
        if os.readlink('/proc/self/fd/'+str(fd)) == str(target) and not lost:
            lost.append(True);raise OSError('uncertain directory fsync')
        return sync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(files.os,'fsync',uncertain)
        with pytest.raises(OSError,match='uncertain directory fsync'):driver.apply('import-template')
    inode = target.stat().st_ino
    assert make().recover('import-template')['directory'] == str(target)
    assert target.stat().st_ino == inode


def test_unrecorded_directory_birth_stays_pending_without_adoption(imported,monkeypatch):
    driver,_,store,template,_,_,request,make = imported
    driver.prepare('import-template',**request);save = driver.files._save_birth
    def lost(item,operation,birth):
        if birth['file'] is not None:raise OSError('lost directory birth')
        return save(item,operation,birth)
    monkeypatch.setattr(driver.files,'_save_birth',lost)
    with pytest.raises(OSError,match='lost directory birth'):driver.apply('import-template')
    target = store/template_digest(template);inode = target.stat().st_ino
    with pytest.raises(Conflict,match='unrecorded'):make().recover('import-template')
    assert target.stat().st_ino == inode and list(target.iterdir()) == []


def test_changed_published_asset_is_refused_without_rewrite(imported):
    driver,_,store,template,_,_,request,make = imported
    driver.prepare('import-template',**request);driver.apply('import-template')
    target = store/template_digest(template)/'disks/base.qcow2'
    target.chmod(0o600);target.write_bytes(b'foreign');target.chmod(0o444)
    with pytest.raises(Conflict,match='metadata changed'):make(readonly=True).observe('import-template')
    assert target.read_bytes() == b'foreign'


def test_unrelated_sibling_change_is_not_a_source_bundle_replacement(imported,monkeypatch):
    driver,source,_,_,_,_,request,_ = imported
    driver.prepare('import-template',**request)
    prepare = TemplateAssetFiles.prepare;changed = []
    def guarded(self,*args,**kwargs):
        preflight = self.preflight;calls = []
        def sibling(value):
            result = preflight(value);calls.append(True)
            if len(calls) == 2 and not changed:
                (source.parent/'unrelated-report.txt').write_text('outside the immutable bundle')
                changed.append(True)
            return result
        self.preflight = sibling
        return prepare(self,*args,**kwargs)
    monkeypatch.setattr(TemplateAssetFiles,'prepare',guarded)
    result = driver.apply('import-template')
    assert changed == [True] and result['template_sha256'] == request['template_sha256']


def test_same_digest_cannot_be_reserved_by_another_operation(imported):
    driver,_,store,_,_,_,request,_ = imported
    reference = driver.prepare('import-template',**request)
    with pytest.raises(Conflict,match='reserved by another'):driver.prepare('another-import',**request)
    assert driver.read('import-template') == reference and list(store.iterdir()) == []


def test_source_bundle_replacement_is_refused_even_with_identical_bytes(imported):
    driver,source,store,_,_,_,request,_ = imported
    driver.prepare('import-template',**request)
    previous = source.with_name('original-source');source.rename(previous)
    shutil.copytree(previous,source)
    with pytest.raises(Conflict,match='source bundle directory changed'):driver.apply('import-template')
    assert list(store.iterdir()) == []


def test_lost_publication_checkpoint_does_not_publish_from_file_presence(imported,monkeypatch):
    driver,source,_,_,_,_,request,make = imported
    driver.prepare('import-template',**request);save = driver._save;lost = []
    def uncertain(value):
        save(value)
        if value['phase'] == 'installing' and all(i['phase'] == 'created' for i in value['items']) and not lost:
            lost.append(True);raise OSError('lost final member checkpoint reply')
    monkeypatch.setattr(driver,'_save',uncertain)
    with pytest.raises(OSError,match='final member checkpoint'):driver.apply('import-template')
    with pytest.raises(Conflict,match='publication missing'):driver.observe('import-template')
    original = deepcopy(driver.read('import-template')['items'])
    shutil.rmtree(source)
    assert make().recover('import-template')['template_sha256'] == request['template_sha256']
    assert driver.read('import-template')['items'] == original


def test_window_expiry_during_final_hash_does_not_publish(imported,monkeypatch):
    import dnlab_runtime.vm_template_install as module
    driver,_,store,_,_,state,request,make = imported
    driver.prepare('import-template',**request);read = module.read_bundle
    def expired(path,digest):
        result = read(path,digest)
        if str(path).startswith(str(store)+'/'):state['active'] = False
        return result
    with monkeypatch.context() as patch:
        patch.setattr(module,'read_bundle',expired)
        with pytest.raises(Conflict,match='window is not active'):driver.apply('import-template')
    value = driver.read('import-template')
    assert value['phase'] == 'installing' and value['proof'] is None
    assert all(item['phase'] == 'created' for item in value['items'])
    with pytest.raises(Conflict,match='publication missing'):driver.observe('import-template')
    state['active'] = True
    assert make().recover('import-template')['template_sha256'] == request['template_sha256']


@pytest.mark.parametrize('path',['manifest.json/child','disks'])
def test_template_path_overlap_is_refused_before_import(template,path):
    template['assets']['extra'] = dict(path=path,sha256='c'*64,size=10,format='raw')
    with pytest.raises(Conflict,match='overlap'):
        bundle_plan('/synthetic/store','/synthetic/source',template,dict(sha256='d'*64,size=12))
