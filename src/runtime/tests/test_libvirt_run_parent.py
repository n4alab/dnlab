"""Per-boot /run contracts, synthetic recovery, and private temporary files."""
from copy import deepcopy
import os
import stat
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_current_session import CurrentSessionView,CurrentSessionPreflight
from dnlab_runtime.libvirt_configuration import compile_revision
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_package_policy import INSTALLED_PACKAGES
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_run_parent import bind_run_parent
from dnlab_runtime.libvirt_volatile_recovery import VolatileDirectories
from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from test_libvirt_install import install,request_profile
from test_libvirt_package_policy import installed_packages
from test_libvirt_volatile_recovery import Directories


@pytest.fixture
def boot_parent(installed_packages):
    driver,original,current,observed,installer,adapter=installed_packages
    original['prerequisites']['os_parents']={
        '/run':dict(device=57,inode=1,uid=0,gid=0,mode=0o755),
        '/var':dict(device=2,inode=5,uid=0,gid=0,mode=0o755)}
    with installer.journal.transaction():installer._save(original)
    observed['prerequisites']['os_parents']=deepcopy(original['prerequisites']['os_parents'])
    observed['prerequisites']['os_parents']['/run']['device']=58
    parent=bind_run_parent(original,current,observed['prerequisites']['os_parents']['/run'])
    return driver,original,current,observed,installer,adapter,parent


def prepare(boot_parent):
    driver,original,current,_,_,_,parent=boot_parent
    return driver.prepare('current-run-parent',original,current,package_policy=INSTALLED_PACKAGES,run_parent=parent)


def test_explicit_parent_is_qualified_only_by_current_observations(boot_parent):
    driver,original,current,observed,installer,adapter,parent=boot_parent
    calls=list(adapter.calls);before=driver.journal.db.total_changes
    assert bind_run_parent(original,current,parent['identity'])==parent
    assert driver.journal.db.total_changes==before
    value=prepare(boot_parent)
    assert value['receipt'] is None and value['run_parent']==parent
    receipt=driver.qualify_persistent(value['id'])
    assert receipt['qualified'] is False and receipt['run_parent_sha256']==fingerprint(parent)
    assert receipt['observation']['prerequisites']['os_parents']['/run']['device']==58
    assert installer.read(original['id'])==original and original['prerequisites']['os_parents']['/run']['device']==57
    assert adapter.calls==calls
    before=driver.journal.db.total_changes
    assert driver.qualify_persistent(value['id'])==receipt
    assert driver.prepare(value['id'],original,current,package_policy=INSTALLED_PACKAGES,run_parent=parent)==driver.read(value['id'])
    assert driver.journal.db.total_changes==before


def test_no_implicit_parent_adoption_or_conversion_of_historical_request(boot_parent):
    driver,original,current,_,_,_,parent=boot_parent
    value=driver.prepare('historical-parent',original,current,package_policy=INSTALLED_PACKAGES)
    with pytest.raises(Conflict):driver.qualify_persistent(value['id'])
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='original post-boot request'):
        driver.prepare(value['id'],original,current,package_policy=INSTALLED_PACKAGES,run_parent=parent)
    assert driver.read(value['id'])==value and driver.journal.db.total_changes==before


@pytest.mark.parametrize('field,value',[('uid',1001),('gid',1002),('mode',0o777),('device',0),('inode',True)])
def test_unqualified_parent_metadata_refused_before_journal_write(boot_parent,field,value):
    driver,original,current,_,_,_,parent=boot_parent
    identity=deepcopy(parent['identity']);identity[field]=value
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='/run parent'):
        bind_run_parent(original,current,identity)
    assert driver.journal.db.total_changes==before


@pytest.mark.parametrize('fault',['boot','namespace','source','path'])
def test_parent_binding_cannot_cross_context_or_source(boot_parent,fault):
    driver,original,current,_,_,_,parent=boot_parent;changed=deepcopy(parent)
    if fault=='boot':changed['context']['boot_id']='foreign-boot'
    elif fault=='namespace':changed['context']['namespaces']['mnt']['inode']+=1
    elif fault=='source':changed['source_sha256']='0'*64
    else:changed['path']='/var'
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='/run parent binding'):
        driver.prepare('foreign-parent',original,current,package_policy=INSTALLED_PACKAGES,run_parent=changed)
    assert driver.journal.db.total_changes==before


@pytest.mark.parametrize('fault',['device','inode','other-parent'])
def test_identity_pinned_in_one_context_and_other_parents_unchanged(boot_parent,fault):
    driver,original,current,observed,_,_,parent=boot_parent;value=prepare(boot_parent)
    parents=observed['prerequisites']['os_parents']
    if fault=='other-parent':parents['/var']['device']+=1
    else:parents['/run'][fault]+=1
    with pytest.raises(Conflict):driver.qualify_persistent(value['id'])
    assert driver.read(value['id'])==value
    replacement=deepcopy(parent);replacement['identity']['device']+=1
    with pytest.raises(Conflict,match='original post-boot request'):
        driver.prepare(value['id'],original,current,package_policy=INSTALLED_PACKAGES,run_parent=replacement)


class PinnedDirectories(Directories):
    def __init__(self,journal,observed,parent):
        super().__init__(journal,observed);self.parent=deepcopy(parent);self.received=[]

    def create(self,item,operation,*,window,run_parent):
        assert run_parent==self.parent
        self.received.append(deepcopy(run_parent))
        return super().create(item,operation,window=window)


def recovery_for(boot_parent):
    driver,_,current,observed,_,_,parent=boot_parent;value=prepare(boot_parent)
    driver.qualify_persistent(value['id'])
    agreement=dict(operation_id='parent-directories',context=current,targets=value['plan']['volatile'],nonce='5'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    files=PinnedDirectories(driver.journal,observed,parent['identity'])
    recovery=VolatileDirectories(driver,files,window=window)
    prepared=recovery.prepare('parent-directories',value['id'])
    return recovery,prepared,files,value


def test_recovery_and_session_preflight_keep_current_parent_bound(boot_parent):
    driver,original,current,observed,installer,_,parent=boot_parent
    recovery,prepared,files,_=recovery_for(boot_parent)
    recovery.apply(prepared['id'])
    assert len(files.received)==2
    for item in original['items']:
        if item['spec']['kind'] in ('file','directory') and not item['spec']['path'].startswith('/run/'):
            files.resources[item['spec']['key']]=deepcopy(item['proof'])
    view=CurrentSessionView(recovery,prepared['id']);source=view.read()
    assert source['postboot']['run_parent_sha256']==fingerprint(parent)
    assert source['prerequisites']['os_parents']['/run']==parent['identity']
    provider=CurrentSessionPreflight(view,snapshot=lambda:dict(context=current,prerequisites=deepcopy(observed['prerequisites'])),
        identity=lambda request:request['expected'],directory_dependency=lambda spec:pytest.fail('unexpected dependency'))
    request=dict(installation=source,source_sha256=fingerprint(source),plan=compile_revision(source))
    assert provider(request)['context']==current
    observed['prerequisites']['os_parents']['/run']['device']+=1
    with pytest.raises(Conflict):provider(request)
    assert installer.read(original['id'])==original


@pytest.mark.parametrize('field',['device','inode'])
def test_parent_change_after_checkpoint_blocks_first_directory_write(boot_parent,monkeypatch,field):
    _,_,_,observed,_,_,_=boot_parent
    recovery,prepared,files,_=recovery_for(boot_parent);save=recovery._save
    def changed(value):
        save(value)
        if any(item['phase']=='create_requested' for item in value['items']):
            observed['prerequisites']['os_parents']['/run'][field]+=1
    monkeypatch.setattr(recovery,'_save',changed)
    with pytest.raises(Conflict):recovery.apply(prepared['id'])
    assert files.calls==[] and files.received==[]
    assert recovery.read(prepared['id'])['phase']=='applying'


def test_reopen_revalidates_parent_receipt(boot_parent):
    driver,_,_,_,_,_,_=boot_parent;value=prepare(boot_parent)
    driver.qualify_persistent(value['id']);stored=driver.read(value['id'])
    stored['receipt']['run_parent_sha256']='0'*64
    driver.journal.db.execute('UPDATE libvirt_postboot_qualifications SET payload=?,fingerprint=? WHERE id=?',
        (canonical(stored),fingerprint(stored),value['id']))
    with pytest.raises(Conflict,match='/run parent receipt'):driver.read(value['id'])


@pytest.mark.parametrize('replaced',[False,True])
def test_filesystem_create_checks_pinned_run_fd_before_birth(install,tmp_path,replaced):
    installer,_,_,_=install;root=tmp_path/'private-root';root.mkdir();run=root/'run';run.mkdir(mode=0o755)
    info=run.stat();identity=dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
    files=InstallationFiles(root,journal=installer.journal)
    item=dict(nonce='6'*32,phase='prepared',proof=None,spec=dict(key='directory:/run/new-session',path='/run/new-session',kind='directory',uid=0,gid=0,mode=0o700))
    window=SimpleNamespace(sha256='7'*64,verify=lambda *args:None)
    if replaced:
        run.rename(root/'old-run');run.mkdir(mode=0o755)
        with pytest.raises(Conflict,match='/run parent replaced'):
            files.create(item,'temporary-directory',window=window,run_parent=identity)
        assert not list(run.iterdir()) and not list((root/'old-run').iterdir())
        assert installer.journal.db.execute('SELECT count(*) FROM libvirt_install_file_births').fetchone()[0]==0
    else:
        receipt=files.create(item,'temporary-directory',window=window,run_parent=identity)
        assert receipt['identity']['device']==identity['device'] and (run/'new-session').is_dir()
