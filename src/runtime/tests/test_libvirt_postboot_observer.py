"""Temporary SQL/volatile paths; persistent and snapshot callbacks synthetic."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_observer import PostBootObserver
from test_libvirt_postboot import postboot
from test_libvirt_install import install,request_profile


@pytest.fixture
def observed(postboot,tmp_path,monkeypatch):
    qualifier,value,installer,_,current,_=postboot
    root=tmp_path/'readonly-root';(root/'run').mkdir(parents=True)
    files=InstallationFiles(str(root),journal=qualifier.journal)
    files=InstallationFiles(str(root),journal=qualifier.journal,readonly=True)
    proofs={item['spec']['key']:deepcopy(item['proof']) for item in value['installation']['items']}
    monkeypatch.setattr(files,'observe',lambda item,creator:deepcopy(proofs[item['spec']['key']]))
    snapshot=dict(context=deepcopy(current['context']),prerequisites=deepcopy(current['prerequisites']))
    observer=PostBootObserver(root,value['installation'],value['context'],source_reader=installer.read,
        snapshot=lambda:deepcopy(snapshot),identity=lambda request:deepcopy(request['expected']),files=files,
        directory_dependency=lambda spec:pytest.fail('no dependency in this synthetic fixture'))
    return observer,value,root,proofs,snapshot


def test_readonly_installer_reads_original_without_initialization_or_writes(install):
    installer,_,prepared,_=install;original=installer.apply(prepared['id']);journal=installer.journal
    journal.db.execute('PRAGMA query_only=ON');before=journal.db.total_changes
    minimal=SimpleNamespace(db=journal.db,lock=journal.lock,execution_lock=journal.execution_lock)
    reader=SessionInstaller(minimal,None,readonly=True)
    assert reader.read(original['id'])==original
    with pytest.raises(Conflict,match='readonly'):reader.prepare('other',{},context={},prerequisites={})
    with pytest.raises(Conflict,match='readonly'):reader.apply(original['id'])
    with pytest.raises(Conflict,match='readonly'):reader._save(original)
    assert journal.db.total_changes==before


def test_observation_keeps_volatiles_unqualified_and_original_proofs(observed):
    observer,value,root,_,_=observed
    first=observer(value)
    assert first['context']==value['context'] and all(state=={'state':'absent'} for state in first['volatile'].values())
    before=deepcopy(value)
    path=root/value['installation']['profile']['session']['runtime_root'].lstrip('/')
    path.mkdir()
    after=observer(value)
    assert all(state=={'state':'present_unqualified'} for key,state in after['volatile'].items() if key=='directory:'+value['installation']['profile']['session']['runtime_root'])
    assert value==before and observer.diagnostics['status']=='collected'
    metadata=next(item for item in observer.diagnostics['targets'] if item['key']=='directory:'+value['installation']['profile']['session']['runtime_root'])['metadata']
    assert metadata['kind']=='directory' and metadata['inode']==path.stat().st_ino


def test_volatile_symlink_is_not_followed_or_claimed(observed):
    observer,value,root,_,_=observed
    target=root/'foreign';target.mkdir();(target/'preserve').write_text('foreign')
    parent=root/value['installation']['profile']['session']['runtime_root'].lstrip('/');parent.mkdir()
    leaf=parent/'libvirt';leaf.symlink_to(target,target_is_directory=True)
    result=observer(value)
    assert result['volatile']['directory:/run/dnlab-libvirt/libvirt']==dict(state='present_unqualified')
    entry=next(item for item in observer.diagnostics['targets'] if item['key']=='directory:/run/dnlab-libvirt/libvirt')
    assert entry['metadata']['kind']=='symlink' and entry['state']=='present_unqualified'
    assert (target/'preserve').read_text()=='foreign' and leaf.is_symlink()


@pytest.mark.parametrize('fault',['boot','persistent','account','source'])
def test_conflicts_preserve_diagnostics_without_mutating_resources(observed,monkeypatch,fault):
    observer,value,root,proofs,snapshot=observed
    if fault=='boot':snapshot['context']['boot_id']='unexpected-third-boot'
    elif fault=='persistent':
        key=next(item['spec']['key'] for item in value['installation']['items'] if item['spec']['kind']=='file')
        proofs[key]={'foreign':'preserve'}
    elif fault=='account':monkeypatch.setattr(observer,'identity',lambda request:None)
    else:monkeypatch.setattr(observer,'source_reader',lambda operation:{})
    before=value.copy()
    with pytest.raises(Conflict):observer(value)
    assert observer.diagnostics['status']=='failed' and observer.diagnostics['error']['type']=='Conflict'
    assert value==before and list((root/'run').iterdir())==[]


def test_snapshot_transition_and_wrong_source_are_rejected(observed,monkeypatch):
    observer,value,_,_,snapshot=observed;calls=[]
    def changed():
        calls.append(1);result=deepcopy(snapshot)
        if len(calls)>1:result['prerequisites']['packages']='changed'
        return result
    monkeypatch.setattr(observer,'snapshot',changed)
    with pytest.raises(Conflict,match='snapshot changed'):observer(value)
    assert observer.diagnostics['status']=='failed'
    foreign=deepcopy(value);foreign['source_sha256']='0'*64
    with pytest.raises(Conflict,match='binding'):observer(foreign)
