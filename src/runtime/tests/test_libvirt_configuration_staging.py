"""Only private temporary unit files; session preflight is synthetic."""
from copy import deepcopy
import os

import pytest

from dnlab_runtime.libvirt_configuration import compile_revision,UNIT
from dnlab_runtime.libvirt_configuration_staging import ConfigurationStaging
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_configuration import revision
from test_libvirt_install import install,request_profile


@pytest.fixture
def staging(revision,tmp_path):
    driver,_,value,_,_=revision
    root=tmp_path/'root';(root/'etc/systemd/system').mkdir(parents=True)
    files=InstallationFiles(str(root),journal=driver.journal)
    source=value['plan']['source_item']
    assert source['spec']['uid']==os.getuid() and source['spec']['gid']==os.getgid()
    proof=files.create(source,value['installation']['id'])
    value=deepcopy(value)
    next(item for item in value['installation']['items'] if item['spec'].get('path')==UNIT)['proof']=proof
    value['plan']=compile_revision(value['installation'])
    value['source_sha256']=fingerprint(value['installation'])
    def preflight(current):
        return dict(revision_sha256=fingerprint(current),source_proof=current['plan']['source_item']['proof'])
    stage=ConfigurationStaging(driver.journal,files,window=driver.window,preflight=preflight)
    return stage,value,root


def test_stage_retains_source_and_reopens_original_candidate(staging):
    stage,value,root=staging;source=root/UNIT.lstrip('/')
    before=(source.read_bytes(),source.stat().st_ino)
    proof=stage.stage(value)
    assert stage.stage(value)==proof and stage.observe(value)==proof
    reopened=ConfigurationStaging(stage.journal,stage.files,window=stage.window,preflight=stage.preflight)
    assert reopened.observe(value)==proof
    assert (source.read_bytes(),source.stat().st_ino)==before
    assert not (root/value['backup'].lstrip('/')).exists()
    candidate=root/value['staging'].lstrip('/')
    assert candidate.stat().st_ino==proof['identity']['inode']
    assert candidate.read_text()==value['plan']['target_spec']['content']


def test_checkpoint_conflict_prevents_candidate_creation(staging,monkeypatch):
    stage,value,root=staging;original=stage._check;calls=[]
    def changed(current,**kwargs):
        calls.append(1)
        if len(calls)==2:raise Conflict('synthetic changed inactive session')
        return original(current,**kwargs)
    monkeypatch.setattr(stage,'_check',changed)
    with pytest.raises(Conflict,match='changed inactive'):stage.stage(value)
    assert not (root/value['staging'].lstrip('/')).exists()
    with pytest.raises(Conflict,match='pending'):stage.stage(value)
    with pytest.raises(Conflict,match='birth missing'):stage.recover(value)


def test_uncertain_fsync_requires_original_birth_recovery(staging,monkeypatch):
    stage,value,root=staging;sync=os.fsync
    def failed(fd):raise OSError('synthetic fsync failure')
    monkeypatch.setattr(os,'fsync',failed)
    with pytest.raises(OSError):stage.stage(value)
    candidate=root/value['staging'].lstrip('/');inode=candidate.stat().st_ino
    with pytest.raises(Conflict,match='pending'):stage.stage(value)
    monkeypatch.setattr(os,'fsync',sync)
    assert stage.recover(value)['identity']['inode']==inode
    assert stage.observe(value)['identity']['inode']==inode


def test_lost_create_response_recovers_original_without_second_create(staging,monkeypatch):
    stage,value,root=staging;create=stage.files.create;calls=[]
    def lost(item,operation):
        calls.append(operation)
        create(item,operation)
        raise OSError('synthetic lost candidate completion response')
    monkeypatch.setattr(stage.files,'create',lost)
    with pytest.raises(OSError,match='lost candidate'):stage.stage(value)
    inode=(root/value['staging'].lstrip('/')).stat().st_ino
    with pytest.raises(Conflict,match='pending'):stage.stage(value)
    assert stage.recover(value)['identity']['inode']==inode
    assert calls==[value['id']]


def test_candidate_observation_does_not_confirm_uncommitted_durability(staging,monkeypatch):
    stage,value,_=staging;save=stage._save
    def lost(record):raise OSError('synthetic journal completion loss')
    monkeypatch.setattr(stage,'_save',lost)
    with pytest.raises(OSError,match='journal completion'):stage.stage(value)
    with pytest.raises(Conflict,match='pending'):stage.observe(value)
    monkeypatch.setattr(stage,'_save',save)
    assert stage.recover(value)==stage.observe(value)


@pytest.mark.parametrize('target',['source','candidate'])
def test_foreign_file_is_preserved(staging,target):
    stage,value,root=staging
    if target=='candidate':stage.stage(value)
    path=root/(UNIT if target=='source' else value['staging']).lstrip('/')
    path.unlink();path.write_text('foreign preserve')
    with pytest.raises(Conflict):stage.stage(value)
    assert path.read_text()=='foreign preserve'


def test_preexisting_stage_is_not_adopted(staging):
    stage,value,root=staging;path=root/value['staging'].lstrip('/')
    path.write_text('foreign preserve')
    with pytest.raises(Conflict,match='birth missing'):stage.stage(value)
    assert path.read_text()=='foreign preserve'
    assert stage._read(value) is None


def test_closed_window_prevents_staging_and_recovery(staging,monkeypatch):
    stage,value,root=staging
    monkeypatch.setattr(stage.window,'observe',lambda:{})
    with pytest.raises(Conflict,match='window'):stage.stage(value)
    with pytest.raises(Conflict,match='window'):stage.recover(value)
    assert not (root/value['staging'].lstrip('/')).exists()
