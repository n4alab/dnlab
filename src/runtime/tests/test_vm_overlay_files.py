"""Real temporary files and ownership; the formatting process stays synthetic."""
from copy import deepcopy
import hashlib
import json
import os
import uuid

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.vm_overlay_files import OverlayFiles, directory_identity
from dnlab_runtime.vm_template import TemplateError
from test_qcow2_header import header


@pytest.fixture
def files(tmp_path):
    root = tmp_path/'disks';root.mkdir(mode=0o700)
    base = tmp_path/'base.raw';raw = b'\0' * 4096;base.write_bytes(raw);base.chmod(0o444)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    identity = directory_identity(parent);os.close(parent)
    operation = 'a' * 32
    item = dict(phase='create_requested',nonce='b'*32,proof=None,
                spec=dict(id='boot',path=str(root/'overlay.qcow2'),base_path=str(base),base_format='raw',
                          base_sha256=hashlib.sha256(raw).hexdigest(),uid=1001,gid=1002,mode=0o600))
    state = dict(arms=0,releases=0,workers={},lost_arm=False,lost_release=False)
    class Runner:
        def arm(self, command):
            state['arms'] += 1;token = uuid.uuid4().hex
            reference = dict(token=token,command_sha256=fingerprint(command),
                             process_record=dict(boot_id='synthetic',pid=123,start_ticks=456,uid=0,gid=0,
                                                 executable_sha256='c'*64,namespace_sha256='d'*64))
            state['workers'][token] = dict(reference=reference,command=deepcopy(command),phase='armed',
                                          fd=os.dup(command['target']['fd']))
            if state['lost_arm']:state['lost_arm']=False;raise OSError('lost arm response')
            return reference
        def original_reference(self, command):
            values = [worker['reference'] for worker in state['workers'].values() if worker['command']==command]
            assert len(values)==1
            return deepcopy(values[0])
        def _read(self, reference):return state['workers'][reference['token']]
        def release(self, reference):
            worker = self._read(reference)
            assert worker['phase']=='armed'
            state['releases'] += 1
            os.pwrite(worker['fd'],header(backing=str(base)),0)
            os.close(worker['fd']);worker['fd']=None
            worker.update(phase='completed',outcome=dict(reference=deepcopy(reference),exit_code=0,stdout='',stderr=''))
            if state['lost_release']:state['lost_release']=False;raise OSError('lost release response')
        def outcome(self, reference):return deepcopy(self._read(reference).get('outcome'))
    journal = Journal(tmp_path/'journal')
    def make(preflight=lambda *args,**kwargs:[], **options):
        return OverlayFiles(journal,root=str(root),parent_identity=identity,binary=dict(path='/usr/bin/qemu-img',sha256='e'*64),
                            runner_factory=Runner,preflight=preflight,**options)
    try:yield make(),item,operation,state,make,root,base
    finally:
        for worker in state['workers'].values():
            if worker['fd'] is not None:os.close(worker['fd'])
        journal.close()


def test_birth_format_and_reopen_preserve_inode_and_guest_data(files):
    driver,item,operation,state,make,root,_ = files
    assert driver.observe(item,operation) is None
    proof=driver.create(item,operation)
    fd=os.open(root/'overlay.qcow2',os.O_RDWR)
    try:os.pwrite(fd,b'guest data',8192)
    finally:os.close(fd)
    before=driver.journal.db.total_changes
    assert make().observe(item,operation)==proof
    assert make().recover(item,operation)==proof
    assert driver.journal.db.total_changes==before
    assert state['arms']==state['releases']==1


@pytest.mark.parametrize('boundary',['arm','release'])
def test_lost_helper_response_recovers_without_second_arm_or_release(files,boundary):
    driver,item,operation,state,make,_,_=files
    state['lost_'+boundary]=True
    with pytest.raises(OSError,match='lost'):driver.create(item,operation)
    proof=make().recover(item,operation)
    assert proof==driver.observe(item,operation)
    assert state['arms']==state['releases']==1


def test_failed_file_fsync_requires_explicit_recovery_before_format(files,monkeypatch):
    driver,item,operation,state,make,_,_=files
    original=os.fsync;failed=[]
    def fault(fd):
        if os.fstat(fd).st_uid==1001 and not failed:
            failed.append(True);raise OSError('synthetic durability failure')
        return original(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',fault)
        with pytest.raises(OSError,match='durability failure'):driver.create(item,operation)
    assert state['arms']==0
    proof=make().recover(item,operation)
    assert proof['identity']['uid']==1001 and state['arms']==1


def test_unrecorded_inode_is_not_adopted_even_with_an_expected_filename(files,monkeypatch):
    driver,item,operation,state,make,root,_=files
    save=driver._save
    def lost(value):
        if value['phase']=='initializing':raise OSError('lost birth identity before save')
        return save(value)
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError):driver.create(item,operation)
    inode=(root/'overlay.qcow2').stat().st_ino
    with pytest.raises(TemplateError,match='not recorded'):make().recover(item,operation)
    assert (root/'overlay.qcow2').stat().st_ino==inode and state['arms']==0


@pytest.mark.parametrize('fault',['missing','replaced','hardlink','backing'])
def test_ready_overlay_conflicts_preserve_files_without_create(files,fault):
    driver,item,operation,state,_,root,_=files
    driver.create(item,operation);path=root/'overlay.qcow2'
    if fault=='missing':path.unlink()
    elif fault=='replaced':path.rename(root/'original');path.write_bytes(b'foreign')
    elif fault=='hardlink':os.link(path,root/'alias')
    else:
        fd=os.open(path,os.O_RDWR)
        try:os.pwrite(fd,header(backing='/foreign/base.raw'),0)
        finally:os.close(fd)
    before=driver.journal.db.total_changes
    with pytest.raises((Conflict,TemplateError)):driver.observe(item,operation)
    with pytest.raises(TemplateError,match='already held'):driver.create(item,operation)
    assert driver.journal.db.total_changes==before and state['arms']==1


def test_foreign_path_is_refused_before_birth_intent(files):
    driver,item,operation,state,_,root,_=files
    (root/'overlay.qcow2').write_bytes(b'foreign')
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='no adoption'):driver.create(item,operation)
    assert driver.journal.db.total_changes==before and state['arms']==0
    assert (root/'overlay.qcow2').read_bytes()==b'foreign'


def test_base_change_invalidates_hash_cache_without_reformat(files):
    driver,item,operation,state,_,_,base=files
    driver.create(item,operation)
    base.chmod(0o600);base.write_bytes(b'x'*4096);base.chmod(0o444)
    with pytest.raises(TemplateError,match='base content differs'):driver.observe(item,operation)
    assert state['arms']==1


def test_parent_replacement_during_observation_is_not_accepted(files):
    driver,item,operation,_,make,root,_=files
    driver.create(item,operation);moved=[]
    def change(*args,**kwargs):
        if not moved:
            moved.append(True);root.rename(root.with_name('original-disks'));root.mkdir(mode=0o700)
        return []
    with pytest.raises(TemplateError,match='parent path replaced'):make(change).observe(item,operation)
    assert list(root.iterdir())==[]


@pytest.mark.parametrize('fault',['stage','exit-type'])
def test_inconsistent_saved_history_cannot_arm_a_new_formatter(files,fault):
    driver,item,operation,state,make,_,_=files
    driver.create(item,operation)
    row=driver.journal.db.execute('SELECT payload FROM vm_overlay_files').fetchone()
    value=json.loads(row[0])
    if fault=='stage':value['phase']='file_ready'
    else:value['outcome']['exit_code']=False
    driver.journal.db.execute('UPDATE vm_overlay_files SET payload=?,fingerprint=?', (canonical(value),fingerprint(value)))
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict):make().recover(item,operation)
    assert state['arms']==1 and driver.journal.db.total_changes==before


def test_readonly_observer_never_creates_schema_or_recovers_formatter(files):
    driver,item,operation,state,make,_,_=files
    proof=driver.create(item,operation)
    driver.journal.db.execute('PRAGMA query_only=ON')
    before=driver.journal.db.total_changes
    observer=make(readonly=True)
    assert observer.observe(item,operation)==proof
    with pytest.raises(TemplateError,match='readonly'):observer.create(item,operation)
    with pytest.raises(TemplateError,match='readonly'):observer.recover(item,operation)
    assert driver.journal.db.total_changes==before and state['arms']==1


def test_preflight_at_release_can_resume_original_unreleased_worker(files):
    driver,item,operation,state,make,_,_=files
    def held(*args,**kwargs):
        row=driver.journal.db.execute('SELECT payload FROM vm_overlay_files').fetchone()
        if row and json.loads(row[0])['phase']=='release_requested':raise Conflict('synthetic management fence')
        return []
    blocked=make(held)
    with pytest.raises(Conflict,match='management fence'):blocked.create(item,operation)
    assert state['arms']==1 and state['releases']==0
    assert make().recover(item,operation)['creation']['exit_code']==0
    assert state['arms']==state['releases']==1


def test_foreign_fifo_is_inspected_only_with_path_descriptor(files,monkeypatch):
    driver,item,operation,state,_,root,_=files
    driver.create(item,operation)
    path=root/'overlay.qcow2';path.rename(root/'original');os.mkfifo(path,0o600)
    original=os.open;target_opens=[]
    def track(name,flags,*args,**kwargs):
        if name=='overlay.qcow2':target_opens.append(flags)
        return original(name,flags,*args,**kwargs)
    monkeypatch.setattr(os,'open',track)
    with pytest.raises(TemplateError,match='regular VM overlay'):driver.observe(item,operation)
    assert len(target_opens)==1 and target_opens[0]&os.O_PATH
    assert state['arms']==1


def test_completed_format_durability_recovery_needs_no_new_runner(files,monkeypatch):
    driver,item,operation,state,make,_,_=files
    fsync=os.fsync;failed=[]
    def fail_final(fd):
        row=driver.journal.db.execute('SELECT payload FROM vm_overlay_files').fetchone()
        if row and json.loads(row[0])['phase']=='formatted' and os.fstat(fd).st_uid==1001 and not failed:
            failed.append(True);raise OSError('synthetic final fsync failure')
        return fsync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',fail_final)
        with pytest.raises(OSError,match='final fsync'):driver.create(item,operation)
    reopened=make()
    monkeypatch.setattr(reopened,'runner_factory',lambda:pytest.fail('completed formatter must not be reopened'))
    assert reopened.recover(item,operation)['creation']['exit_code']==0
    assert state['arms']==state['releases']==1
