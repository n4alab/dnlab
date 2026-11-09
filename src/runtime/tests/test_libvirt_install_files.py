"""Only temporary files: no host accounts, units, daemons or network operations."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path

import pytest

from dnlab_runtime.libvirt_install_files import InstallationFiles, MARKER
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict


@pytest.fixture
def files(tmp_path):
    (tmp_path/'config').mkdir()
    spec=dict(key='file:/config/session.conf',kind='file',path='/config/session.conf',
        uid=os.getuid(),gid=os.getgid(),mode=0o644,content='listen_tcp = 0\n')
    spec['sha256']=hashlib.sha256(spec['content'].encode()).hexdigest()
    item=dict(spec=spec,nonce='a'*32,phase='create_requested',proof=None)
    journal=Journal(tmp_path/'journal')
    yield InstallationFiles(tmp_path,journal=journal),item,tmp_path
    journal.close()


def test_exclusive_birth_is_recoverable_and_never_overwrites(files):
    adapter,item,root=files
    assert adapter.observe(item,'install') is None
    receipt=adapter.create(item,'install')
    assert receipt==adapter.observe(item,'install')
    assert (root/'config/session.conf').read_text()==item['spec']['content']
    with pytest.raises((FileExistsError,Conflict)):adapter.create(item,'install')
    assert receipt==InstallationFiles(root,journal=adapter.journal).observe(item,'install')


def test_readonly_observer_uses_existing_births_without_initializing_or_writing(files,monkeypatch):
    import sqlite3
    import threading
    from types import SimpleNamespace
    adapter,item,root=files
    receipt=adapter.create(item,'install')
    db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
    adapter.journal.db.backup(db)
    db.execute('PRAGMA query_only=ON')
    journal=SimpleNamespace(db=db,lock=threading.RLock(),execution_lock=threading.RLock())
    monkeypatch.setattr(os,'fsync',lambda *args:pytest.fail('readonly observer cannot fsync'))
    before=db.total_changes
    try:
        readonly=InstallationFiles(root,journal=journal,readonly=True)
        assert readonly.observe(item,'install')==receipt
        with pytest.raises(Conflict,match='readonly'):readonly.create(item,'install')
        with pytest.raises(Conflict,match='readonly'):readonly.recover(item,'install')
        assert db.total_changes==before
    finally:db.close()


@pytest.mark.parametrize('fault',['nonce','intent','content','mode','hardlink','missing-marker'])
def test_observation_rejects_replacements_and_unqualified_files(files,fault):
    adapter,item,root=files;adapter.create(item,'install');path=root/'config/session.conf'
    operation='install';request=deepcopy(item)
    if fault=='nonce':request['nonce']='b'*32
    elif fault=='intent':operation='other'
    elif fault=='content':path.write_text('foreign')
    elif fault=='mode':path.chmod(0o600)
    elif fault=='hardlink':os.link(path,root/'foreign-link')
    else:os.removexattr(path,MARKER)
    before=path.read_bytes()
    with pytest.raises(Conflict):adapter.observe(request,operation)
    assert path.read_bytes()==before


def test_symlink_leaf_and_parent_never_write_foreign_file(files):
    adapter,item,root=files;foreign=root/'foreign';foreign.mkdir();target=foreign/'target';target.write_text('preserve')
    (root/'config/session.conf').symlink_to(target)
    with pytest.raises((FileExistsError,Conflict)):adapter.create(item,'install')
    with pytest.raises(Conflict):adapter.observe(item,'install')
    (root/'config/session.conf').unlink();(root/'config').rmdir();(root/'config').symlink_to(foreign)
    with pytest.raises(OSError):adapter.create(item,'install')
    assert target.read_text()=='preserve' and not (foreign/'session.conf').exists()


def test_fsync_failure_retains_uncertain_file_without_retry(files,monkeypatch):
    adapter,item,root=files
    def fail(fd):raise OSError('synthetic fsync failure')
    monkeypatch.setattr(os,'fsync',fail)
    with pytest.raises(OSError):adapter.create(item,'install')
    assert (root/'config/session.conf').exists()
    with pytest.raises((FileExistsError,Conflict)):adapter.create(item,'install')


def test_directory_creation_requires_separate_birth_primitive(files):
    adapter,item,root=files
    item['spec']=dict(key='directory:/new',kind='directory',path='/new',uid=os.getuid(),gid=os.getgid(),mode=0o700)
    with pytest.raises(Conflict,match='separately qualified'):adapter.create(item,'install')
    assert not (root/'new').exists()


def test_short_writes_are_completed_on_original_fd(files,monkeypatch):
    adapter,item,_=files;write=os.write
    monkeypatch.setattr(os,'write',lambda fd,data:write(fd,data[:2]))
    assert adapter.create(item,'install')==adapter.observe(item,'install')


def test_failed_durability_is_not_reported_as_a_qualified_recovery_birth(files,monkeypatch):
    adapter,item,_=files
    def fail(fd):raise OSError('synthetic directory/file fsync failure')
    monkeypatch.setattr(os,'fsync',fail)
    with pytest.raises(OSError):adapter.create(item,'install')
    # A marker may exist even though durability was never confirmed. Read-only
    # observation alone must not turn that into an accepted installation birth.
    with pytest.raises(Conflict,match='durab'):
        adapter.observe(item,'install')


@pytest.mark.parametrize('failed_sync',[1,2])
def test_explicit_recovery_syncs_original_file_and_parent_then_commits(files,monkeypatch,failed_sync):
    adapter,item,root=files;sync=os.fsync;calls=[]
    def fail(fd):
        calls.append(fd)
        if len(calls)==failed_sync:raise OSError('synthetic sync failure')
        return sync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',fail)
        with pytest.raises(OSError):adapter.create(item,'install')
    birth=adapter._birth(item,'install');identity=deepcopy(birth['file'])
    assert birth['phase']=='durability_pending'
    reopened=InstallationFiles(root,journal=adapter.journal)
    with pytest.raises(Conflict,match='durability pending'):reopened.observe(item,'install')
    calls=[]
    def record(fd):calls.append(os.fstat(fd).st_ino);return sync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',record)
        receipt=reopened.recover(item,'install')
    assert calls==[identity['inode'],birth['parent']['inode']]
    assert reopened._birth(item,'install')['phase']=='durability_confirmed'
    assert receipt==reopened.observe(item,'install')
    assert {key:receipt['identity'][key] for key in identity}==identity


def test_recovery_sync_failure_keeps_pending_and_never_recreates(files,monkeypatch):
    adapter,item,root=files
    def fail(fd):raise OSError('synthetic sync failure')
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',fail)
        with pytest.raises(OSError):adapter.create(item,'install')
        original=adapter._birth(item,'install')
        with pytest.raises(OSError):adapter.recover(item,'install')
    assert adapter._birth(item,'install')==original
    assert (root/'config/session.conf').read_text()==item['spec']['content']
    with pytest.raises(Conflict,match='held'):adapter.create(item,'install')


@pytest.mark.parametrize('replace',['file','parent'])
def test_recovery_preserves_replacement_without_syncing_it(files,monkeypatch,replace):
    adapter,item,root=files
    def fail(fd):raise OSError('synthetic sync failure')
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',fail)
        with pytest.raises(OSError):adapter.create(item,'install')
    path=root/'config/session.conf';marker=os.getxattr(path,MARKER)
    if replace=='parent':
        (root/'config').rename(root/'original-config');(root/'config').mkdir()
    else:path.rename(root/'original-file')
    path.write_text(item['spec']['content']);path.chmod(item['spec']['mode']);os.setxattr(path,MARKER,marker)
    before=path.stat();pending=adapter._birth(item,'install')
    with monkeypatch.context() as patch:
        patch.setattr(os,'fsync',lambda fd:pytest.fail('replacement must not be synced'))
        with pytest.raises(Conflict,match='differs|replaced'):adapter.recover(item,'install')
    assert adapter._birth(item,'install')==pending
    assert path.stat().st_ino==before.st_ino and path.read_text()==item['spec']['content']


def test_lost_confirmation_commit_response_reuses_original_birth(files,monkeypatch):
    from contextlib import contextmanager
    adapter,item,_=files;transaction=adapter.journal.transaction;lost=[]
    @contextmanager
    def commit():
        with transaction():yield
        birth=adapter._birth(item,'install')
        if birth and birth['phase']=='durability_confirmed' and not lost:
            lost.append(True);raise OSError('synthetic lost commit response')
    monkeypatch.setattr(adapter.journal,'transaction',commit)
    with pytest.raises(OSError):adapter.create(item,'install')
    assert adapter.observe(item,'install')==adapter.recover(item,'install')
    with pytest.raises(Conflict,match='held'):adapter.create(item,'install')


def test_coordinator_waits_for_explicit_file_durability_recovery(tmp_path,monkeypatch):
    from dnlab_runtime.libvirt_install import SessionInstaller
    from dnlab_runtime.libvirt_service_profile import render_profile, ROLES
    from test_libvirt_install import Adapter
    request=dict(session=dict(host_id='synthetic-host',uid=1001,gid=1002,uri='qemu:///session',
        socket='/run/dnlab-libvirt/libvirt/libvirt-sock',runtime_root='/run/dnlab-libvirt',
        state_root='/var/lib/dnlab-libvirt'),libvirt_version='11.3.0-3+deb13u3',
        account_name='dnlab-libvirt',group_name='dnlab-libvirt',kvm_gid=108,layout_version=2,
        driver_config_root='/var/lib/dnlab-libvirt-control',
        binaries={role:dict(path='/usr/sbin/'+role,sha256='a'*64) for role in ROLES})
    root=tmp_path/'root';root.mkdir()
    # Pre-existing synthetic parents only; this is not directory/account provisioning.
    for path in render_profile(**request)['files']:
        (root/path.lstrip('/')).parent.mkdir(parents=True,exist_ok=True)
    journal=Journal(tmp_path/'integration-journal')
    try:
        files=InstallationFiles(root,journal=journal)
        class Bridge(Adapter):
            def observe(self,value):
                result=super().observe(value)
                for item in value['items']:
                    if item['spec']['kind']=='file':
                        result['targets'][item['spec']['key']]=files.observe(item,value['id'])
                return result
            def create(self,item,operation):
                if item['spec']['kind']=='file':
                    self.calls.append(item['spec']['key'])
                    return files.create(item,operation)
                return super().create(item,operation)
        adapter=Bridge();driver=SessionInstaller(journal,adapter)
        value=driver.prepare('files-integration',request,context={'boot':'synthetic'},
            prerequisites={'packages':'synthetic'})
        def fail(fd):raise OSError('synthetic first-file fsync failure')
        with monkeypatch.context() as patch:
            patch.setattr(os,'fsync',fail)
            with pytest.raises(OSError):driver.apply(value['id'])
        saved=driver.read(value['id']);pending=next(i for i in saved['items'] if i['phase']=='create_requested')
        calls=list(adapter.calls)
        with pytest.raises(Conflict,match='durability pending'):driver.apply(value['id'])
        assert driver.read(value['id'])==saved and adapter.calls==calls
        files.recover(pending,value['id'])
        assert driver.apply(value['id'])['phase']=='installed_not_started'
        assert adapter.calls.count(pending['spec']['key'])==1
    finally:journal.close()
