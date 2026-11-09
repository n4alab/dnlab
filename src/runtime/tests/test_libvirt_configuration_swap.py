"""Actual renameat2 only on private temporary files; service preflight synthetic."""
import os

import pytest

from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT
from dnlab_runtime.libvirt_configuration_swap import ConfigurationSwap,EXCHANGE,NOREPLACE
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_configuration_staging import staging
from test_libvirt_configuration import revision
from test_libvirt_install import install,request_profile


@pytest.fixture
def swap(staging):
    stage,value,root=staging
    stage.stage(value)
    def preflight(current):
        return dict(revision_sha256=fingerprint(current),unchanged_sha256=current['plan']['unchanged_sha256'],services_inactive=True)
    return ConfigurationSwap(stage,preflight=preflight),value,root


def test_exchange_preserves_original_backup_and_new_birth(swap):
    driver,value,root=swap
    old=value['plan']['source_item']['proof']['identity']
    new=driver.staging.observe(value)['identity']
    receipt=driver.execute(value)
    assert receipt['backup']['identity']==old and receipt['replacement']['identity']==new
    assert (root/UNIT.lstrip('/')).stat().st_ino==new['inode']
    backup=root/value['backup'].lstrip('/')
    assert backup.stat().st_ino==old['inode'] and backup.read_text()==value['plan']['source_item']['spec']['content']
    assert not (root/value['staging'].lstrip('/')).exists()
    assert driver.execute(value)==receipt and driver.recover(value)==receipt
    ConfigurationRevision._receipt(value,receipt)


@pytest.mark.parametrize('boundary',[EXCHANGE,NOREPLACE])
def test_lost_rename_response_recovers_without_repeating_that_rename(swap,monkeypatch,boundary):
    driver,value,_=swap;rename=driver._rename;calls=[]
    def lost(current,source,target,flags):
        calls.append(flags);rename(current,source,target,flags)
        if flags==boundary:raise OSError('synthetic lost rename response')
    monkeypatch.setattr(driver,'_rename',lost)
    with pytest.raises(OSError,match='lost rename'):driver.execute(value)
    with pytest.raises(Conflict,match='pending'):driver.execute(value)
    receipt=driver.recover(value)
    assert receipt==driver.observe(value)
    assert calls==[EXCHANGE,NOREPLACE]


def test_rename_not_executed_cannot_be_repeated(swap,monkeypatch):
    driver,value,root=swap
    monkeypatch.setattr(driver,'_rename',lambda *args:(_ for _ in ()).throw(OSError('synthetic not executed')))
    with pytest.raises(OSError):driver.execute(value)
    with pytest.raises(Conflict):driver.recover(value)
    assert (root/UNIT.lstrip('/')).stat().st_ino==value['plan']['source_item']['proof']['identity']['inode']
    assert not (root/value['backup'].lstrip('/')).exists()


def test_foreign_backup_blocks_exchange_without_overwrite(swap):
    driver,value,root=swap;backup=root/value['backup'].lstrip('/')
    backup.write_text('foreign preserve')
    with pytest.raises(Conflict,match='occupied'):driver.execute(value)
    assert backup.read_text()=='foreign preserve'
    assert driver._read(value) is None
    assert (root/UNIT.lstrip('/')).read_text()==value['plan']['source_item']['spec']['content']


def test_checkpoint_conflict_blocks_exchange(swap,monkeypatch):
    driver,value,root=swap
    # Insert is a direct transaction; inject at the actual post-checkpoint check.
    check=driver._check;calls=[]
    def changed(current,**kwargs):
        calls.append(1)
        if len(calls)==2:raise Conflict('synthetic changed complete preflight')
        return check(current,**kwargs)
    monkeypatch.setattr(driver,'_check',changed)
    with pytest.raises(Conflict,match='changed complete'):driver.execute(value)
    assert driver._read(value)['phase']=='exchange_requested'
    assert (root/UNIT.lstrip('/')).read_text()==value['plan']['source_item']['spec']['content']


def test_failed_sync_keeps_uncertain_exchange_until_explicit_recovery(swap,monkeypatch):
    driver,value,_=swap;sync=os.fsync
    monkeypatch.setattr(os,'fsync',lambda fd:(_ for _ in ()).throw(OSError('synthetic fsync failure')))
    with pytest.raises(OSError,match='fsync'):driver.execute(value)
    assert driver._read(value)['phase']=='exchange_requested'
    with pytest.raises(Conflict,match='pending'):driver.observe(value)
    monkeypatch.setattr(os,'fsync',sync)
    assert driver.recover(value)==driver.observe(value)


def test_replacement_after_completion_is_preserved_and_rejected(swap):
    driver,value,root=swap;driver.execute(value)
    unit=root/UNIT.lstrip('/');unit.unlink();unit.write_text('foreign preserve')
    with pytest.raises(Conflict):driver.observe(value)
    with pytest.raises(Conflict):driver.recover(value)
    assert unit.read_text()=='foreign preserve'


def test_backup_destination_appearing_at_syscall_is_never_overwritten(swap,monkeypatch):
    import dnlab_runtime.libvirt_configuration_swap as module
    driver,value,root=swap;rename=module.rename_siblings
    backup=root/value['backup'].lstrip('/')
    def raced(parent,source,target,flags):
        if flags==NOREPLACE:backup.write_text('foreign preserve')
        rename(parent,source,target,flags)
    monkeypatch.setattr(module,'rename_siblings',raced)
    with pytest.raises(FileExistsError):driver.execute(value)
    assert driver._read(value)['phase']=='backup_requested'
    with pytest.raises(Conflict):driver.recover(value)
    assert backup.read_text()=='foreign preserve'
    assert (root/value['staging'].lstrip('/')).stat().st_ino==value['plan']['source_item']['proof']['identity']['inode']


def test_unsupported_exchange_has_no_rename_fallback(swap,monkeypatch):
    import errno
    import dnlab_runtime.libvirt_configuration_swap as module
    driver,value,root=swap;calls=[]
    def unsupported(*args):
        calls.append(args[-1]);raise OSError(errno.ENOSYS,'synthetic unsupported renameat2')
    monkeypatch.setattr(module,'rename_siblings',unsupported)
    with pytest.raises(OSError):driver.execute(value)
    with pytest.raises(Conflict):driver.recover(value)
    assert calls==[EXCHANGE]
    assert (root/UNIT.lstrip('/')).read_text()==value['plan']['source_item']['spec']['content']


def test_closed_window_at_checkpoint_preserves_original(swap,monkeypatch):
    driver,value,root=swap;rename=driver._rename
    def closed(*args):
        monkeypatch.setattr(driver.window,'observe',lambda:{})
        return rename(*args)
    monkeypatch.setattr(driver,'_rename',closed)
    with pytest.raises(Conflict,match='window'):driver.execute(value)
    assert driver._read(value)['phase']=='exchange_requested'
    assert (root/UNIT.lstrip('/')).read_text()==value['plan']['source_item']['spec']['content']


def test_completed_observation_is_readonly_after_window_closes(swap,monkeypatch):
    driver,value,_=swap;proof=driver.execute(value)
    monkeypatch.setattr(driver.window,'observe',lambda:{})
    before=driver.journal.db.total_changes
    assert driver.observe(value)==proof
    assert driver.journal.db.total_changes==before
