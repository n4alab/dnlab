"""Real temporary overlay files, synthetic formatter/domain authorization."""
from copy import deepcopy
import os

import pytest

from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_overlay_retirement import OverlayRetirement
from test_vm_overlay_files import files


@pytest.fixture
def retirement(files):
    driver,item,operation,state,_,root,base = files
    item = deepcopy(item);item['proof'] = driver.create(item,operation);item['phase'] = 'ready'
    receipt = dict(operation_id=operation,context={'host_id':'synthetic'},
        targets=['file:'+item['spec']['path']],nonce='c'*32)
    state['window'] = deepcopy(receipt);state['writers_absent'] = True
    window = ProvisioningWindow(receipt,lambda:deepcopy(state['window']))
    def preflight(value):
        return dict(operation_id=operation,spec_sha256=fingerprint(item['spec']),
            definition_retirement_sha256='d'*64,domain_absent_verified=True,
            writers_absent=state['writers_absent'],resources_verified=True)
    def make():return OverlayRetirement(driver,window=window,preflight=preflight)
    yield make(),item,operation,state,make,root,base


def test_remove_original_once_and_reopen_preserves_birth_and_base(retirement):
    driver,item,operation,state,make,root,base = retirement
    original = driver.files._load(item,operation);content = base.read_bytes()
    prepared = driver.prepare(item,operation,definition_retirement_sha256='d'*64)
    result = driver.apply(item,operation)
    assert prepared['phase'] == 'prepared' and result['phase'] == 'removed'
    assert list(root.iterdir()) == [] and base.read_bytes() == content
    assert driver.files._load(item,operation) == original
    assert make().prepare(item,operation,definition_retirement_sha256='d'*64) == result
    assert make().apply(item,operation) == result
    assert state['arms'] == state['releases'] == 1


@pytest.mark.parametrize('fault',['missing','replaced','writer','window','quarantine'])
def test_conflicts_preserve_files_and_prevent_removal(retirement,fault):
    driver,item,operation,state,_,root,_ = retirement;path = root/'overlay.qcow2'
    prepared = driver.prepare(item,operation,definition_retirement_sha256='d'*64)
    if fault == 'missing':path.rename(root/'retained-original')
    elif fault == 'replaced':path.rename(root/'retained-original');path.write_bytes(b'foreign')
    elif fault == 'writer':state['writers_absent'] = False
    elif fault == 'window':state['window']['nonce'] = 'e'*32
    else:(root/prepared['quarantine']).write_bytes(b'foreign')
    before = {p.name:p.read_bytes() for p in root.iterdir()}
    with pytest.raises(RuntimeErrorBase):driver.apply(item,operation)
    assert {p.name:p.read_bytes() for p in root.iterdir()} == before


@pytest.mark.parametrize('boundary',['rename','unlink','fsync'])
def test_lost_result_recovers_without_repeating_mutation(retirement,monkeypatch,boundary):
    driver,item,operation,_,make,root,_ = retirement
    driver.prepare(item,operation,definition_retirement_sha256='d'*64)
    calls = [];module = 'dnlab_runtime.vm_overlay_retirement'
    with monkeypatch.context() as patch:
        if boundary == 'rename':
            from dnlab_runtime.vm_overlay_retirement import rename_siblings
            def lost(*args):
                calls.append(True);rename_siblings(*args);raise OSError('lost rename result')
            patch.setattr(module+'.rename_siblings',lost)
        elif boundary == 'unlink':
            unlink = os.unlink
            def lost(*args,**kwargs):
                calls.append(True);unlink(*args,**kwargs);raise OSError('lost unlink result')
            patch.setattr(os,'unlink',lost)
        else:
            fsync = os.fsync
            def lost(fd):
                if not list(root.iterdir()):
                    calls.append(True);raise OSError('lost directory durability')
                return fsync(fd)
            patch.setattr(os,'fsync',lost)
        with pytest.raises(OSError,match='lost'):driver.apply(item,operation)
    assert len(calls) == 1
    result = make().apply(item,operation)
    assert result['phase'] == 'removed' and list(root.iterdir()) == []


def test_uncertain_rename_before_effect_is_not_repeated(retirement,monkeypatch):
    driver,item,operation,_,make,root,_ = retirement
    driver.prepare(item,operation,definition_retirement_sha256='d'*64)
    def failed(*args):raise OSError('rename did not return')
    with monkeypatch.context() as patch:
        patch.setattr('dnlab_runtime.vm_overlay_retirement.rename_siblings',failed)
        with pytest.raises(OSError):driver.apply(item,operation)
    with pytest.raises(RuntimeErrorBase,match='no resend'):make().apply(item,operation)
    assert (root/'overlay.qcow2').exists()


def test_preflight_is_rechecked_after_requested_checkpoint(retirement,monkeypatch):
    driver,item,operation,state,_,root,_ = retirement
    driver.prepare(item,operation,definition_retirement_sha256='d'*64);save = driver._save
    def change(value):
        save(value)
        if value['phase'] == 'rename_requested':state['writers_absent'] = False
    monkeypatch.setattr(driver,'_save',change)
    with pytest.raises(RuntimeErrorBase):driver.apply(item,operation)
    assert [p.name for p in root.iterdir()] == ['overlay.qcow2']


def test_reoccupation_rolls_back_completion_and_preserves_foreign_file(retirement,monkeypatch):
    driver,item,operation,_,_,root,_ = retirement
    driver.prepare(item,operation,definition_retirement_sha256='d'*64);write = driver._write
    def change(value):
        write(value)
        if value['phase'] == 'removed':(root/'overlay.qcow2').write_bytes(b'foreign')
    monkeypatch.setattr(driver,'_write',change)
    with pytest.raises(RuntimeErrorBase,match='reappeared'):driver.apply(item,operation)
    assert driver.read(item,operation)['phase'] == 'unlink_requested'
    assert (root/'overlay.qcow2').read_bytes() == b'foreign'
