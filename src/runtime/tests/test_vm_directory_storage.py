"""Composed directory/storage admission with synthetic filesystem/formatter IO."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_directory_storage import DirectoryVMStorage
from dnlab_runtime.vm_template import TemplateError
from test_vm_directories import directories
from test_vm_definition import definition, template, instance
from test_vm_definition_fences import install_fence


@pytest.fixture
def storage(directories,template,monkeypatch):
    directory,definitions,birth,dstate,_,sdk = directories
    operation = birth['creator_operation_id']
    directory.prepare(operation);ready = directory.apply(operation)
    state = dict(files={},creates=0,recovers=0,lost=False,checkpoint=None,assets=True,writers=[])
    class Files:
        def __init__(self,journal,*,root,parent_identity,binary,runner_factory,preflight):
            self.journal,self.root,self.parent_identity,self.preflight = journal,root,parent_identity,preflight
        def observe(self,item,operation):
            result = state['files'].get(item['spec']['path'])
            if result is not None:self.preflight(deepcopy(item),operation,mutating=False)
            return deepcopy(result)
        def create(self,item,operation):
            self.preflight(deepcopy(item),operation,mutating=True)
            if state['checkpoint']:state['checkpoint']()
            self.preflight(deepcopy(item),operation,mutating=True)
            state['creates'] += 1;spec = item['spec']
            proof = dict(operation_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(spec),
                identity=dict(device=4,inode=3000,uid=spec['uid'],gid=spec['gid'],mode=spec['mode']),
                creation=dict(request_sha256=fingerprint(dict(operation_id=operation,nonce=item['nonce'],spec=spec)),
                              worker_reference_sha256='f'*64,exit_code=0))
            state['files'][spec['path']] = proof
            if state['lost']:raise OSError('lost original formatter reply')
            return deepcopy(proof)
        def recover(self,item,operation):
            self.preflight(deepcopy(item),operation,mutating=True);state['recovers'] += 1
            result = self.observe(item,operation)
            if result is None:raise Conflict('original overlay birth unavailable')
            return result
    monkeypatch.setattr('dnlab_runtime.vm_directory_storage.OverlayFiles',Files)
    def make():
        return DirectoryVMStorage(directory,operation,
            assets=lambda value:dict(template_sha256=birth['template_sha256'],assets_verified=state['assets']),
            writers=lambda value:deepcopy(state['writers']),binary=dict(path='/usr/bin/qemu-img',sha256='e'*64),
            runner_factory=lambda:None)
    driver = make();driver.prepare(operation,template,'/templates/synthetic')
    return driver,operation,state,make,directory,dstate,definitions,ready


def test_directory_receipt_binds_overlay_creation_and_reopen(storage):
    driver,operation,state,make,directory,_,_,ready = storage
    result = driver.apply(operation)
    assert result['phase']=='ready' and state['creates']==1
    assert make().apply(operation)==result and state['creates']==1
    assert directory.observe(operation)==ready
    assert driver.files.root==ready['spec']['path']
    assert driver.files.parent_identity['inode']==ready['proof']['identity']['inode']


def test_lost_overlay_reply_recovers_under_same_directory_birth(storage):
    driver,operation,state,make,directory,_,_,ready = storage
    state['lost'] = True
    with pytest.raises(OSError,match='lost original'):driver.apply(operation)
    result = make().apply(operation)
    assert result['phase']=='ready' and state['creates']==state['recovers']==1
    assert directory.observe(operation)==ready


@pytest.mark.parametrize('fault',['missing','inode','nonce','context','assets','writer'])
def test_changed_prerequisites_preserve_original_directory_and_block_overlay(storage,fault):
    driver,operation,state,_,_,dstate,_,ready = storage
    if fault=='missing':dstate['files'].pop(ready['spec']['path'])
    elif fault in ('inode','nonce'):
        proof = dstate['files'][ready['spec']['path']]
        if fault=='inode':proof['identity']['inode'] += 1
        else:proof['nonce'] = 'c'*32
    elif fault=='context':dstate['context']['namespaces']['mnt']['inode'] += 1
    elif fault=='assets':state['assets'] = False
    else:state['writers'] = [{},{}]
    before = driver.journal.db.total_changes
    with pytest.raises((Conflict,TemplateError)):driver.apply(operation)
    assert driver.journal.db.total_changes==before
    assert state['creates']==state['recovers']==0 and not state['files']
    assert dstate['creates']==1


def test_directory_loss_at_lower_checkpoint_stops_allocation_and_recovery(storage):
    driver,operation,state,make,_,dstate,_,ready = storage
    state['checkpoint'] = lambda:dstate['files'].pop(ready['spec']['path'])
    with pytest.raises(Conflict,match='missing or replaced'):driver.apply(operation)
    assert driver.read(operation)['items'][0]['phase']=='create_requested'
    assert state['creates']==0
    with pytest.raises(Conflict,match='missing or replaced'):make()
    assert state['recovers']==0 and dstate['creates']==1


def test_definition_before_overlay_allocation_refuses_without_files(storage):
    driver,operation,state,_,_,_,definitions,_ = storage
    definitions.apply(operation)
    with pytest.raises(TemplateError,match='precede domain'):driver.apply(operation)
    assert state['creates']==0


def test_ready_overlay_can_be_inspected_after_definition_without_new_allocation(storage):
    driver,operation,state,make,_,_,definitions,_ = storage
    ready = driver.apply(operation);definitions.apply(operation)
    assert make().apply(operation)==ready and state['creates']==1


@pytest.mark.parametrize('fault',['operation','item','parent'])
def test_lower_checkpoint_rejects_other_owner_item_or_parent(storage,fault):
    driver,operation,state,_,_,_,_,_ = storage
    item = deepcopy(driver.read(operation)['items'][0])
    if fault=='operation':operation = 'd'*32
    elif fault=='item':item['nonce'] = 'd'*32
    else:driver.files.parent_identity['inode'] += 1
    with pytest.raises(TemplateError):driver.files.preflight(item,operation,mutating=True)
    assert state['creates']==state['recovers']==0


@pytest.mark.parametrize('fence',['closed','held'])
@pytest.mark.parametrize('boundary',['outer-save','lower-checkpoint'])
def test_fence_at_creation_checkpoint_blocks_disk_and_preserves_directory(storage,monkeypatch,fence,boundary):
    driver,operation,state,_,directory,dstate,definitions,ready = storage
    if boundary=='outer-save':
        save = driver._save
        def checkpoint(value):
            save(value)
            if value['items'][0]['phase']=='create_requested':install_fence(definitions.journal,fence)
        monkeypatch.setattr(driver,'_save',checkpoint)
    else:state['checkpoint'] = lambda:install_fence(definitions.journal,fence)
    with pytest.raises(Conflict):driver.apply(operation)
    assert driver.read(operation)['items'][0]['phase']=='create_requested'
    assert state['creates']==state['recovers']==0
    assert directory.observe(operation)==ready and dstate['creates']==1


def test_lost_overlay_reply_cannot_recover_through_management_fence(storage):
    driver,operation,state,make,_,_,definitions,_ = storage
    state['lost'] = True
    with pytest.raises(OSError):driver.apply(operation)
    install_fence(definitions.journal,'held')
    with pytest.raises(Conflict):make().apply(operation)
    assert state['creates']==1 and state['recovers']==0
