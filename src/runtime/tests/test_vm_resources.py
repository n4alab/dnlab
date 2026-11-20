"""Whole resource admission with real controllers and synthetic host adapters."""
from copy import deepcopy
from threading import RLock
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_resources import VMResourcePreflight, VMResourceRegistry
from test_vm_directory_storage import storage, directories, definition, template, instance
from test_vm_taps import taps as taps_fixture
from test_vm_boot import boot as boot_fixture


@pytest.fixture
def resources(storage, definition, monkeypatch):
    disks,operation,state,_,directory,_,definitions,_=storage
    disks.apply(operation)
    value=definitions.read(operation)
    local=(definitions,value['birth'],value['xml'],definition[3],definition[4],definition[5])
    taps,_,tstate,_,_,_,_=taps_fixture.__wrapped__(local)
    taps.apply(operation)
    capability=VMResourcePreflight(disks,taps)
    definitions.preflight=capability
    return capability,disks,taps,state,tstate,local,monkeypatch


def test_complete_resource_observers_allow_define_boot_and_replay(resources):
    capability,storage,taps,state,tstate,local,monkeypatch=resources
    boot,operation,_,_,_=boot_fixture.__wrapped__(local,monkeypatch)
    def writers(value):
        record=boot.definitions.read(operation).get('boot',{}).get('process_record')
        return [deepcopy(record)] if record else []
    storage.writers=writers;taps.writers=writers
    original=taps.preflight
    def host(value):
        proof=original(value);proof['guest_writers_absent']=not bool(writers(value))
        return proof
    taps.preflight=host
    result=boot.apply(operation)
    assert result['boot']['phase']=='running'
    assert capability(result)['overlays_verified'] is True
    assert boot.apply(operation)==result
    assert state['creates']==1 and len(tstate['creates'])==len(taps.read(operation)['items'])


@pytest.mark.parametrize('fault',['overlay','endpoint','template'])
def test_complete_resource_preflight_rejects_conflict_before_define(resources,fault):
    capability,storage,taps,state,tstate,local,_=resources
    definitions,birth,_,domains,_,_=local;operation=birth['creator_operation_id']
    if fault=='overlay':next(iter(state['files'].values()))['identity']['inode']+=1
    elif fault=='endpoint':next(iter(tstate['proofs'].values()))['worker_reference_sha256']='f'*64
    else:state['assets']=False
    with pytest.raises(RuntimeErrorBase):definitions.apply(operation)
    assert not domains['domains'] and definitions.read(operation)['phase']=='prepared'


def test_resource_registry_dispatches_original_creator_instead_of_last_registration(monkeypatch):
    definitions=SimpleNamespace(journal=SimpleNamespace(execution_lock=RLock()))
    registry=VMResourceRegistry(definitions);calls=[]
    def capability(operation):
        item=object.__new__(VMResourcePreflight)
        item.definitions=definitions;item.operation=operation
        item.storage=SimpleNamespace(directories=object(),read=lambda op:dict(id=op))
        item.taps=object()
        return item
    def verify(self,value):
        assert value['birth']['creator_operation_id']==self.operation
        calls.append(self.operation);return self.operation
    monkeypatch.setattr(VMResourcePreflight,'__call__',verify)
    first,second=capability('first'),capability('second')
    registry.register(first);registry.register(second)
    assert registry(dict(birth=dict(creator_operation_id='first')))=='first'
    assert registry(dict(birth=dict(creator_operation_id='second')))=='second'
    assert calls==['first','second']
    with pytest.raises(RuntimeErrorBase,match='not registered'):
        registry(dict(birth=dict(creator_operation_id='foreign')))
    with pytest.raises(RuntimeErrorBase,match='cannot change'):registry.register(capability('first'))
    assert registry.register(first) is first
