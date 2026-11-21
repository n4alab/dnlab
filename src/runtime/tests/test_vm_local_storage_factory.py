"""Original controller/actor wiring; formatter, filesystem and TUN are inert."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_local_storage_factory import VMLocalStorageFactory
from test_vm_directory_storage import storage as storage_fixture, directories, definition, template, instance
from test_vm_tap_local import local as local_fixture, kernel


@pytest.fixture
def factory(directories,definition,template,kernel,monkeypatch):
    directory,definitions,birth,_,_,_ = directories;operation = birth['creator_operation_id']
    local_definition = (definitions,birth,definitions.read(operation)['xml'],definition[3],definition[4],definition[5])
    lease = local_fixture.__wrapped__(local_definition,kernel)
    taps,endpoints,_,actor,devices,_,_ = next(lease)
    lower = storage_fixture.__wrapped__(directories,template,monkeypatch)
    state = dict(epoch={'id':'f'*32},profiles=True,assets=True,writers=[],references=0)
    def reference(command):
        assert command == actor['command'];state['references'] += 1
        return deepcopy(actor['reference'])
    runtime = SimpleNamespace(journal=definitions.journal,check=lambda:deepcopy(state['epoch']),
        reference=reference,verify=lambda ref,command:ref==actor['reference'] and command==actor['command'])
    writers = lambda value:deepcopy(state['writers']);taps.writers = writers
    class Assets:
        def __call__(self,value):return self.verify(birth=value['birth'],template=value['template'],bundle_root=value['bundle_root'])
        def verify(self,**request):return dict(template_sha256=birth['template_sha256'],assets_verified=state['assets'])
    formatter = dict(python=dict(path='/usr/bin/python3.13',sha256='a'*64),
                     worker=dict(path='/qualified/tools/vm_overlay_worker_main.py',sha256='b'*64))
    binary = dict(path='/usr/bin/qemu-img',sha256='c'*64)
    def verify(profile,image):
        return fingerprint(dict(formatter=profile,binary=image)) if state['profiles'] else '0'*64
    driver = VMLocalStorageFactory(directory,taps,runtime,assets=Assets(),writers=writers,
        formatter=formatter,binary=binary,verify_formatter=verify)
    try:yield SimpleNamespace(driver=driver,operation=operation,state=state,actor=actor,files=lower[2],devices=devices)
    finally:lease.close()


def test_original_storage_and_actor_are_reused_without_spawning_taps_or_workers(factory):
    e = factory;storage = e.driver(e.operation)
    assert e.driver(e.operation) is storage and e.devices == []
    prepared = storage.prepare(e.operation,storage.read(e.operation)['template'],'/templates/synthetic')
    ready = storage.apply(e.operation)
    assert ready['phase'] == 'ready' and prepared['phase'] == 'prepared'
    assert e.driver(e.operation) is storage and storage.apply(e.operation) == ready
    assert e.files['creates'] == 1 and e.state['references'] > 1
    assert e.devices == []


@pytest.mark.parametrize('fault',['epoch','profile','assets','writer'])
def test_changed_prerequisites_stop_before_first_overlay_create(factory,fault):
    e = factory;storage = e.driver(e.operation)
    if fault == 'epoch':e.state['epoch']['id'] = 'e'*32
    elif fault == 'profile':e.state['profiles'] = False
    elif fault == 'assets':e.state['assets'] = False
    else:e.state['writers'] = [{'foreign':True}]
    with pytest.raises(RuntimeErrorBase):storage.apply(e.operation)
    assert e.files['creates'] == 0 and e.devices == []


def test_lost_original_actor_is_not_replaced_by_storage_factory(factory):
    e = factory;e.actor['actor_alive'] = False
    with pytest.raises(RuntimeErrorBase):e.driver(e.operation)
    assert e.files['creates'] == 0 and e.devices == []


def test_mutated_formatter_profile_is_not_used_for_new_storage(factory):
    e = factory;e.driver.formatter['worker']['sha256'] = 'd'*64
    with pytest.raises(RuntimeErrorBase,match='prerequisites'):e.driver(e.operation)
    assert e.files['creates'] == 0 and e.state['references'] == 0


def test_original_tap_provider_cannot_be_replaced(factory):
    e = factory;e.driver.taps.endpoints = object()
    with pytest.raises(RuntimeErrorBase,match='prerequisites'):e.driver(e.operation)
    assert e.files['creates'] == 0 and e.state['references'] == 0
