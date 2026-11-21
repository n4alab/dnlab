"""Factory wiring across event/QMP/kernel controllers, with inert providers."""
from copy import deepcopy
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_qemu_boot_factory import VMQEMUBootFactory
from test_vm_creation_event_binding import pipeline, event_boot, creation, process, observer, boot, definition, template, instance


@pytest.fixture
def factory(pipeline):
    p = pipeline;definitions = p.driver.definitions
    policy = deepcopy(p.kernel.policy);policy['gid'] = definitions.session.profile['gid']
    policy['boot_id'] = definitions.session.proof()['daemon']['boot_id']
    p.kernel.boot.write_text(policy['boot_id']+'\n')
    qemu = dict(path=ET.fromstring(p.events.original['xml']).findtext('devices/emulator'),sha256=policy['executable_sha256'])
    state = dict(binary=True,checks=0)
    def verify(value):
        assert value == qemu
        state['checks'] += 1
        return fingerprint(value) if state['binary'] else '0'*64
    def make(**changes):
        args = dict(qemu=qemu,policy=policy,verify_qemu=verify,
                    correlator=p.capture.correlator,process_factory=p.capture.process_factory)
        args.update(changes)
        return VMQEMUBootFactory(definitions,p.events.source,p.events.source.runtime,p.extension,**args)
    return SimpleNamespace(driver=make(),make=make,p=p,state=state,qemu=qemu,policy=policy)


def test_factory_reuses_original_boot_and_one_creation_receipt(factory):
    e = factory;operation = e.p.events.operation
    driver = e.driver(operation)
    assert e.driver(operation) is driver and e.p.events.state['starts'] == 0
    result = driver.apply(operation)
    assert result['boot']['phase'] == 'running'
    assert result['boot']['process_record']['process']['boot_id'] == e.policy['boot_id']
    assert driver.apply(operation) == result
    assert e.p.control == dict(queries=1,correlations=1)
    assert e.p.events.state['starts'] == e.p.events.state['resumes'] == 1
    assert e.state['checks'] > 1


@pytest.mark.parametrize('fault',['binary','policy','observer'])
def test_changed_qualified_inputs_prevent_vm_start(factory,fault):
    e = factory;driver = e.driver(e.p.events.operation)
    if fault == 'binary':e.state['binary'] = False
    elif fault == 'policy':e.driver.policy['minimum_start_ticks'] += 1
    else:e.p.events.source.observer = lambda *args:None
    with pytest.raises(RuntimeErrorBase,match='prerequisites'):driver.apply(e.p.events.operation)
    assert e.p.events.state['starts'] == 0 and e.p.control['queries'] == 0


def test_wrong_binary_boot_or_credentials_are_refused_before_wiring(factory):
    e = factory
    for key,value in (('uid',0),('gid',999),('boot_id','other'),('executable_sha256','f'*64)):
        policy = deepcopy(e.policy);policy[key] = value
        with pytest.raises(RuntimeErrorBase):e.make(policy=policy)
    assert e.p.events.state['starts'] == e.p.control['queries'] == 0


def test_lost_query_reply_is_not_reissued_by_factory(factory):
    e = factory;driver = e.driver(e.p.events.operation);monitor = e.p.extension.qemuMonitorCommand
    def lost(*args):monitor(*args);raise OSError('lost fixed QMP reply')
    e.p.extension.qemuMonitorCommand = lost
    with pytest.raises(OSError,match='lost fixed'):driver.apply(e.p.events.operation)
    with pytest.raises(RuntimeErrorBase):driver.recover_creation(e.p.events.operation)
    assert e.p.control['queries'] == 1 and e.p.events.state['starts'] == 1 and e.p.events.state['resumes'] == 0
