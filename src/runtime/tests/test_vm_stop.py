"""Explicit hypervisor stop remains distinct from guest shutdown; effects inert."""
from copy import deepcopy
import os
import select

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_shutdown import VMShutdownDriver, VMStopDriver, stopped_proof
from dnlab_runtime.qemu_process import QEMUExitWitness
from test_vm_tap_handoff_shutdown import stopped, handed, local, kernel, definition, template, instance, monitor_case


@pytest.fixture
def stop(stopped, monkeypatch):
    s = stopped
    domain = s.e.handoff.definitions.connection.lookupByUUIDString(s.running['birth']['uuid'])
    state = dict(calls=[],auto_exit=True,lost=False,method='libvirt-sigterm',explicit=True,reason=2)
    def policy(value):
        return dict(method=state['method'],template_sha256=value['birth']['template_sha256'],
                    policy_sha256='b'*64,explicit=state['explicit'])
    driver = VMStopDriver(s.e.driver,capability=policy)
    def finish():
        s.finish();s.state['reason'] = state['reason']
    def request(self, flags):
        assert flags == 1 and driver.read(s.id)['phase'] == 'requested'
        state['calls'].append(flags)
        if state['auto_exit']:finish()
        if state['lost']:raise OSError('lost explicit Stop VD response')
        return 0
    monkeypatch.setattr(type(domain),'destroyFlags',request,raising=False)
    # Any ACPI fallback would be a test failure, not a successful stop.
    monkeypatch.setattr(type(domain),'shutdownFlags',lambda *args:pytest.fail('unexpected NOS shutdown'))
    s.nos_driver,s.driver = s.driver,driver
    s.stop_state,s.stop_finish = state,finish
    return s


def test_explicit_stop_uses_graceful_flag_once_and_preserves_taps(stop):
    s = stop;e = s.e
    original_taps = deepcopy(e.taps.read(e.operation))
    s.driver.prepare(s.id,e.operation,s.witness)
    result = s.driver.apply(s.id,s.witness)
    assert result['phase'] == 'completed'
    assert result['proof']['kind'] == 'explicit-qemu-stop-v1'
    assert result['proof']['reason'] == 'hypervisor-stop'
    assert result['proof']['guest_shutdown_verified'] is False
    assert e.taps.observe(e.operation) == original_taps
    assert stopped_proof(e.handoff.definitions,s.running) == result['proof']
    assert s.driver.apply(s.id) == result and s.stop_state['calls'] == [1]
    assert s.state['calls'] == 0  # no ACPI action


def test_pending_stop_never_repeats_or_escalates_the_request(stop):
    s = stop;s.stop_state['auto_exit'] = False
    s.driver.prepare(s.id,s.e.operation,s.witness)
    assert s.driver.apply(s.id,s.witness)['phase'] == 'requested'
    assert s.driver.apply(s.id,s.witness)['phase'] == 'requested'
    assert s.stop_state['calls'] == [1]
    s.stop_finish()
    assert s.driver.apply(s.id,s.witness)['phase'] == 'completed'
    assert s.stop_state['calls'] == [1]


def test_lost_stop_response_recovers_original_exit_without_second_request(stop):
    s = stop;s.stop_state['lost'] = True
    s.driver.prepare(s.id,s.e.operation,s.witness)
    with pytest.raises(OSError,match='lost explicit'):s.driver.apply(s.id,s.witness)
    assert s.driver.read(s.id)['phase'] == 'requested'
    assert s.driver.apply(s.id,s.witness)['phase'] == 'completed'
    assert s.stop_state['calls'] == [1]


@pytest.mark.parametrize('reason',[0,1,3])
def test_unexpected_exit_reason_is_not_reclassified_as_explicit_stop(stop, reason):
    s = stop;s.stop_state['reason'] = reason
    s.driver.prepare(s.id,s.e.operation,s.witness)
    with pytest.raises(RuntimeErrorBase):s.driver.apply(s.id,s.witness)
    assert s.driver.read(s.id)['phase'] == 'requested' and s.stop_state['calls'] == [1]


@pytest.mark.parametrize('explicit',[False,1])
def test_policy_must_be_explicit_before_any_request(stop, explicit):
    s = stop;s.stop_state['explicit'] = explicit
    with pytest.raises(RuntimeErrorBase,match='explicit original'):s.driver.prepare(s.id,s.e.operation,s.witness)
    assert s.stop_state['calls'] == []


def test_nos_driver_cannot_adopt_an_explicit_stop_record(stop):
    s = stop;s.driver.prepare(s.id,s.e.operation,s.witness)
    with pytest.raises(RuntimeErrorBase,match='no fallback'):s.nos_driver.read(s.id)
    assert s.stop_state['calls'] == []


def test_pending_nos_shutdown_cannot_be_implicitly_replaced(stop):
    s = stop;s.nos_driver.prepare(s.id,s.e.operation,s.witness)
    with pytest.raises(RuntimeErrorBase,match='no replacement'):
        s.driver.prepare('e'*32,s.e.operation,s.witness)
    assert s.stop_state['calls'] == []
    assert s.nos_driver.read(s.id)['capability']['method'] == 'acpi'


def test_policy_changed_after_prepare_blocks_stop_request(stop):
    s = stop;s.driver.prepare(s.id,s.e.operation,s.witness)
    s.stop_state['explicit'] = False
    with pytest.raises(RuntimeErrorBase,match='qualification changed'):
        s.driver.apply(s.id,s.witness)
    assert s.stop_state['calls'] == []


def test_stop_then_definition_and_tap_retirement_share_original_exit(stop, monkeypatch):
    from test_vm_tap_handoff_retirement import cleanup as cleanup_fixture
    pipeline = cleanup_fixture.__wrapped__(stop,monkeypatch)
    try:
        driver,s,_,_ = next(pipeline)
        assert driver.apply('remove-transferred')['phase'] == 'removed'
        assert s.e.state['links'] == {} and s.stop_state['calls'] == [1]
        assert s.state['calls'] == 0
    finally:
        pipeline.close()


def test_original_monitored_paused_boot_can_stop_without_resuming_guest(handed, monkeypatch):
    e = handed
    def pause(value):raise OSError('synthetic hold before CPU resume')
    monkeypatch.setattr(e.driver,'_before_resume',pause)
    with pytest.raises(OSError,match='hold before CPU resume'):e.driver.apply(e.operation)
    original = e.handoff.definitions.read(e.operation)
    assert original['boot']['phase'] == 'monitored_paused' and e.boot['resumes'] == 0
    state = dict(alive=True,calls=0)
    domain = e.handoff.definitions.connection.lookupByUUIDString(original['birth']['uuid'])
    monkeypatch.setattr(type(domain),'state',lambda self,flags:(3,0) if state['alive'] else (5,2))
    e.taps.writers = lambda value:[deepcopy(original['boot']['process_record'])] if state['alive'] else []
    previous = e.taps.preflight
    def resources(value):
        result = previous(value);result['guest_writers_absent'] = not state['alive'];return result
    e.taps.preflight = resources
    fd = os.open('/dev/null',os.O_RDONLY | os.O_CLOEXEC)
    class Poll:
        def poll(self, timeout):return [] if state['alive'] else [(fd,select.POLLIN | select.POLLHUP)]
    def verify():
        assert state['alive'];return deepcopy(original['boot']['process_record']['process'])
    witness = QEMUExitWitness(original['boot']['process_record'],verify=verify,context=lambda:None,poll=Poll(),fd=fd)
    driver = VMStopDriver(e.driver,capability=lambda value:dict(method='libvirt-sigterm',explicit=True,
        template_sha256=value['birth']['template_sha256'],policy_sha256='b'*64))
    def stop_vm(self, flags):
        assert flags == 1;state.update(alive=False,calls=state['calls']+1);domain.active=0;return 0
    monkeypatch.setattr(type(domain),'destroyFlags',stop_vm,raising=False)
    try:
        driver.prepare('f'*32,e.operation,witness)
        assert e.handoff.read(e.operation)['phase'] == 'acquired'
        result = driver.apply('f'*32,witness)
        assert result['phase'] == 'completed' and not result['proof']['guest_shutdown_verified']
        assert e.handoff.definitions.read(e.operation)['boot']['phase'] == 'monitored_paused'
        assert e.boot['resumes'] == 0 and state['calls'] == 1
    finally:
        witness._active = False;os.close(fd)
