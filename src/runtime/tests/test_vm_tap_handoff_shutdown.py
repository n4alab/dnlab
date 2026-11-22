"""Handoff and shutdown composition with inert TUN/SDK/pidfd effects."""
from copy import deepcopy
import os
import select
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict, RuntimeErrorBase
from dnlab_runtime.qemu_process import QEMUExitWitness
from dnlab_runtime.vm_shutdown import VMShutdownDriver
from test_vm_tap_handoff import handed, local, kernel, definition, template, instance, monitor_case
from test_vm_tap_link_events import packet


@pytest.fixture
def stopped(handed, monkeypatch):
    e = handed;running = e.driver.apply(e.operation)
    domain = e.handoff.definitions.connection.lookupByUUIDString(running['birth']['uuid'])
    state = dict(calls=0, reason=0, exited=False, foreign=False, reads_at_exit=None, after=None)
    fd = os.open('/dev/null',os.O_RDONLY | os.O_CLOEXEC)
    class Poll:
        def poll(self, timeout):
            assert timeout == 0
            return [(fd,select.POLLIN | select.POLLHUP)] if state['exited'] else []
    def verify():
        if state['exited']:raise Conflict('synthetic original QEMU exited')
        return deepcopy(running['boot']['process_record']['process'])
    witness = QEMUExitWitness(running['boot']['process_record'],verify=verify,
                              context=lambda:None,poll=Poll(),fd=fd)
    def writers(value):
        if state['foreign']:return [{'foreign':True}]
        return [] if state['exited'] else [deepcopy(running['boot']['process_record'])]
    e.taps.writers = writers
    previous = e.taps.preflight
    def preflight(value):
        result = previous(value);result['guest_writers_absent'] = not bool(writers(value))
        return result
    e.taps.preflight = preflight
    monkeypatch.setattr(type(domain),'state',lambda self,flags:(e.boot['cpu'],state['reason']))
    driver = VMShutdownDriver(e.driver,capability=lambda value:dict(method='acpi',
        template_sha256=value['birth']['template_sha256'],qualification_sha256='a'*64,qualified=True))
    shutdown_id = 'c'*32
    def finish():
        domain.active = 0;e.boot['cpu'] = 5
        state.update(reason=1,exited=True,reads_at_exit=e.control['reads'])
        e.control['descriptors'] = False  # a dead QEMU can no longer satisfy this observer
        source = e.handoff.read(e.operation)['tap_set']['items'][0]['spec']['tap']
        e.events['queue'].append(packet(name=source['name'],index=source['ifindex']))
    def request(self, flags):
        assert flags == 1 and driver.read(shutdown_id)['phase'] == 'requested'
        state['calls'] += 1;finish()
        if state['after']:state['after']()
        return 0
    monkeypatch.setattr(type(domain),'shutdownFlags',request,raising=False)
    recorder = e.handoff.monitor.record
    def record(value):
        if value['phase'] == 'events':
            assert not e.handoff.journal.db.in_transaction, 'event consumption nested in SQL publication'
        recorder(value)
    e.handoff.monitor.record = record
    try:
        yield SimpleNamespace(e=e,driver=driver,id=shutdown_id,witness=witness,state=state,finish=finish,running=running)
    finally:
        witness._active = False;os.close(fd)


def test_original_shutdown_publishes_without_observing_dead_qemu_fds(stopped):
    s = stopped;e = s.e
    s.driver.prepare(s.id,e.operation,s.witness)
    result = s.driver.apply(s.id,s.witness)
    assert result['phase'] == 'completed' and result['proof']['reason'] == 'guest-shutdown'
    assert e.taps.observe(e.operation)['phase'] == 'retained'
    assert e.control['reads'] == s.state['reads_at_exit']
    assert s.driver.apply(s.id) == result and s.state['calls'] == 1
    assert all(device._fd is None for device in e.devices)
    assert e.handoff.read(e.operation)['phase'] == 'acquired'


def test_process_absence_without_committed_shutdown_does_not_qualify_taps(stopped):
    s = stopped;s.driver.prepare(s.id,s.e.operation,s.witness)
    s.finish()
    with pytest.raises(RuntimeErrorBase,match='verified shutdown'):
        s.e.taps.observe(s.e.operation)
    assert s.driver.read(s.id)['phase'] == 'prepared' and s.state['calls'] == 0


def test_foreign_writer_rolls_back_shutdown_completion_and_retry_sends_no_acpi(stopped):
    s = stopped;s.driver.prepare(s.id,s.e.operation,s.witness)
    s.state['after'] = lambda:s.state.update(foreign=True)
    with pytest.raises(RuntimeErrorBase):s.driver.apply(s.id,s.witness)
    assert s.driver.read(s.id)['phase'] == 'requested' and s.state['calls'] == 1
    s.state['foreign'] = False
    assert s.driver.apply(s.id,s.witness)['phase'] == 'completed'
    assert s.state['calls'] == 1 and s.e.control['reads'] == s.state['reads_at_exit']


def test_monitor_loss_after_exit_preserves_pending_shutdown(stopped):
    s = stopped;s.driver.prepare(s.id,s.e.operation,s.witness)
    s.state['after'] = s.e.handoff.monitor.close
    with pytest.raises(RuntimeErrorBase):s.driver.apply(s.id,s.witness)
    assert s.driver.read(s.id)['phase'] == 'requested'
    assert s.state['calls'] == 1 and s.e.handoff.read(s.e.operation)['phase'] == 'acquired'
