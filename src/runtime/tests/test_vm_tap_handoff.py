"""Real TAP/boot controllers and journal; kernel, QEMU and descriptor reads inert."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_qemu_boot_factory import _QualifiedBoot
from dnlab_runtime.vm_tap_device import TUNSETIFF
from dnlab_runtime.vm_tap_handoff import HandoffTapEndpoints, VMTapHandoff
from test_vm_tap_local import local, kernel, definition, template, instance
from test_vm_tap_link_events import case as monitor_case, packet
from test_vm_boot import boot as boot_fixture


@pytest.fixture
def handed(local, monitor_case, definition, monkeypatch):
    taps, old, initial, state, devices, _, _ = local
    monitor, events = monitor_case
    monitor.runtime.journal = taps.journal
    # The source fixture has only journal intents; no device exists yet.
    assert not devices and all(i['phase'] == 'prepared' for i in initial['items'])
    def create(*args):
        device = old.device_factory(*args)
        ioctl = device.ioctl
        def observed(fd, command, value=None):
            result = ioctl(fd, command, value)
            if command == TUNSETIFF:
                events['queue'].append(packet(name=device.spec['name'], index=device.spec['ifindex']))
            return result
        device.ioctl = observed
        return device
    endpoints = HandoffTapEndpoints(taps.journal, monitor=monitor,
        read_context=old.read_context, inventory=old.inventory, verify_worker=old.verify_worker,
        device_factory=create, process_id=old.process_id)
    taps.endpoints = endpoints;endpoints.attach(taps)
    endpoints.bind(initial['id'],state['reference'])
    control = dict(descriptors=True, reads=0)
    class Descriptors:
        def __init__(self, process, *, verify_links):
            self.process,self.verify_links = process,verify_links
        def observe(self, names, scope):
            control['reads'] += 1
            assert self.verify_links(names,scope)['continuity_verified']
            if not control['descriptors']:raise Conflict('synthetic missing QEMU TAP FD')
            return dict(process_record_sha256=fingerprint(self.process.record),context_sha256=fingerprint(scope),
                        descriptors=[dict(name=name,fd=index+50) for index,name in enumerate(names)],continuity_verified=True)
    handoff = VMTapHandoff(taps,process_factory=lambda record:SimpleNamespace(record=record),
                           descriptors_factory=Descriptors)
    taps.apply(initial['id'])
    definitions = taps.definitions
    previous = definitions.preflight
    def resources(value):
        taps.observe(value['birth']['creator_operation_id'])
        return previous(value)
    definitions.preflight = resources
    original_preflight = taps.preflight
    def preflight(value):
        state['writer'] = definitions.read(value['id']).get('boot',{}).get('process_record') is not None
        return original_preflight(value)
    taps.preflight = preflight
    def writers(value):
        record = definitions.read(value['id']).get('boot',{}).get('process_record')
        return [] if record is None else [deepcopy(record)]
    taps.writers = writers
    base, operation, boot_state, _, _ = boot_fixture.__wrapped__(definition,monkeypatch)
    handoff.prepare(operation)
    driver = _QualifiedBoot(definitions,prerequisites=lambda:None,handoff=handoff,
        source=base.source,capture_started=base.capture_started,observer=base.observer)
    yield SimpleNamespace(handoff=handoff,driver=driver,operation=operation,state=state,
                          boot=boot_state,events=events,devices=devices,control=control,taps=taps)


def test_real_boot_closes_original_creators_then_acquires_before_resume(handed):
    e = handed
    original = deepcopy(e.taps.read(e.operation))
    assert all(device._fd is not None for device in e.devices)
    result = e.driver.apply(e.operation)
    assert result['boot']['phase'] == 'running'
    receipt = e.handoff.read(e.operation)
    assert receipt['phase'] == 'acquired' and all(i['phase'] == 'released' for i in receipt['items'])
    assert all(device._fd is None for device in e.devices)
    assert e.taps.read(e.operation) == original  # historic birth retained, not rewritten
    assert e.driver.apply(e.operation) == result
    assert e.boot['starts'] == e.boot['resumes'] == 1
    assert e.state['calls'].count(TUNSETIFF) == len(e.devices)


def test_missing_qemu_acquisition_keeps_guest_paused(handed):
    e = handed;e.control['descriptors'] = False
    with pytest.raises(RuntimeErrorBase,match='missing QEMU TAP FD'):
        e.driver.apply(e.operation)
    assert e.boot['starts'] == 1 and e.boot['resumes'] == 0 and e.boot['cpu'] == 3
    assert e.handoff.read(e.operation)['phase'] == 'released'
    e.control['descriptors'] = True
    assert e.driver.apply(e.operation)['boot']['phase'] == 'running'
    assert e.boot['starts'] == e.boot['resumes'] == 1


def test_lost_monitor_before_boot_leaves_all_creator_fds_open(handed):
    e = handed;e.handoff.monitor.close()
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.boot['starts'] == e.boot['resumes'] == 0
    assert all(device._fd is not None for device in e.devices)


def test_deleted_and_recreated_tap_never_reaches_start(handed):
    e = handed;tap = e.taps.read(e.operation)['items'][0]['spec']['tap']
    e.events['queue'] += [packet(kind=17,name=tap['name'],index=tap['ifindex']),
                         packet(name=tap['name'],index=tap['ifindex'])]
    with pytest.raises(RuntimeErrorBase,match='removed, renamed or replaced'):
        e.driver.apply(e.operation)
    assert e.boot['starts'] == e.boot['resumes'] == 0
    assert all(device._fd is not None for device in e.devices)


def test_generic_boot_cannot_bypass_explicit_handoff(handed):
    e = handed;e.driver.handoff = None
    with pytest.raises(RuntimeErrorBase,match='not released before boot'):
        e.driver.apply(e.operation)
    assert e.boot['starts'] == e.boot['resumes'] == 0
    assert all(device._fd is not None for device in e.devices)


def test_lost_close_receipt_save_reuses_original_ack_without_second_close(handed, monkeypatch):
    e = handed;save = e.handoff._save;failures = []
    def fail_once(value):
        if not failures and value['items'][0]['phase'] == 'released':
            failures.append(True)
            raise OSError('synthetic lost close publication')
        return save(value)
    monkeypatch.setattr(e.handoff,'_save',fail_once)
    with pytest.raises(OSError,match='lost close publication'):
        e.driver.apply(e.operation)
    pending = e.handoff.read(e.operation)
    assert pending['items'][0]['phase'] == 'close_requested'
    assert e.devices[0]._fd is None and len(e.handoff.closed) == 1
    assert e.boot['starts'] == e.boot['resumes'] == 0
    assert e.driver.apply(e.operation)['boot']['phase'] == 'running'
    assert len(e.handoff.closed) == len(e.devices)
    assert e.boot['starts'] == e.boot['resumes'] == 1
    assert e.state['calls'].count(TUNSETIFF) == len(e.devices)


def test_lost_acquisition_publication_never_restarts_qemu(handed, monkeypatch):
    e = handed;save = e.handoff._save;failures = []
    def fail_once(value):
        if value['phase'] == 'acquired' and not failures:
            failures.append(True)
            raise OSError('synthetic acquisition publication failure')
        return save(value)
    monkeypatch.setattr(e.handoff,'_save',fail_once)
    with pytest.raises(OSError,match='acquisition publication'):
        e.driver.apply(e.operation)
    assert e.handoff.read(e.operation)['phase'] == 'released'
    assert e.boot['starts'] == 1 and e.boot['resumes'] == 0 and e.boot['cpu'] == 3
    assert e.driver.apply(e.operation)['boot']['phase'] == 'running'
    assert e.boot['starts'] == e.boot['resumes'] == 1


def test_actor_changed_after_close_checkpoint_prevents_any_close(handed, monkeypatch):
    e = handed;save = e.handoff._save
    def changed(value):
        save(value)
        if value['items'][0]['phase'] == 'close_requested':
            e.state['actor_alive'] = False
    monkeypatch.setattr(e.handoff,'_save',changed)
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert all(device._fd is not None for device in e.devices) and not e.handoff.closed
    assert e.boot['starts'] == e.boot['resumes'] == 0
    # A checkpoint without the original close acknowledgement is uncertain,
    # even when the actor becomes observable again. Do not resend close.
    e.state['actor_alive'] = True
    with pytest.raises(RuntimeErrorBase,match='no repeated close'):
        e.driver.apply(e.operation)
    assert all(device._fd is not None for device in e.devices)


def test_old_retirement_lease_cannot_reopen_a_handed_off_descriptor(handed):
    e = handed;e.driver.apply(e.operation)
    item = e.taps.read(e.operation)['items'][0]
    with pytest.raises(RuntimeErrorBase,match='separate qualified retirement'):
        e.handoff.endpoints.retirement_lease(item,e.operation,preflight=lambda value:None)


def test_handoff_remains_in_backend_and_cleanup_inventory(handed):
    from dnlab_runtime.backend_reservations import vm_reservations
    from dnlab_runtime.inspection import cleanup_inventory
    e = handed;birth = e.handoff.read(e.operation)['birth']
    rows = vm_reservations(e.handoff.journal,birth['lab_id'],birth['node_id'])
    assert 'vm_tap_handoffs' in {row['table'] for row in rows}
    assert 'vm_tap_handoffs' in cleanup_inventory(e.handoff.journal,birth['lab_id'])['blocked']


def test_later_tap_configuration_conflict_blocks_all_creator_closes(handed):
    e = handed
    name = e.taps.read(e.operation)['items'][-1]['spec']['tap']['name']
    e.state['links'][name]['address'] = '02:00:00:00:00:ab'
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert all(device._fd is not None for device in e.devices)
    assert not e.handoff.closed and e.boot['starts'] == e.boot['resumes'] == 0


def test_management_fence_after_prepare_blocks_creator_close(handed):
    from test_vm_definition_fences import install_fence
    e = handed
    with e.handoff.journal.transaction():install_fence(e.handoff.journal,'held')
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert all(device._fd is not None for device in e.devices)
    assert not e.handoff.closed and e.boot['starts'] == e.boot['resumes'] == 0
