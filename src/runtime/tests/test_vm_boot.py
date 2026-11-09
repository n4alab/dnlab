"""Paused boot checkpoints with SDK and host providers entirely synthetic."""
from contextlib import contextmanager
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_observer import LibvirtDomainObserver, creation_reference
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_boot import VMBootDriver
from dnlab_runtime.vm_events import VMEventTracker
from dnlab_runtime.vm_template import TemplateError
from test_vm_definition import definition, template, instance
from test_vm_definition_fences import install_fence


@pytest.fixture
def boot(definition, monkeypatch):
    definitions, birth, xml, state, _, domain_type = definition
    operation = birth['creator_operation_id']
    original = definitions.apply(operation)
    domain = state['domains'][birth['uuid']]
    state.update(cpu=5, managed_save=0, starts=0, resumes=0, lost_start=False,
                 lost_resume=False, monitor_alive=True, receipts=[], armed=False)
    process = dict(boot_id='synthetic-boot', pid=1234, start_ticks=5678, executable_sha256='e'*64)

    class Process:
        @contextmanager
        def capture(self, observed_birth):
            assert observed_birth == birth
            yield deepcopy(process)

    def observe(reference, process_record):
        assert process_record['birth'] == birth
        assert fingerprint(process_record['process']) == reference['process_sha256']
        return LibvirtDomainObserver(definitions.connection, reference,
                                     xml_inactive_flag=2, process=Process())

    class Source:
        def arm(self, value):
            assert value['boot']['phase'] == 'arming_requested'
            assert definitions.read(operation)['boot'] == value['boot']
            assert domain.active == 0
            state['armed'] = True
            ack = dict(source_id=value['boot']['source_id'], collector_id='f'*32,
                       request_fingerprint=value['request_fingerprint'],
                       birth_sha256=fingerprint(birth), ready=True)
            state['receipts'].append(deepcopy(ack))
            return ack

        def activate(self, value):
            assert state['cpu'] == 3
            assert definitions.read(operation)['boot']['reference'] == value['boot']['reference']
            assert definitions.read(operation)['boot']['process_record'] == value['boot']['process_record']
            tracker = VMEventTracker(definitions.journal, driver.observer(value['boot']['reference'], value['boot']['process_record']))
            tracked = tracker.begin(value['boot']['source_id'], birth)
            assert tracked['guest_readiness'] == 'unknown'
            state['tracker'] = tracker
            ack = dict(source_id=value['boot']['source_id'], collector_id='f'*32,
                       reference_sha256=fingerprint(value['boot']['reference']),
                       process_record_sha256=fingerprint(value['boot']['process_record']), active=True)
            state['receipts'].append(deepcopy(ack))
            return ack

        def verify(self, receipt):
            return state['monitor_alive'] and receipt in state['receipts']

    def start(self, flags):
        assert flags == 1 and state['armed']
        assert definitions.read(operation)['boot']['phase'] == 'start_requested'
        state['starts'] += 1
        self.active = 1
        state['cpu'] = 3
        if state['lost_start']:raise OSError('lost start response')
        return 0

    def resume(self):
        saved = definitions.read(operation)['boot']
        assert saved['phase'] == 'resume_requested'
        assert saved['reference'] and saved['activation_ack']['active'] is True
        assert state['tracker'].read(saved['source_id'])['phase'] == 'active'
        state['resumes'] += 1
        state['cpu'] = 1
        if state['lost_resume']:raise OSError('lost resume response')
        return 0

    monkeypatch.setattr(domain_type, 'XMLDesc', lambda self, flag: self.xml)
    monkeypatch.setattr(domain_type, 'state', lambda self, flag: (state['cpu'], 0), raising=False)
    monkeypatch.setattr(domain_type, 'hasManagedSaveImage', lambda self, flag: state['managed_save'], raising=False)
    monkeypatch.setattr(domain_type, 'createWithFlags', start, raising=False)
    monkeypatch.setattr(domain_type, 'resume', resume, raising=False)

    def capture(value, current):
        assert current is domain and state['cpu'] == 3
        assert definitions.read(operation)['boot']['phase'] == 'start_requested'
        reference = creation_reference(birth, uri=state['uri'], persistent_xml=xml, live_xml=xml, process=process)
        record = dict(birth=deepcopy(birth), process=deepcopy(process), uid=1001, gid=1001,
                      cmdline_sha256='a'*64, namespaces={name:dict(device=4,inode=index)
                          for index,name in enumerate(('pid','mnt','net','user'),1)})
        return dict(reference=reference, process_record=record)

    driver = VMBootDriver(definitions, source=Source(), capture_started=capture, observer=observe)
    return driver, operation, state, process, original


def test_paused_boot_persists_original_process_and_events_before_resume(boot):
    driver, operation, state, process, original = boot
    result = driver.apply(operation)
    assert result['boot']['phase'] == 'running'
    assert result['birth'] == original['birth'] and result['lab_generation'] == original['lab_generation']
    assert result['request_fingerprint'] == original['request_fingerprint']
    assert result['boot']['process_record']['process'] == process
    assert driver.apply(operation) == result
    assert state['starts'] == state['resumes'] == 1
    assert state['calls'].count(('define',)) == 1


def test_lost_start_response_retains_paused_domain_without_second_start(boot):
    driver, operation, state, _, _ = boot
    state['lost_start'] = True
    with pytest.raises(OSError, match='lost start'):driver.apply(operation)
    saved = driver.definitions.read(operation)
    assert saved['boot']['phase'] == 'start_requested' and saved['boot']['recovery_required']
    assert saved['boot']['reference'] is None
    with pytest.raises(Conflict, match='not repeated'):driver.apply(operation)
    assert state['starts'] == 1 and state['resumes'] == 0 and state['cpu'] == 3
    assert len(state['domains']) == 1


def test_lost_resume_response_recovers_original_running_instance_readonly(boot):
    driver, operation, state, _, _ = boot
    state['lost_resume'] = True
    with pytest.raises(OSError, match='lost resume'):driver.apply(operation)
    saved = driver.definitions.read(operation)['boot']
    assert saved['phase'] == 'resume_requested' and saved['recovery_required']
    result = driver.apply(operation)
    assert result['boot']['phase'] == 'running'
    assert result['boot']['reference'] == saved['reference']
    assert state['starts'] == state['resumes'] == 1


def test_managed_save_is_not_discarded_or_restored_implicitly(boot):
    driver, operation, state, _, _ = boot
    state['managed_save'] = 1
    with pytest.raises(Conflict, match='managed save'):driver.apply(operation)
    assert state['starts'] == state['resumes'] == 0 and not state['armed']


@pytest.mark.parametrize('fault', ['monitor', 'process'])
def test_replay_refuses_replaced_process_or_lost_original_monitor(boot, fault):
    driver, operation, state, process, _ = boot
    saved = driver.apply(operation)
    if fault == 'monitor':state['monitor_alive'] = False
    else:process['start_ticks'] += 1
    expected_error = TemplateError if fault == 'monitor' else Conflict
    with pytest.raises(expected_error):driver.apply(operation)
    assert driver.definitions.read(operation)['boot']['reference'] == saved['boot']['reference']
    assert state['starts'] == state['resumes'] == 1


@pytest.mark.parametrize('stage', ['start_requested', 'resume_requested'])
@pytest.mark.parametrize('fence', ['closing', 'held'])
def test_checkpoint_fences_prevent_start_or_resume(boot, monkeypatch, stage, fence):
    driver, operation, state, _, _ = boot
    save = driver.definitions._save
    def checkpoint(identifier, value):
        save(identifier, value)
        if value.get('boot', {}).get('phase') == stage:
            install_fence(driver.journal, fence)
    monkeypatch.setattr(driver.definitions, '_save', checkpoint)
    with pytest.raises(Conflict):driver.apply(operation)
    saved = driver.definitions.read(operation)
    assert saved['boot']['phase'] == stage and saved['boot']['recovery_required']
    assert state['starts'] == (0 if stage == 'start_requested' else 1)
    assert state['resumes'] == 0


def test_crash_after_start_intent_never_repeats_start(boot, monkeypatch):
    driver, operation, state, _, _ = boot
    advance = driver._advance
    def checkpoint(identifier, before, after, **updates):
        result = advance(identifier, before, after, **updates)
        if after == 'start_requested':raise SystemExit('crash')
        return result
    monkeypatch.setattr(driver, '_advance', checkpoint)
    with pytest.raises(SystemExit):driver.apply(operation)
    monkeypatch.setattr(driver, '_advance', advance)
    assert driver.definitions.read(operation)['boot']['phase'] == 'start_requested'
    with pytest.raises(Conflict, match='not repeated'):driver.apply(operation)
    assert state['starts'] == 0 and state['resumes'] == 0
