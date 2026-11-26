"""Actual session/observer composition; every service/filesystem provider is inert."""
from copy import deepcopy
from types import SimpleNamespace
import pytest

import image_build_prepare as module
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process

@pytest.fixture
def prepared(executor,monkeypatch):
    hold,operation,state,native,commands,adapter=executor
    observer=adapter.observation
    receipt=dict(synthetic=True,owner=observer.profile['actor'])
    native['ledger']['ledger_sha256']=fingerprint(receipt)
    calls=[]
    def captured_binding(**kwargs):
        calls.append('binding');assert kwargs['original_actor']==observer.profile['actor'];return deepcopy(receipt)
    def captured_ledger(**kwargs):
        calls.append('ledger');assert kwargs['original_actor']==observer.profile['actor'];return deepcopy(receipt)
    monkeypatch.setattr(module,'LinuxProcess',lambda:observer.process)
    monkeypatch.setattr(module,'ImageBuildNamespaceQuery',lambda *args,**kw:observer.query)
    monkeypatch.setattr(module,'ImageBuildEngine',lambda cid:adapter.engine)
    monkeypatch.setattr(module,'capture_binding',captured_binding)
    monkeypatch.setattr(module,'capture_ledger',captured_ledger)
    monkeypatch.setattr(module,'ImageBuildBinding',lambda *args,**kw:observer.binding)
    monkeypatch.setattr(module,'JobLedger',lambda *args,**kw:observer.ledger)
    wiring={}
    def activity(*args,**kwargs):
        wiring.update(kwargs);return observer.activity
    monkeypatch.setattr(module,'ImageBuildActivity',activity)
    proof=dict(valid=True)
    kwargs=dict(api=observer.api,expected_inspect=deepcopy(native['inspect']),
        expected_capture=deepcopy(native['capture']),expected_context=deepcopy(native['context']),
        expected_copies=deepcopy(observer.profile['copies']),expected_binding=deepcopy(native['binding']),
        runtime=commands.runtime,read_context=observer.context,verify_original=lambda:proof['valid'],
        paths={},identities={},container_log_dir='/synthetic/logs',checkout='/synthetic/vrnetlab',
        lock_sha256='a'*64,proc_identity={},build_roots=['/synthetic'],
        scope=hold.read(operation)['scope'],window=hold.window,cleanup=hold.cleanup,
        shell_asset=dict(container_id=observer.profile['actor']['container_id'],image_id=observer.profile['actor']['image_id'],
                         path='/usr/bin/dash',sha256='d'*64),record_activity=lambda evidence:None)
    return SimpleNamespace(module=module,kwargs=kwargs,calls=calls,state=state,native=native,proof=proof,
                           operation=operation,adapter=adapter,wiring=wiring)

def test_readonly_preparation_builds_real_session_without_service_actions(prepared):
    e=prepared;result=e.module.prepare_session(**e.kwargs)
    assert result.observation['running'] is True
    assert result.profile['ledger_sha256']==fingerprint(result.ledger)
    assert result.session.profile==result.profile
    assert e.calls==['binding','ledger'] and e.state['actions']==[]
    assert e.wiring['record'] is e.kwargs['record_activity']
    assert e.wiring['qualify_healthcheck'] is result.healthcheck
    assert result.session.hold.journal.db.execute(
        'SELECT COUNT(*) FROM image_build_control_commands').fetchone()[0]==0

@pytest.mark.parametrize('fault',['source','process','generation','original'])
def test_original_conflicts_stop_before_receipt_capture_or_service_effects(prepared,fault):
    e=prepared
    if fault=='source':e.kwargs['expected_copies'][next(iter(e.kwargs['expected_copies']))]='2'*64
    elif fault=='process':e.native['capture']['process']['start_ticks']='replacement'
    elif fault=='generation':e.native['inspect']['State']['StartedAt']='replacement'
    else:e.proof['valid']=False
    with pytest.raises(TemplateError):e.module.prepare_session(**e.kwargs)
    assert e.calls==[] and e.state['actions']==[]


def test_durable_activity_writer_is_mandatory_before_preparation(prepared):
    e=prepared;e.kwargs['record_activity']=None
    with pytest.raises(TemplateError,match='diagnostic writer'):e.module.prepare_session(**e.kwargs)
    assert e.calls==[] and e.state['actions']==[]


def test_healthcheck_generation_provider_reads_pending_original_start_checkpoint(prepared,monkeypatch):
    e=prepared;result=e.module.prepare_session(**e.kwargs);driver=result.session
    driver.executor.term=e.adapter.term
    assert driver.acquire(e.operation)['held'] is True
    e.state['cleanup']=True;start=driver.executor.engine.start
    def busy():
        start();e.native['activity']=False
    monkeypatch.setattr(driver.executor.engine,'start',busy)
    with pytest.raises(TemplateError,match='activity'):driver.restore(e.operation)
    hold=driver.hold.read(e.operation);reference=hold['actions']['start']['reference']
    saved=driver.commands.qualified_snapshot(reference)
    assert saved['outcome'] is None
    assert result.healthcheck.startup(hold)==saved['start_progress']
    e.native['activity']=True
    assert driver.restore(e.operation,recover=True)['phase']=='restored'
    completed=driver.hold.read(e.operation)
    assert result.healthcheck.startup(completed)==saved['start_progress']
    assert e.state['actions'].count('start')==1
    corrupt=driver.commands._read(reference);corrupt['details']['startup']['generation']['started_at']='foreign'
    driver.commands._save(corrupt)
    with pytest.raises(TemplateError,match='completed startup proof differs'):
        result.healthcheck.startup(completed)


def test_unknown_start_ack_never_creates_healthcheck_generation_proof(prepared):
    e=prepared;result=e.module.prepare_session(**e.kwargs);driver=result.session
    driver.executor.term=e.adapter.term
    driver.acquire(e.operation);e.state.update(cleanup=True,fault='start_lost')
    with pytest.raises(OSError,match='lost start ACK'):driver.restore(e.operation)
    hold=driver.hold.read(e.operation)
    with pytest.raises(TemplateError,match='durable start acknowledgement'):result.healthcheck.startup(hold)
    assert e.state['actions'].count('start')==1
