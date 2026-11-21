"""Full boot/creation/proc/storage pipeline, with inert host and SDK effects."""
from copy import deepcopy
import select
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.backend_reservations import available
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.vm_shutdown import VMShutdownDriver, stopped_proof
from dnlab_runtime.vm_writer_census import SessionWriterCensus, UNITS
from test_vm_creation_event_binding import pipeline, event_boot, creation, process, observer, boot, definition, template, instance
from test_vm_storage import make_storage
from test_vm_taps import taps as taps_fixture
from test_vm_boot import boot as boot_fixture


@pytest.fixture
def boot(definition,monkeypatch):
    taps=taps_fixture.__wrapped__(definition)
    taps[0].apply(taps[1]['id'])
    value=boot_fixture.__wrapped__(definition,monkeypatch)
    value[0].definitions._synthetic_taps=taps
    return value


@pytest.fixture
def shutdown(pipeline,template,monkeypatch):
    p=pipeline;e=p.events;definitions=p.driver.definitions
    storage,_,files,_,_=make_storage(definitions,e.original['birth'],template);storage.apply(e.operation)
    record=deepcopy(p.kernel.record);record['gid']=1001
    session=definitions.session.profile
    services={unit:dict(pid=i,start_ticks=i+100,boot_id=definitions.session.proof()['daemon']['boot_id'],
        namespaces=deepcopy(record['namespaces']),pidfd_alive=True,uids=[session['uid']]*4,
        gids=[session['gid']]*4,groups=[],executable_sha256='e'*64,argv=['synthetic'],environment={})
        for i,unit in enumerate(UNITS,10)}
    control=dict(calls=0,auto_exit=True,lost_ack=False,witness=None,after_effect=None,extra=[],qualified=True)
    def inventory():
        rows=[{key:value[key] for key in ('pid','uids','gids','groups')} for value in services.values()]
        if e.state['domains'][e.original['birth']['uuid']].isActive():
            rows.append(dict(pid=record['process']['pid'],uids=[record['uid']]*4,gids=[record['gid']]*4,groups=[]))
        return deepcopy(rows+control['extra'])
    storage.writers=SessionWriterCensus(definitions,inventory=inventory,services=services,
        observe_services=lambda:deepcopy(services),observer=p.driver.observer)
    taps,_,tapstate,_,_,_,_=definitions._synthetic_taps
    taps.writers=storage.writers;host=taps.preflight
    def host_preflight(value):
        result=host(value);result['guest_writers_absent']=not bool(storage.writers(value));return result
    taps.preflight=host_preflight
    original=definitions.preflight
    def resources(value):
        storage.observe(e.operation);taps.observe(e.operation)
        return original(value)
    definitions.preflight=resources
    running=p.driver.apply(e.operation)
    def capability(value):
        return dict(method='acpi',template_sha256=value['birth']['template_sha256'],
                    qualification_sha256='a'*64,qualified=control['qualified'])
    driver=VMShutdownDriver(p.driver,capability=capability);operation='d'*32
    domain=e.state['domains'][running['birth']['uuid']]
    e.state['shutdown_reason']=0
    monkeypatch.setattr(type(domain),'state',lambda self,flags:(e.state['cpu'],e.state['shutdown_reason']))
    def finish():
        domain.active=0;e.state.update(cpu=5,shutdown_reason=1)
        p.kernel.state['events']=[(control['witness']._fd,select.POLLIN|select.POLLHUP)]
    def request(self,flags):
        assert flags==1 and driver.read(operation)['phase']=='requested'
        assert driver.read(operation)['proof'] is None
        control['calls']+=1
        if control['auto_exit']:finish()
        if control['after_effect']:control['after_effect']()
        if control['lost_ack']:raise OSError('lost ACPI reply')
        return 0
    monkeypatch.setattr(type(domain),'shutdownFlags',request,raising=False)
    return SimpleNamespace(driver=driver,operation=operation,p=p,running=running,storage=storage,
        files=files,taps=taps,tapstate=tapstate,control=control,finish=finish,process=p.driver._observer(running).process)


def test_shutdown_publishes_original_exit_before_writer_absence_is_accepted(shutdown):
    e=shutdown
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness']=witness
        prepared=e.driver.prepare(e.operation,e.p.events.operation,witness)
        assert prepared['phase']=='prepared' and e.control['calls']==0
        result=e.driver.apply(e.operation,witness)
        assert result['phase']=='completed' and result['proof']['exit']['reference']==prepared['witness']
        assert e.storage.observe(e.p.events.operation)['phase']=='ready'
        assert e.storage.writers(e.storage.read(e.p.events.operation))==[]
        assert e.taps.observe(e.p.events.operation)['phase']=='retained'
    descriptors=len(e.p.kernel.state['fds'])
    assert e.driver.apply(e.operation)==result
    assert len(e.p.kernel.state['fds'])==descriptors and e.control['calls']==1
    assert e.files['creates']==1 and e.p.events.state['starts']==e.p.events.state['resumes']==1
    assert e.p.driver.definitions.read(e.p.events.operation)==e.running


def test_requested_shutdown_only_observes_and_never_resends(shutdown):
    e=shutdown;e.control['auto_exit']=False
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness']=witness;e.driver.prepare(e.operation,e.p.events.operation,witness)
        assert e.driver.apply(e.operation,witness)['phase']=='requested'
        assert e.driver.apply(e.operation,witness)['phase']=='requested'
        assert e.control['calls']==1
        e.finish()
        assert e.driver.apply(e.operation,witness)['phase']=='completed' and e.control['calls']==1


def test_lost_reply_recovers_original_exit_without_second_acpi(shutdown):
    e=shutdown;e.control['lost_ack']=True
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness']=witness;e.driver.prepare(e.operation,e.p.events.operation,witness)
        with pytest.raises(OSError,match='lost ACPI'):e.driver.apply(e.operation,witness)
        assert e.driver.read(e.operation)['phase']=='requested' and e.driver.read(e.operation)['request_ack'] is None
        result=e.driver.apply(e.operation,witness)
        assert result['phase']=='completed' and result['request_ack'] is None and e.control['calls']==1


@pytest.mark.parametrize('fault',['overlay','writer','tap'])
def test_conflict_rolls_back_exit_publication_and_preserves_resources(shutdown,fault):
    e=shutdown;path=next(iter(e.files['files']));original=deepcopy(e.files['files'][path])
    tapname=next(iter(e.tapstate['proofs']));tap=deepcopy(e.tapstate['proofs'][tapname])
    def change():
        if fault=='overlay':e.files['files'][path]['identity']['inode']+=1
        elif fault=='writer':e.control['extra']=[dict(pid=60000,uids=[1001]*4,gids=[1001]*4,groups=[])]
        else:e.tapstate['proofs'][tapname]['worker_reference_sha256']='e'*64
    e.control['after_effect']=change
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness']=witness;e.driver.prepare(e.operation,e.p.events.operation,witness)
        with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation,witness)
        assert e.driver.read(e.operation)['phase']=='requested' and e.driver.read(e.operation)['proof'] is None
        assert e.control['calls']==1 and e.files['creates']==1
        e.files['files'][path]=original;e.control['extra']=[];e.tapstate['proofs'][tapname]=tap
        assert e.driver.apply(e.operation,witness)['phase']=='completed'
        assert e.control['calls']==1


def test_unqualified_template_is_rejected_without_request(shutdown):
    e=shutdown;e.control['qualified']=False
    with e.process.exit_witness(e.running['birth']) as witness:
        with pytest.raises(RuntimeErrorBase,match='qualified original template'):
            e.driver.prepare(e.operation,e.p.events.operation,witness)
    assert e.control['calls']==0
    assert e.driver.journal.db.execute('SELECT count(*) FROM vm_shutdown_intents').fetchone()[0]==0


def test_pending_shutdown_cannot_replace_its_original_pidfd_lease(shutdown):
    e=shutdown;e.control['auto_exit']=False
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness']=witness;e.driver.prepare(e.operation,e.p.events.operation,witness)
        e.driver.apply(e.operation,witness)
        with e.process.exit_witness(e.running['birth']) as other:
            with pytest.raises(RuntimeErrorBase,match='no reacquisition'):e.driver.apply(e.operation,other)
        assert e.control['calls']==1
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.driver.read(e.operation)['phase']=='requested'


def test_second_shutdown_request_cannot_take_over_original_boot(shutdown):
    e=shutdown
    with e.process.exit_witness(e.running['birth']) as witness:
        original=e.driver.prepare(e.operation,e.p.events.operation,witness)
        with pytest.raises(RuntimeErrorBase,match='no replacement'):
            e.driver.prepare('e'*32,e.p.events.operation,witness)
        with pytest.raises(RuntimeErrorBase,match='another VM'):
            e.driver.prepare(e.operation,'e'*32,witness)
    assert e.driver.read(e.operation)==original and e.control['calls']==0


@pytest.mark.parametrize('qualified',[False,1])
def test_qualification_change_before_request_keeps_original_intent(shutdown,qualified):
    e=shutdown
    with e.process.exit_witness(e.running['birth']) as witness:
        e.driver.prepare(e.operation,e.p.events.operation,witness)
        e.control['qualified']=qualified
        with pytest.raises(RuntimeErrorBase,match='qualification changed'):e.driver.apply(e.operation,witness)
    assert e.driver.read(e.operation)['phase']=='prepared' and e.control['calls']==0


def test_ack_persistence_failure_retains_primary_error_and_original_exit(shutdown,monkeypatch):
    e=shutdown;write=e.driver._write
    def fail(value):
        if value['request_ack'] is not None:raise OSError('ACK persistence failed')
        if value['error_type']:raise RuntimeError('diagnostic persistence failed')
        return write(value)
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness']=witness;e.driver.prepare(e.operation,e.p.events.operation,witness)
        monkeypatch.setattr(e.driver,'_write',fail)
        with pytest.raises(OSError,match='ACK persistence failed') as caught:e.driver.apply(e.operation,witness)
        assert any('diagnostic persistence failed' in note for note in caught.value.__notes__)
        assert e.driver.read(e.operation)['phase']=='requested' and e.driver.read(e.operation)['request_ack'] is None
        monkeypatch.setattr(e.driver,'_write',write)
        assert e.driver.apply(e.operation,witness)['phase']=='completed' and e.control['calls']==1


def test_shutdown_authority_survives_missing_child_metadata(shutdown):
    e=shutdown;journal=e.driver.journal;birth=e.running['birth']
    with e.process.exit_witness(birth) as witness:
        value=e.driver.prepare(e.operation,e.p.events.operation,witness)
        # Synthetic corruption: the durable parent must independently prevent
        # a container takeover or metadata cleanup, even without child rows.
        tables=[row[0] for row in journal.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                if row[0].startswith('vm_') and row[0]!='vm_shutdown_intents']
        with journal.transaction():
            for table in tables:journal.db.execute('DROP TABLE '+table)
            journal.db.execute('DELETE FROM resources')
        with pytest.raises(RuntimeErrorBase):available(journal,birth['lab_id'],birth['node_id'],'docker')
        assert cleanup_inventory(journal,birth['lab_id'])['blocked']==['vm_shutdown_intents']
        assert e.driver.read(e.operation)==value and e.control['calls']==0
