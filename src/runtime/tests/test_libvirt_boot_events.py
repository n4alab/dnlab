"""SDK feed -> durable boot/event reducer; domains and loop are synthetic."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_boot_events import LibvirtBootEvents
from dnlab_runtime.manifest import RuntimeErrorBase
from test_vm_boot import boot, definition, template, instance


@pytest.fixture
def event_boot(boot,monkeypatch):
    driver,operation,state,process,original=boot
    journal=driver.journal;domain=state['domains'][original['birth']['uuid']]
    control=dict(epoch=dict(id='e'*32),clock=0.0,fail_ack=False,omit_started=False)
    class Feed:
        connection=driver.definitions.connection
        id='d'*32
        loop_sha256='f'*64
        sequence=0
        acknowledged=0
        lost=False
        queue=[]
        def read(self,after):
            if self.lost:raise OSError('original connection lost')
            assert self.acknowledged<=after<=self.sequence
            return dict(feed_id=self.id,loop_sha256=self.loop_sha256,
                        events=deepcopy([event for event in self.queue if event['sequence']>after]))
        def acknowledge(self,sequence):
            if control['fail_ack']:
                control['fail_ack']=False;raise OSError('ack response lost')
            if sequence>self.acknowledged:
                row=journal.db.execute('SELECT sequence FROM vm_libvirt_raw_events WHERE feed_id=? AND sequence=?',
                                       (self.id,sequence)).fetchone()
                assert row is not None, 'queue ack before durable commit'
            self.acknowledged=sequence
            self.queue=[event for event in self.queue if event['sequence']>sequence]
        def emit(self,event=None,detail=None,*,kind='lifecycle',uuid=None):
            self.sequence+=1
            self.queue.append(dict(sequence=self.sequence,uuid=uuid or original['birth']['uuid'],kind=kind,event=event,detail=detail))
    feed=Feed()
    def pause(seconds):control['clock']+=seconds
    source=LibvirtBootEvents(driver.definitions,feed,runtime=SimpleNamespace(check=lambda:deepcopy(control['epoch'])),
                            observer=driver.observer,clock=lambda:control['clock'],pause=pause,timeout=0.03)
    driver.source=source;state['tracker']=source.tracker
    domain_type=type(domain);start=domain_type.createWithFlags;resume=domain_type.resume
    def started(self,flags):
        saved=driver.definitions.read(operation)
        assert source.read(saved['boot']['source_id'])['phase']=='armed'
        assert source.verify(saved['boot']['source_ack'])
        # Bridge the inherited fake domain's old Source-specific marker to
        # the actual durable source acknowledgement tested here.
        state['armed']=True
        result=start(self,flags)
        if not control['omit_started']:
            feed.emit(2,0);feed.emit(3,0)
        return result
    def resumed(self):
        result=resume(self);feed.emit(4,0);return result
    monkeypatch.setattr(domain_type,'createWithFlags',started)
    monkeypatch.setattr(domain_type,'resume',resumed)
    return SimpleNamespace(driver=driver,source=source,operation=operation,state=state,process=process,
                           original=original,feed=feed,control=control)


def test_real_boot_contract_consumes_durable_feed_before_cpu_resume(event_boot):
    e=event_boot;result=e.driver.apply(e.operation);source_id=result['boot']['source_id']
    assert result['boot']['phase']=='running'
    saved=e.source.read(source_id)
    assert saved['phase']=='active' and saved['initial']==dict(started=1,paused=2,resumed=3)
    assert saved['cursor']==e.feed.acknowledged==3 and not e.feed.queue
    assert e.driver.apply(e.operation)==result
    e.feed.emit(kind='reboot')
    assert e.source.verify(result['boot']['activation_ack'])
    tracked=e.source.tracker.read(source_id)
    assert tracked['reboot_count']==1 and tracked['guest_readiness']=='unknown'
    assert tracked['original']['process']==e.process
    assert e.state['starts']==e.state['resumes']==1


def test_lost_queue_ack_resumes_committed_batch_without_duplicate_reboot(event_boot):
    e=event_boot;result=e.driver.apply(e.operation)
    e.feed.emit(kind='reboot');e.control['fail_ack']=True
    with pytest.raises(OSError,match='ack response'):e.source.verify(result['boot']['activation_ack'])
    assert e.source._feed()['cursor']==4 and e.feed.acknowledged==3
    assert e.source.verify(result['boot']['activation_ack'])
    assert e.source.tracker.read(result['boot']['source_id'])['reboot_count']==1
    assert e.feed.acknowledged==4 and not e.feed.queue


def test_lost_reduction_checkpoint_reuses_original_tracker_result(event_boot,monkeypatch):
    e=event_boot;result=e.driver.apply(e.operation);save=e.source._save;lost=[]
    def checkpoint(value):
        if value['tracker_sequence']==1 and not lost:
            lost.append(True);raise OSError('source checkpoint response lost')
        return save(value)
    monkeypatch.setattr(e.source,'_save',checkpoint)
    e.feed.emit(kind='reboot')
    with pytest.raises(OSError,match='checkpoint'):e.source.verify(result['boot']['activation_ack'])
    assert e.source.verify(result['boot']['activation_ack'])
    assert e.source.tracker.read(result['boot']['source_id'])['reboot_count']==1


def test_activation_requires_observed_original_boot_event_before_resume(event_boot):
    e=event_boot;e.control['omit_started']=True
    with pytest.raises(RuntimeErrorBase,match='not observed'):e.driver.apply(e.operation)
    result=e.driver.definitions.read(e.operation)
    assert result['boot']['phase']=='activation_requested' and result['boot']['recovery_required']
    assert e.state['cpu']==3 and e.state['starts']==1 and e.state['resumes']==0


@pytest.mark.parametrize('fault',['disconnect','epoch','process','second_start','pause','unknown'])
def test_uncertain_or_foreign_events_never_restart_original_vm(event_boot,fault):
    e=event_boot;result=e.driver.apply(e.operation)
    if fault=='disconnect':e.feed.lost=True
    elif fault=='epoch':e.control['epoch']['id']='a'*32
    elif fault=='process':
        e.process['start_ticks']+=1;e.feed.emit(kind='reboot')
    elif fault=='second_start':e.feed.emit(2,0)
    elif fault=='pause':e.feed.emit(3,0)
    else:e.feed.emit(99,0)
    with pytest.raises((RuntimeErrorBase,OSError)):e.source.verify(result['boot']['activation_ack'])
    assert e.state['starts']==e.state['resumes']==1


@pytest.mark.parametrize('event',[5,8])
def test_stop_and_crash_are_recovery_events_not_ordinary_exit_proof(event_boot,event):
    e=event_boot;result=e.driver.apply(e.operation);e.feed.emit(event,0)
    with pytest.raises(RuntimeErrorBase,match='qualified recovery'):e.source.verify(result['boot']['activation_ack'])
    tracked=e.source.tracker.read(result['boot']['source_id'])
    assert tracked['phase']=='recovery_required' and tracked['guest_readiness']=='unknown'
    assert e.state['starts']==e.state['resumes']==1


def test_other_domain_events_are_retained_without_domain_adoption(event_boot):
    e=event_boot;result=e.driver.apply(e.operation)
    other='00000000-0000-4000-8000-000000000002';e.feed.emit(2,0,uuid=other)
    assert e.source.verify(result['boot']['activation_ack'])
    rows=e.source.journal.db.execute('SELECT * FROM vm_libvirt_boot_sources').fetchall()
    assert len(rows)==1 and rows[0]['domain_uuid']==result['birth']['uuid']
    assert e.source.journal.db.execute('SELECT count(*) FROM vm_libvirt_raw_events').fetchone()[0]==4
    assert len(e.state['domains'])==1


def test_gap_does_not_commit_or_ack_a_partial_batch(event_boot):
    e=event_boot;result=e.driver.apply(e.operation)
    e.feed.sequence+=1;e.feed.emit(kind='reboot')
    with pytest.raises(RuntimeErrorBase,match='history gap'):e.source.verify(result['boot']['activation_ack'])
    assert e.source._feed()['cursor']==3 and e.feed.acknowledged==3


def test_reconstructed_collector_cannot_renew_original_continuity(event_boot):
    e=event_boot;e.driver.apply(e.operation)
    with pytest.raises(RuntimeErrorBase,match='cannot be reconstructed'):
        LibvirtBootEvents(e.driver.definitions,e.feed,runtime=SimpleNamespace(check=lambda:e.control['epoch']),
                          observer=e.driver.observer)
    assert e.state['starts']==e.state['resumes']==1


@pytest.mark.parametrize('action',['arm','activate'])
def test_explicit_lost_monitor_reply_recovery_reads_original_receipt_only(event_boot,monkeypatch,action):
    e=event_boot;original=getattr(e.source,action);calls=[]
    def lost(value):
        calls.append(True);original(value);raise OSError('original monitor reply lost')
    monkeypatch.setattr(e.source,action,lost)
    with pytest.raises(OSError,match='monitor reply'):e.driver.apply(e.operation)
    saved=e.driver.definitions.read(e.operation)
    assert saved['boot']['phase']==('arming_requested' if action=='arm' else 'activation_requested')
    with pytest.raises(RuntimeErrorBase,match='not repeated'):e.driver.apply(e.operation)
    result=e.driver.recover_events(e.operation)
    assert result['boot']['phase']==('armed' if action=='arm' else 'monitored_paused')
    assert calls==[True] and e.state['resumes']==0 and e.state['starts']==(0 if action=='arm' else 1)
    assert e.driver.apply(e.operation)['boot']['phase']=='running'
    assert calls==[True] and e.state['starts']==e.state['resumes']==1


def test_missing_activation_receipt_cannot_be_learned_during_recovery(event_boot):
    e=event_boot;e.control['omit_started']=True
    with pytest.raises(RuntimeErrorBase,match='not observed'):e.driver.apply(e.operation)
    with pytest.raises(RuntimeErrorBase,match='active source receipt missing'):e.driver.recover_events(e.operation)
    assert e.state['cpu']==3 and e.state['starts']==1 and e.state['resumes']==0


def test_lifecycle_before_arm_is_refused_before_initial_start(event_boot):
    e=event_boot;e.feed.emit(2,0)
    with pytest.raises(RuntimeErrorBase,match='before original event arm'):e.driver.apply(e.operation)
    assert e.state['starts']==e.state['resumes']==0
    assert e.source.journal.db.execute('SELECT count(*) FROM vm_libvirt_boot_sources').fetchone()[0]==0


def test_delayed_definition_notification_does_not_become_a_boot_event(event_boot):
    e=event_boot;e.feed.emit(0,0)
    result=e.driver.apply(e.operation)
    source=e.source.read(result['boot']['source_id'])
    assert source['initial']==dict(started=2,paused=3,resumed=4)
    assert source['cursor']==4 and e.state['starts']==e.state['resumes']==1


def test_missing_persisted_event_is_not_silently_skipped(event_boot):
    e=event_boot;result=e.driver.apply(e.operation);e.feed.emit(kind='reboot');e.source.pump()
    e.source.journal.db.execute('DELETE FROM vm_libvirt_raw_events WHERE feed_id=? AND sequence=4',(e.feed.id,))
    with pytest.raises(RuntimeErrorBase,match='history incomplete'):e.source.verify(result['boot']['activation_ack'])
    assert e.source.read(result['boot']['source_id'])['cursor']==3
    assert e.source.tracker.read(result['boot']['source_id'])['reboot_count']==0
