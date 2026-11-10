"""Ordered synthetic events and temporary journals; no systemd connection."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation_events import ActivationEventMonitor
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_activation_acknowledgements import acknowledgements
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def events(acknowledgements):
    ledger,item,_,state,complete,_=acknowledgements
    request,_=ledger._request(item,'activation')
    transport=dict(events=[],alive=True,continuous=True,correlated=True,lost=False,pin_valid=True,pins={})
    subscription=dict(token='1'*32,request_sha256=fingerprint(request),context_sha256=fingerprint(request['context']),
        manager_owner=':1.42',barrier=0)
    class Stream:
        def verify(self,reference,request):return reference==subscription and transport['alive']
        def read(self,reference,*,after,limit):
            if transport['lost']:raise OSError('synthetic stream response lost')
            rows=deepcopy(transport['events'][after:after+limit])
            return dict(subscription_sha256=fingerprint(reference),after=after,through=after+len(rows),
                continuous=transport['continuous'],events=rows)
    class Processes:
        def verify(self,reference,request,subscription):
            process=state['witness']['service']['process']
            return (transport['pin_valid'] and reference==transport['pins'].get(reference['token'])
                and reference['pid']==process['pid'] and reference['start_ticks']==process['start_ticks'])
    def factory():
        return ActivationEventMonitor(ledger.journal,binary=ledger.binary,activation_reader=ledger.activation_reader,
            command_intent=ledger.command_intent,command_reader=ledger.command_reader,stream=Stream(),processes=Processes(),
            correlate=lambda *args:transport['correlated'],observe=lambda *args:deepcopy(state['witness']['service']))
    monitor=factory();reference=monitor.register(request,subscription);ledger.monitor=monitor
    def emit(kind,**fields):
        if kind=='invocation':
            process=state['witness']['service']['process']
            pin=dict(kind='original-service-process-v1',token=format(len(transport['pins'])+1,'032x'),
                request_sha256=fingerprint(request),subscription_sha256=fingerprint(subscription),
                invocation_id=fields['invocation_id'],pid=fields['pid'],start_ticks=process['start_ticks'],
                boot_id=request['context']['boot_id'],namespaces_sha256=fingerprint(request['context']['namespaces']))
            transport['pins'][pin['token']]=deepcopy(pin);fields['process_reference']=pin
        transport['events'].append(dict(sequence=len(transport['events'])+1,kind=kind,unit=item['spec']['unit'],**fields))
    def born():
        emit('job-new',job_path='/org/freedesktop/systemd1/job/12')
        row=state['witness']['service']['unit']
        emit('invocation',invocation_id=row['invocation_id'],pid=row['pid'])
        emit('job-removed',job_path='/org/freedesktop/systemd1/job/12',result='done')
    return ledger,item,request,subscription,reference,monitor,state,transport,complete,emit,born,factory


def test_original_events_qualify_acknowledgement_and_reopen_readonly(events):
    ledger,item,request,subscription,reference,monitor,_,_,complete,_,born,factory=events
    ledger.prepare(item,'activation',reference);complete();born()
    receipt=ledger.qualify(item,'activation')
    reopened=factory();ledger.monitor=reopened
    before=ledger.journal.db.total_changes
    assert ledger.original_receipt(item,'activation')==receipt
    assert reopened.register(request,subscription)==reference
    assert ledger.journal.db.total_changes==before


def test_cannot_replace_original_subscription_or_register_after_command(events):
    ledger,item,request,subscription,reference,monitor,_,_,complete,_,_,factory=events
    foreign=deepcopy(subscription);foreign['token']='2'*32
    with pytest.raises(Conflict):monitor.register(request,foreign)
    assert monitor.verify(reference,request)
    complete()
    # A different activation step has no registered monitor and must not accept a late subscription.
    value=ledger.activation_reader('activation');value['items'][2]['phase']='requested'
    ledger.activation_reader=lambda operation:deepcopy(value)
    late=factory();other=value['items'][2]
    from dnlab_runtime.libvirt_activation_commands import command_plan
    other_request=dict(request,spec=other['spec'],nonce=other['nonce'],
        command_sha256=fingerprint(command_plan(value['installation'],other,'activation',ledger.binary)))
    other_subscription=dict(subscription,request_sha256=fingerprint(other_request))
    late.stream.verify=lambda *args:True
    with pytest.raises(Conflict,match='before original command intent'):late.register(other_request,other_subscription)


@pytest.mark.parametrize('fault',['loss','sequence','uncorrelated','duplicate_job','replacement','failed_job'])
def test_event_loss_ambiguity_or_substitution_stays_pending(events,fault):
    ledger,item,request,_,reference,monitor,_,transport,complete,emit,born,_=events
    ledger.prepare(item,'activation',reference);complete();born()
    if fault=='loss':transport['continuous']=False
    elif fault=='sequence':transport['events'][1]['sequence']=99
    elif fault=='uncorrelated':transport['correlated']=False
    elif fault=='duplicate_job':emit('job-new',job_path='/org/freedesktop/systemd1/job/13')
    elif fault=='replacement':emit('invocation',invocation_id='9'*32,pid=9999)
    else:transport['events'][-1]['result']='failed'
    with pytest.raises(Conflict):ledger.qualify(item,'activation')
    saved=ledger.journal.db.execute('SELECT payload FROM libvirt_activation_event_monitors').fetchone()[0]
    assert '"phase":"pending"' in saved
    with pytest.raises(Conflict,match='monitor pending'):monitor.read_original(reference,request)
    assert ledger.journal.db.execute('SELECT payload FROM libvirt_activation_event_monitors').fetchone()[0]==saved


def test_lost_stream_response_recovers_original_subscription(events):
    ledger,item,_,_,reference,_,_,transport,complete,_,born,_=events
    ledger.prepare(item,'activation',reference);complete();born();transport['lost']=True
    with pytest.raises(OSError):ledger.qualify(item,'activation')
    transport['lost']=False
    assert ledger.recover(item,'activation')==ledger.original_receipt(item,'activation')


def test_partial_stream_preserves_first_invocation_until_job_completes(events):
    _,_,request,_,reference,monitor,state,_,complete,emit,_,_=events
    complete();emit('job-new',job_path='/org/freedesktop/systemd1/job/12')
    row=state['witness']['service']['unit']
    emit('invocation',invocation_id=row['invocation_id'],pid=row['pid'])
    with pytest.raises(Conflict,match='evidence pending'):monitor.read_original(reference,request)
    emit('job-removed',job_path='/org/freedesktop/systemd1/job/12',result='done')
    assert monitor.read_original(reference,request)['service']==state['witness']['service']


def test_current_matching_unit_cannot_override_event_generation(events):
    _,_,request,_,reference,monitor,state,_,complete,_,born,_=events
    complete();born();state['witness']['service']['unit']['invocation_id']='8'*32
    with pytest.raises(Conflict,match='first event'):monitor.read_original(reference,request)


def test_replaced_stream_and_changed_original_process_are_not_adopted(events):
    _,_,request,_,reference,monitor,state,transport,complete,_,born,_=events
    complete();born();proof=monitor.read_original(reference,request)
    state['witness']['service']['process']['start_ticks']+=1
    with pytest.raises(Conflict,match='process or pidfd'):monitor.read_original(reference,request)
    transport['alive']=False
    with pytest.raises(Conflict,match='stream lost'):monitor.verify(reference,request)
    assert proof['service']['process']['start_ticks']!=state['witness']['service']['process']['start_ticks']


def test_process_replaced_before_first_ready_observation_is_not_adopted(events):
    _,_,request,_,reference,monitor,state,_,complete,emit,_,_=events
    complete();emit('job-new',job_path='/org/freedesktop/systemd1/job/12')
    row=state['witness']['service']['unit']
    emit('invocation',invocation_id=row['invocation_id'],pid=row['pid'])
    with pytest.raises(Conflict,match='evidence pending'):monitor.read_original(reference,request)
    state['witness']['service']['process']['start_ticks']+=1
    emit('job-removed',job_path='/org/freedesktop/systemd1/job/12',result='done')
    with pytest.raises(Conflict):monitor.read_original(reference,request)


@pytest.mark.parametrize('fault',['missing','pidfd','ticks','context','token'])
def test_missing_or_changed_initial_process_pin_cannot_qualify(events,fault):
    _,_,request,_,reference,monitor,_,transport,complete,_,born,_=events
    complete();born();pin=transport['events'][1]['process_reference']
    if fault=='missing':transport['events'][1].pop('process_reference')
    elif fault=='pidfd':transport['pin_valid']=False
    elif fault=='ticks':pin['start_ticks']+=1
    elif fault=='context':pin['boot_id']='foreign'
    else:pin['token']='f'*32
    with pytest.raises(Conflict):monitor.read_original(reference,request)
    assert '"proof":null' in monitor.journal.db.execute('SELECT payload FROM libvirt_activation_event_monitors').fetchone()[0]
