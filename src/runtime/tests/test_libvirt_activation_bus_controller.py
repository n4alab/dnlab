"""Compose real controller/event/job journals, string worker and simulated bus."""
from copy import deepcopy
import json

import pytest

from dnlab_runtime.libvirt_activation_bus import BusStartPlan,StartJobReceipts,serve
from dnlab_runtime.libvirt_activation_commands import command_plan
from dnlab_runtime.libvirt_activation_controller import ActivationController
from dnlab_runtime.libvirt_activation_events import ActivationEventMonitor
from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from test_libvirt_activation_controller import controller
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def bus_controller(controller,monkeypatch):
    old,reference,_,state,_=controller
    original=old.commands.runner;source=old.source;holder={}
    data=dict(connections={},replies={},subscriptions={},streams={},pins={},lost=None)
    planner=BusStartPlan(dict(kind='dbus-start-v1',worker_sha256='1'*64,library_sha256='2'*64))
    def verify(worker,command,connection):
        return original.verify(worker,command) and data['connections'].get(worker['token'])==connection
    jobs=StartJobReceipts(old.journal,verify=verify,read_reply=lambda ref:deepcopy(data['replies'].get(ref['token'])))
    class Runner:
        def arm(self,command):
            ref=original.arm(command)
            if 'transport' in command:
                connection=dict(token=ref['token'],context_sha256=fingerprint(source['context']),manager_owner=':1.42',unique_name=':1.43')
                data['connections'][ref['token']]=connection
                jobs.prepare(command,source['context'],connection,ref)
            return ref
        def verify(self,ref,command):return original.verify(ref,command)
        def outcome(self,ref):return original.outcome(ref)
        def completed_outcome(self,ref):return original.completed_outcome(ref)
        def release(self,ref):
            worker=state['workers'][ref['token']];command=worker['command']
            if 'transport' not in command:return original.release(ref)
            unit=command['body'][0];connection=data['connections'][ref['token']];reply={};ack={}
            class Bus:
                def verify(self,conn,cmd):return verify(ref,cmd,conn)
                def start_unit(self,conn,cmd,*,timeout):
                    assert timeout==5 and conn==connection and cmd==command
                    # Reuse only the synthetic service transition, never the old worker transport.
                    worker['command']=dict(argv=['/usr/bin/systemctl','start','--',unit])
                    try:original.release(ref)
                    finally:worker['command']=command
                    worker['outcome']=None
                    row=state['events'][unit];request=data['subscriptions'][unit]['request']
                    subscription=data['subscriptions'][unit]['reference'];job='/org/freedesktop/systemd1/job/'+str(len(state['calls']))
                    pin=dict(kind='original-service-process-v1',token=ref['token'],request_sha256=fingerprint(request),
                        subscription_sha256=fingerprint(subscription),invocation_id=row['unit']['invocation_id'],
                        pid=row['process']['pid'],start_ticks=row['process']['start_ticks'],boot_id=source['context']['boot_id'],
                        namespaces_sha256=fingerprint(source['context']['namespaces']))
                    data['pins'][pin['token']]=deepcopy(pin)
                    fields=[dict(kind='job-new',job_path=job),dict(kind='invocation',invocation_id=row['unit']['invocation_id'],
                        pid=row['unit']['pid'],process_reference=pin),dict(kind='job-removed',job_path=job,result='done')]
                    data['streams'][unit]=[dict(sequence=i+1,unit=unit,**event) for i,event in enumerate(fields)]
                    return dict(call_serial=17,reply_serial=17,sender=':1.42',signature='o',body=[job])
            class Source:
                def __init__(self):self.lines=[canonical(dict(token=ref['token'],command=command,connection=connection))+'\n',
                    canonical(dict(release=ref['token'],command_sha256=fingerprint(command),connection_sha256=fingerprint(connection)))+'\n']
                def readline(self,limit):return self.lines.pop(0) if self.lines else canonical(ack)+'\n'
            class Sink:
                def write(self,line):
                    frame=json.loads(line)
                    if 'job' in frame:
                        reply.update(frame['job']);data['replies'][ref['token']]=deepcopy(reply);ack.update(jobs.collect(command))
                def flush(self):pass
            serve(Source(),Sink(),bus=Bus())
            worker['outcome']=dict(reference=deepcopy(ref),exit_code=0,stdout='',stderr='')
            if data['lost']==unit:raise OSError('synthetic original D-Bus release reply lost')
    class Stream:
        def verify(self,subscription,request):
            entry=data['subscriptions'].get(request['spec']['unit'])
            return entry==dict(reference=subscription,request=request)
        def read(self,subscription,*,after,limit):
            entries=[(unit,entry) for unit,entry in data['subscriptions'].items() if entry['reference']==subscription]
            assert len(entries)==1
            rows=deepcopy(data['streams'].get(entries[0][0],[])[after:after+limit])
            return dict(subscription_sha256=fingerprint(subscription),after=after,through=after+len(rows),continuous=True,events=rows)
    class Processes:
        def verify(self,pin,request,subscription):
            row=state['events'].get(request['spec']['unit'])
            return row is not None and data['pins'].get(pin['token'])==pin and row['process']['start_ticks']==pin['start_ticks']
    def correlate(request,subscription,event):
        value=holder['driver'].driver.read('activation')
        item=next(i for i in value['items'] if i['nonce']==request['nonce'])
        return jobs.correlate(planner(source,item,'activation',old.binary),subscription,event)
    monitor=ActivationEventMonitor(old.journal,binary=old.binary,activation_reader=lambda op:holder['driver'].driver.read(op),
        command_intent=lambda item,op:holder['driver'].commands.inspect_intent(item,op),
        command_reader=lambda item,op:holder['driver'].commands.inspect_completion(item,op),stream=Stream(),processes=Processes(),
        correlate=correlate,observe=lambda request,pin:deepcopy(state['events'][request['spec']['unit']]),command_builder=planner)
    driver=ActivationController(old.journal,source,operation='activation',window=old.window,binary=old.binary,runner=Runner(),
        source_reader=old.source_reader,monitor=monitor,resources=old.resources,inventory=old.inventory,empty=old.empty,command_builder=planner)
    holder['driver']=driver;reference=driver.prepare();references={}
    for index,item in enumerate(reference['items']):
        if item['spec']['kind']!='start':continue
        request=driver.monitor_request(reference,item)
        subscription=dict(token=format(index,'032x'),request_sha256=fingerprint(request),context_sha256=fingerprint(source['context']),
            manager_owner=':1.42',barrier=0)
        data['subscriptions'][item['spec']['unit']]=dict(reference=subscription,request=request)
        references[item['spec']['unit']]=monitor.register(request,subscription)
    driver.bind_monitors(references)
    monkeypatch.setattr('dnlab_runtime.libvirt_activation_bus.os.geteuid',lambda:0)
    return driver,reference,state,data,jobs


def test_full_bus_start_event_and_acknowledgement_path(bus_controller):
    driver,reference,state,_,jobs=bus_controller
    result=driver.apply_original(reference)
    assert result['phase']=='ready_empty' and len(state['calls'])==4
    assert jobs.journal.db.execute('SELECT count(*) FROM libvirt_activation_start_jobs').fetchone()[0]==3
    assert driver.apply_original(reference)==result and len(state['calls'])==4


def test_original_job_and_monitor_survive_lost_release_reply_without_new_start(bus_controller):
    driver,reference,state,data,_=bus_controller
    data['lost']=driver.source['profile']['service_order'][0]
    with pytest.raises(OSError):driver.apply_original(reference)
    assert len(state['calls'])==2
    driver.recover_original(reference)
    assert len(state['calls'])==2
    assert driver.apply_original(reference)['phase']=='ready_empty' and len(state['calls'])==4


def test_changing_plan_cannot_reuse_bound_monitors_or_fall_back_to_systemctl(bus_controller):
    driver,reference,state,_,_=bus_controller
    driver.command_builder=command_plan
    with pytest.raises(Conflict):driver.apply_original(reference)
    assert state['calls']==[]
