"""String frames, simulated bus and temporary metadata journal only."""
from copy import deepcopy
import json

import pytest

from dnlab_runtime.libvirt_activation_bus import StartJobReceipts,serve,start_plan
from dnlab_runtime.libvirt_activation_commands import command_plan
from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from test_libvirt_activation_acknowledgements import acknowledgements
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def worker(acknowledgements,monkeypatch):
    original,item,_,_,_,_=acknowledgements
    _,source=original._request(item,'activation')
    command=start_plan(source,item,'activation',dict(kind='dbus-start-v1',worker_sha256='1'*64,library_sha256='2'*64))
    connection=dict(token='3'*32,context_sha256=fingerprint(source['context']),manager_owner=':1.42',unique_name=':1.43')
    reference=dict(token='4'*32,command_sha256=fingerprint(command),process_record=dict(boot_id=source['context']['boot_id'],
        pid=4567,start_ticks=6789,uid=0,gid=0,executable_sha256='5'*64,namespace_sha256=fingerprint(source['context']['namespaces'])))
    state=dict(valid=True,calls=[],result=None,ack=None,frames=[],lost_call=False,lost_ack=False,reads=0,
        reply=dict(call_serial=17,reply_serial=17,sender=':1.42',signature='o',body=['/org/freedesktop/systemd1/job/91']))
    def verify(ref,cmd,conn):return state['valid'] and ref==reference and cmd==command and conn==connection
    def read_reply(ref):
        assert ref==reference;state['reads']+=1
        return deepcopy(state['result'])
    receipts=StartJobReceipts(original.journal,verify=verify,read_reply=read_reply)
    receipts.prepare(command,source['context'],connection,reference)
    class Bus:
        def verify(self,conn,cmd):return state['valid'] and conn==connection and cmd==command
        def start_unit(self,conn,cmd,*,timeout):
            assert conn==connection and cmd==command and timeout==5
            state['calls'].append(deepcopy(cmd))
            if state['lost_call']:raise OSError('synthetic method response lost')
            return deepcopy(state['reply'])
    class Sink:
        def write(self,line):
            value=json.loads(line);state['frames'].append(value)
            if 'job' in value:
                state['result']=deepcopy(value['job']);state['ack']=receipts.collect(command)
                if state['lost_ack']:raise OSError('synthetic durable acknowledgement lost')
        def flush(self):pass
    class Source:
        def __init__(self):
            self.lines=[canonical(dict(token=reference['token'],command=command,connection=connection))+'\n',
                canonical(dict(release=reference['token'],command_sha256=fingerprint(command),connection_sha256=fingerprint(connection)))+'\n']
        def readline(self,limit):
            if self.lines:return self.lines.pop(0)
            return canonical(state['ack'])+'\n' if state['ack'] is not None else ''
    monkeypatch.setattr('dnlab_runtime.libvirt_activation_bus.os.geteuid',lambda:0)
    return receipts,command,connection,reference,state,Bus(),Source(),Sink(),source,item,original.binary


def test_one_call_original_job_committed_before_worker_ack_and_readonly_replay(worker):
    receipts,command,connection,reference,state,bus,source,sink,installation,_,_=worker
    result=serve(source,sink,bus=bus)
    assert len(state['calls'])==1 and result==state['result']
    assert receipts._read(command)['phase']=='committed'
    before=receipts.journal.db.total_changes;reads=state['reads']
    assert receipts.collect(command)==state['ack']
    assert receipts.prepare(command,installation['context'],connection,reference)['result']==result
    assert receipts.journal.db.total_changes==before and state['reads']==reads
    subscription=dict(context_sha256=connection['context_sha256'],manager_owner=connection['manager_owner'])
    assert receipts.correlate(command,subscription,dict(unit=command['body'][0],job_path=result['reply']['body'][0]))


def test_wrong_release_cannot_call_bus(worker):
    receipts,command,_,_,state,bus,source,sink,_,_,_=worker
    source.lines[1]=canonical(dict(release='foreign'))+'\n'
    with pytest.raises(Conflict,match='release differs'):serve(source,sink,bus=bus)
    assert state['calls']==[] and receipts._read(command)['phase']=='prepared'


@pytest.mark.parametrize('fault',['sender','serial','job','signature'])
def test_foreign_method_reply_cannot_be_committed(worker,fault):
    receipts,command,_,_,state,bus,source,sink,_,_,_=worker
    if fault=='sender':state['reply']['sender']=':1.99'
    elif fault=='serial':state['reply']['reply_serial']=18
    elif fault=='job':state['reply']['body']=['/foreign/91']
    else:state['reply']['signature']='s'
    with pytest.raises(Conflict,match='method reply'):serve(source,sink,bus=bus)
    assert len(state['calls'])==1 and receipts._read(command)['phase']=='prepared' and state['ack'] is None


def test_lost_method_response_stays_pending_without_resend(worker):
    receipts,command,_,_,state,bus,source,sink,_,_,_=worker;state['lost_call']=True
    with pytest.raises(OSError):serve(source,sink,bus=bus)
    with pytest.raises(Conflict,match='pending; no resend'):receipts.collect(command)
    assert len(state['calls'])==1 and receipts._read(command)['phase']=='prepared'


def test_lost_ack_reuses_original_committed_job_without_worker_retry(worker):
    receipts,command,_,_,state,bus,source,sink,_,_,_=worker;state['lost_ack']=True
    with pytest.raises(OSError):serve(source,sink,bus=bus)
    assert receipts.collect(command)==state['ack'] and len(state['calls'])==1


def test_replacement_worker_or_connection_cannot_replace_intent(worker):
    receipts,command,connection,reference,_,_,_,_,installation,_,_=worker
    foreign=deepcopy(reference);foreign['process_record']['start_ticks']+=1
    with pytest.raises(Conflict,match='cannot be replaced'):receipts.prepare(command,installation['context'],connection,foreign)
    foreign=deepcopy(connection);foreign['manager_owner']=':1.99'
    with pytest.raises(Conflict,match='cannot be replaced'):receipts.prepare(command,installation['context'],foreign,reference)


def test_monitor_cannot_correlate_another_job_or_manager(worker):
    receipts,command,connection,_,_,bus,source,sink,_,_,_=worker;serve(source,sink,bus=bus)
    subscription=dict(context_sha256=connection['context_sha256'],manager_owner=connection['manager_owner'])
    event=dict(unit=command['body'][0],job_path='/org/freedesktop/systemd1/job/92')
    with pytest.raises(Conflict,match='original returned'):receipts.correlate(command,subscription,event)
    event['job_path']='/org/freedesktop/systemd1/job/91';subscription['manager_owner']=':1.99'
    with pytest.raises(Conflict,match='original returned'):receipts.correlate(command,subscription,event)


def test_distinct_transport_cannot_reinterpret_systemctl_intent(worker):
    _,command,connection,reference,state,bus,source,sink,installation,item,binary=worker
    old=command_plan(installation,item,'activation',binary)
    assert fingerprint(old)!=fingerprint(command)
    source.lines[0]=canonical(dict(token=reference['token'],command=old,connection=connection))+'\n'
    with pytest.raises(Conflict,match='D-Bus start command'):serve(source,sink,bus=bus)
    assert state['calls']==[] and state['frames']==[]


def test_connection_change_after_release_prevents_method_call(worker):
    receipts,command,_,_,state,bus,source,sink,_,_,_=worker
    read=source.readline
    def changed(limit):
        line=read(limit)
        if 'release' in json.loads(line):state['valid']=False
        return line
    source.readline=changed
    with pytest.raises(Conflict,match='connection or transport'):serve(source,sink,bus=bus)
    assert state['calls']==[] and receipts._read(command)['phase']=='prepared'
