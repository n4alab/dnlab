"""Fake child/observer and temporary binary bytes only; never spawn a process."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import io
import json
import os

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_commands import command_plan
from dnlab_runtime.libvirt_account_runner import AccountProcessRunner,collect_output,ready_line
from dnlab_runtime.libvirt_install import targets
from dnlab_runtime.libvirt_provisioning import account_request
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_profile import request_profile


@pytest.fixture
def runner(tmp_path,request_profile):
    resources={};digests={}
    for name,data in [('useradd',b'\x7fELFfake account binary'),('python',b'\x7fELFfake interpreter'),('worker',b'# synthetic worker source\n')]:
        path=tmp_path/name;path.write_bytes(data);path.chmod(0o755 if name!='worker' else 0o644)
        resources[name]=path;digests[name]=hashlib.sha256(data).hexdigest()
    @contextmanager
    def opener(path):
        name='useradd' if path=='/usr/sbin/useradd' else path.rsplit('/',1)[-1]
        fd=os.open(resources[name],os.O_RDONLY)
        try:yield fd
        finally:os.close(fd)
    spec=next(i for i in targets(render_profile(**request_profile)) if i['kind']=='account')
    request=account_request(dict(spec=spec,nonce='a'*32),'install')
    command=command_plan(request,{'useradd':dict(path='/usr/sbin/useradd',sha256=digests['useradd'])})
    profile=dict(python=dict(path='/qualified/python',sha256=digests['python']),worker=dict(path='/qualified/worker',sha256=digests['worker']))
    state=dict(spawns=[],process=None,verified=True,exit_verified=True,ready_wrong=False,output_pending=False,identity=None,request=deepcopy(request))
    class Input(io.BytesIO):
        def close(self):self.was_closed=True;state['identity']=deepcopy(request['expected'])
    class Process:
        pid=123
        def __init__(self):self.stdin=Input();self.stdin.was_closed=False;self.stdout=io.BytesIO();self.stderr=io.BytesIO()
    def spawn(argv,**kwargs):
        state['spawns'].append((argv,kwargs));state['process']=Process();return state['process']
    class Observer:
        def capture(self,process):
            return dict(boot_id='synthetic',pid=process.pid,start_ticks=456,uid=0,gid=0,
                executable_sha256=digests['python'],namespace_sha256='f'*64)
        def bind(self,reference,process,command):pass
        def retire(self,reference):pass
        def verify(self,reference,process,command,phase):return state['verified']
        def exit(self,process,reference):return state['exit_verified']
    def ready(process):
        packet=json.loads(process.stdin.getvalue().splitlines()[0])
        return dict(ready='wrong' if state['ready_wrong'] else packet['token'],command_sha256=fingerprint(packet['command']))
    def output(process,live):
        if state['output_pending']:return None
        assert process.stdin.was_closed
        return dict(exit_code=0,stdout='synthetic output',stderr='')
    journal=Journal(tmp_path/'journal');observer=Observer()
    def make():return AccountProcessRunner(journal,profile=profile,observer=observer,spawn=spawn,opener=opener,read_ready=ready,read_output=output)
    yield make(),command,state,make
    journal.close()


def test_arm_is_blocked_until_reference_and_release_are_durable(runner):
    driver,command,state,_=runner
    reference=driver.arm(command);process=state['process']
    assert len(process.stdin.getvalue().splitlines())==1 and not process.stdin.was_closed
    assert driver._read(reference)['phase']=='armed'
    assert driver.verify(reference,command)
    driver.release(reference)
    release=json.loads(process.stdin.getvalue().splitlines()[1])
    assert release==dict(release=reference['token'],command_sha256=fingerprint(command))
    result=driver.outcome(reference)
    assert result['exit_code']==0 and driver.outcome(reference)==result
    with pytest.raises(Conflict,match='not repeated'):driver.release(reference)
    assert len(state['spawns'])==1
    argv,options=state['spawns'][0]
    assert argv[1:4]==['-B','-I','-S'] and options['close_fds'] is True
    assert len(options['pass_fds'])==3 and options['cwd']=='/'


def test_readonly_completion_does_not_collect_pending_worker(runner,monkeypatch):
    driver,command,_,_=runner
    reference=driver.arm(command)
    driver.release(reference)
    monkeypatch.setattr(driver,'read_output',lambda *args:pytest.fail('readonly preflight cannot collect output'))
    before=driver.journal.db.total_changes
    assert driver.completed_outcome(reference) is None
    assert driver.journal.db.total_changes==before


def test_readonly_completion_reopens_committed_evidence_without_retirement(runner,monkeypatch):
    driver,command,_,make=runner
    reference=driver.arm(command)
    driver.release(reference)
    result=driver.outcome(reference)
    reopened=make()
    monkeypatch.setattr(reopened,'_retire',lambda *args:pytest.fail('readonly completion cannot retire worker'))
    before=driver.journal.db.total_changes
    assert reopened.completed_outcome(reference)==result
    assert driver.journal.db.total_changes==before


def test_lost_release_commit_response_does_not_resend(runner,monkeypatch):
    driver,command,state,_=runner;reference=driver.arm(command);save=driver._save
    def lost(value):
        save(value)
        if value['phase']=='released':raise OSError('synthetic lost release acknowledgement')
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError):driver.release(reference)
    assert driver.outcome(reference)['exit_code']==0
    with pytest.raises(Conflict,match='not repeated'):driver.release(reference)
    assert len(state['process'].stdin.getvalue().splitlines())==2


def test_lost_parent_waiter_is_not_reconstructed_from_pid(runner):
    driver,command,state,make=runner;reference=driver.arm(command);driver.release(reference)
    reopened=make()
    with pytest.raises(Conflict,match='waiter unavailable'):reopened.outcome(reference)
    with pytest.raises(Conflict,match='not repeated'):reopened.release(reference)
    assert len(state['spawns'])==1


def test_committed_outcome_can_be_read_after_reopen_without_spawn(runner):
    driver,command,state,make=runner;reference=driver.arm(command);driver.release(reference)
    result=driver.outcome(reference)
    assert make().outcome(reference)==result and len(state['spawns'])==1


def test_process_change_after_release_checkpoint_prevents_writing_release(runner,monkeypatch):
    driver,command,state,_=runner;reference=driver.arm(command);save=driver._save
    def changed(value):
        save(value)
        if value['phase']=='release_requested':state['verified']=False
    monkeypatch.setattr(driver,'_save',changed)
    with pytest.raises(Conflict,match='release boundary'):driver.release(reference)
    assert len(state['process'].stdin.getvalue().splitlines())==1


def test_exit_requires_original_observer_proof_before_completion(runner):
    driver,command,state,_=runner;reference=driver.arm(command);driver.release(reference);state['exit_verified']=False
    with pytest.raises(Conflict,match='exit'):driver.outcome(reference)
    assert driver._read(reference)['phase']=='released'


def test_pending_output_keeps_same_worker_and_never_respawns(runner):
    driver,command,state,_=runner;reference=driver.arm(command);driver.release(reference);state['output_pending']=True
    assert driver.outcome(reference) is None
    assert driver._read(reference)['phase']=='released'
    assert len(state['spawns'])==1


def test_wrong_ready_does_not_send_release(runner):
    driver,command,state,_=runner;state['ready_wrong']=True
    with pytest.raises(Conflict,match='ready differs'):driver.arm(command)
    assert len(state['process'].stdin.getvalue().splitlines())==1


def pipe_process(stdout=b'',stderr=b'',status=0):
    class Process:
        def poll(self):return status
    process=Process();writers=[]
    for key,data in [('stdout',stdout),('stderr',stderr)]:
        read,write=os.pipe();setattr(process,key,os.fdopen(read,'rb',buffering=0))
        os.write(write,data);os.close(write)
    return process


def test_real_pipe_output_is_bounded_without_a_real_child():
    process=pipe_process(b'out',b'err')
    try:
        value=collect_output(process,dict(stdout=b'',stderr=b'',eof=set()),timeout=0.1)
        assert value==dict(exit_code=0,stdout='out',stderr='err')
    finally:process.stdout.close();process.stderr.close()


def test_output_limit_preserves_pending_without_signals():
    process=pipe_process(b'xx')
    try:
        with pytest.raises(Conflict,match='exceeds bound'):
            collect_output(process,dict(stdout=b'x'*65535,stderr=b'',eof=set()),timeout=0.1)
    finally:process.stdout.close();process.stderr.close()


def test_readiness_reads_only_original_bounded_frame_without_child():
    process=pipe_process(b'{"ready":"token"}\n')
    try:assert ready_line(process,timeout=0.1)=={'ready':'token'}
    finally:process.stdout.close();process.stderr.close()


def test_different_capture_pid_is_rejected_before_reference_or_release(runner,monkeypatch):
    driver,command,state,_=runner;capture=driver.observer.capture
    def changed(process):
        record=capture(process);record['pid']+=1;return record
    monkeypatch.setattr(driver.observer,'capture',changed)
    with pytest.raises(Conflict,match='process differs'):driver.arm(command)
    assert len(state['process'].stdin.getvalue().splitlines())==1
    assert not state['process'].stdin.was_closed and state['identity'] is None


def test_oversized_request_is_refused_before_spawn(runner):
    driver,command,state,_=runner;command['argv'][7]='/'+('a'*20000)
    with pytest.raises(Conflict,match='frame bound'):driver.arm(command)
    assert state['spawns']==[]


def test_account_command_helper_uses_runner_original_exit_without_second_release(runner):
    from dnlab_runtime.libvirt_account_commands import AccountCommandHelper
    driver,command,state,_=runner;request=state['request']
    def preflight(value):return dict(qualified=True,command_sha256=fingerprint(value),context_sha256='a'*64,inputs_sha256='b'*64)
    helper=AccountCommandHelper(driver.journal,binaries={'useradd':command['binary']},runner=driver,
        inspect=lambda value:deepcopy(state['identity']),preflight=preflight)
    result=helper.create(request)
    assert result==helper.completion(request)
    assert result['identity']==request['expected'] and len(state['spawns'])==1
    assert len(state['process'].stdin.getvalue().splitlines())==2
