"""Simulated worker/observer only; no account program or subprocess is executed."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import os
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import libvirt_worker_bootstrap_canary as module
from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_commands import command_plan
from dnlab_runtime.libvirt_account_runner import worker_argv
from dnlab_runtime.manifest import Conflict,fingerprint


@pytest.fixture
def fixture(tmp_path):
    files={};sha={}
    for key,data in [('groupadd',b'\x7fELFfake group binary'),('python',b'\x7fELFfake interpreter'),('worker',b'# fake worker source, never run\n')]:
        path=tmp_path/key;path.write_bytes(data);path.chmod(0o644 if key=='worker' else 0o755)
        files[key]=path;sha[key]=hashlib.sha256(data).hexdigest()
    profile=dict(python=dict(path='/qualified/python',sha256=sha['python']),worker=dict(path='/qualified/worker',sha256=sha['worker']))
    request=dict(intent_id='bootstrap-canary',nonce='a'*32,spec_sha256='b'*64,kind='group',expected=dict(name='dnlab-libvirt',gid=1002))
    command=command_plan(request,{'groupadd':dict(path='/usr/sbin/groupadd',sha256=sha['groupadd'])})
    state=dict(spawns=[],verified=True,ready=True,exit_verified=True,output_pending=False,status=1,
        stderr='Traceback (most recent call last):\n  synthetic traceback\n'+module.REFUSAL,closed=False,wait_timeout=False,close_error=False,waits=0)
    class Input(io.BytesIO):
        def flush(self):state['frames']=self.getvalue().splitlines()
        def close(self):
            super().close()
            if state['close_error']:raise BrokenPipeError('synthetic original pipe already closed')
    class Process:
        pid=123
        def __init__(self):self.stdin=Input();self.stdout=io.BytesIO();self.stderr=io.BytesIO()
        def wait(self,timeout):
            assert timeout==12 and self.stdin.closed
            state['waits']+=1
            if state['wait_timeout']:raise TimeoutError('synthetic original worker timeout')
            return state['status']
    def spawn(argv,**kwargs):state['spawns'].append((argv,kwargs));state['process']=Process();return state['process']
    class Observer:
        def capture(self,process):return dict(boot_id='synthetic',pid=123,start_ticks=456,uid=0,gid=0,
            executable_sha256=sha['python'],namespace_sha256='f'*64)
        def bind(self,reference,process,cmd):state['reference']=deepcopy(reference)
        def verify(self,reference,process,cmd,phase):assert phase=='armed';return state['verified']
        def exit(self,process,reference):return state['exit_verified']
        def retire(self,reference):state['retired']=True
        def close(self):state['closed']=True
    @contextmanager
    def opener(path):
        key=path.rsplit('/',1)[-1];fd=os.open(files[key],os.O_RDONLY)
        try:yield fd
        finally:os.close(fd)
    def ready(process):
        packet=json.loads(state['frames'][0])
        return dict(ready=packet['token'] if state['ready'] else 'foreign',command_sha256=fingerprint(command))
    def output(process,live):
        assert process.stdin.closed
        if state['output_pending']:return None
        return dict(exit_code=state['status'],stdout='',stderr=state['stderr'])
    journal=Journal(tmp_path/'journal');observer=Observer()
    def run():return module.run(journal,command,profile,observer=observer,spawn=spawn,opener=opener,read_ready=ready,read_output=output)
    yield run,state,journal,command,profile
    journal.close()


def stored(journal):return json.loads(journal.db.execute('SELECT payload FROM libvirt_worker_bootstrap_canaries').fetchone()['payload'])


def test_original_bootstrap_receives_only_one_arm_frame_then_eof(fixture):
    run,state,journal,command,profile=fixture;result=run()
    assert result['phase']=='completed' and result['qualified'] and result['cleanup_verified']
    assert result['release_sent'] is False and len(state['frames'])==1
    packet=json.loads(state['frames'][0]);assert packet==dict(token=result['token'],command=command)
    assert result['reference']==state['reference'] and state['retired'] and state['closed']
    argv,options=state['spawns'][0]
    fds=options['pass_fds'];assert argv==worker_argv(profile,*fds)
    assert options['close_fds'] and options['cwd']=='/' and argv[1:4]==['-B','-I','-S']
    assert state['process'].stdout.closed and state['process'].stderr.closed and stored(journal)==result


@pytest.mark.parametrize('fault',['readiness','verify','status','refusal','pending_output','exit_proof','timeout'])
def test_failure_preserves_pending_without_release_or_second_process(fixture,fault):
    run,state,journal,_,_=fixture
    if fault=='readiness':state['ready']=False
    elif fault=='verify':state['verified']=False
    elif fault=='status':state['status']=0
    elif fault=='refusal':state['stderr']='unexpected stderr\n'
    elif fault=='pending_output':state['output_pending']=True
    elif fault=='exit_proof':state['exit_verified']=False
    else:state['wait_timeout']=True
    with pytest.raises((Conflict,TimeoutError)):run()
    value=stored(journal)
    assert value['phase']=='pending' and value['cleanup_verified'] is False and value['release_sent'] is False
    assert len(state['spawns'])==1 and len(state['frames'])==1 and state['closed']
    assert state['process'].stdin.closed and state['process'].stdout.closed and state['process'].stderr.closed


def test_existing_canary_is_never_relaunched(fixture):
    run,state,journal,_,_=fixture;run()
    with pytest.raises(Conflict,match='one-shot'):run()
    assert len(state['spawns'])==1 and stored(journal)['phase']=='completed'


def test_no_worker_without_explicit_execution_switch(tmp_path,monkeypatch):
    monkeypatch.setattr(sys,'argv',['canary','--request','unused','--profile','unused','--output',str(tmp_path/'new')])
    with pytest.raises(SystemExit) as error:module.main()
    assert error.value.code==2 and not (tmp_path/'new').exists()


def test_readiness_error_survives_broken_pipe_and_owned_streams_are_closed(fixture):
    run,state,journal,_,_=fixture
    state.update(ready=False,close_error=True)
    with pytest.raises(Conflict,match='readiness differs'):run()
    assert state['waits']==1 and state['closed']
    assert state['process'].stdout.closed and state['process'].stderr.closed
    assert stored(journal)['phase']=='pending' and not stored(journal)['cleanup_verified']


def test_primary_error_survives_both_pipe_failure_and_wait_timeout(fixture):
    run,state,journal,_,_=fixture
    state.update(ready=False,close_error=True,wait_timeout=True)
    with pytest.raises(Conflict,match='readiness differs'):run()
    saved=stored(journal)
    assert saved['error']['type']=='Conflict'
    assert [error['step'] for error in saved['cleanup_errors']]==['stdin_close','original_wait']
    assert state['waits']==1 and state['closed']
    assert state['process'].stdout.closed and state['process'].stderr.closed
    assert not saved['qualified'] and not saved['cleanup_verified'] and saved['phase']=='pending'


def test_stdout_close_failure_does_not_skip_stderr_or_observer(fixture,monkeypatch):
    run,state,journal,_,_=fixture;spawn_state=state['spawns']
    # Inject only the fake stdout close; all lifecycle checks and exit remain real recipe code.
    class Output(io.BytesIO):
        def close(self):super().close();raise OSError('synthetic stdout close failure')
    # Install the fake stream at the existing observer capture boundary.
    captured=[]
    original_proof=module.reference_proof
    def proof(reference,command):
        original_proof(reference,command)
        if not captured:
            captured.append(True);state['process'].stdout=Output()
    monkeypatch.setattr(module,'reference_proof',proof)
    with pytest.raises(OSError,match='stdout close failure'):run()
    saved=stored(journal)
    assert state['process'].stdout.closed and state['process'].stderr.closed and state['closed']
    assert saved['phase']=='pending' and not saved['cleanup_verified'] and not saved['qualified']
    assert saved['cleanup_errors'][0]['step']=='stdout_close'
    assert len(spawn_state)==1


def test_startup_failure_keeps_observed_ready_and_stderr_before_stream_close(fixture):
    run,state,journal,_,_=fixture
    state.update(ready=False,stderr='synthetic bootstrap traceback\n')
    with pytest.raises(Conflict,match='readiness differs'):run()
    saved=stored(journal)
    assert saved['ready']['ready']=='foreign'
    assert saved['cleanup_outcome']['stderr']=='synthetic bootstrap traceback\n'
    assert saved['error']['type']=='Conflict' and saved['phase']=='pending'
    assert not saved['cleanup_verified'] and state['process'].stderr.closed
