"""Complete persistent hold with real adapters and simulated native I/O."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import sys
import select
import signal

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_control import ImageBuildEngine, OriginalImageBuildTerm
from image_build_executor import ImageBuildExecutor
from image_build_observation import ImageBuildApiNotReady, process_digest
from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.image_build_hold import ImageBuildHold
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import TemplateError
from test_image_build_control import frame, log_lines
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def executor(observation,runtime_process):
    observer,_,native,_=observation
    runtime,epoch,_,_,_=runtime_process
    context=ImageBuildCommands._context(epoch);profile=observer.profile
    profile['context']=deepcopy(context);native['context']=deepcopy(context)
    profile['generation']['started_at']='2026-11-18T09:00:00Z'
    native['inspect']['State']['StartedAt']=profile['generation']['started_at']
    profile['actor']['context_sha256']=fingerprint(context)
    profile['actor']['process_sha256']=process_digest(profile['capture'],profile['generation'])
    observer.profile_sha256=fingerprint(profile)
    state=dict(cleanup=False,window=True,actions=[],fault=None,after_term=None)
    scope={key:key for key in ('gate_id','lab_id','coordinator_id','window_id')}
    scope.update(host_id=context['host_id'],boot_id=context['boot_id'])
    drivers={}
    def preflight(command):
        value=drivers['hold'].read(command['operation_id']);drivers['hold']._pre(value,command['action'])
        return dict(command_sha256=fingerprint(command),scope_sha256=fingerprint(scope),
                    actor_sha256=fingerprint(command['actor']),window_active=True)
    commands=ImageBuildCommands(runtime,read_hold=lambda op:drivers['hold'].read(op),preflight=preflight,
        execute=lambda command,reference:drivers['executor'](command,reference))
    hold=ImageBuildHold(runtime.journal,observe=observer,commands=commands,
        window=lambda value:dict(active=state['window'],scope_sha256=fingerprint(scope)),
        cleanup=lambda value:dict(resources_absent=state['cleanup'],pending_operations=0,
                                 scope_sha256=fingerprint(scope),receipt_sha256='9'*64))
    drivers['hold']=hold
    observer.exit_receipt=lambda value:commands.outcome(value['actions']['stop']['reference'])
    observer.startup=lambda value:commands.details(value['actions']['start']['reference'])['details']['startup']
    class Connection:
        def __init__(self,path,timeout):assert path=='/synthetic/docker.sock' and timeout==10
        def request(self,method,path,body,headers):
            assert path.startswith('/containers/'+profile['actor']['container_id'])
            self.body=b'';self.status=204
            if path.endswith('/update'):
                state['actions'].append('policy')
                native['inspect']['HostConfig']['RestartPolicy']=json.loads(body)['RestartPolicy']
                self.status=200;self.body=b'{"Warnings":null}'
            elif path.endswith('/start'):
                state['actions'].append('start')
                native['inspect']['State'].update(Running=True,Status='running',Pid=45,StartedAt='2026-11-18T09:01:00Z',ExitCode=0)
                native['capture']['process'].update(pid=45,start_ticks='56')
                if state['fault']=='start_lost':raise OSError('lost start ACK')
                if state['fault']=='start_304':self.status=304
                if state['fault']=='start_binding':native['binding']['state']='drift'
            else:
                assert method=='GET' and '/logs?' in path;state['actions'].append('logs')
                self.status=200;self.body=frame(b''.join(log_lines()))
                if state['fault']=='logs':self.body=self.body[:-1]
        def getresponse(self):
            stream=io.BytesIO(self.body);stream.status=self.status;return stream
        def close(self):pass
    state['exited']=False
    observer.process._view=lambda pid:deepcopy(native['capture']['process'])
    def pidfd(pid,flags):
        assert (pid,flags)==(profile['capture']['process']['pid'],0)
        return os.open('/dev/null',os.O_RDONLY)
    class Poll:
        def register(self,fd,events):assert events==select.POLLIN;self.fd=fd
        def poll(self,timeout):return [(self.fd,select.POLLIN)] if state['exited'] else []
    def send(fd,number,info,flags):
        assert number==signal.SIGTERM and info is None and flags==0
        state['actions'].append('term');state['exited']=True
        native['inspect']['State'].update(Running=False,Status='exited',Pid=0,ExitCode=143)
        if state['after_term']:state['after_term']()
    term=OriginalImageBuildTerm(process=observer.process,pidfd_open=pidfd,poll_factory=Poll,
                               send_signal=send,namespace_pid=lambda pid:1)
    engine=ImageBuildEngine(profile['actor']['container_id'],socket_path='/synthetic/docker.sock',connection=Connection)
    drivers['executor']=ImageBuildExecutor(commands,hold,observer,engine=engine,term=term)
    op='1'*32
    hold.prepare(op,scope=scope,original_actor=profile['actor'],restart_policy=profile['policy'],
                 binding_sha256=fingerprint(profile['binding']),jobs_sha256=native['ledger']['jobs_sha256'])
    return hold,op,state,native,commands,drivers['executor']


def test_real_dispatch_and_observation_complete_hold_restore_and_startup_publication(executor):
    hold,op,state,_,commands,_=executor
    assert hold.acquire(op)['held'] is True
    assert state['actions']==['policy','term','logs']
    state['cleanup']=True
    assert hold.restore(op)['phase']=='restored'
    value=hold.read(op);start=value['actions']['start']
    proof=commands.details(start['reference'])['details']['startup']
    assert proof['actor']==start['outcome']['evidence']['actor']
    assert proof['capture']['process']['pid']==45 and proof['generation']['started_at']=='2026-11-18T09:01:00Z'
    assert state['actions']==['policy','term','logs','start','policy']
    assert hold.restore(op)['phase']=='restored'


@pytest.mark.parametrize('fault',['logs','ledger','activity','window','exit_code'])
def test_stop_postcondition_failure_stays_pending_without_second_term(executor,fault):
    hold,op,state,native,commands,adapter=executor
    if fault=='logs':state['fault']='logs'
    else:
        def after():
            if fault=='ledger':native['ledger']['ledger_sha256']='8'*64
            elif fault=='activity':native['activity']=False
            elif fault=='exit_code':native['inspect']['State']['ExitCode']=137
            else:state['window']=False
        state['after_term']=after
    with pytest.raises(TemplateError):hold.acquire(op)
    assert hold.read(op)['phase']=='policy_disabled'
    reference=hold.read(op)['actions']['stop']['reference']
    assert commands.outcome(reference) is None
    item=hold.read(op)['actions']['stop']
    with pytest.raises(TemplateError,match='already attempted'):
        adapter(item['command'],reference)
    with pytest.raises(TemplateError,match='uncertain'):hold.acquire(op,recover=True)
    assert state['actions'].count('term')==1


@pytest.mark.parametrize('fault',['start_lost','start_304','start_binding'])
def test_uncertain_or_unqualified_start_never_restarts_again(executor,fault):
    hold,op,state,native,commands,_=executor;hold.acquire(op)
    state.update(cleanup=True,fault=fault)
    with pytest.raises((OSError,TemplateError)):hold.restore(op)
    reference=hold.read(op)['actions']['start']['reference']
    assert commands.outcome(reference) is None and hold.read(op)['phase']=='cleanup_verified'
    with pytest.raises(TemplateError,match='uncertain'):hold.restore(op,recover=True)
    assert state['actions'].count('start')==1
    assert native['inspect']['HostConfig']['RestartPolicy']==dict(Name='no',MaximumRetryCount=0)


def test_executor_rejects_missing_reference_without_native_action(executor):
    hold,op,state,_,commands,adapter=executor
    command=dict(action='stop')
    with pytest.raises(Conflict,match='reference missing'):
        adapter(command,dict(token='0'*32))
    assert state['actions']==[]


def test_delayed_docker_exit_is_observed_without_another_term(executor):
    hold,op,state,native,_,adapter=executor;pauses=[]
    state['after_term']=lambda:native['inspect']['State'].update(Running=True,Status='running',Pid=44)
    def pause(delay):
        pauses.append(delay)
        native['inspect']['State'].update(Running=False,Status='exited',Pid=0)
    adapter.pause=pause
    assert hold.acquire(op)['held'] is True
    assert pauses==[0.05] and state['actions'].count('term')==1


def test_docker_exit_timeout_retains_original_dispatch_without_resend(executor):
    hold,op,state,native,_,adapter=executor
    state['after_term']=lambda:native['inspect']['State'].update(Running=True,Status='running',Pid=44)
    times=iter([0,11]);adapter.clock=lambda:next(times)
    with pytest.raises(TemplateError,match='exit observation timed out'):hold.acquire(op)
    with pytest.raises(TemplateError,match='uncertain'):hold.acquire(op,recover=True)
    assert state['actions']==['policy','term']


def test_native_dispatch_checkpoint_rechecks_window_before_first_docker_mutation(executor,monkeypatch):
    hold,op,state,_,commands,_=executor;save=commands._save
    def checkpoint(value):
        save(value)
        if value.get('native_dispatch_started'):state['window']=False
    monkeypatch.setattr(commands,'_save',checkpoint)
    with pytest.raises(TemplateError,match='window'):hold.acquire(op)
    value=hold.read(op);item=value['actions']['disable_restart']
    assert value['phase']=='prepared' and commands.outcome(item['reference']) is None
    assert state['actions']==[]


def test_readiness_refused_connection_waits_on_same_generation_without_second_start(executor):
    hold,op,state,_,_,adapter=executor;hold.acquire(op);state['cleanup']=True
    query=adapter.observation.query;attempts=[];pauses=[]
    def ready(value,capture):
        attempts.append(capture['process']['pid'])
        if len(attempts)==1:raise ImageBuildApiNotReady('original API starting')
        return query(value,capture)
    adapter.observation.query=ready;adapter.pause=pauses.append
    assert hold.restore(op)['phase']=='restored'
    assert attempts[:2]==[45,45] and pauses==[0.05] and state['actions'].count('start')==1


@pytest.mark.parametrize('fault',['timeout','process','window'])
def test_startup_wait_conflict_keeps_original_start_pending_without_adoption(executor,fault):
    hold,op,state,native,commands,adapter=executor;hold.acquire(op);state['cleanup']=True
    attempts=[];now=[0]
    def unavailable(value,capture):
        attempts.append(capture['process']['pid'])
        raise ImageBuildApiNotReady('original API starting')
    def pause(delay):
        if fault=='timeout':now[0]=31
        elif fault=='process':native['inspect']['State']['Pid']=99
        else:state['window']=False
    adapter.observation.query=unavailable;adapter.pause=pause;adapter.clock=lambda:now[0]
    with pytest.raises(TemplateError):hold.restore(op)
    assert attempts==[45] and state['actions'].count('start')==1
    assert commands.outcome(hold.read(op)['actions']['start']['reference']) is None
    with pytest.raises(TemplateError,match='uncertain'):hold.restore(op,recover=True)


def test_startup_readiness_still_requires_full_activity_after_api_is_ready(executor):
    hold,op,state,native,_,adapter=executor;hold.acquire(op);state['cleanup']=True
    start=adapter.engine.start;query=adapter.observation.query
    def starting():start();native['activity']=False
    adapter.engine.start=starting
    def ready(value,capture):
        native['activity']=True
        return query(value,capture)
    adapter.observation.query=ready
    assert hold.restore(op)['phase']=='restored'
    assert state['actions'].count('start')==1


def test_non_api_connection_refusal_is_not_a_readiness_retry(executor):
    hold,op,state,_,_,adapter=executor;hold.acquire(op);state['cleanup']=True
    start=adapter.engine.start;pauses=[]
    def unavailable(value):raise ConnectionRefusedError('Docker lock transport unavailable')
    def started():
        start();adapter.observation.binding=unavailable
    adapter.engine.start=started;adapter.pause=pauses.append
    with pytest.raises(ConnectionRefusedError,match='Docker lock'):hold.restore(op)
    assert pauses==[] and state['actions'].count('start')==1


def test_ready_api_with_residual_activity_does_not_complete_start(executor):
    hold,op,state,native,commands,adapter=executor;hold.acquire(op);state['cleanup']=True
    start=adapter.engine.start;pauses=[]
    def started():start();native['activity']=False
    adapter.engine.start=started;adapter.pause=pauses.append
    with pytest.raises(TemplateError,match='activity'):hold.restore(op)
    assert commands.outcome(hold.read(op)['actions']['start']['reference']) is None
    assert pauses==[] and state['actions'].count('start')==1
