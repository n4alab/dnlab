"""Original parent/waiter and child frames entirely simulated."""
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from libvirt_loop_canary_transport import LoopCanaryParent, serve
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint


@pytest.fixture
def transport(tmp_path):
    journal=Journal(tmp_path/'journal')
    request=dict(nonce='a'*32,command=dict(binary=dict(path='/qualified/python',sha256='b'*64),
        argv=['/qualified/python','-B','-I','-S','/proc/self/fd/worker'],
        environment=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',LIBVIRT_AUTOSTART='0')))
    record=dict(pid=123,executable_sha256='b'*64)
    epoch=dict(id='c'*32,snapshot=dict(record=record))
    result=dict(phase='awaiting_process_exit',qualified=True,cleanup_verified=False,
        requires_original_process_exit=True,gate_allowed=False,epoch_sha256=fingerprint(epoch))
    state=dict(spawns=0,frames=[],waits=0,timeout=False,verified=True,status=0,retired=False,reads=0,
               stdout='',stderr='')
    class Input(io.BytesIO):
        def write(self,data):state['frames'].append(data);return super().write(data)
    class Process:
        pid=123
        args=request['command']['argv']
        stdin=Input();stdout=io.BytesIO();stderr=io.BytesIO()
        def wait(self,timeout):
            assert timeout==10 and self.stdin.closed;state['waits']+=1
            if state['timeout']:raise TimeoutError('original waiter timeout')
            return state['status']
    process=Process()
    class Observer:
        def capture(self,current):assert current is process;return deepcopy(record)
        def bind(self,reference,current,command):assert current is process
        def verify(self,reference,current,command,phase):assert current is process;return state['verified']
        def exit(self,current,reference):assert current is process and current.stdin.closed;return True
        def retire(self,reference):state['retired']=True
    def spawn(command):assert command==request['command'];state['spawns']+=1;return process
    frames=[dict(ready=request['nonce'],request_sha256=fingerprint(request)),
            dict(result=deepcopy(result),epoch=deepcopy(epoch),request_sha256=fingerprint(request))]
    def read_frame(current):
        assert current is process;state['reads']+=1
        return deepcopy(frames[state['reads']-1])
    parent=LoopCanaryParent(journal,observer=Observer(),spawn=spawn,
                            preflight=lambda packet:fingerprint(request),read_frame=read_frame,
                            read_output=lambda process,partial:dict(exit_code=state['status'],stdout=state['stdout'],stderr=state['stderr']))
    yield SimpleNamespace(parent=parent,request=request,journal=journal,state=state,frames=frames,
                          process=process,record=record,result=result,epoch=epoch)
    journal.close()


def test_parent_binds_original_process_and_releases_once_then_qualifies_exit(transport):
    e=transport;result=e.parent.run(e.request)
    assert result['phase']=='completed' and result['qualified'] and result['cleanup_verified']
    assert result['exit_code']==0 and e.state['retired'] and e.state['spawns']==1
    assert [json.loads(frame) for frame in e.state['frames']]==[
        dict(release=e.request['nonce'],request_sha256=fingerprint(e.request))]
    assert e.process.stdout.closed and e.process.stderr.closed
    with pytest.raises(RuntimeErrorBase,match='cannot be replaced'):e.parent.run(e.request)
    assert e.state['spawns']==1


@pytest.mark.parametrize('fault',['ready','report_process','report_gate','status','verify'])
def test_bad_evidence_never_qualifies_canary_or_starts_another_process(transport,fault):
    e=transport
    if fault=='ready':e.frames[0]['ready']='d'*32
    elif fault=='report_process':e.frames[1]['epoch']['snapshot']['record']['pid']=456
    elif fault=='report_gate':e.frames[1]['result']['gate_allowed']=True
    elif fault=='status':e.state['status']=7
    else:e.state['verified']=False
    if fault=='status':result=e.parent.run(e.request)
    else:
        with pytest.raises(RuntimeErrorBase):e.parent.run(e.request)
        result=e.parent._read()
    assert result['phase']=='failed' and not result['qualified'] and result['cleanup_verified']
    assert e.state['spawns']==1 and e.process.stdin.closed


def test_exit_timeout_retains_original_waiter_for_observation_only_recovery(transport):
    e=transport;e.state['timeout']=True
    with pytest.raises(TimeoutError,match='original waiter'):e.parent.run(e.request)
    saved=e.parent._read()
    assert saved['phase']=='pending' and not saved['cleanup_verified'] and not e.state['retired']
    assert len(e.state['frames'])==1 and e.parent.process is e.process
    assert not e.process.stdout.closed and not e.process.stderr.closed
    e.state['timeout']=False
    result=e.parent.recover_exit()
    assert result['phase']=='failed' and not result['qualified'] and result['cleanup_verified']
    assert len(e.state['frames'])==1 and e.state['spawns']==1 and e.state['retired']
    assert e.process.stdout.closed and e.process.stderr.closed


def test_reopened_parent_cannot_adopt_waiter_or_launch_another_child(transport):
    e=transport;e.parent.run(e.request)
    other=LoopCanaryParent(e.journal,observer=e.parent.observer,spawn=e.parent.spawn,preflight=e.parent.preflight)
    with pytest.raises(RuntimeErrorBase,match='original parent'):other.recover_exit()
    with pytest.raises(RuntimeErrorBase,match='one-shot'):other.run(e.request)
    assert e.state['spawns']==1


@pytest.mark.parametrize('release',[None,dict(release='foreign')])
def test_child_eof_or_foreign_release_never_enters_sdk_runner(transport,release):
    e=transport;written=[];calls=[]
    with pytest.raises(RuntimeErrorBase,match='parent release'):
        serve(e.request,object(),object(),preflight=lambda:None,read_frame=lambda:release,write_frame=written.append,
              runner=lambda *args,**kwargs:calls.append(True))
    assert not calls and written==[dict(ready=e.request['nonce'],request_sha256=fingerprint(e.request))]


def test_child_reports_original_epoch_then_requires_eof(transport):
    e=transport;frames=iter([dict(release=e.request['nonce'],request_sha256=fingerprint(e.request)),None]);written=[]
    runtime=SimpleNamespace(check=lambda:deepcopy(e.epoch))
    assert serve(e.request,runtime,object(),preflight=lambda:None,read_frame=lambda:next(frames),write_frame=written.append,
                 runner=lambda *args,**kwargs:deepcopy(e.result))==0
    assert written[1]==dict(result=e.result,epoch=e.epoch,request_sha256=fingerprint(e.request))


def test_extra_child_stdout_is_preserved_and_fails_qualification(transport):
    e=transport;e.state.update(stdout='unexpected extra frame\n',stderr='original child diagnostic\n')
    result=e.parent.run(e.request)
    assert result['phase']=='failed' and not result['qualified'] and result['cleanup_verified']
    assert result['output']['stdout']==e.state['stdout'] and result['output']['stderr']==e.state['stderr']
