"""Actual sealed memfd and file reads; Popen and process exit are simulated."""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from libvirt_loop_canary_launcher import FDLoopLauncher, ENVIRONMENT, SEALS
from libvirt_loop_canary_transport import LoopCanaryParent
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint


@pytest.fixture
def launcher(tmp_path):
    journal=Journal(tmp_path/'journal');python=tmp_path/'python';worker=tmp_path/'worker.py'
    python.write_bytes(b'\x7fELF'+b'x'*64);worker.write_text('# synthetic child source\n')
    python.chmod(0o755);worker.chmod(0o644)
    profile={name:dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
             for name,path in (('python',python),('worker',worker))}
    state=dict(spawns=0,closed=[],opened=[],kwargs=None,command=None,scope=True,status=None,uncertain=False)
    process=SimpleNamespace(pid=123,poll=lambda:state['status'])
    @contextmanager
    def opener(path):
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);state['opened'].append(fd)
        try:yield fd
        finally:os.close(fd);state['closed'].append(fd)
    def spawn(command,**kwargs):
        state.update(spawns=state['spawns']+1,command=deepcopy(command),kwargs=kwargs)
        if state['uncertain']:raise TimeoutError('synthetic launch outcome unknown')
        process.args=deepcopy(command)
        return process
    def create():return FDLoopLauncher(journal,profile,preflight=lambda value:fingerprint(value) if state['scope'] else None,
                                       opener=opener,spawn=spawn)
    current=create()
    try:yield SimpleNamespace(journal=journal,python=python,worker=worker,profile=profile,state=state,
                             create=create,launcher=current,process=process)
    finally:
        # Fixture-owned FDs only. No process was ever started by these tests.
        current.stack.close();journal.close()


def test_prepares_immutable_inherited_packet_without_starting_a_child(launcher):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,dict(scope='synthetic loop-only child'))
    assert e.state['spawns']==0 and l.check(request)==fingerprint(request)
    assert request['command']['argv']==[str(e.python),'-B','-I','-S',
        '/proc/self/fd/'+str(l.files['worker']),'--bootstrap-fd',str(l.files['bootstrap'])]
    assert request['command']['environment']==ENVIRONMENT
    fd=l.files['bootstrap'];packet=os.pread(fd,1024*1024,0)
    assert json.loads(packet)==dict(request=request,bootstrap=dict(scope='synthetic loop-only child'))
    assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==SEALS
    for action in (lambda:os.write(fd,b'x'),lambda:os.ftruncate(fd,0)):
        with pytest.raises(OSError):action()
    assert l.check(request)==fingerprint(request)
    l.close();assert l.closed and len(e.state['opened'])==len(e.state['closed'])
    with pytest.raises(RuntimeErrorBase):l.spawn(request['command'])


def test_original_waiter_is_returned_with_only_pinned_fds_and_fixed_environment(launcher):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,{})
    process=l.spawn(request['command'])
    assert process is e.process and e.state['spawns']==1
    kwargs=e.state['kwargs']
    assert kwargs['executable']=='/proc/self/fd/'+str(l.files['python'])
    assert set(kwargs['pass_fds'])==set(l.files.values())
    assert kwargs['close_fds'] is True and kwargs['cwd']=='/' and kwargs['env']==ENVIRONMENT
    assert l.check(request)==fingerprint(request)
    with pytest.raises(RuntimeErrorBase):l.spawn(request['command'])
    with pytest.raises(RuntimeErrorBase):l.close()
    assert not l.closed and e.state['spawns']==1


@pytest.mark.parametrize('fault',['scope','worker','python','command','journal'])
def test_changed_evidence_is_refused_before_popen(launcher,fault):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,{})
    command=deepcopy(request['command'])
    if fault=='scope':e.state['scope']=False
    elif fault=='worker':e.worker.write_text('# changed child\n')
    elif fault=='python':e.python.write_bytes(b'\x7fELFchanged')
    elif fault=='command':command['argv'].append('--foreign')
    else:
        with e.journal.transaction():e.journal.db.execute("UPDATE libvirt_loop_fd_launchers SET fingerprint=?",('0'*64,))
    with pytest.raises(RuntimeErrorBase):l.spawn(command)
    assert e.state['spawns']==0


def test_uncertain_popen_is_never_repeated_and_keeps_original_fds(launcher):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,{});e.state['uncertain']=True
    with pytest.raises(TimeoutError,match='outcome unknown'):l.spawn(request['command'])
    assert l.value['phase']=='pending' and not l.closed and e.state['spawns']==1
    with pytest.raises(RuntimeErrorBase):l.spawn(request['command'])
    with pytest.raises(RuntimeErrorBase):l.close()
    assert e.state['spawns']==1 and len(e.state['closed'])==0


def test_reopened_launcher_cannot_overwrite_original_intent_or_close_its_fds(launcher):
    e=launcher;l=e.launcher;l.prepare('a'*32,{})
    original=tuple(e.journal.db.execute('SELECT * FROM libvirt_loop_fd_launchers').fetchone())
    other=e.create()
    with pytest.raises(RuntimeErrorBase,match='one-shot'):other.prepare('a'*32,{})
    with pytest.raises(RuntimeErrorBase):other.close()
    assert tuple(e.journal.db.execute('SELECT * FROM libvirt_loop_fd_launchers').fetchone())==original
    assert not l.closed and other.value is None


@pytest.mark.parametrize('fault',['running','missing_cleanup','different_parent','different_exit'])
def test_launcher_fds_remain_until_qualified_original_parent_exit(launcher,fault):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,{});l.spawn(request['command'])
    result=dict(phase='completed',cleanup_verified=True,exit_code=0)
    e.state['status']=0
    parent=SimpleNamespace(journal=e.journal,request=request,process=e.process,_read=lambda:deepcopy(result))
    if fault=='running':e.state['status']=None
    elif fault=='missing_cleanup':result['cleanup_verified']=False
    elif fault=='different_parent':parent.process=object()
    else:e.state['status']=1
    with pytest.raises(RuntimeErrorBase):l.close(parent=parent)
    assert not l.closed and len(e.state['closed'])==0


def test_qualified_original_parent_exit_releases_own_descriptors_once(launcher):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,{});l.spawn(request['command'])
    e.state['status']=0
    parent=SimpleNamespace(journal=e.journal,request=request,process=e.process,
        _read=lambda:dict(phase='completed',cleanup_verified=True,exit_code=0))
    fds=list(l.files.values());l.close(parent=parent)
    assert l.closed and l.value['phase']=='closed'
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(RuntimeErrorBase):l.close(parent=parent)


def test_fd_launcher_composes_with_real_parent_journal_release_and_exit(launcher):
    e=launcher;l=e.launcher;request=l.prepare('a'*32,dict(scope='synthetic'))
    process=e.process;process.stdin=io.BytesIO();process.stdout=io.BytesIO();process.stderr=io.BytesIO()
    def wait(timeout):
        assert timeout==10 and process.stdin.closed
        e.state['status']=0;return 0
    process.wait=wait
    record=dict(pid=123,executable_sha256=e.profile['python']['sha256'])
    epoch=dict(snapshot=dict(record=record))
    class Observer:
        def capture(self,current):assert current is process;return deepcopy(record)
        def bind(self,reference,current,command):assert current is process
        def verify(self,reference,current,command,phase):return current is process
        def exit(self,current,reference):return current is process and e.state['status']==0
        def retire(self,reference):pass
    frames=iter([dict(ready=request['nonce'],request_sha256=fingerprint(request)),
        dict(request_sha256=fingerprint(request),epoch=epoch,result=dict(phase='awaiting_process_exit',
            qualified=True,cleanup_verified=False,requires_original_process_exit=True,gate_allowed=False,
            epoch_sha256=fingerprint(epoch)))])
    parent=LoopCanaryParent(e.journal,observer=Observer(),spawn=l.spawn,preflight=l.check,
        read_frame=lambda current:next(frames),
        read_output=lambda current,state:dict(exit_code=0,stdout='',stderr=''))
    result=parent.run(request)
    assert result['qualified'] and result['cleanup_verified'] and result['phase']=='completed'
    assert e.state['spawns']==1 and process.stdin.closed and process.stdout.closed and process.stderr.closed
    l.close(parent=parent)
    assert l.closed and l.value['phase']=='closed'
