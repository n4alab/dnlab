"""Canary transport is simulated; no process or host observation is performed."""
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import libvirt_account_observer_canary as canary
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict


@pytest.fixture
def fixture(tmp_path):
    binary=tmp_path/'python';binary.write_bytes(b'\x7fELFsynthetic interpreter')
    profile=dict(path='/qualified/python',sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    state=dict(spawns=[],ready=True,verified=True,status=0,closed=False,events=[],timeout=False)
    class Process:
        pid=123
        def __init__(self):self.stdin=io.BytesIO();self.stdout=io.BytesIO();self.stderr=io.BytesIO()
        def wait(self,timeout):
            assert timeout==12 and self.stdin.closed
            state['events'].append('wait')
            if state['timeout']:raise TimeoutError('synthetic original waiter timeout')
            return state['status']
    def spawn(argv,**kwargs):
        state['spawns'].append((argv,kwargs));state['process']=Process();return state['process']
    class Observer:
        def capture(self,process):return dict(pid=process.pid,executable_sha256=profile['sha256'])
        def bind(self,reference,process,command):state['events'].append('bind')
        def verify(self,reference,process,command,phase):return state['verified']
        def exit(self,process,reference):
            assert process.stdin.closed;state['events'].append('exit');return True
        def retire(self,reference):state['events'].append('retire')
        def close(self):state['closed']=True
    @contextmanager
    def opener(path):
        assert path==profile['path']
        with binary.open('rb') as stream:yield stream.fileno()
    observer=Observer();journal=Journal(tmp_path/'journal')
    def run():return canary.run(journal,profile,spawn=spawn,observer=observer,opener=opener,
        read_ready=lambda process:dict(ready='observer-canary' if state['ready'] else 'foreign'))
    yield run,state,journal
    journal.close()


def row(journal):return json.loads(journal.db.execute('SELECT payload FROM libvirt_account_observer_canaries').fetchone()['payload'])


def test_canary_only_runs_fixed_inert_python_then_eof(fixture):
    run,state,journal=fixture;result=run()
    assert result['qualified'] and result['cleanup_verified'] and result['phase']=='completed'
    assert state['events']==['bind','wait','exit','retire','wait'] and state['closed']
    argv,options=state['spawns'][0]
    assert argv==['/qualified/python','-B','-I','-S','-c',canary.CHILD]
    assert options['close_fds'] and options['cwd']=='/' and len(options['pass_fds'])==1
    assert not any('useradd' in value or 'groupadd' in value for value in argv)
    assert state['process'].stdout.closed and state['process'].stderr.closed
    assert row(journal)==result


@pytest.mark.parametrize('fault',['readiness','verify','exit_status','timeout'])
def test_failure_stays_pending_without_signal_or_second_process(fixture,fault):
    run,state,journal=fixture
    if fault=='readiness':state['ready']=False
    elif fault=='verify':state['verified']=False
    elif fault=='exit_status':state['status']=4
    else:state['timeout']=True
    with pytest.raises((Conflict,TimeoutError)):run()
    saved=row(journal)
    assert saved['phase']=='pending' and saved['cleanup_verified'] is False
    assert state['closed'] and len(state['spawns'])==1
    assert state['process'].stdin.closed
    assert state['process'].stdout.closed and state['process'].stderr.closed


def test_reopened_journal_does_not_start_another_process(fixture):
    run,state,journal=fixture;run()
    with pytest.raises(Conflict,match='one-shot'):run()
    assert len(state['spawns'])==1 and row(journal)['phase']=='completed'


def test_no_execution_without_explicit_switch(tmp_path,monkeypatch):
    monkeypatch.setattr(sys,'argv',['canary','--python','/qualified/python','--sha256','a'*64,'--output',str(tmp_path/'new')])
    with pytest.raises(SystemExit) as error:canary.main()
    assert error.value.code==2 and not (tmp_path/'new').exists()
