"""Retirement journal/dispatch tests with simulated original canary and I/O."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_canary_cleanup import CanaryCleanup
from dnlab_runtime.journal import Journal
from dnlab_runtime.vm_template import TemplateError, require
from test_image_build_canary import canary


@pytest.fixture
def cleanup(canary,tmp_path):
    _,_,request,current,_=canary;journal=Journal(tmp_path/'journal');cid=current['Id']
    current.update(RestartCount=0);current['State'].update(Running=True,Pid=45,StartedAt='original-start',ExitCode=0)
    config=deepcopy(request['config']);config['Labels']=deepcopy(current['Config']['Labels'])
    record=dict(id='c'*32,container_id=cid,phase='running',effective_config=config,original=dict(config=request['config']))
    state=dict(current=current,record=record,actions=[],fault=None,ledger=True,race=False)
    class Docker:
        def inspect(self,identity):
            return deepcopy(state['current']) if identity in (cid,request['spec']['container_name']) else None
        def remove(self,identity):
            assert identity==cid and not state['current']['State']['Running']
            state['actions'].append('remove');state['current']=None
            if state['fault']=='remove':state['fault']=None;raise OSError('lost remove response')
        def signal(self,*args):pytest.fail('untracked signal reached native transport')
    backend=SimpleNamespace(docker=Docker())
    class Fixture:
        def get(self):return deepcopy(state['record'])
        def bind_response(self,value):
            current=backend.docker.inspect(cid)
            require(current is not None and current['Id']==value['container_id'], 'original fixture ID differs')
            return current
        def cleanup(self):
            if state['race']:
                state['current']['State'].update(Running=True,Status='running',Pid=99)
            current=backend.docker.inspect(request['spec']['container_name'])
            if current is not None:
                if current['State']['Running']:backend.docker.signal(cid,'SIGTERM')
                backend.docker.remove(cid)
            state['record']['phase']='cleaned'
    fixture=Fixture();fixture.journal=journal;fixture.backend=backend
    fixture.request=request['request'];fixture.spec=request['spec']
    startup=dict(reference=dict(token='original'),capture=dict(process=dict(pid=45)),
                 generation=dict(started_at='original-start',restart_count=0),actor=dict(original=True))
    hold=dict(phase='restored',actor=dict(container_id=cid),actions=dict(start=dict(reference=startup['reference'])))
    class Observation:
        def __call__(self,value):
            return dict(actor=startup['actor'],running=state['current']['State']['Running'],
                        restart_policy=deepcopy(state['current']['HostConfig']['RestartPolicy']))
        def _conditions(self,value,pid):require(state['ledger'], 'original ledger differs')
    class Engine:
        container_id=cid
        def update_policy(self,policy):
            state['actions'].append('policy');state['current']['HostConfig']['RestartPolicy']=deepcopy(policy)
            if state['fault']=='policy':raise OSError('lost policy response')
        def shutdown_logs(self,started,pid):
            assert (started,pid)==('original-start',1)
            return dict(ordinary_shutdown_log_verified=True,namespace_pid=1)
    class Term:
        @contextmanager
        def pin(self,capture,identity,copies):
            assert capture==startup['capture'] and identity==cid;yield self
        def term(self,preflight):
            assert preflight() is True;state['actions'].append('term')
            state['current']['State'].update(Running=False,Status='exited',Pid=0,ExitCode=143)
            if state['fault']=='term':raise OSError('lost TERM result')
            return dict(pidfd_exit_verified=True,term_count=1,force_used=False,namespace_pid=1)
    session=SimpleNamespace(runtime=SimpleNamespace(journal=journal,check=lambda:None),
        hold=SimpleNamespace(read=lambda op:deepcopy(hold)),commands=SimpleNamespace(details=lambda ref:dict(details=dict(startup=deepcopy(startup)))),
        executor=SimpleNamespace(engine=Engine(),term=Term(),clock=lambda:0,pause=lambda _:None),
        observation=Observation(),profile=dict(copies={}))
    driver=CanaryCleanup(fixture,session,'a'*32)
    try:yield driver,state,journal
    finally:journal.close()


def test_retirement_updates_policy_terms_and_removes_only_after_verified_exit(cleanup):
    driver,state,journal=cleanup;intent=driver.prepare()
    assert state['actions']==[]
    result=driver.execute(intent['id']);assert result['phase']=='removed'
    assert state['actions']==['policy','term','remove']
    assert journal.db.execute('SELECT 1 FROM resources').fetchone() is None
    assert driver.execute(intent['id'])==result and state['actions']==['policy','term','remove']


@pytest.mark.parametrize('fault',['policy','term'])
def test_uncertain_policy_or_term_is_not_resent(cleanup,fault):
    driver,state,_=cleanup;intent=driver.prepare();state['fault']=fault
    with pytest.raises(OSError):driver.execute(intent['id'])
    before=list(state['actions'])
    with pytest.raises(TemplateError,match='uncertain'):driver.execute(intent['id'])
    assert state['actions']==before and 'remove' not in before


def test_lost_remove_response_recovers_absence_without_second_delete_or_signal(cleanup):
    driver,state,journal=cleanup;intent=driver.prepare();state['fault']='remove'
    with pytest.raises(OSError,match='remove'):driver.execute(intent['id'])
    assert driver.execute(intent['id'])['phase']=='removed'
    assert state['actions']==['policy','term','remove']
    assert journal.db.execute('SELECT 1 FROM resources').fetchone() is None


def test_foreign_identity_after_policy_checkpoint_blocks_native_update(cleanup,monkeypatch):
    driver,state,_=cleanup;intent=driver.prepare();save=driver._save
    def checkpoint(value):
        save(value)
        if value['phase']=='policy_requested':state['current']['Id']='f'*64
    monkeypatch.setattr(driver,'_save',checkpoint)
    with pytest.raises(TemplateError,match='ID'):driver.execute(intent['id'])
    assert state['actions']==[]


def test_restart_race_during_final_fixture_cleanup_cannot_send_another_signal(cleanup):
    driver,state,_=cleanup;intent=driver.prepare();state['race']=True
    with pytest.raises(TemplateError,match='another signal'):driver.execute(intent['id'])
    assert state['actions']==['policy','term'] and state['current'] is not None
