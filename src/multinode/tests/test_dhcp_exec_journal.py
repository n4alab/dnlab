"""Crash boundaries of one persisted Docker exec and one daemon generation."""
from copy import deepcopy

import pytest

from dnlab_multinode.services import jumphost_host as module


class World:
    def __init__(self):
        self.container={'id':'c'*64,'image':'sha256:'+'b'*64,'started_at':'original','namespace':1}
        self.intent={'nonce':'a'*32,'container':deepcopy(self.container),'phase':'intent',
            'exec_id':None,'create_attempts':0,'start_attempted':False,'observed_exec_ids':[],'service':None}
        self.saved=deepcopy(self.intent);self.execs={};self.calls=[];self.starts=0;self.service=None
        self.fault=None;self.fail_save=None

    def save(self):
        if self.fail_save and self.fail_save(self.intent):raise OSError('journal fsync failed')
        self.saved=deepcopy(self.intent)

    def reopen(self):
        self.intent=deepcopy(self.saved)

    def preflight(self):
        if self.fault=='preflight':raise module.JumphostError('original assets replaced')
        return {'container':deepcopy(self.container),'exec_ids':list(self.execs)}

    def runner(self):
        return module.JournaledDHCPExec(self.intent,self.save,self.preflight,lambda:deepcopy(self.service),docker=self)

    def call(self,method,path,payload=None,*,missing=False):
        self.calls.append((method,path,deepcopy(payload)))
        if path.endswith('/exec'):
            if self.fault=='before-create':raise module.JumphostError('request not delivered')
            identity=f'{len(self.execs)+1:064x}'
            self.execs[identity]={'ID':identity,'ContainerID':self.container['id'],
                'ProcessConfig':{'tty':False,'privileged':False,'user':'0',
                    'entrypoint':payload['Cmd'][0],'arguments':payload['Cmd'][1:]},
                'OpenStdin':False,'OpenStdout':False,'OpenStderr':False,
                'Running':False,'ExitCode':None,'Pid':0}
            if self.fault=='after-create':raise module.JumphostError('create reply lost')
            return {'Id':identity}
        identity=path.split('/')[2]
        if method=='GET':
            if identity not in self.execs and not missing:raise module.DockerExecError(404)
            return deepcopy(self.execs.get(identity))
        assert path.endswith('/start')
        if self.fault=='before-start':raise module.JumphostError('start request not delivered')
        value=self.execs[identity]
        if value['Running'] or value['ExitCode'] is not None:raise module.DockerExecError(409)
        self.starts+=1
        value.update(Running=False,ExitCode=0,Pid=90)
        self.service={'container':deepcopy(self.container),'operation_nonce':self.intent['nonce'],'host_pid':77,'start':'first'}
        if self.fault=='after-start':raise module.JumphostError('start reply lost')
        return {}


def test_success_and_idempotent_retry_keep_one_exec_and_one_process():
    w=World();result=w.runner().run()
    assert result==w.service and w.saved['phase']=='ready'
    assert w.runner().run()==result and len(w.execs)==w.starts==1


@pytest.mark.parametrize('fault',['before-create','after-create','before-start','after-start'])
def test_lost_requests_and_replies_resume_original_intent(fault):
    w=World();w.fault=fault
    with pytest.raises(module.JumphostError):w.runner().run()
    w.reopen();w.fault=None
    assert w.runner().run()==w.service
    assert len(w.execs)==w.starts==1


@pytest.mark.parametrize('phase',['before-create','created','starting','ready'])
def test_save_failure_never_executes_past_an_unpersisted_boundary(phase):
    w=World()
    def fail(intent):
        if phase=='before-create':return intent['create_attempts']>0
        return intent['phase']==phase
    w.fail_save=fail
    with pytest.raises(OSError):w.runner().run()
    if phase in ('before-create','created','starting'):assert w.starts==0
    w.reopen();w.fail_save=None
    assert w.runner().run()==w.service
    assert len(w.execs)==w.starts==1


def created():
    w=World();w.fault='before-start'
    with pytest.raises(module.JumphostError):w.runner().run()
    w.reopen();w.fault=None
    return w


def test_missing_bound_exec_without_service_never_allocates_another_exec():
    w=created();w.execs={};before=len(w.calls)
    with pytest.raises(module.JumphostError,match='missing'):w.runner().run()
    assert all(method=='GET' for method,path,payload in w.calls[before:]) and w.starts==0


def test_missing_exec_metadata_can_recover_a_fully_qualified_started_daemon():
    w=World();w.fault='after-start'
    with pytest.raises(module.JumphostError):w.runner().run()
    w.reopen();w.fault=None;w.execs={}
    assert w.runner().run()==w.service and w.starts==1


@pytest.mark.parametrize('change',['container','command','user','stdin','status','id'])
def test_foreign_or_malformed_exec_is_refused_before_start(change):
    w=created();value=w.execs[w.intent['exec_id']]
    if change=='container':value['ContainerID']='f'*64
    if change=='command':value['ProcessConfig']['entrypoint']='sh'
    if change=='user':value['ProcessConfig']['user']='65534'
    if change=='stdin':value['OpenStdin']=True
    if change=='status':value['Running']='false'
    if change=='id':value['ID']='f'*64
    with pytest.raises(module.JumphostError,match='ownership'):w.runner().run()
    assert w.starts==0


def test_lost_create_does_not_adopt_an_execution_without_persisted_start():
    w=World();w.fault='after-create'
    with pytest.raises(module.JumphostError):w.runner().run()
    w.reopen();w.fault=None;next(iter(w.execs.values())).update(ExitCode=0,Pid=90)
    with pytest.raises(module.JumphostError,match='already run'):w.runner().run()
    assert w.starts==0


@pytest.mark.parametrize('change',['nonce','container','absent'])
def test_ready_retry_refuses_replacement_and_never_restarts(change):
    w=World();w.runner().run()
    if change=='nonce':w.service['operation_nonce']='f'*32
    if change=='container':w.service['container']['id']='f'*64
    if change=='absent':w.service=None
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.starts==1


def test_preflight_failure_and_unbound_service_prevent_create():
    for fault in ('preflight','service'):
        w=World()
        if fault=='preflight':w.fault=fault
        else:w.service={'container':deepcopy(w.container),'operation_nonce':w.intent['nonce']}
        with pytest.raises(module.JumphostError):w.runner().run()
        assert w.calls==[]


def test_completed_exec_without_start_intent_is_not_adopted():
    w=created();w.intent['start_attempted']=False
    w.intent['phase']='created'
    w.execs[w.intent['exec_id']].update(ExitCode=0,Pid=90)
    with pytest.raises(module.JumphostError,match='persisted start'):w.runner().run()
    assert w.starts==0


@pytest.mark.parametrize('change',['ready-proof','exec-membership','phase','unbound-start'])
def test_inconsistent_journal_rejected_before_any_docker_call(change):
    w=World()
    if change=='ready-proof':
        w.runner().run();w.intent['service']=None
    if change=='exec-membership':
        w=created();w.intent['observed_exec_ids']=[]
    if change=='phase':w.intent['phase']='created'
    if change=='unbound-start':w.intent['start_attempted']=True
    count=len(w.calls)
    with pytest.raises(module.JumphostError,match='inconsistent'):w.runner().run()
    assert len(w.calls)==count


@pytest.mark.parametrize('completed',[False,True])
def test_start_conflict_is_accepted_only_when_same_exec_really_ran(completed):
    w=World();call=w.call
    def race(method,path,payload=None,**kwargs):
        if method=='POST' and path.endswith('/start'):
            if completed:call(method,path,payload,**kwargs)
            raise module.DockerExecError(409)
        return call(method,path,payload,**kwargs)
    w.call=race
    if completed:
        assert w.runner().run()==w.service and w.starts==1
    else:
        with pytest.raises(module.DockerExecError) as error:w.runner().run()
        assert error.value.status==409 and w.starts==0
    assert len(w.execs)==1
