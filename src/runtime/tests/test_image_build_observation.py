"""Concrete observer composition with simulated Docker/process/API providers."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_observation import ImageBuildObservation, artifact_digest, process_digest, terminal_jobs_digest
from cleanup_container_observer import config_digest
from dnlab_runtime.image_build_hold import ImageBuildHold, NO_RESTART
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def observation():
    original_policy = dict(Name='unless-stopped',MaximumRetryCount=0)
    inspected = dict(Id='a'*64,Image='sha256:'+'b'*64,Config={},HostConfig=dict(RestartPolicy=deepcopy(original_policy)),
        Mounts=[],Path='/usr/bin/python3',Args=['api.py'],RestartCount=0,
        State=dict(Pid=44,Running=True,Status='running',StartedAt='original',FinishedAt='',ExitCode=0,OOMKilled=False,Error=''),
        NetworkSettings=dict(Networks=dict(mgmt=dict(NetworkID='network-original',EndpointID='endpoint-original'))))
    capture = dict(process=dict(pid=44,start_ticks='55'),
        sources={'/opt/dnlab-image-build/api.py':dict(sha256='e'*64,metadata=[])},executable=dict(sha256='c'*64))
    context = dict(host_id='master',boot_id='original');generation = dict(started_at='original',restart_count=0)
    binding = dict(state='aligned',repository='https://github.com/n4alab/vrnetlab.git',branch='dnlab',
                   requested_commit='d'*40,current_commit='d'*40,detail=None)
    copies = {'/opt/dnlab-image-build/api.py':'e'*64};jobs=[dict(id='f'*16,status='success')]
    actor = dict(container_id=inspected['Id'],image_id=inspected['Image'],config_sha256=config_digest(inspected),
        artifact_sha256=artifact_digest(inspected['Image'],copies,capture['executable']['sha256']),
        context_sha256=fingerprint(context),process_sha256=process_digest(capture,generation))
    profile = dict(actor=actor,context=context,policy=original_policy,capture=capture,generation=generation,copies=copies,
                   binding=binding,ledger_sha256='1'*64,networks=dict(mgmt='network-original'))
    owner = dict(actor=deepcopy(actor),policy=deepcopy(original_policy),binding_sha256=fingerprint(binding),
                 jobs_sha256=terminal_jobs_digest(jobs),actions={},scope=dict(host_id=context['host_id'],boot_id=context['boot_id']))
    state = dict(inspect=inspected,capture=deepcopy(capture),context=deepcopy(context),binding=deepcopy(binding),jobs=jobs,
        ledger=dict(ledger_sha256='1'*64,jobs_sha256=terminal_jobs_digest(jobs)),activity=True,exit=None,startup=None,
        after_query=None,queries=0)
    class API:
        def inspect(self,cid):assert cid==inspected['Id'];return deepcopy(state['inspect'])
    class Process:
        @contextmanager
        def capture(self,pid,cid,files):
            assert pid==state['capture']['process']['pid'] and files==copies
            yield deepcopy(state['capture'])
    def query(value,process):
        state['queries'] += 1
        result = dict(health=dict(ok=True),jobs=deepcopy(state['jobs']),binding=deepcopy(state['binding']))
        if state['after_query']:state['after_query']()
        return result
    def activity(value):return dict(container_pids=[state['inspect']['State']['Pid']] if state['inspect']['State']['Running'] else [],
                                   host_build_processes=[] if state['activity'] else [123],complete=True)
    driver = ImageBuildObservation(API(),profile,context=lambda:deepcopy(state['context']),query=query,
        binding=lambda value:deepcopy(state['binding']),ledger=lambda value:deepcopy(state['ledger']),activity=activity,
        exit_receipt=lambda value:deepcopy(state['exit']),startup=lambda value:deepcopy(state['startup']),process=Process())
    return driver,owner,state,profile


def test_original_running_observation_and_tracked_policy_change(observation):
    driver,owner,state,profile = observation
    assert driver(owner)['actor']==profile['actor']
    state['inspect']['HostConfig']['RestartPolicy']=deepcopy(NO_RESTART)
    assert driver(owner)['restart_policy']==NO_RESTART and state['queries']==2


@pytest.mark.parametrize('fault',['process','context','scope','network','policy','config','ledger','activity','jobs','binding'])
def test_changed_original_inputs_are_refused(observation,fault):
    driver,owner,state,_ = observation
    if fault=='process':state['capture']['process']['start_ticks']='99'
    elif fault=='context':state['context']['boot_id']='changed'
    elif fault=='scope':owner['scope']['boot_id']='foreign-boot'
    elif fault=='network':state['inspect']['NetworkSettings']['Networks']['mgmt']['NetworkID']='foreign'
    elif fault=='policy':state['inspect']['HostConfig']['RestartPolicy']=dict(Name='always',MaximumRetryCount=0)
    elif fault=='config':state['inspect']['Config']['User']='foreign'
    elif fault=='ledger':state['ledger']['ledger_sha256']='2'*64
    elif fault=='activity':state['activity']=False
    elif fault=='jobs':state['jobs'][0]['status']='running'
    else:state['binding']['state']='degraded'
    with pytest.raises(TemplateError):driver(owner)


def test_docker_restart_during_api_observation_refuses(observation):
    driver,owner,state,_ = observation
    state['after_query'] = lambda:state['inspect']['State'].update(StartedAt='replacement')
    with pytest.raises(TemplateError,match='Docker observation changed'):driver(owner)


def stop_receipt(owner,state):
    item = dict(reference=dict(token='original'),command=dict(action='stop'))
    owner['actions']['stop'] = item
    proof = dict(process_sha256=owner['actor']['process_sha256'],pidfd_exit_verified=True,ordinary_shutdown_verified=True,
                 drain_verified=True,term_count=1,force_used=False,exit_code=143)
    state['exit'] = dict(reference=deepcopy(item['reference']),command_sha256=fingerprint(item['command']),dispatch_count=1,evidence=proof)
    state['inspect']['State'].update(Running=False,Status='exited',Pid=0,ExitCode=143)


def test_exited_docker_state_without_original_exit_receipt_is_not_a_hold(observation):
    driver,owner,state,_ = observation;stop_receipt(owner,state);state['exit']=None
    with pytest.raises(TemplateError,match='receipt unavailable'):driver(owner)
    assert state['queries']==0


def test_stopped_snapshot_requires_original_drain_and_unchanged_ledger(observation):
    driver,owner,state,profile = observation;stop_receipt(owner,state)
    snapshot=driver(owner)
    assert snapshot['running'] is False and snapshot['actor']==profile['actor'] and state['queries']==0
    state['exit']['evidence']['drain_verified']=False
    with pytest.raises(TemplateError,match='shutdown/drain'):driver(owner)


def test_same_container_restart_requires_original_start_command_receipt(observation):
    driver,owner,state,_ = observation
    owner['actions']['start'] = dict(reference=dict(token='start-original'),command=dict(action='start'))
    state['inspect']['State'].update(Pid=66,StartedAt='new-start')
    state['capture']['process'].update(pid=66,start_ticks='77')
    with pytest.raises(TemplateError):driver(owner)
    start = owner['actions']['start'];generation = dict(started_at='new-start',restart_count=0)
    new_actor = deepcopy(owner['actor']);new_actor['process_sha256']=process_digest(state['capture'],generation)
    state['startup'] = dict(reference=deepcopy(start['reference']),command_sha256=fingerprint(start['command']),
        capture=deepcopy(state['capture']),generation=generation,actor=new_actor,original_start_verified=True)
    assert driver(owner)['actor']==new_actor
    state['startup']['reference']['token']='foreign-start'
    with pytest.raises(TemplateError,match='same-command'):driver(owner)


def test_restarted_process_cannot_claim_original_artifact_with_changed_sources(observation):
    driver,owner,state,_ = observation
    start = dict(reference=dict(token='start-original'),command=dict(action='start'));owner['actions']['start']=start
    state['inspect']['State'].update(Pid=66,StartedAt='new-start')
    state['capture']['process'].update(pid=66,start_ticks='77')
    state['capture']['sources']['/opt/dnlab-image-build/api.py']['sha256']='0'*64
    generation = dict(started_at='new-start',restart_count=0)
    changed = deepcopy(owner['actor']);changed['process_sha256']=process_digest(state['capture'],generation)
    state['startup'] = dict(reference=start['reference'],command_sha256=fingerprint(start['command']),capture=deepcopy(state['capture']),
        generation=generation,actor=changed,original_start_verified=True)
    with pytest.raises(TemplateError,match='artifact differs'):driver(owner)


def test_observer_prepares_real_hold_journal_but_closed_window_blocks_commands(observation,tmp_path):
    observer,owner,state,profile = observation
    class NoCommands:
        def forbidden(self,*args):pytest.fail('no mutating command allowed during prepare')
        arm=original_reference=verify=release=outcome=forbidden
    journal = Journal(tmp_path/'hold-journal')
    try:
        driver = ImageBuildHold(journal,observe=observer,commands=NoCommands(),
            window=lambda value:dict(active=False,scope_sha256=fingerprint(value['scope'])),cleanup=lambda value:None)
        scope = {key:key for key in ('gate_id','lab_id','host_id','coordinator_id','boot_id','window_id')}
        scope.update(host_id=profile['context']['host_id'],boot_id=profile['context']['boot_id'])
        saved = driver.prepare('1'*32,scope=scope,original_actor=profile['actor'],restart_policy=profile['policy'],
                               binding_sha256=owner['binding_sha256'],jobs_sha256=owner['jobs_sha256'])
        assert saved['phase']=='prepared' and not saved['actions'] and state['queries']==2
        with pytest.raises(TemplateError,match='window unavailable'):driver.acquire(saved['id'])
        assert driver.read(saved['id'])==saved
    finally:journal.close()


def test_api_log_projection_is_separate_from_immutable_job_ledger(observation):
    driver,owner,state,_ = observation
    state['jobs'][0]['log']=['API projection can be truncated on load']
    assert driver(owner)['jobs_sha256']==owner['jobs_sha256']
    state['ledger']['ledger_sha256']='9'*64
    with pytest.raises(TemplateError,match='ledger changed'):driver(owner)
