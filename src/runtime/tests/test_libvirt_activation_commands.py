"""Command journal boundaries with simulated activation state and blocked runner."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation_commands import ActivationCommands,command_plan
from dnlab_runtime.libvirt_account_worker import validate_command as account_command
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_activation import activation,request_profile


@pytest.fixture
def command(activation):
    driver,_,value,_=activation;value=deepcopy(value)
    # The authoritative activation reader below is simulated, including context.
    value['installation']['context']['namespaces']={name:dict(device=1,inode=index+10)
        for index,name in enumerate(('pid','mnt','net','user'))}
    value['installation_sha256']=fingerprint(value['installation'])
    value['items'][0]['phase']='requested'
    state=dict(calls=[],plan=None,reference=None,outcome=None,lost=False,missing=False,arm_lost=False,
        verified=True,rc=0,inputs='a'*64,foreign_worker=False)
    class Runner:
        def arm(self,plan):
            state['calls'].append('arm');state['plan']=deepcopy(plan)
            reference=dict(token='e'*32,command_sha256=fingerprint(plan),process_record=dict(
                boot_id='foreign' if state['foreign_worker'] else value['installation']['context']['boot_id'],pid=123,start_ticks=456,
                uid=0,gid=0,executable_sha256='d'*64,namespace_sha256=fingerprint(value['installation']['context']['namespaces'])))
            state['reference']=deepcopy(reference)
            if state['arm_lost']:raise OSError('synthetic arm response lost')
            return reference
        def verify(self,reference,plan):
            assert reference==state['reference'] and plan==state['plan'];return state['verified']
        def release(self,reference):
            assert reference==state['reference'];state['calls'].append('release')
            if not state['missing']:state['outcome']=dict(reference=deepcopy(reference),exit_code=state['rc'],stdout='',stderr='synthetic diagnostic')
            if state['lost']:raise OSError('synthetic release response lost')
        def outcome(self,reference):
            assert reference==state['reference'];return deepcopy(state['outcome'])
    def preflight(plan):
        return dict(qualified=True,command_sha256=fingerprint(plan),installation_sha256=value['installation_sha256'],
            context_sha256=fingerprint(value['installation']['context']),inputs_sha256=state['inputs'])
    helper=ActivationCommands(driver.journal,binary=dict(path='/usr/bin/systemctl',sha256='b'*64),runner=Runner(),
        activation_reader=lambda operation:deepcopy(value),preflight=preflight)
    return helper,value,state


@pytest.mark.parametrize('index',range(4))
def test_fixed_commands_record_single_execution_and_original_completion(command,index):
    helper,value,state=command
    value['items'][0]['phase']='prepared';item=value['items'][index];item['phase']='requested'
    proof=helper.execute(item,value['id'])
    assert helper.completion(item,value['id'])==proof and state['calls']==['arm','release']
    argv=state['plan']['argv']
    assert argv==(['/usr/bin/systemctl','daemon-reload'] if index==0 else ['/usr/bin/systemctl','start','--',item['spec']['unit']])
    assert helper._read(item,value['id'])['phase']=='completed'
    assert proof['sha256']==fingerprint(state['plan'])
    with pytest.raises(Conflict,match='already tracked'):helper.execute(item,value['id'])
    with pytest.raises(Conflict):account_command(state['plan'])


def test_lost_release_reply_uses_original_outcome_without_resend(command):
    helper,value,state=command;item=value['items'][0];state['lost']=True
    with pytest.raises(OSError,match='release response'):helper.execute(item,value['id'])
    assert helper._read(item,value['id'])['phase']=='release_requested'
    before=helper.journal.db.total_changes
    assert helper.completion(item,value['id'])['exit_code']==0 and helper.journal.db.total_changes==before
    assert helper.recover(item,value['id'])==helper.completion(item,value['id'])
    assert state['calls']==['arm','release']


def test_uncertain_outcome_cannot_resend_or_rearm(command):
    helper,value,state=command;item=value['items'][0];state['missing']=True
    with pytest.raises(Conflict,match='pending'):helper.execute(item,value['id'])
    assert helper.completion(item,value['id']) is None
    with pytest.raises(Conflict,match='pending'):helper.recover(item,value['id'])
    with pytest.raises(Conflict,match='already tracked'):helper.execute(item,value['id'])
    assert state['calls']==['arm','release']


def test_lost_arm_reply_preserves_intent_without_release(command):
    helper,value,state=command;item=value['items'][0];state['arm_lost']=True
    with pytest.raises(OSError,match='arm response'):helper.execute(item,value['id'])
    assert helper._read(item,value['id'])['phase']=='arming_requested'
    assert helper.completion(item,value['id']) is None
    with pytest.raises(Conflict):helper.recover(item,value['id'])
    with pytest.raises(Conflict,match='already tracked'):helper.execute(item,value['id'])
    assert state['calls']==['arm']


@pytest.mark.parametrize('fault',['preflight','step_confirmed','worker'])
def test_release_boundary_conflicts_preserve_blocked_worker(command,monkeypatch,fault):
    helper,value,state=command;item=deepcopy(value['items'][0]);save=helper._save
    def changed(current):
        save(current)
        if current['phase']=='release_requested':
            if fault=='preflight':state['inputs']='f'*64
            elif fault=='step_confirmed':value['items'][0]['phase']='confirmed'
            else:state['verified']=False
    monkeypatch.setattr(helper,'_save',changed)
    with pytest.raises(Conflict):helper.execute(item,value['id'])
    assert state['calls']==['arm']


def test_foreign_worker_context_cannot_be_released(command):
    helper,value,state=command;state['foreign_worker']=True
    with pytest.raises(Conflict,match='worker context'):helper.execute(value['items'][0],value['id'])
    assert state['calls']==['arm']


def test_failed_original_command_is_not_success_or_retried(command):
    helper,value,state=command;item=value['items'][0];state['rc']=1
    with pytest.raises(Conflict,match='successful activation command'):helper.execute(item,value['id'])
    with pytest.raises(Conflict):helper.completion(item,value['id'])
    assert state['outcome']['stderr']=='synthetic diagnostic' and state['calls']==['arm','release']


def test_changed_original_outcome_cannot_replace_completion(command):
    helper,value,state=command;item=value['items'][0];helper.execute(item,value['id'])
    state['outcome']['stdout']='foreign output'
    with pytest.raises(Conflict,match='outcome changed'):helper.completion(item,value['id'])
    assert state['calls']==['arm','release']


def test_unqualified_unit_or_binary_cannot_form_command(command):
    helper,value,_=command;item=deepcopy(value['items'][0]);item['spec']['kind']='stop'
    with pytest.raises(Conflict):command_plan(value['installation'],item,value['id'],helper.binary)
    with pytest.raises(Conflict):command_plan(value['installation'],value['items'][0],value['id'],dict(path='/bin/sh',sha256='a'*64))


def test_original_completion_is_readonly_and_does_not_recurse_into_resource_preflight(command,monkeypatch):
    helper,value,state=command;item=value['items'][0]
    proof=helper.execute(item,value['id'])
    monkeypatch.setattr(helper.runner,'completed_outcome',helper.runner.outcome,raising=False)
    monkeypatch.setattr(helper,'preflight',lambda *a:pytest.fail('original completion recursed into resources'))
    monkeypatch.setattr(helper.runner,'verify',lambda *a:pytest.fail('original completion adopted a live worker'))
    before=helper.journal.db.total_changes
    assert helper.original_completion(item,value['id'])==proof
    assert helper.journal.db.total_changes==before and state['calls']==['arm','release']
