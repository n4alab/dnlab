"""No account binary or process is launched: every runner operation is simulated."""
from copy import deepcopy
from contextlib import contextmanager

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_commands import AccountCommandHelper,command_plan
from dnlab_runtime.libvirt_install import targets
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.libvirt_provisioning import account_request
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_profile import request_profile


@pytest.fixture(params=['group','account'])
def command(tmp_path,request_profile,request):
    spec=next(i for i in targets(render_profile(**request_profile)) if i['kind']==request.param)
    value=account_request(dict(spec=spec,nonce='a'*32),'install')
    binaries={role:dict(path='/usr/sbin/'+role,sha256='b'*64) for role in ('useradd','groupadd')}
    state=dict(identity=None,calls=[],command=None,reference=None,outcome=None,lost=False,missing=False,
        preflight='c'*64,verified=True,arm_lost=False,rc=0,spec=deepcopy(spec))
    class Runner:
        def arm(self,plan):
            state['calls'].append('arm');state['command']=deepcopy(plan)
            reference=dict(token='e'*32,command_sha256=fingerprint(plan),process_record=dict(
                boot_id='synthetic',pid=123,start_ticks=456,uid=0,gid=0,
                executable_sha256='d'*64,namespace_sha256='f'*64))
            state['reference']=reference
            if state['arm_lost']:raise OSError('synthetic lost arm response')
            return deepcopy(reference)
        def verify(self,reference,plan):
            assert reference==state['reference'] and plan==state['command']
            return state['verified']
        def release(self,reference):
            assert reference==state['reference'];state['calls'].append('release')
            state['identity']=deepcopy(value['expected'])
            if not state['missing']:
                state['outcome']=dict(reference=deepcopy(reference),exit_code=state['rc'],stdout='',stderr='synthetic diagnostic')
            if state['lost']:raise OSError('synthetic lost release response')
        def outcome(self,reference):
            assert reference==state['reference'];return deepcopy(state['outcome'])
    def preflight(plan):return dict(qualified=True,command_sha256=fingerprint(plan),
        context_sha256=state['preflight'],inputs_sha256='a'*64)
    journal=Journal(tmp_path/'journal')
    helper=AccountCommandHelper(journal,binaries=binaries,runner=Runner(),
        inspect=lambda request:deepcopy(state['identity']),preflight=preflight)
    yield helper,value,state
    journal.close()


def test_fixed_command_and_original_completion_are_persisted_once(command):
    helper,request,state=command
    receipt=helper.create(request)
    assert receipt==helper.completion(request)
    assert state['calls']==['arm','release']
    argv=state['command']['argv']
    assert argv[-2:]==['--','dnlab-libvirt']
    assert '--force' not in argv and '--non-unique' not in argv
    if request['kind']=='account':
        for flag in ('--no-create-home','--no-user-group','--no-log-init'):assert flag in argv
        assert argv[argv.index('--comment')+1]==request['expected']['comment']
        assert argv[argv.index('--password')+1]=='!'
    assert helper._read(request)['phase']=='completed'
    with pytest.raises(Conflict,match='already tracked'):helper.create(request)
    assert state['calls']==['arm','release']


def test_lost_release_response_reads_original_runner_completion_without_resend(command):
    helper,request,state=command;state['lost']=True
    with pytest.raises(OSError):helper.create(request)
    assert helper._read(request)['phase']=='release_requested'
    assert helper.completion(request)['identity']==request['expected']
    with pytest.raises(Conflict,match='already tracked'):helper.create(request)
    assert state['calls']==['arm','release']


def test_uncertain_outcome_never_releases_again(command):
    helper,request,state=command;state['missing']=True
    with pytest.raises(Conflict,match='pending'):helper.create(request)
    saved=helper._read(request)
    assert helper.completion(request) is None
    with pytest.raises(Conflict,match='already tracked'):helper.create(request)
    assert helper._read(request)==saved and state['calls']==['arm','release']


def test_lost_arm_response_never_arms_or_releases_again(command):
    helper,request,state=command;state['arm_lost']=True
    with pytest.raises(OSError):helper.create(request)
    assert helper.completion(request) is None
    with pytest.raises(Conflict,match='already tracked'):helper.create(request)
    assert state['calls']==['arm']


def test_preflight_change_after_checkpoint_prevents_release(command,monkeypatch):
    helper,request,state=command;save=helper._save
    def change(value):
        save(value)
        if value['phase']=='release_requested':state['preflight']='0'*64
    monkeypatch.setattr(helper,'_save',change)
    with pytest.raises(Conflict,match='preflight changed'):helper.create(request)
    assert state['calls']==['arm'] and state['identity'] is None


def test_new_account_at_release_boundary_prevents_mutation(command,monkeypatch):
    helper,request,state=command;save=helper._save
    def change(value):
        save(value)
        if value['phase']=='release_requested':state['identity']={'foreign':True}
    monkeypatch.setattr(helper,'_save',change)
    with pytest.raises(Conflict,match='release boundary'):helper.create(request)
    assert state['calls']==['arm'] and state['identity']=={'foreign':True}


def test_failed_command_cannot_be_adopted_even_if_identity_matches(command):
    helper,request,state=command;state['rc']=9
    with pytest.raises(Conflict,match='command failed'):helper.create(request)
    assert helper.completion(request) is None
    assert helper._read(request)['phase']=='release_requested' and state['calls']==['arm','release']


def test_changed_original_worker_is_refused(command):
    helper,request,state=command;state['verified']=False
    with pytest.raises(Conflict,match='worker verification'):helper.create(request)
    assert state['calls']==['arm']


def test_changed_completion_or_current_resource_is_refused(command):
    helper,request,state=command;helper.create(request)
    saved=deepcopy(state['outcome']);state['outcome']['reference']['token']='0'*32
    with pytest.raises(Conflict,match='outcome differs'):helper.completion(request)
    state['outcome']=saved;state['identity']={'foreign':True}
    with pytest.raises(Conflict,match='resource differs'):helper.completion(request)
    assert state['calls']==['arm','release']


@pytest.mark.parametrize('lost',[False,True])
def test_account_adapter_recovers_original_tracked_command_without_reexecution(command,lost):
    from dnlab_runtime.libvirt_provisioning import InstallationAccounts,ProvisioningWindow
    helper,request,state=command;state['lost']=lost
    item=dict(spec=deepcopy(state['spec']),nonce=request['nonce'])
    receipt=dict(operation_id='install',context={'boot':'synthetic'},targets=[item['spec']['key']],nonce='b'*32)
    window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    adapter=InstallationAccounts(helper.journal,helper)
    if lost:
        with pytest.raises(OSError):adapter.create(item,'install',window=window)
        with pytest.raises(Conflict,match='uncertain'):adapter.observe(item,'install')
        result=adapter.recover(item,'install',window=window)
    else:result=adapter.create(item,'install',window=window)
    assert result==adapter.observe(item,'install')
    assert result['identity']==request['expected']
    assert state['calls']==['arm','release']
