"""Administrative policy restoration, using only simulated native providers."""
from copy import deepcopy

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_admin_recovery import AdministrativeRecovery


@pytest.fixture
def administrative(tmp_path):
    journal=Journal(tmp_path/'journal')
    request=dict(id='1'*32,nonce='2'*32,original_sha256='3'*64,owner_sha256='4'*64,service_sha256='5'*64,
                 restart_policy=dict(Name='unless-stopped',MaximumRetryCount=0))
    state=dict(alive=True,policy=dict(Name='no',MaximumRetryCount=0),actions=[],conflict=False,lost=None)
    def preflight(current,*,owner_alive,restart_policy):
        assert current==request
        return dict(original_sha256=request['original_sha256'],owner_sha256=request['owner_sha256'],
            service_sha256=request['service_sha256'],owner_alive=state['alive'],restart_policy=deepcopy(state['policy']),
            execution_lock_held=True,no_native_dispatch=True,vm_resources_absent=not state['conflict'],window_active=True)
    def terminate(current,*,check):
        check();state['actions'].append('term');state['alive']=False
        if state['lost']=='term':raise OSError('TERM response lost')
        return dict(owner_sha256=current['owner_sha256'],pidfd_exit_verified=True,term_count=1,force_used=False)
    def update(policy):
        state['actions'].append('policy');state['policy']=deepcopy(policy)
        if state['lost']=='policy':raise OSError('policy response lost')
    def retire(current,proof):
        state['actions'].append('retire')
        return dict(original_sha256=current['original_sha256'],recovery_id=current['id'],
                    claim_released=True,old_start_uncertain=True)
    driver=AdministrativeRecovery(journal,preflight=preflight,terminate_owner=terminate,update_policy=update,retire_claim=retire)
    yield driver,request,state
    journal.close()


def test_separate_recovery_never_reports_old_start_success(administrative):
    driver,request,state=administrative
    assert driver.prepare(request)['phase']=='prepared' and state['actions']==[]
    result=driver.apply(request['id'])
    assert result['phase']=='completed' and result['retirement']['old_start_uncertain'] is True
    assert state['actions']==['term','policy','retire']
    assert driver.apply(request['id'])==result and state['actions']==['term','policy','retire']


def test_uncertain_owner_term_is_not_repeated_or_inferred_from_absence(administrative):
    driver,request,state=administrative;driver.prepare(request);state['lost']='term'
    with pytest.raises(OSError):driver.apply(request['id'])
    assert state['alive'] is False
    with pytest.raises(TemplateError,match='TERM uncertain'):driver.apply(request['id'])
    assert state['actions']==['term'] and driver.read(request['id'])['phase']=='owner_term_requested'


def test_lost_policy_response_recovers_by_observation_only(administrative):
    driver,request,state=administrative;driver.prepare(request);state['lost']='policy'
    with pytest.raises(OSError):driver.apply(request['id'])
    assert driver.read(request['id'])['phase']=='policy_requested'
    assert driver.apply(request['id'])['phase']=='completed'
    assert state['actions']==['term','policy','retire']


@pytest.mark.parametrize('checkpoint',['owner_term_requested','owner_exited','policy_requested','policy_verified'])
def test_full_preflight_after_checkpoint_prevents_next_mutation(administrative,monkeypatch,checkpoint):
    driver,request,state=administrative;driver.prepare(request);save=driver._save
    def changed(value,**kwargs):
        save(value,**kwargs)
        if value['phase']==checkpoint:state['conflict']=True
    monkeypatch.setattr(driver,'_save',changed)
    with pytest.raises(TemplateError,match='preflight'):driver.apply(request['id'])
    assert state['actions']==([] if checkpoint=='owner_term_requested' else
                             ['term'] if checkpoint in ('owner_exited','policy_requested') else ['term','policy'])


def test_changed_intent_cannot_replace_original(administrative):
    driver,request,state=administrative;original=driver.prepare(request);changed=deepcopy(request);changed['nonce']='6'*32
    with pytest.raises(TemplateError,match='cannot be replaced'):driver.prepare(changed)
    assert driver.read(request['id'])==original and state['actions']==[]


@pytest.mark.parametrize('field,value',[('old_start_uncertain',False),('claim_released',1),('recovery_id','9'*32)])
def test_reopen_rejects_inconsistent_terminal_receipt(administrative,field,value):
    driver,request,state=administrative;driver.prepare(request);result=driver.apply(request['id'])
    result['retirement'][field]=value
    driver.journal.db.execute('UPDATE image_build_admin_recoveries SET payload=?,fingerprint=? WHERE id=?',
        (canonical(result),fingerprint(result),request['id']))
    actions=deepcopy(state['actions'])
    with pytest.raises(TemplateError,match='retirement receipt'):driver.apply(request['id'])
    assert state['actions']==actions
