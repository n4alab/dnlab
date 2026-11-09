"""VM definition must honor the same lab fences as native workloads."""
import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.lab_closure import put as put_closure
from dnlab_runtime.management_barrier import put as put_management
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from test_vm_definition import definition, template, instance


def install_fence(journal, fence):
    if fence in ('closing','closed'):
        put_closure(journal,'lab',{'closure_id':'1'*32,'generation':1,'phase':fence,'stops':{'2'*64:'old-node'}})
    else:
        put_management(journal,'lab',{'barrier_id':'3'*32,'generation':1,'plan_fingerprint':'4'*64,
            'phase':fence,'workloads':{},'workload_fingerprint':fingerprint({})})


@pytest.mark.parametrize('stage',['prepare','apply'])
@pytest.mark.parametrize('fence',['closing','closed','held','applying'])
def test_vm_definition_cannot_cross_lab_fences(definition,tmp_path,stage,fence):
    original,birth,xml,state,_,_=definition
    journal=Journal(tmp_path/'fenced')
    try:
        driver=VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)
        if stage=='apply':driver.prepare('before-fence',birth,xml)
        with journal.transaction():
            install_fence(journal,fence)
        with pytest.raises(Conflict):
            if stage=='prepare':driver.prepare('after-fence',birth,xml)
            else:driver.apply(birth['creator_operation_id'])
        assert ('define',) not in state['calls'] and state['domains']=={}
    finally:journal.close()


def test_original_lab_epoch_is_not_reinterpreted_after_reopen(definition):
    driver,birth,xml,state,_,_=definition
    original=driver.read(birth['creator_operation_id'])
    assert original['lab_generation']==1
    with driver.journal.transaction():
        put_closure(driver.journal,'lab',{'closure_id':'1'*32,'generation':2,'phase':'open','stops':{}})
    with pytest.raises(Conflict,match='generation differs'):driver.apply(birth['creator_operation_id'])
    with pytest.raises(Conflict,match='generation differs'):driver.prepare('first-define',birth,xml)
    with pytest.raises(Conflict,match='content differs'):driver.prepare('first-define',birth,xml,lab_generation=2)
    assert driver.read(birth['creator_operation_id'])==original and state['calls']==[]


def test_new_lab_epoch_requires_explicit_context_distinct_from_vm_generation(definition,tmp_path):
    original,birth,xml,state,_,_=definition
    journal=Journal(tmp_path/'reopened')
    try:
        driver=VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)
        with journal.transaction():
            put_closure(journal,'lab',{'closure_id':'1'*32,'generation':2,'phase':'open','stops':{}})
        with pytest.raises(Conflict,match='generation differs'):driver.prepare('new-epoch',birth,xml)
        assert journal.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0]==0
        value=driver.prepare('new-epoch',birth,xml,lab_generation=2)
        assert value['lab_generation']==2 and value['birth']['generation']==1
        assert driver.apply(birth['creator_operation_id'])['phase']=='defined'
        assert state['calls'].count(('define',))==1
    finally:journal.close()


def test_prepare_rechecks_fence_inside_admission_transaction(definition,tmp_path,monkeypatch):
    original,birth,xml,state,_,_=definition
    journal=Journal(tmp_path/'prepare-race')
    try:
        driver=VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)
        observe=driver.session.observe
        def acquire():
            proof=observe()
            with journal.transaction():install_fence(journal,'held')
            return proof
        monkeypatch.setattr(driver.session,'observe',acquire)
        with pytest.raises(Conflict,match='management operation'):driver.prepare('prepare-race',birth,xml)
        assert journal.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0]==0
        assert state['calls']==[]
    finally:journal.close()


@pytest.mark.parametrize('fence',['closing','held'])
def test_fence_after_durable_checkpoint_blocks_define_and_retains_original_intent(definition,monkeypatch,fence):
    driver,birth,_,state,_,_=definition
    before=driver.read(birth['creator_operation_id']);save=driver._save
    def checkpoint(operation,value):
        save(operation,value)
        if value['phase']=='define_requested':install_fence(driver.journal,fence)
    monkeypatch.setattr(driver,'_save',checkpoint)
    with pytest.raises(Conflict):driver.apply(birth['creator_operation_id'])
    after=driver.read(birth['creator_operation_id'])
    assert after['phase']=='recovery_required'
    assert after['request_fingerprint']==before['request_fingerprint']
    assert after['birth']==before['birth'] and after['lab_generation']==before['lab_generation']
    assert state['domains']=={} and ('define',) not in state['calls']


def test_fence_raised_by_preflight_is_rechecked_before_checkpoint(definition,monkeypatch):
    driver,birth,_,state,_,_=definition
    preflight=driver.preflight;before=driver.read(birth['creator_operation_id'])
    def check(value):
        receipt=preflight(value)
        with driver.journal.transaction():install_fence(driver.journal,'held')
        return receipt
    monkeypatch.setattr(driver,'preflight',check)
    with pytest.raises(Conflict):driver.apply(birth['creator_operation_id'])
    assert driver.read(birth['creator_operation_id'])==before
    assert state['domains']=={} and ('define',) not in state['calls']


def test_defined_replay_honors_fence_but_history_remains_readable(definition):
    driver,birth,xml,state,_,_=definition
    saved=driver.apply(birth['creator_operation_id']);calls=list(state['calls'])
    with driver.journal.transaction():install_fence(driver.journal,'held')
    with pytest.raises(Conflict):driver.prepare('first-define',birth,xml)
    with pytest.raises(Conflict):driver.apply(birth['creator_operation_id'])
    assert driver.read(birth['creator_operation_id'])==saved and state['calls']==calls


def test_late_fence_preserves_defined_resource_without_implicit_cleanup(definition,monkeypatch):
    driver,birth,_,state,_,_=definition
    define=driver.connection.defineXMLFlags
    def create(*args):
        domain=define(*args)
        with driver.journal.transaction():install_fence(driver.journal,'closed')
        return domain
    monkeypatch.setattr(driver.connection,'defineXMLFlags',create)
    with pytest.raises(Conflict):driver.apply(birth['creator_operation_id'])
    assert driver.read(birth['creator_operation_id'])['phase']=='recovery_required'
    assert state['calls'].count(('define',))==1 and len(state['domains'])==1
    assert state['domains'][birth['uuid']].active==0
