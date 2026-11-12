"""Retire only original never-booted domains; SDK and resources are synthetic."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition_retirement import UnstartedDefinitionRetirement
from test_vm_definition import definition, template, instance


@pytest.fixture
def retirement(definition):
    driver,birth,_,state,_,Domain = definition
    value = driver.apply(birth['creator_operation_id'])
    domain = state['domains'][birth['uuid']]
    domain.autostart = lambda:state.get('autostart',0)
    domain.hasManagedSaveImage = lambda flags:state.get('save',0)
    domain.snapshotNum = lambda flags:state.get('snapshots',0)
    domain.checkpointCount = lambda:state.get('checkpoints',0)
    def undefine(flags):
        assert flags == 0;state['calls'].append(('undefine',))
        if state.get('before_undefine'):raise OSError('uncertain before undefine')
        state['domains'].pop(birth['uuid'])
        if state.get('lost_undefine'):raise OSError('lost undefine response')
        return 0
    domain.undefineFlags = undefine
    def preflight(current):
        return dict(definition_sha256=current.get('retirement',{}).get('definition_sha256',fingerprint(current)),
            session_sha256=current['session_sha256'],never_started=True,
            writers_absent=not state.get('writer'),resources_unchanged=True)
    retire = UnstartedDefinitionRetirement(driver,preflight=preflight)
    return retire,driver,birth,state,domain,value


def test_retirement_preserves_birth_history_and_all_resource_reservations(retirement):
    retire,driver,birth,state,_,original = retirement
    held = [tuple(row) for row in driver.journal.db.execute('SELECT * FROM resources ORDER BY key')]
    value = retire.prepare('retire',birth['creator_operation_id'])
    assert value['definition'] == original
    assert driver.read(birth['creator_operation_id'])['phase'] == 'retirement_requested'
    with pytest.raises(Conflict):driver.apply(birth['creator_operation_id'])
    result = retire.apply('retire')
    assert result['phase'] == 'retired' and result['proof']['never_started']
    assert result['proof']['undefine_response'] == {'return_code':0}
    assert driver.read(birth['creator_operation_id'])['phase'] == 'retired'
    assert [tuple(row) for row in driver.journal.db.execute('SELECT * FROM resources ORDER BY key')] == held
    assert retire.apply('retire') == result
    assert retire.prepare('retire',birth['creator_operation_id']) == result
    assert state['calls'].count(('define',)) == state['calls'].count(('undefine',)) == 1


@pytest.mark.parametrize('fault',['active','xml','autostart','save','snapshots','checkpoints','writer','boot'])
def test_conflicts_prevent_retirement_mutations(retirement,fault):
    retire,driver,birth,state,domain,_ = retirement
    if fault == 'active':domain.active = 1
    elif fault == 'xml':domain.xml = domain.xml.replace('</domain>','<description>foreign</description></domain>')
    elif fault == 'boot':
        value=driver.read(birth['creator_operation_id']);value['boot']={'pending':True}
        with driver.journal.transaction():driver._save(birth['creator_operation_id'],value)
    else:state[fault] = 1
    before = driver.journal.db.total_changes
    with pytest.raises(RuntimeErrorBase):retire.prepare('retire',birth['creator_operation_id'])
    assert driver.journal.db.total_changes == before and ('undefine',) not in state['calls']


def test_lost_undefine_response_recovers_absence_without_resend(retirement):
    retire,driver,birth,state,_,_ = retirement
    retire.prepare('retire',birth['creator_operation_id']);state['lost_undefine'] = True
    with pytest.raises(OSError):retire.apply('retire')
    assert retire.read('retire')['phase'] == 'undefine_requested'
    result = retire.apply('retire')
    assert result['phase'] == 'retired' and result['proof']['undefine_response'] is None
    assert state['calls'].count(('undefine',)) == 1


def test_uncertain_presence_stays_pending_without_resend(retirement):
    retire,driver,birth,state,_,_ = retirement
    retire.prepare('retire',birth['creator_operation_id']);state['before_undefine'] = True
    with pytest.raises(OSError):retire.apply('retire')
    with pytest.raises(Conflict,match='no resend'):retire.apply('retire')
    assert retire.read('retire')['phase'] == 'undefine_requested'
    assert state['calls'].count(('undefine',)) == 1


def test_conflict_after_requested_checkpoint_prevents_undefine(retirement,monkeypatch):
    retire,_,birth,state,domain,_ = retirement
    retire.prepare('retire',birth['creator_operation_id']);original=retire._save
    def save(value):
        original(value)
        if value['phase'] == 'undefine_requested':domain.active = 1
    monkeypatch.setattr(retire,'_save',save)
    with pytest.raises(Conflict):retire.apply('retire')
    assert ('undefine',) not in state['calls'] and retire.read('retire')['phase'] == 'undefine_requested'


def test_original_creation_receipt_is_not_backfilled(retirement):
    retire,driver,birth,state,_,_ = retirement
    value=driver.read(birth['creator_operation_id']);value.pop('creation_ack')
    with driver.journal.transaction():driver._save(birth['creator_operation_id'],value)
    with pytest.raises(RuntimeErrorBase):retire.prepare('retire',birth['creator_operation_id'])
    assert ('undefine',) not in state['calls']


def test_missing_definition_before_intent_does_not_qualify_cleanup(retirement):
    retire,_,birth,state,_,_ = retirement
    state['domains'].clear()
    with pytest.raises(Conflict):retire.prepare('retire',birth['creator_operation_id'])
    assert ('undefine',) not in state['calls']


def test_reappearing_domain_rolls_back_final_retirement(retirement,monkeypatch):
    retire,_,birth,state,domain,_ = retirement
    retire.prepare('retire',birth['creator_operation_id']);original=retire._save
    def save(value):
        original(value)
        if value['phase'] == 'retired':state['domains'][birth['uuid']] = domain
    monkeypatch.setattr(retire,'_save',save)
    with pytest.raises(Conflict):retire.apply('retire')
    assert retire.read('retire')['phase'] == 'undefine_requested'
    assert state['calls'].count(('undefine',)) == 1


def test_retirement_receipt_independently_blocks_backend_and_lab_cleanup(retirement):
    from dnlab_runtime.backend_reservations import available
    from dnlab_runtime.inspection import cleanup_inventory
    retire,driver,birth,_,_,_=retirement
    retire.prepare('retire',birth['creator_operation_id']);retire.apply('retire')
    with driver.journal.transaction():
        driver.journal.db.execute('DELETE FROM vm_definition_intents WHERE id=?',(birth['creator_operation_id'],))
    with pytest.raises(Conflict):available(driver.journal,birth['lab_id'],birth['node_id'],'docker')
    result=cleanup_inventory(driver.journal,birth['lab_id'])
    assert 'vm_definition_retirements' in result['blocked'] and birth['node_id'] in result['nodes']


def test_unqualified_normalization_can_retire_only_the_recorded_original_response(definition):
    driver,birth,_,state,_,_=definition;state['normalize']=True
    with pytest.raises(Conflict,match='normalization'):driver.apply(birth['creator_operation_id'])
    original=driver.read(birth['creator_operation_id'])
    assert original['ack'] is None and original['creation_ack'] is not None
    domain=state['domains'][birth['uuid']]
    domain.autostart=lambda:0;domain.hasManagedSaveImage=lambda flags:0
    domain.snapshotNum=lambda flags:0;domain.checkpointCount=lambda:0
    def undefine(flags):
        assert flags==0;state['calls'].append(('undefine',));state['domains'].pop(birth['uuid']);return 0
    domain.undefineFlags=undefine
    def preflight(current):
        return dict(definition_sha256=current.get('retirement',{}).get('definition_sha256',fingerprint(current)),
            session_sha256=current['session_sha256'],never_started=True,writers_absent=True,resources_unchanged=True)
    retire=UnstartedDefinitionRetirement(driver,preflight=preflight)
    retire.prepare('retire',birth['creator_operation_id'])
    assert retire.apply('retire')['phase']=='retired'
    assert state['calls'].count(('define',))==state['calls'].count(('undefine',))==1
