"""Durable guest reboot reduction using private SQLite and fake observations."""
from copy import deepcopy

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vm_events import VMEventTracker


@pytest.fixture
def tracker(tmp_path):
    journal=Journal(tmp_path/'journal')
    birth=dict(uuid='12345678-1234-4234-8234-123456789abc',lab_id='lab',node_id='vd',host_id='worker',
        generation=1,creator_operation_id='a'*32,nonce='b'*32,template_sha256='c'*64)
    observed={'birth':deepcopy(birth),'config_sha256':'d'*64,
        'process':{'boot_id':'synthetic-boot','pid':123,'start_ticks':456,'executable_sha256':'e'*64}}
    calls=[]
    def observe(expected):
        assert expected==birth;calls.append(1)
        return deepcopy(observed)
    value=VMEventTracker(journal,observe)
    value.begin('f'*32,birth)
    yield value,birth,observed,calls
    journal.close()


def test_guest_reboot_is_journalled_without_changing_original_generation(tracker):
    value,birth,_,calls=tracker
    original=value.read('f'*32)
    receipt=value.record('f'*32,1,'reboot')
    assert receipt['state']['phase']=='active' and receipt['state']['reboot_count']==1
    assert receipt['state']['birth']==birth and receipt['state']['original']==original['original']
    assert receipt['state']['guest_readiness']=='unknown' and len(calls)==2
    changes=value.journal.db.total_changes
    assert value.record('f'*32,1,'reboot')==receipt
    assert value.journal.db.total_changes==changes
    with pytest.raises(Conflict,match='different content'):value.record('f'*32,1,'crash')
    assert value.read('f'*32)==receipt['state']


@pytest.mark.parametrize('fault',['uuid','nonce','config','pid','boot','executable','missing-process'])
def test_changed_domain_or_process_requires_recovery_without_adoption(tracker,fault):
    value,birth,observed,_=tracker
    original=value.read('f'*32)['original']
    if fault=='uuid':observed['birth']['uuid']='22345678-1234-4234-8234-123456789abc'
    elif fault=='nonce':observed['birth']['nonce']='9'*32
    elif fault=='config':observed['config_sha256']='9'*64
    elif fault=='pid':observed['process']['pid']=999
    elif fault=='boot':observed['process']['boot_id']='other-boot'
    elif fault=='executable':observed['process']['executable_sha256']='9'*64
    else:observed['process']=None
    receipt=value.record('f'*32,1,'reboot')
    assert receipt['state']['phase']=='recovery_required'
    assert receipt['state']['reboot_count']==0 and receipt['state']['original']==original
    assert receipt['state']['birth']==birth


@pytest.mark.parametrize('kind',['crash','stopped','started','connection-lost'])
def test_other_lifecycle_events_never_authorize_restart_or_safe_shutdown(tracker,kind):
    value,_,_,_=tracker
    result=value.record('f'*32,1,kind)
    assert result['state']['phase']=='recovery_required' and result['state']['reboot_count']==0
    assert 'shutdown_verified' not in result['state'] and 'restart' not in result
    following=value.record('f'*32,2,'reboot')
    assert following['state']['phase']=='recovery_required' and following['state']['reboot_count']==0


def test_sequence_gap_and_new_collector_cannot_silently_reopen_stream(tracker):
    value,birth,_,_=tracker
    value.record('f'*32,3,'reboot')
    assert value.read('f'*32)['phase']=='recovery_required'
    with pytest.raises(Conflict,match='qualified recovery'):value.begin('f'*32,birth)
    with pytest.raises(Conflict,match='implicitly replaced'):value.begin('1'*32,birth)
    reopened=VMEventTracker(value.journal,value.observe)
    assert reopened.read('f'*32)==value.read('f'*32)
    changes=value.journal.db.total_changes
    with pytest.raises(Conflict,match='continuity'):reopened.record('f'*32,4,'reboot')
    assert value.journal.db.total_changes==changes


def test_even_active_history_does_not_prove_continuity_after_collector_restart(tracker):
    value,birth,_,_=tracker
    reopened=VMEventTracker(value.journal,value.observe)
    with pytest.raises(Conflict,match='continuity'):reopened.begin('f'*32,birth)
    with pytest.raises(Conflict,match='continuity'):reopened.record('f'*32,1,'reboot')
    assert value.read('f'*32)['last_sequence']==0


def test_corrupt_stream_is_not_relearned_from_current_domain(tracker):
    value,birth,_,calls=tracker
    value.journal.db.execute("UPDATE vm_event_streams SET payload='{}'")
    before=len(calls)
    with pytest.raises(Conflict,match='integrity'):value.begin('f'*32,birth)
    assert len(calls)==before


def test_vm_stream_vetoes_cleanup_for_its_lab_without_sql_writes(tracker):
    from dnlab_runtime.inspection import cleanup_inventory
    value,_,_,_=tracker
    before=value.journal.db.total_changes
    assert cleanup_inventory(value.journal,'lab')=={'nodes':['vd'],'blocked':['vm_event_streams']}
    assert cleanup_inventory(value.journal,'foreign')=={'nodes':[],'blocked':[]}
    value.record('f'*32,1,'connection-lost')
    changes=value.journal.db.total_changes
    assert cleanup_inventory(value.journal,'lab')=={'nodes':['vd'],'blocked':['vm_event_streams']}
    assert value.journal.db.total_changes==changes and changes>before


def test_corrupt_vm_inventory_refuses_finalization_instead_of_ignoring_it(tracker):
    from dnlab_runtime.inspection import cleanup_inventory
    value,_,_,_=tracker
    value.journal.db.execute("UPDATE vm_event_streams SET payload='{}'")
    before=value.journal.db.total_changes
    with pytest.raises(Conflict,match='inventory requires'):cleanup_inventory(value.journal,'lab')
    assert value.journal.db.total_changes==before
