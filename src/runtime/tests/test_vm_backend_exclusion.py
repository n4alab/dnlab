"""Cross-backend admission must reserve the logical node before allocation."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vm_definition import VMDefinitionDriver
from test_runtime import runtime, request, stop, run
from test_vm_definition import definition, template, instance


def native_start():
    value=request(lab_id='lab',node_id='vd')
    value['spec']['endpoints']=[]
    return value


def test_prepared_vm_intent_blocks_native_container_admission(definition):
    driver,_,_,state,_,_=definition
    with pytest.raises(Conflict):driver.journal.submit(native_start())
    assert ('define',) not in state['calls'] and state['domains']=={}


def test_pending_native_start_blocks_vm_intent_preparation(definition,tmp_path):
    original,birth,xml,state,_,_=definition
    journal=Journal(tmp_path/'other-journal')
    try:
        driver=VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)
        journal.submit(native_start())
        with pytest.raises(Conflict):driver.prepare('vm-after-native',birth,xml)
        assert ('define',) not in state['calls'] and state['domains']=={}
    finally:journal.close()


def vm_driver(journal, original):
    return VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)


def test_vm_reservation_blocks_native_plan_before_backend_reads(runtime,definition,monkeypatch):
    engine,journal,docker,linux=runtime
    original,birth,xml,_,_,_=definition
    driver=vm_driver(journal,original);driver.prepare('reserve-vm',birth,xml)
    before=journal.db.total_changes
    monkeypatch.setattr(engine.backend,'inspect',lambda *args:pytest.fail('plan reached container backend'))
    with pytest.raises(Conflict,match='reserved by VM'):engine.plan(native_start())
    assert journal.db.total_changes==before and docker.calls==linux.commands==[]


def test_plan_detects_vm_reservation_appearing_during_observation(runtime,definition,monkeypatch):
    engine,journal,docker,linux=runtime
    original,birth,xml,_,_,_=definition
    driver=vm_driver(journal,original);inspect=engine.backend.inspect;inserted=[]
    def observe(*args):
        result=inspect(*args)
        if not inserted:
            inserted.append(True);driver.prepare('reserve-during-plan',birth,xml)
        return result
    monkeypatch.setattr(engine.backend,'inspect',observe)
    with pytest.raises(Conflict,match='changed during read-only planning'):engine.plan(native_start())
    assert inserted==[True] and journal.pending()==[] and docker.calls==linux.commands==[]


def test_uncertain_vm_definition_holds_node_after_reopen(definition,monkeypatch):
    driver,birth,_,state,_,_=definition
    define=driver.connection.defineXMLFlags
    def crash(*args):
        define(*args)
        raise SystemExit('synthetic crash before acknowledgement')
    monkeypatch.setattr(driver.connection,'defineXMLFlags',crash)
    with pytest.raises(SystemExit):driver.apply(birth['creator_operation_id'])
    reopened=vm_driver(driver.journal,driver)
    assert reopened.read(birth['creator_operation_id'])['phase']=='define_requested'
    with pytest.raises(Conflict,match='reserved by VM'):driver.journal.submit(native_start())
    with pytest.raises(Conflict,match='not repeated'):reopened.apply(birth['creator_operation_id'])
    assert state['calls'].count(('define',))==1 and len(state['domains'])==1


@pytest.mark.parametrize('phase',['recovery_required','cancelled'])
def test_native_pending_cleanup_holds_node_even_with_terminal_status(definition,tmp_path,phase):
    original,birth,xml,state,_,_=definition
    journal=Journal(tmp_path/'pending-cleanup')
    try:
        driver=vm_driver(journal,original)
        operation=journal.submit(native_start())
        journal.phase(operation['id'],phase)
        before=journal.db.total_changes
        with pytest.raises(Conflict,match='cleanup is still pending'):driver.prepare('vm-after-failure',birth,xml)
        assert journal.db.total_changes==before and ('define',) not in state['calls']
    finally:journal.close()


def test_verified_native_stop_allows_explicit_vm_preparation(runtime,definition):
    engine,journal,docker,_=runtime
    original,birth,xml,state,_,_=definition
    driver=vm_driver(journal,original)
    assert run(engine,journal,native_start())['phase']=='completed'
    assert run(engine,journal,stop(lab_id='lab',node_id='vd'))['phase']=='completed'
    assert docker.containers=={}
    first=driver.prepare('explicit-vm-after-stop',birth,xml)
    before=journal.db.total_changes
    assert driver.prepare('explicit-vm-after-stop',birth,xml)==first
    assert journal.db.total_changes==before and ('define',) not in state['calls']


@pytest.mark.parametrize('other', [{'lab_id':'other-lab'},{'node_id':'other-node'}])
def test_other_logical_nodes_are_not_blocked(definition,other):
    driver,_,_,state,_,_=definition
    value=native_start();value.update(other)
    assert driver.journal.submit(value)['phase']=='queued'
    assert ('define',) not in state['calls']


def test_atomic_admission_on_two_journal_connections_has_one_winner(definition,tmp_path):
    original,birth,xml,state,_,_=definition
    left=Journal(tmp_path/'race');right=Journal(tmp_path/'race')
    try:
        driver=vm_driver(right,original);ready=threading.Barrier(2)
        def native():
            ready.wait(timeout=3)
            try:left.submit(native_start());return 'accepted'
            except Conflict:return 'refused'
        def vm():
            ready.wait(timeout=3)
            try:driver.prepare('race-vm',birth,xml);return 'accepted'
            except Conflict:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as workers:
            first=workers.submit(native);second=workers.submit(vm)
            assert sorted([first.result(timeout=5),second.result(timeout=5)])==['accepted','refused']
        native_count=left.db.execute('SELECT count(*) FROM operations').fetchone()[0]
        vm_count=left.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0]
        assert native_count+vm_count==1 and state['domains']=={} and ('define',) not in state['calls']
    finally:left.close();right.close()


def test_preexisting_mixed_reservations_require_recovery_without_compensation(runtime,definition):
    engine,journal,docker,linux=runtime
    original,birth,_,state,_,_=definition
    operation=journal.submit(native_start())
    vm_driver(journal,original)
    # Reproduce state written by the previous admission bug, without using
    # the now-protected VM prepare path or allocating either workload.
    saved=original.journal.db.execute('SELECT * FROM vm_definition_intents').fetchone()
    journal.db.execute('INSERT INTO vm_definition_intents VALUES(?,?,?,?,?,?,?,?)',tuple(saved))
    vm_before=journal.db.execute('SELECT payload,fingerprint FROM vm_definition_intents').fetchone()
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert engine.reconcile(operation['id'],force=True)['phase']=='recovery_required'
    assert journal.db.execute('SELECT payload,fingerprint FROM vm_definition_intents').fetchone()==vm_before
    assert docker.calls==linux.commands==[] and ('define',) not in state['calls']


def test_corrupt_vm_reservation_cannot_be_ignored_by_native_admission(definition):
    driver,_,_,state,_,_=definition
    driver.journal.db.execute("UPDATE vm_definition_intents SET payload='{}'")
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='reservation requires qualified recovery'):
        driver.journal.submit(native_start())
    assert driver.journal.db.total_changes==before
    assert driver.journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert state['domains']=={}
