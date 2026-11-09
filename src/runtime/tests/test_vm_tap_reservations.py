"""Distinct VM intents must not reserve the same host TAP interface name."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.libvirt_xml import OWNER_NS
from dnlab_runtime.manifest import Conflict
from test_vm_definition import definition, template, instance


def test_two_vm_definitions_cannot_share_host_tap_names(definition):
    driver,birth,xml,state,_,_=definition
    original=driver.read(birth['creator_operation_id'])
    second=deepcopy(birth)
    second.update(uuid='22345678-1234-4234-8234-123456789abc',node_id='second-vd',
                  creator_operation_id='e'*32,nonce='f'*32)
    root=ET.fromstring(xml)
    root.find('name').text='dnlab-test-second-vd'
    root.find('uuid').text=second['uuid']
    owner=root.find('metadata/{'+OWNER_NS+'}owner')
    for key in ('node_id','creator_operation_id','nonce'):owner.set(key,second[key])
    second_xml=ET.tostring(root,encoding='unicode')
    # Names and domain UUIDs differ; the interface targets remain the original
    # dt-data0/dt-mgmt0 on the same local host and must fail during admission.
    with pytest.raises(Conflict,match='reserved'):
        driver.prepare('second-vm',second,second_xml)
    assert driver.read(birth['creator_operation_id'])==original
    assert driver.journal.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0]==1
    assert state['domains']=={} and ('define',) not in state['calls']


def native(tap='dt-data0'):
    from test_runtime import request
    value=request(lab_id='other-lab',node_id='native-vd')
    value['spec']['endpoints'][0]['host_interface']=tap
    return value


def test_vm_blocks_container_interface_before_submission(definition):
    driver,birth,xml,state,_,_=definition
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='resource reserved'):
        driver.journal.submit(native())
    assert driver.journal.db.total_changes==before
    assert state['domains']=={}
    assert driver.prepare('first-define',birth,xml)['phase']=='prepared'


def test_container_blocks_vm_without_partial_reservations(definition,tmp_path):
    from dnlab_runtime.journal import Journal
    from test_vm_backend_exclusion import vm_driver
    original,birth,xml,state,_,_=definition
    journal=Journal(tmp_path/'container-first')
    try:
        driver=vm_driver(journal,original)
        journal.submit(native())
        before=[tuple(row) for row in journal.db.execute('SELECT * FROM resources ORDER BY key')]
        with pytest.raises(Conflict,match='resource reserved'):
            driver.prepare('vm',birth,xml)
        assert [tuple(row) for row in journal.db.execute('SELECT * FROM resources ORDER BY key')]==before
        assert journal.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0]==0
        assert state['domains']=={}
    finally:journal.close()


@pytest.mark.parametrize('fault',['missing','creator','extra'])
def test_retry_and_apply_refuse_changed_original_reservations(definition,fault):
    driver,birth,xml,state,_,_=definition
    db=driver.journal.db
    if fault=='missing':db.execute("DELETE FROM resources WHERE key='interface:dt-data0'")
    elif fault=='creator':db.execute("UPDATE resources SET operation_id=?",('e'*32,))
    else:db.execute('INSERT INTO resources VALUES(?,?,?,?)',
        ('interface:unexpected',birth['lab_id'],birth['node_id'],birth['creator_operation_id']))
    before=db.total_changes
    with pytest.raises(Conflict,match='TAP reservations differ'):driver.prepare('first-define',birth,xml)
    with pytest.raises(Conflict,match='TAP reservations differ'):driver.apply(birth['creator_operation_id'])
    assert db.total_changes==before and state['domains']=={} and state['calls']==[]


def test_uncertain_define_preserves_tap_reservations_on_reopen(definition):
    from test_vm_backend_exclusion import vm_driver
    driver,birth,_,state,_,_=definition
    state['lost']=True
    with pytest.raises(OSError):driver.apply(birth['creator_operation_id'])
    reopened=vm_driver(driver.journal,driver)
    with pytest.raises(Conflict,match='not repeated'):reopened.apply(birth['creator_operation_id'])
    with pytest.raises(Conflict,match='resource reserved'):driver.journal.submit(native())
    assert driver.journal.db.execute('SELECT count(*) FROM resources').fetchone()[0]==2


@pytest.mark.parametrize('competitor',['container','vm'])
def test_atomic_tap_admission_across_connections(definition,tmp_path,competitor):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from dnlab_runtime.journal import Journal
    from test_vm_backend_exclusion import vm_driver
    original,birth,xml,state,_,_=definition
    left=Journal(tmp_path/'race');right=Journal(tmp_path/'race')
    try:
        first=vm_driver(left,original);second=vm_driver(right,original)
        other=deepcopy(birth)
        other.update(uuid='22345678-1234-4234-8234-123456789abc',node_id='other-vm',
            creator_operation_id='e'*32,nonce='f'*32)
        root=ET.fromstring(xml);root.find('uuid').text=other['uuid'];root.find('name').text='other-vm'
        owner=root.find('metadata/{'+OWNER_NS+'}owner')
        for key in ('node_id','creator_operation_id','nonce'):owner.set(key,other[key])
        other_xml=ET.tostring(root,encoding='unicode')
        barrier=threading.Barrier(2)
        def attempt(action):
            barrier.wait(timeout=3)
            try:action();return 'accepted'
            except Conflict:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(attempt,lambda:first.prepare('first',birth,xml))
            b=pool.submit(attempt,lambda:right.submit(native()) if competitor=='container'
                else second.prepare('second',other,other_xml))
            assert sorted([a.result(timeout=5),b.result(timeout=5)])==['accepted','refused']
        assert left.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0]+left.db.execute('SELECT count(*) FROM operations').fetchone()[0]==1
        assert state['domains']=={} and state['calls']==[]
    finally:left.close();right.close()
