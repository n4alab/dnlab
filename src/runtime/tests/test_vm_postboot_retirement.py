"""Post-boot metadata retirement; real journals, synthetic host observations."""
from copy import deepcopy
import json
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.vm_taps import VMTaps
from dnlab_runtime.vm_template import TemplateError
from vm_prepared_cancellation import prepared_state, prepared_tap_state
from vm_postboot_retirement import proof, retire_vm, completed_vm, release_hold
from test_vm_prepared_cancellation import (
    prepared, isolated_definition, executor, observation, runtime_process, template, instance,
)


@pytest.fixture
def postboot(prepared):
    hold, hold_id, state, driver, before, _, _, calls = prepared
    db = hold.journal.db;operation = before['operation'];epoch = before['epoch']
    initial = json.loads(before['initial']['payload']);initial['last_step'] = 'directory'
    db.execute('UPDATE vm_initial_starts SET payload=?,fingerprint=? WHERE id=?',
               (canonical(initial), fingerprint(initial), operation))
    db.execute('CREATE TABLE vm_tap_intents (id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE,payload TEXT,fingerprint TEXT)')
    db.execute('CREATE TABLE vm_tap_ifindices (ifindex INTEGER PRIMARY KEY,operation_id TEXT,interface_name TEXT)')
    context = dict(boot_id=epoch['snapshot']['record']['boot_id'], **epoch['snapshot']['namespaces']['net'])
    definition = driver.read(operation)
    requests = [dict(nonce=str(i+1)*32, name=target.get('dev'), ifindex=100+i, vnet_header=True)
                for i, target in enumerate(ET.fromstring(definition['xml']).findall('devices/interface/target'))]
    reader = object.__new__(VMTaps);reader.definitions = driver
    specs = reader._plan(definition, context, requests)
    taps = dict(id=operation, birth=definition['birth'], definition_sha256=definition['request_fingerprint'],
                context=context, phase='prepared', items=[dict(spec=s,phase='prepared',proof=None) for s in specs])
    db.execute('INSERT INTO vm_tap_intents VALUES(?,?,?,?)',
               (operation, definition['birth']['uuid'], canonical(taps), fingerprint(taps)))
    for r in requests:db.execute('INSERT INTO vm_tap_ifindices VALUES(?,?,?)', (r['ifindex'],operation,r['name']))
    original = prepared_tap_state(db, operation=operation, hold_id=hold_id, epoch=epoch,
                                  session_profile=driver.session.profile)
    current = dict(host_id=epoch['profile']['host_id'],boot_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                   namespaces=deepcopy(epoch['snapshot']['namespaces']))
    request = dict(id='a'*32,nonce='b'*32,restoration_id='c'*32,
                   original_sha256=fingerprint(original),checkpoint_sha256='d'*64,current_context=current)
    observed = proof(request,original)
    return db,request,original,observed,hold,calls


def test_retire_then_restore_preserves_history_and_never_dispatches(postboot):
    db,request,original,observed,hold,calls = postboot
    result = retire_vm(db,request,original,observe=lambda:deepcopy(observed))
    assert result['prepared_tap_count'] and not result['guest_shutdown_claimed']
    assert not result['original_process_reused']
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 1
    assert completed_vm(db,request,original) == result
    before = db.total_changes
    assert retire_vm(db,request,original,observe=lambda:deepcopy(observed)) == result
    assert db.total_changes == before
    receipt = dict(restoration_id=request['restoration_id'],retirement_id=request['id'],
        current_context=request['current_context'],container_id=json.loads(original['hold']['payload'])['actor']['container_id'],
        running_healthy=True,original_policy_restored=True,original_config_verified=True,generation_verified=True)
    final = release_hold(db,request,original,receipt,observe_restored=lambda:deepcopy(receipt))
    assert final['phase'] == 'completed' and final['original'] == original
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 0
    assert hold.read(original['infrastructure_claim']['operation_id'])['phase'] == 'held'
    assert release_hold(db,request,original,receipt,observe_restored=lambda:deepcopy(receipt)) == final
    assert not any(c[0]=='define' for c in calls['calls'])


@pytest.mark.parametrize('fault',['released-tap','changed-index','worker','definition-ack'])
def test_unqualified_or_dispatched_state_keeps_all_claims(postboot,fault):
    db,request,original,observed,hold,_ = postboot;op = original['operation']
    if fault == 'worker':
        db.execute('CREATE TABLE unknown_worker (payload TEXT)');db.execute("INSERT INTO unknown_worker VALUES('pending')")
    elif fault == 'changed-index':db.execute('UPDATE vm_tap_ifindices SET ifindex=ifindex+1000')
    else:
        table = 'vm_tap_intents' if fault=='released-tap' else 'vm_definition_intents'
        value = json.loads(db.execute('SELECT payload FROM '+table).fetchone()[0])
        if fault=='released-tap':value['items'][0]['phase']='create_requested';value['phase']='creating'
        else:value['creation_ack']={'foreign':True}
        db.execute('UPDATE '+table+' SET payload=?,fingerprint=? WHERE id=?',(canonical(value),fingerprint(value),op))
    before = db.total_changes
    with pytest.raises((TemplateError,Conflict)):
        retire_vm(db,request,original,observe=lambda:deepcopy(observed))
    assert db.total_changes == before
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == len(original['vm_claims'])+1
    assert db.execute('SELECT COUNT(*) FROM lab_closures').fetchone()[0] == 0


def test_same_boot_and_missing_absence_refuse_without_mutation(postboot):
    db,request,original,observed,_,_ = postboot
    bad = deepcopy(request);bad['current_context']['boot_id']=original['epoch']['snapshot']['record']['boot_id']
    with pytest.raises(TemplateError,match='new-boot'):retire_vm(db,bad,original,observe=lambda:observed)
    bad_observed = deepcopy(observed);bad_observed['domains_absent']=False
    with pytest.raises(TemplateError,match='observation'):retire_vm(db,request,original,observe=lambda:bad_observed)
    assert db.execute('SELECT COUNT(*) FROM lab_closures').fetchone()[0] == 0
    # The old live-owner operation retains its original, narrower contract.
    with pytest.raises(TemplateError):prepared_state(db,operation=original['operation'],
        hold_id=original['infrastructure_claim']['operation_id'],epoch=original['epoch'])


def test_observer_loss_rolls_back_vm_and_hold_retirement(postboot):
    db,request,original,observed,_,_ = postboot;count=[]
    def fail_second():
        count.append(True)
        if len(count)==2:raise OSError('observation lost')
        return deepcopy(observed)
    with pytest.raises(OSError):retire_vm(db,request,original,observe=fail_second)
    assert prepared_tap_state(db,operation=original['operation'],
        hold_id=original['infrastructure_claim']['operation_id'],epoch=original['epoch'],
        session_profile=original['prepared_taps']['session_profile']) == original
    retire_vm(db,request,original,observe=lambda:deepcopy(observed))
    with pytest.raises(TemplateError):release_hold(db,request,original,{},observe_restored=lambda:{})
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 1
