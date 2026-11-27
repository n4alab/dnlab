"""Prepared-only cancellation with original journals and synthetic native IO."""
from copy import deepcopy
import json

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.lab_closure import check as lab_check
from dnlab_runtime.libvirt_session import DedicatedSession
from dnlab_runtime.libvirt_xml import render_domain
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_template import TemplateError, template_digest
from vm_prepared_cancellation import prepared_state, request_proof, cancel_prepared, completed
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process
from test_vm_definition import definition as original_definition
from test_vm_template import template, instance


@pytest.fixture
def isolated_definition(template, instance, tmp_path):
    directory = tmp_path/'definition-fixture'
    directory.mkdir()
    generator = original_definition.__wrapped__(template, instance, directory)
    yield next(generator)
    with pytest.raises(StopIteration): next(generator)


@pytest.fixture
def prepared(executor, isolated_definition, instance, template):
    hold, hold_id, state, native, commands, adapter = executor
    hold.acquire(hold_id)
    old_driver, _, _, calls, proof, _ = isolated_definition
    epoch = commands.runtime.check();scope = hold.read(hold_id)['scope']
    plan = deepcopy(instance);plan['domain'].update(lab_id=scope['lab_id'],host_id=scope['host_id'])
    profile = deepcopy(old_driver.session.profile);profile['host_id'] = scope['host_id']
    proof = deepcopy(proof);proof['profile_sha256'] = fingerprint(profile)
    session = DedicatedSession(profile, lambda: deepcopy(proof))
    driver = VMDefinitionDriver(hold.journal, old_driver.connection, session, old_driver.preflight, no_domain_code=42)
    birth = {k:plan['domain'][k] for k in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256'] = template_digest(template);operation = birth['creator_operation_id']
    value = driver.prepare('first-cancel', birth, render_domain(template, **plan))
    initial = dict(id=operation,birth=birth,definition_sha256=value['request_fingerprint'],template=template,
        bundle_root=plan['bundle_root'],tap_context={},tap_requests=[],phase='pending',last_step='preflight',
        error_type='CleanupCompatibilityError',receipt=None)
    db = hold.journal.db
    db.execute('CREATE TABLE vm_initial_starts (id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
    db.execute('INSERT INTO vm_initial_starts VALUES(?,?,?)',(operation,canonical(initial),fingerprint(initial)))
    original = prepared_state(db,operation=operation,hold_id=hold_id,epoch=epoch)
    request = dict(id='e'*32,nonce='f'*32,original_sha256=fingerprint(original),
                   owner_sha256=fingerprint(epoch['snapshot']),absence_sha256='a'*64)
    observed = request_proof(request,original)
    return hold,hold_id,state,driver,original,request,observed,calls


def test_archive_closes_old_generation_and_keeps_original_hold_restorable(prepared):
    hold,hold_id,state,driver,original,request,observed,calls = prepared;db = hold.journal.db
    result = cancel_prepared(db,request,original,observe=lambda:deepcopy(observed))
    assert result['history_preserved'] and result['vm_never_created'] and not result['guest_shutdown_claimed']
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 1
    assert json.loads(db.execute('SELECT payload FROM vm_prepared_cancellations').fetchone()[0])['original'] == original
    assert hold.read(hold_id)['phase'] == 'held'
    birth = json.loads(original['definition']['payload'])['birth']
    with pytest.raises(Conflict,match='closing or closed'):
        driver.prepare('first-cancel',birth,json.loads(original['definition']['payload'])['xml'])
    with pytest.raises(Conflict,match='closing or closed'):
        lab_check(hold.journal,dict(lab_id=birth['lab_id'],node_id=birth['node_id'],request_id='other',action='start',lab_generation=1))
    before = db.total_changes
    assert cancel_prepared(db,request,original,observe=lambda:deepcopy(observed)) == result
    assert db.total_changes == before
    state['cleanup'] = True
    assert hold.restore(hold_id)['phase'] == 'restored'
    assert completed(db,request,original) == result
    assert not any(row[0]=='define' for row in calls['calls'])


@pytest.mark.parametrize('field',['domains_absent','directory_absent','taps_absent','original_owner_alive'])
def test_failed_absence_or_owner_proof_preserves_everything(prepared,field):
    hold,hold_id,_,_,original,request,observed,_ = prepared;db=hold.journal.db
    observed[field] = False;before = db.total_changes
    with pytest.raises(TemplateError,match='observation differs'):
        cancel_prepared(db,request,original,observe=lambda:deepcopy(observed))
    assert prepared_state(db,operation=original['operation'],hold_id=hold_id,epoch=original['epoch']) == original
    assert db.execute('SELECT 1 FROM lab_closures').fetchone() is None
    assert db.execute("SELECT 1 FROM sqlite_master WHERE name='vm_prepared_cancellations'").fetchone() is None


def test_failure_after_archiving_rolls_back_archive_fence_and_claims(prepared):
    hold,hold_id,_,_,original,request,observed,_ = prepared;db=hold.journal.db;checks=[]
    def observer():
        checks.append(True)
        if len(checks)==2:raise OSError('synthetic observation lost')
        return deepcopy(observed)
    with pytest.raises(OSError,match='observation lost'):
        cancel_prepared(db,request,original,observe=observer)
    assert prepared_state(db,operation=original['operation'],hold_id=hold_id,epoch=original['epoch']) == original
    assert db.execute('SELECT 1 FROM lab_closures').fetchone() is None


@pytest.mark.parametrize('fault',['definition-dispatched','allocation-step','foreign-worker','lost-claim'])
def test_nonprepared_or_unqualified_state_refuses(prepared,fault):
    hold,hold_id,_,_,original,_,_,_ = prepared;db=hold.journal.db
    if fault=='foreign-worker':
        db.execute('CREATE TABLE unexpected_workers (id TEXT)');db.execute("INSERT INTO unexpected_workers VALUES('other')")
    elif fault=='lost-claim':db.execute('DELETE FROM resources WHERE key=?',(original['vm_claims'][0]['key'],))
    else:
        table='vm_definition_intents' if fault=='definition-dispatched' else 'vm_initial_starts'
        row=db.execute('SELECT payload FROM '+table).fetchone();value=json.loads(row[0])
        if fault=='definition-dispatched':value['phase']='defining'
        else:value['last_step']='directory'
        db.execute('UPDATE '+table+' SET payload=?,fingerprint=?',(canonical(value),fingerprint(value)))
    with pytest.raises(TemplateError):prepared_state(db,operation=original['operation'],hold_id=hold_id,epoch=original['epoch'])


def test_unacknowledged_write_binding_never_opens_original_writable(prepared, monkeypatch):
    from image_build_admin_fence import OriginalGateFence
    import image_build_unreleased_execution
    from vm_prepared_cancellation import execute_cancellation
    hold,_,_,_,original,request,observed,_ = prepared
    fence = object.__new__(OriginalGateFence)
    fence.database=hold.journal.db;fence.binding={'synthetic':'binding'};fence.baseline={'synthetic':'raw'}
    opened=[]
    def forbidden(_):opened.append(True);raise AssertionError('unexpected writer')
    monkeypatch.setattr(image_build_unreleased_execution,'_writer',forbidden)
    with pytest.raises(TemplateError,match='write binding required'):
        execute_cancellation(fence,request,original,observe=lambda:deepcopy(observed),persist=lambda *_:None)
    assert opened == []
