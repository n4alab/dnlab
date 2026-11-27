"""Policy retirement uses synthetic I/O and preserves the uncertain command."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_policy_retirement import (
    ObservedPolicyRecovery, policy_receipt, policy_state, retire_policy,
    policy_observation, execute_policy_retirement,
)
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def pending_policy(executor, monkeypatch):
    hold, operation, state, native, commands, adapter = executor
    hold.acquire(operation)
    state['cleanup'] = True
    original = adapter.engine.update_policy
    def response_lost(restart):
        original(restart)
        raise ProcessLookupError('healthcheck exited after update')
    monkeypatch.setattr(adapter.engine, 'update_policy', response_lost)
    with pytest.raises(ProcessLookupError):
        hold.restore(operation)
    pending = hold.read(operation)['actions']['restore_restart']['reference']['token']
    epoch = commands.runtime.check()
    args = dict(hold_id=operation, command_id=pending, epoch=epoch)
    proof = policy_state(hold.journal.db, **args)
    request = dict(id='7'*32, nonce='8'*32, original_sha256=fingerprint(proof),
                   owner_sha256=fingerprint(epoch['snapshot']), service_sha256='9'*64,
                   restart_policy=deepcopy(hold.read(operation)['policy']))
    exited = dict(owner_sha256=request['owner_sha256'], pidfd_exit_verified=True,
                  term_count=1, force_used=False)
    return hold, commands, state, args, proof, request, exited


def test_policy_retirement_preserves_known_start_and_uncertain_response(pending_policy):
    hold, commands, state, args, proof, request, exited = pending_policy
    db = hold.journal.db
    before = db.total_changes
    assert policy_state(db, **args) == proof and db.total_changes == before
    actions = deepcopy(state['actions'])
    receipt = retire_policy(db, request, exited, **args, check=lambda: None)
    assert receipt == policy_receipt(request)
    assert policy_state(db, **args, claim_present=False) == proof
    reference = proof['hold']['actions']['restore_restart']['reference']
    with pytest.raises(TemplateError, match='administratively retired'):
        commands.outcome(reference)
    assert commands._read(reference, historical=True)['outcome'] is None
    assert state['actions'] == actions
    before = db.total_changes
    assert retire_policy(db, request, exited, **args, check=lambda: None) == receipt
    assert db.total_changes == before


def test_foreign_workload_blocks_policy_retirement(pending_policy):
    hold, _, _, args, _, request, exited = pending_policy
    db = hold.journal.db
    db.execute('CREATE TABLE vm_definition_intents (id TEXT)')
    db.execute('INSERT INTO vm_definition_intents VALUES(?)', ('foreign',))
    before = db.total_changes
    with pytest.raises(TemplateError, match='workload'):
        retire_policy(db, request, exited, **args, check=lambda: None)
    assert db.total_changes == before
    assert db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 1


def test_changed_service_observation_rolls_back_metadata_retirement(pending_policy):
    hold, _, _, args, proof, request, exited = pending_policy
    calls = []
    def check():
        calls.append(True)
        if len(calls) == 3:
            raise TemplateError('generation changed')
    with pytest.raises(TemplateError, match='generation changed'):
        retire_policy(hold.journal.db, request, exited, **args, check=check)
    assert policy_state(hold.journal.db, **args) == proof
    assert hold.journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone() is None


def test_missing_original_start_ack_is_not_adopted(pending_policy):
    hold, _, _, args, _, _, _ = pending_policy
    db = hold.journal.db
    row = db.execute("SELECT id,payload FROM image_build_control_commands WHERE action='start'").fetchone()
    import json
    from dnlab_runtime.manifest import canonical
    value = json.loads(row['payload'])
    del value['start_ack']
    db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=? WHERE id=?',
               (canonical(value), fingerprint(value), row['id']))
    with pytest.raises(TemplateError):
        policy_state(db, **args)


@pytest.fixture
def observed_recovery(tmp_path):
    journal = Journal(tmp_path/'admin')
    request = dict(id='1'*32, nonce='2'*32, original_sha256='3'*64,
                   owner_sha256='4'*64, service_sha256='5'*64,
                   restart_policy=dict(Name='unless-stopped', MaximumRetryCount=0))
    state = dict(alive=True, lost=False, actions=[], policy=deepcopy(request['restart_policy']))
    def preflight(current, *, owner_alive, restart_policy):
        assert current == request
        return dict(original_sha256=request['original_sha256'], owner_sha256=request['owner_sha256'],
                    service_sha256=request['service_sha256'], owner_alive=state['alive'],
                    restart_policy=deepcopy(state['policy']), execution_lock_held=True,
                    no_native_dispatch=True, vm_resources_absent=True, window_active=True)
    def terminate(current, *, check):
        check()
        state['actions'].append('owner-term')
        state['alive'] = False
        if state['lost']:
            raise OSError('owner response lost')
        return dict(owner_sha256=current['owner_sha256'], pidfd_exit_verified=True,
                    term_count=1, force_used=False)
    def retire(current, proof):
        state['actions'].append('metadata-retirement')
        return policy_receipt(current)
    driver = ObservedPolicyRecovery(journal, preflight=preflight,
                                    terminate_owner=terminate, retire_claim=retire)
    yield driver, request, state
    journal.close()


def test_observational_recovery_never_calls_service_update(observed_recovery):
    driver, request, state = observed_recovery
    driver.prepare(request)
    result = driver.apply(request['id'])
    assert result['phase'] == 'completed'
    assert state['actions'] == ['owner-term', 'metadata-retirement']
    assert driver.apply(request['id']) == result
    assert state['actions'] == ['owner-term', 'metadata-retirement']


def test_uncertain_owner_exit_cannot_be_retried(observed_recovery):
    driver, request, state = observed_recovery
    driver.prepare(request)
    state['lost'] = True
    with pytest.raises(OSError):
        driver.apply(request['id'])
    with pytest.raises(TemplateError, match='TERM uncertain'):
        driver.apply(request['id'])
    assert state['actions'] == ['owner-term']


def test_policy_must_already_match_before_owner_signal(observed_recovery):
    driver, request, state = observed_recovery
    state['policy'] = dict(Name='no', MaximumRetryCount=0)
    with pytest.raises(TemplateError, match='preflight'):
        driver.prepare(request)
    assert state['actions'] == []


def test_legacy_policy_action_phase_is_rejected(observed_recovery):
    from dnlab_runtime.manifest import canonical
    driver, request, state = observed_recovery
    value = driver.prepare(request)
    value.update(phase='policy_requested', owner_exit=dict(owner_sha256=request['owner_sha256'],
                 pidfd_exit_verified=True, term_count=1, force_used=False))
    driver.journal.db.execute('UPDATE image_build_admin_recoveries SET payload=?,fingerprint=? WHERE id=?',
                              (canonical(value), fingerprint(value), request['id']))
    with pytest.raises(TemplateError, match='cannot request a policy action'):
        driver.apply(request['id'])
    assert state['actions'] == []


@pytest.fixture
def policy_physical(pending_policy, tmp_path):
    import os
    import sqlite3
    from image_build_admin_fence import identity
    hold, _, _, args, original, request, exited = pending_policy
    root = tmp_path/'original'
    root.mkdir(mode=0o700)
    db = sqlite3.connect(root/'journal.sqlite3', isolation_level=None)
    db.row_factory = sqlite3.Row
    hold.journal.db.backup(db)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('UPDATE metadata SET version=version')
    (root/'workload.lock').touch(mode=0o600)
    for name in ('journal.sqlite3', 'journal.sqlite3-wal'):
        os.chmod(root/name, 0o600)
    binding = {name: identity((root if name == 'directory' else root/name).stat())
               for name in ('directory', 'workload.lock', 'journal.sqlite3', 'journal.sqlite3-wal')}
    try:
        yield root, binding, db, args, original, request, exited
    finally:
        db.close()


def test_physical_write_requires_durable_binding_first(policy_physical, tmp_path, monkeypatch):
    from image_build_admin_fence import OriginalGateFence
    import image_build_policy_retirement as execution
    root, binding, db, args, original, request, exited = policy_physical
    saved = {}
    writer = execution._writer
    def persist(name, value):
        saved[name] = deepcopy(value)
        return fingerprint(value)
    def open_writer(fence):
        assert list(saved) == ['write-binding.json']
        return writer(fence)
    monkeypatch.setattr(execution, '_writer', open_writer)
    with OriginalGateFence(root, binding) as fence:
        fence.snapshot(tmp_path/'snapshot')
        receipt = execute_policy_retirement(fence, request, original, exited, arguments=args,
            observe=lambda: policy_observation(request, owner_alive=False), persist=persist)
    assert receipt == policy_receipt(request)
    assert policy_state(db, **args, claim_present=False) == original


def test_failed_binding_ack_never_opens_original_writer(policy_physical, tmp_path, monkeypatch):
    from image_build_admin_fence import OriginalGateFence
    import image_build_policy_retirement as execution
    root, binding, db, args, original, request, exited = policy_physical
    def forbidden(_):
        raise AssertionError('writer must not open')
    monkeypatch.setattr(execution, '_writer', forbidden)
    with OriginalGateFence(root, binding) as fence:
        fence.snapshot(tmp_path/'snapshot')
        with pytest.raises(TemplateError, match='not acknowledged'):
            execute_policy_retirement(fence, request, original, exited, arguments=args,
                observe=lambda: policy_observation(request, owner_alive=False), persist=lambda *args: '0'*64)
    assert policy_state(db, **args) == original


def test_lost_report_recovers_checkpointed_receipt_without_new_writer(policy_physical, tmp_path, monkeypatch):
    from image_build_admin_fence import OriginalGateFence
    from image_build_unreleased_execution import CheckpointedRetirementFence
    import image_build_policy_retirement as execution
    root, binding, db, args, original, request, exited = policy_physical
    def lost(name, value):
        if name == 'retirement.json':
            raise OSError('lost report after commit')
        return fingerprint(value)
    with OriginalGateFence(root, binding) as fence:
        fence.snapshot(tmp_path/'first-copy')
        with pytest.raises(OSError, match='lost report'):
            execute_policy_retirement(fence, request, original, exited, arguments=args,
                observe=lambda: policy_observation(request, owner_alive=False), persist=lost)
    db.close()
    assert not (root/'journal.sqlite3-wal').exists()
    def forbidden(_):
        raise AssertionError('completed receipt must not open a writer')
    monkeypatch.setattr(execution, '_writer', forbidden)
    with CheckpointedRetirementFence(root, binding) as fence:
        fence.snapshot(tmp_path/'second-copy')
        receipt = execute_policy_retirement(fence, request, original, exited, arguments=args,
            observe=lambda: policy_observation(request, owner_alive=False),
            persist=lambda name, value: fingerprint(value))
    assert receipt == policy_receipt(request)
    assert not (root/'journal.sqlite3-wal').exists()
