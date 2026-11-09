"""Durable registration/reopen with synthetic runtime IO and real local SQL."""
from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_native_scope_proof import capture_birth
from native_scope_registration import NativeScopeRegistration, bind_gate_context
from dnlab_multinode.services.runtime_operations import OperationStore, RuntimeOperationError
from tests.test_cleanup_native_scope_proof import native_scope, definitions


@pytest.fixture
def registration(native_scope, tmp_path):
    proof, _, state, _, _, original = native_scope
    store = OperationStore(tmp_path / 'coordinator')
    for key in ('start', 'stop'):
        entry = state[key]
        store.prepare(entry['request'], entry['target'], entry['journal_id'])
        store.observe('demo', key, {'id': entry['operation_id'], 'lab': 'demo', 'node': 'vd',
                                  'request_id': key, 'phase': 'completed'})
    workload = SimpleNamespace(store=store, runtime=proof.runtime, api=proof.docker,
        start=deepcopy(state['start']['request']), record=dict(lab='demo', node='vd', nonce='2' * 32,
        target=deepcopy(state['start']['target']), journal_id=original['journal_id'],
        container_id=original['container_id'], gate_context=deepcopy(proof.context), phase='running'))
    captures = []
    def capture(**options):
        captures.append(1)
        return capture_birth(**options)
    value = NativeScopeRegistration(workload, context=proof.context, definitions=proof.definitions,
        stop_request_id='stop', process=proof.process, scopes=proof.scopes, capture=capture)
    yield value, state, captures
    store.close()


def test_capture_reuses_original_completed_start_without_resource_mutations(registration):
    value, _, captures = registration
    first = value.register()
    assert len(captures) == 1
    assert first['birth']['container_id'] == value.cid
    before = value.workload.store.db.total_changes
    assert value.register() == first
    assert len(captures) == 1 and value.workload.store.db.total_changes == before


def test_reopened_registration_does_not_recapture(registration):
    value, _, captures = registration
    original = value.register()
    def forbidden(**options): raise AssertionError('recapture attempted')
    reopened = NativeScopeRegistration(value.workload, context=value.context, definitions=value.definitions,
        stop_request_id='stop', process=value.process, scopes=value.scopes, capture=forbidden)
    assert reopened.register() == original and captures == [1]


def test_committed_response_loss_recovers_original_row_without_second_capture(registration, monkeypatch):
    value, _, captures = registration
    save = value.workload.store.save_gate_scope_birth
    def lost(*args):
        save(*args)
        raise OSError('synthetic lost commit response')
    monkeypatch.setattr(value.workload.store, 'save_gate_scope_birth', lost)
    with pytest.raises(OSError): value.register()
    monkeypatch.setattr(value.workload.store, 'save_gate_scope_birth', save)
    assert value.register()['birth']['container_id'] == value.cid and captures == [1]


def test_immutable_row_rejects_replacement_without_overwrite(registration):
    value, _, _ = registration
    original = value.register(); changed = deepcopy(original)
    changed['birth']['nonce'] = '9' * 32
    with pytest.raises(RuntimeOperationError, match='cannot change'):
        value.workload.store.save_gate_scope_birth('demo', value.context['gate_id'], value.cid, changed)
    assert value.workload.store.gate_scope_birth('demo', value.context['gate_id'], value.cid) == original


def test_existing_record_conflict_never_triggers_recapture(registration):
    value, state, captures = registration
    value.register()
    state['container']['State']['StartedAt'] = 'foreign-start'
    with pytest.raises(ValueError): value.register()
    assert captures == [1]


def test_removed_proof_uses_same_saved_birth_without_sql_writes(registration):
    value, state, captures = registration
    value.register(); original = value._saved()
    state['container'] = None; state['scope'] = {'rows': [], 'bodies': {}}
    before = value.workload.store.db.total_changes
    assert value.proof()(value.intent('removed'), {})['action'] == 'removed'
    assert value._saved() == original and value.workload.store.db.total_changes == before
    assert captures == [1]


def test_corrupt_saved_payload_is_not_relearned(registration):
    value, _, captures = registration
    value.register()
    value.workload.store.db.execute("UPDATE gate_scope_births SET payload='{}'")
    with pytest.raises(RuntimeOperationError, match='integrity differs'): value.register()
    assert captures == [1]


def test_gate_context_must_be_bound_before_workload_creation(registration):
    value, _, _ = registration
    row = dict(lab='demo', target={'host': 'master'}, phase='planned')
    bind_gate_context(row, value.context, existing=False)
    assert row['gate_context'] == value.context
    bind_gate_context(row, value.context, existing=True)
    row.pop('gate_context')
    with pytest.raises(ValueError, match='existing fixture'):
        bind_gate_context(row, value.context, existing=True)
    row['phase'] = 'running'
    with pytest.raises(ValueError, match='precede workload creation'):
        bind_gate_context(row, value.context, existing=False)


def test_missing_original_fixture_gate_binding_refuses_without_writes(registration):
    value, _, captures = registration
    value.workload.record.pop('gate_context')
    before = value.workload.store.db.total_changes
    with pytest.raises(ValueError, match='pre-create gate context'):
        NativeScopeRegistration(value.workload, context=value.context, definitions=value.definitions, stop_request_id='stop')
    assert captures == [] and value.workload.store.db.total_changes == before


def test_real_http_fixture_binds_gate_before_any_start_and_refuses_conversion(registration, tmp_path):
    from http_workload_fixture import Workload
    value, _, _ = registration
    runtime = SimpleNamespace(expected_journal_id='d' * 32)
    options = dict(root=tmp_path, lab='demo', node='vd', image='sha256:' + 'e' * 64,
        management={'network': 'fixture', 'ipv4': '192.0.2.2'}, target={'host': 'master'},
        runtime=runtime, store=object())
    workload = Workload(**options, gate_context=value.context)
    assert workload.record['phase'] == 'planned' and workload.record['gate_context'] == value.context
    original = workload.path.read_bytes()
    reopened = Workload(**options, gate_context=value.context)
    assert reopened.record['nonce'] == workload.record['nonce']
    conflict = deepcopy(value.context); conflict['window_id'] = 'foreign'
    with pytest.raises(ValueError, match='original gate context'):
        Workload(**options, gate_context=conflict)
    assert workload.path.read_bytes() == original
    legacy_root = tmp_path / 'legacy'; legacy_root.mkdir()
    options['root'] = legacy_root
    legacy = Workload(**options)
    original = legacy.path.read_bytes()
    with pytest.raises(ValueError, match='original gate context'):
        Workload(**options, gate_context=value.context)
    assert legacy.path.read_bytes() == original
