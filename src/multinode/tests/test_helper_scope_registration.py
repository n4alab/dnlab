"""Helper registration against real local SQL, simulated ownership and Docker."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from helper_scope_registration import HelperScopeRegistration
from dnlab_multinode.services.runtime_operations import OperationStore
from dnlab_multinode.services.jumphost_host import JumphostError
from tests.test_cleanup_helper_scope_proof import proof_case, helper, dns_world, jump_world, relay


@pytest.fixture
def registration(proof_case, tmp_path):
    owner, worker, backend, cleanup, state, payload, proof, intent, calls = proof_case
    store = OperationStore(tmp_path / 'coordinator')
    captures = []
    def capture(*args, **kwargs):
        captures.append(1)
        return deepcopy(payload)
    options = dict(definitions=proof.definitions, docker=proof.docker, process=proof.process,
                   scopes=proof.scopes, capture=capture)
    value = HelperScopeRegistration(store, owner, proof.origin, **options)
    yield value, options, captures, backend, cleanup, state
    store.close()


def test_registration_reopens_without_recapture_or_resource_writes(registration):
    value, options, captures, backend, _, _ = registration
    before = deepcopy(backend.values)
    original = value.register()
    reopened = HelperScopeRegistration(value.store, value.owner, value.origin, **options)
    changes = value.store.db.total_changes
    assert reopened.register() == original
    assert value.store.db.total_changes == changes and captures == [1]
    assert backend.values == before


def test_lost_commit_response_reuses_original_birth(registration, monkeypatch):
    value, _, captures, _, _, _ = registration
    save = value.store.save_gate_scope_birth
    def lost(*args):
        save(*args)
        raise OSError('synthetic lost commit response')
    monkeypatch.setattr(value.store, 'save_gate_scope_birth', lost)
    with pytest.raises(OSError): value.register()
    monkeypatch.setattr(value.store, 'save_gate_scope_birth', save)
    original = value._saved()
    assert value.register() == original and captures == [1]


def test_conflicting_generation_preserves_original_record_without_capture(registration):
    value, _, captures, backend, _, _ = registration
    original = value.register()
    next(iter(backend.values.values()))['State']['StartedAt'] = 'foreign'
    before = deepcopy(backend.values)
    error = JumphostError if value.owner.role == 'jumphost' else ValueError
    message = 'jumphost namespace generation changed' if value.owner.role == 'jumphost' else 'original helper Docker configuration or process changed'
    with pytest.raises(error, match=message): value.register()
    assert value._saved() == original and captures == [1] and backend.values == before


def test_cleanup_proof_retains_birth_without_sql_writes(registration):
    value, _, captures, _, cleanup, state = registration
    original = value.register()
    cleanup(); state['scope'] = {'rows': [], 'bodies': {}}
    changes = value.store.db.total_changes
    assert value.proof()(value.intent('removed'), {})['action'] == 'removed'
    assert value._saved() == original and value.store.db.total_changes == changes and captures == [1]
