"""Observer composition with synthetic providers; no proc, Docker or SSH IO."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_compatibility import CleanupAttestation, CleanupCompatibilityError, ENTRYPOINTS
from cleanup_execution import canonical_digest
from cleanup_observation import CleanupObservation
from tests.test_cleanup_attestation import protocol


@pytest.fixture
def assembly(protocol):
    _, api, context, actors, current, receipts, clock, _ = protocol
    conditions = {key: deepcopy(value) for key, value in current.items() if key != 'actors'}
    calls = []
    descriptors = {role: {'synthetic_role': role} for role in ENTRYPOINTS}
    observed = {}
    for role, actor in actors.items():
        evidence = {'original_generation': role}
        actor['artifact_sha256'] = canonical_digest(descriptors[role])
        actor['generation_sha256'] = canonical_digest(evidence)
        receipts[role]['artifact_sha256'] = actor['artifact_sha256']
        observed[role] = {key: value for key, value in actor.items() if key != 'qualification_sha256'}
        observed[role]['evidence'] = evidence
    class Receipts:
        def describe(self, role):
            calls.append(('receipt', role))
            return deepcopy(descriptors[role])
    def environment():
        calls.append(('environment',))
        return deepcopy(conditions)
    def container(engine, role, profile, descriptor):
        assert engine is api and descriptor == descriptors[role]
        assert profile['container_id'] == actors[role]['container_id']
        calls.append(('container', role))
        return deepcopy(observed[role])
    def native(descriptor):
        assert descriptor == descriptors['native']
        calls.append(('native',))
        return deepcopy(observed['native'])
    observer = CleanupObservation(api, Receipts(), {
        role: {'container_id': actors[role]['container_id']} for role in ('daemon', 'multinode')},
        native=native, environment=environment, container=container)
    token = CleanupAttestation(context, actors, verify_execution=lambda role, actor: receipts[role],
                               observe=observer, clock=lambda: clock[0], lifetime=10)
    return observer, token, api, conditions, observed, calls


def test_composed_observer_drives_admission_and_fresh_recheck(assembly):
    observer, token, api, _, _, calls = assembly
    assert token.recheck(api)['qualified'] is True
    expected = [('environment',), ('receipt', 'daemon'), ('container', 'daemon'),
                ('receipt', 'multinode'), ('container', 'multinode'),
                ('receipt', 'native'), ('native',), ('environment',)]
    assert calls == expected
    assert token.recheck(api)['qualified'] is True
    assert calls == expected * 2
    assert api.calls == [('GET', '/containers/json?all=1')] * 2


@pytest.mark.parametrize('field', ['window_active', 'native_cli_excluded', 'image_build_held',
                                  'unexpected_actors'])
def test_missing_conditions_stop_before_actor_observation(assembly, field):
    _, token, api, conditions, _, calls = assembly
    conditions[field] = ['unknown'] if field == 'unexpected_actors' else False
    with pytest.raises(CleanupCompatibilityError):
        token.recheck(api)
    assert calls == [('environment',)]


@pytest.mark.parametrize('role,field', [('native', 'artifact_sha256'),
    ('native', 'container_id'), ('daemon', 'container_id'),
    ('multinode', 'generation_sha256')])
def test_conflict_invalidates_and_does_not_adopt(assembly, role, field):
    _, token, api, _, observed, _ = assembly
    original = observed[role][field]
    observed[role][field] = 'e' * 64
    with pytest.raises(CleanupCompatibilityError):
        token.recheck(api)
    observed[role][field] = original
    with pytest.raises(CleanupCompatibilityError) as caught:
        token.recheck(api)
    assert 'invalidated' in str(caught.value.__cause__)


def test_changed_window_during_observation_is_rejected(assembly):
    observer, _, _, conditions, _, calls = assembly
    original = observer._native
    def native(descriptor):
        result = original(descriptor)
        conditions['context']['window_id'] = 'replacement'
        return result
    observer._native = native
    with pytest.raises(ValueError, match='conditions changed'):
        observer()
    assert calls[-1] == ('environment',)


def test_provider_error_is_not_converted_to_success(assembly):
    observer, token, api, _, _, _ = assembly
    def unavailable(descriptor):
        raise OSError('synthetic installation read failure')
    observer._native = unavailable
    with pytest.raises(CleanupCompatibilityError) as caught:
        token.recheck(api)
    assert isinstance(caught.value.__cause__, OSError)
