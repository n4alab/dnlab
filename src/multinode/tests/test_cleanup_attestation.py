"""Local gate admission protocol; all observers and inventories are inert."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_compatibility import (
    CleanupAttestation, CleanupCompatibilityError, ENTRYPOINTS,
    require_qualified_cleanup,
)
from tests.test_cleanup_compatibility_fixture import Engine, daemon


@pytest.fixture
def protocol():
    context = dict(gate_id='gate-1', lab_id='fixture', host_id='master',
                   coordinator_id='only-coordinator', boot_id='boot-1',
                   window_id='window-1', image_build_hold_sha256='f' * 64)
    actors = {role: dict(container_id=None if role == 'native' else digit * 64,
                        artifact_sha256='1' * 64, generation_sha256='2' * 64,
                        qualification_sha256='3' * 64)
              for role, digit in [('daemon', 'a'), ('multinode', 'b'), ('native', 'c')]}
    current = dict(context=deepcopy(context),
                   actors={role: {k: v for k, v in actor.items() if k != 'qualification_sha256'}
                           for role, actor in actors.items()},
                   window_active=True, native_cli_excluded=True,
                   image_build_held=True, unexpected_actors=[])
    receipts = {role: dict(receipt_sha256=actor['qualification_sha256'],
                          artifact_sha256=actor['artifact_sha256'],
                          executed_entrypoints=sorted(ENTRYPOINTS[role]),
                          scope='custom-protection-synthetic-v1')
                for role, actor in actors.items()}
    clock = [0.0]
    calls = []
    def verify(role, actor):
        calls.append(('receipt', role))
        return deepcopy(receipts[role])
    def observe():
        calls.append(('observe',))
        return deepcopy(current)
    token = CleanupAttestation(context, actors, verify_execution=verify,
                               observe=observe, clock=lambda: clock[0], lifetime=10)
    api = Engine([daemon(), daemon(Id='b' * 64, Names=['/multinode'],
                  Labels={'com.docker.compose.service': 'multinode'}, Command='')])
    return token, api, context, actors, current, receipts, clock, calls


def test_admission_requires_qualification_and_fresh_observation_then_rechecks(protocol):
    token, api, context, actors, current, receipts, clock, calls = protocol
    result = require_qualified_cleanup(api, attestation=token)
    assert result['qualified'] is True and result['gate_context'] == context
    assert calls == [('receipt', role) for role in actors] + [('observe',)]
    calls.clear()
    assert token.recheck(api)['qualified'] is True
    assert len(calls) == 4
    assert api.calls == [('GET', '/containers/json?all=1')] * 2


@pytest.mark.parametrize('field', ['boot_id', 'window_id', 'gate_id', 'lab_id',
                                  'host_id', 'coordinator_id', 'image_build_hold_sha256'])
def test_changed_context_is_rejected_without_adoption(protocol, field):
    token, api, _, _, current, *_ = protocol
    current['context'][field] = 'different'
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)
    assert api.calls == [('GET', '/containers/json?all=1')]


@pytest.mark.parametrize('field', ['artifact_sha256', 'generation_sha256', 'container_id'])
def test_replaced_actor_is_rejected_and_old_token_cannot_resume(protocol, field):
    token, api, _, _, current, *_ = protocol
    old = current['actors']['multinode'][field]
    current['actors']['multinode'][field] = 'e' * 64
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)
    current['actors']['multinode'][field] = old
    with pytest.raises(CleanupCompatibilityError) as caught: token.recheck(api)
    assert 'invalidated' in str(caught.value.__cause__)


@pytest.mark.parametrize('field', ['window_active', 'native_cli_excluded', 'image_build_held'])
def test_lost_window_or_unheld_image_build_blocks_admission(protocol, field):
    token, api, _, _, current, *_ = protocol
    current[field] = False
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)


def test_missing_execution_receipt_cannot_be_replaced_by_source_identity(protocol):
    token, api, _, _, _, receipts, *_ = protocol
    receipts['daemon'] = None
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)


@pytest.mark.parametrize('field', ['receipt_sha256', 'artifact_sha256', 'scope'])
def test_receipt_must_match_the_pinned_artifact_and_scope(protocol, field):
    token, api, _, _, _, receipts, *_ = protocol
    receipts['native'][field] = 'wrong'
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)


def test_qualifying_only_cleanup_command_does_not_cover_sync(protocol):
    token, api, _, _, _, receipts, *_ = protocol
    receipts['native']['executed_entrypoints'] = ['cli-cleanup']
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)


@pytest.mark.parametrize('change', ['new', 'missing', 'unrecognized'])
def test_container_and_external_actor_census_changes_block_admission(protocol, change):
    token, api, _, _, current, *_ = protocol
    if change == 'new': api.inventory.append(daemon(Id='d' * 64))
    elif change == 'missing': api.inventory.pop()
    else: current['unexpected_actors'].append('unknown-native-entrypoint')
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)


def test_inventory_read_failure_invalidates_without_retry(protocol):
    token, _, *_ = protocol
    class Failed:
        def request(self, *args): raise TimeoutError('synthetic failure')
    with pytest.raises(CleanupCompatibilityError) as caught: token.recheck(Failed())
    assert isinstance(caught.value.__cause__, TimeoutError)
    assert token._invalid is True


@pytest.mark.parametrize('time', [10.0, -1.0, float('nan')])
def test_expiry_and_clock_changes_are_not_renewed(protocol, time):
    token, api, _, _, _, _, clock, calls = protocol
    clock[0] = time
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)
    assert calls == []


def test_expiry_during_observation_blocks_first_allocation(protocol):
    token, api, _, _, current, _, clock, _ = protocol
    def slow():
        clock[0] = 11
        return deepcopy(current)
    token._observe = slow
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)


def test_caller_mutation_cannot_rewrite_pinned_scope_or_actor(protocol):
    token, api, context, actors, *_ = protocol
    context['lab_id'] = 'foreign'
    actors['daemon']['generation_sha256'] = 'e' * 64
    result = token.recheck(api)
    assert result['gate_context']['lab_id'] == 'fixture'
    result['gate_context']['lab_id'] = 'foreign'
    assert token.recheck(api)['gate_context']['lab_id'] == 'fixture'


def test_json_claim_or_capability_label_is_not_an_attestation(protocol):
    _, api, *_ = protocol
    with pytest.raises(CleanupCompatibilityError):
        require_qualified_cleanup(api, attestation={'qualified': True})
