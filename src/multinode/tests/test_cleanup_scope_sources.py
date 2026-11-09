"""Gate-owned scope transitions with synthetic proof providers; no host IO."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_execution import canonical_digest
from cleanup_scope_sources import QualifiedScopeSources, ROOT
from tests.test_cleanup_census import census


def descriptor(rows):
    return {'complete': True, 'candidates': sorted(deepcopy(rows), key=lambda row: row['source_id'])}


@pytest.fixture
def scope():
    cid = 'a' * 64
    path = ROOT + '/docker-' + cid + '.scope'
    directory = {'source_id': ROOT, 'kind': 'directory', 'metadata': [1, 2, 16877, 0, 0, 10, 20, 30], 'names': ['session-original.scope']}
    baseline = descriptor([directory,
        {'source_id': ROOT + '/session-original.scope', 'kind': 'file', 'sha256': 'b' * 64},
        {'source_id': '/etc/cron.d/policy', 'kind': 'file', 'sha256': 'c' * 64}])
    rows = [{'source_id': path, 'kind': 'file', 'sha256': 'd' * 64},
            {'source_id': path + '.d', 'kind': 'directory', 'names': ['50-DevicePolicy.conf']},
            {'source_id': path + '.d/50-DevicePolicy.conf', 'kind': 'file', 'sha256': 'e' * 64}]
    current = descriptor(baseline['candidates'] + rows)
    root = next(row for row in current['candidates'] if row['source_id'] == ROOT)
    root['names'] += [Path(path).name, Path(path).name + '.d']
    root['metadata'][5:] = [100, 200, 300]
    context = dict(gate_id='gate', lab_id='lab', host_id='master', coordinator_id='only',
                   boot_id='boot', window_id='window', image_build_hold_sha256='f' * 64)
    intent = {'action': 'created', 'container_id': cid, 'nonce': '1' * 32,
              'journal_sha256': '2' * 64, 'birth_sha256': '3' * 64, 'rows': rows}
    calls = []
    def verify(actual, observed):
        calls.append((deepcopy(actual), deepcopy(observed)))
        return {'context': deepcopy(context), **{key: actual[key] for key in (
            'action', 'container_id', 'nonce', 'journal_sha256', 'birth_sha256')},
            'definition_profile_sha256': '4' * 64, 'rows_sha256': canonical_digest(actual['rows'])}
    qualifier = QualifiedScopeSources(baseline, context=context, definition_profile_sha256='4' * 64,
                                      transitions=lambda: [deepcopy(intent)], verify=verify)
    return qualifier, baseline, current, intent, context, calls


def test_creation_projects_only_proven_scope_and_reverifies_every_call(scope):
    qualifier, baseline, current, _, _, calls = scope
    original = deepcopy(current)
    assert qualifier(current) == baseline
    assert qualifier(current) == baseline
    assert current == original and len(calls) == 2


def test_verified_removal_uses_original_baseline_rows_and_absence(scope):
    original, baseline, created, intent, context, calls = scope
    intent['action'] = 'removed'
    qualifier = QualifiedScopeSources(created, context=context, definition_profile_sha256='4' * 64,
        transitions=lambda: [intent], verify=original._verify)
    assert qualifier(baseline) == created
    assert calls[0][1] == {}


@pytest.mark.parametrize('change', ['policy', 'foreign-scope', 'parent-owner', 'parent-inode',
                                  'definition', 'missing-scope', 'symlink', 'duplicate'])
def test_unrelated_or_unqualified_changes_are_not_projected(scope, change):
    qualifier, _, current, intent, _, calls = scope
    rows = current['candidates']
    root = next(row for row in rows if row['source_id'] == ROOT)
    if change == 'policy': next(row for row in rows if row['source_id'].startswith('/etc/'))['sha256'] = '5' * 64
    elif change == 'foreign-scope':
        root['names'].append('session-foreign.scope')
        rows.append({'source_id': ROOT + '/session-foreign.scope', 'kind': 'file', 'sha256': '5' * 64})
    elif change == 'parent-owner': root['metadata'][3] = 1000
    elif change == 'parent-inode': root['metadata'][1] += 1
    elif change == 'definition': next(row for row in rows if row['source_id'].endswith('.conf'))['sha256'] = '5' * 64
    elif change == 'missing-scope': rows.remove(next(row for row in rows if row['source_id'].endswith('a' * 64 + '.scope')))
    elif change == 'symlink':
        row = next(row for row in rows if row['source_id'].endswith('.conf'))
        row['kind'] = 'symlink'
        intent['rows'] = [deepcopy(row) if value['source_id'] == row['source_id'] else value for value in intent['rows']]
    else: rows.append(deepcopy(rows[0]))
    with pytest.raises(ValueError): qualifier(current)


@pytest.mark.parametrize('field', ['context', 'nonce', 'birth_sha256', 'journal_sha256',
                                  'definition_profile_sha256', 'rows_sha256'])
def test_receipt_must_match_original_gate_birth_journal_and_profile(scope, field):
    qualifier, _, current, *_ = scope
    verify = qualifier._verify
    def changed(*args):
        receipt = verify(*args)
        receipt[field] = {'gate_id': 'foreign'} if field == 'context' else '9' * 64
        return receipt
    qualifier._verify = changed
    with pytest.raises(ValueError, match='current scope proof differs'): qualifier(current)


def test_no_proof_or_failed_current_read_does_not_authorize_delta(scope):
    qualifier, _, current, *_ = scope
    qualifier._transitions = lambda: []
    with pytest.raises(ValueError, match='unqualified scheduled'): qualifier(current)
    qualifier._transitions = lambda: (_ for _ in ()).throw(OSError('synthetic journal failure'))
    with pytest.raises(OSError): qualifier(current)


def test_census_normalizes_scopes_but_retains_actual_observation_and_default_denial(scope, census):
    qualifier, baseline, current, *_ = scope
    observer, _, sources, *_ = census
    sources.clear(); sources.update(current)
    observer._scheduled = canonical_digest(baseline)
    observer._qualify_sources = qualifier
    result = observer()
    assert result['scheduled_sha256'] == canonical_digest(baseline)
    assert result['observed_scheduled_sha256'] == canonical_digest(current)
    assert result['gate_allowed'] is False
    observer._qualify_sources = None
    with pytest.raises(ValueError, match='descriptor differs'): observer()
