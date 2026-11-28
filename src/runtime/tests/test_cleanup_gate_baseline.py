"""Synthetic same-process baseline capture; no host inventory is read."""
from copy import deepcopy
import os
from pathlib import Path
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from cleanup_execution import canonical_digest
from cleanup_gate_baseline import BaselineComparisonError, capture
from cleanup_scope_sources import ROOT


def case():
    context = dict(boot_id='original', namespaces={'pid': {'device': 1, 'inode': 2}})
    owner = dict(pid=os.getpid(), start_ticks='42', boot_id='original',
                 namespace_sha256=canonical_digest(context['namespaces']),
                 executable_sha256='a'*64, cmdline_sha256='b'*64)
    parent = dict(source_id=ROOT, kind='directory', names=['original.scope'],
                  metadata=[57, 1, stat.S_IFDIR | 0o755, 0, 0, 60, 10, 10])
    file = dict(source_id=ROOT+'/original.scope', kind='file', sha256='c'*64,
                metadata=[57, 2, stat.S_IFREG | 0o644, 0, 0, 3, 1, 1])
    historical = dict(complete=True, candidates=[parent, file])
    current = deepcopy(historical)
    current['candidates'][0]['metadata'][6:] = [20, 20]
    return context, owner, historical, current


def test_current_timestamps_are_saved_without_normalizing_later_comparisons():
    context, owner, historical, current = case()
    original = deepcopy(historical)
    saved = []
    result = capture(historical, context=context, read_sources=lambda: deepcopy(current),
                     verify_actors=lambda: 'd'*64, read_owner=lambda: deepcopy(owner), persist=saved.append)
    assert result == saved[0] and result['baseline'] == current
    assert result['current_sha256'] == canonical_digest(current)
    assert result['current_sha256'] != result['historical_sha256']
    assert historical == original


def test_unstable_initial_reads_do_not_publish_a_baseline():
    context, owner, historical, current = case()
    changed = deepcopy(current)
    changed['candidates'][0]['metadata'][6] += 1
    reads = iter([current, changed])
    saved = []
    with pytest.raises(ValueError, match='during baseline capture'):
        capture(historical, context=context, read_sources=lambda: deepcopy(next(reads)),
                verify_actors=lambda: 'd'*64, read_owner=lambda: deepcopy(owner), persist=saved.append)
    assert saved == []


@pytest.mark.parametrize('change', ['file', 'entries', 'inode', 'mode', 'size', 'paths'])
def test_only_old_parent_timestamps_can_change_before_the_gate(change):
    context, owner, historical, current = case()
    if change == 'file':
        current['candidates'][1]['sha256'] = 'f'*64
    elif change == 'entries':
        current['candidates'][0]['names'].append('foreign.scope')
    elif change == 'paths':
        current['candidates'].pop()
    else:
        index = {'inode': 1, 'mode': 2, 'size': 5}[change]
        current['candidates'][0]['metadata'][index] += 1
    saved = []
    with pytest.raises(ValueError):
        capture(historical, context=context, read_sources=lambda: deepcopy(current),
                verify_actors=lambda: 'd'*64, read_owner=lambda: deepcopy(owner), persist=saved.append)
    assert saved == []


@pytest.mark.parametrize('change', ['owner', 'actors', 'sources'])
def test_change_at_persistence_is_refused_without_returning_a_baseline(change):
    context, owner, historical, current = case()
    state = dict(owner=owner, actors='d'*64, sources=current)
    saved = []

    def persist(value):
        saved.append(value)
        if change == 'owner':
            state['owner']['start_ticks'] = '43'
        elif change == 'actors':
            state['actors'] = 'e'*64
        else:
            state['sources']['candidates'][0]['metadata'][6] += 1

    with pytest.raises(ValueError, match='after persistence'):
        capture(historical, context=context, read_sources=lambda: deepcopy(state['sources']),
                verify_actors=lambda: state['actors'], read_owner=lambda: deepcopy(state['owner']), persist=persist)
    assert len(saved) == 1


def ssh_case():
    context, owner, historical, current = case()
    row = deepcopy(current['candidates'][1])
    row['source_id'] = ROOT+'/session-c35.scope'
    row['metadata'][1] = 35
    current['candidates'].append(row)
    current['candidates'][0]['names'].append('session-c35.scope')
    current['candidates'][0]['metadata'][5] += 20

    def qualify(sid, source):
        assert sid == 'c35' and source == row
        return dict(session_id=sid, context_sha256=canonical_digest(context),
                    source_sha256=canonical_digest(source), qualification_sha256='f'*64)

    return context, owner, historical, current, qualify


def test_ssh_is_opt_in_requalified_and_saved_without_relaxing_later_comparison():
    context, owner, historical, current, qualify = ssh_case()
    calls, saved = [], []

    def verify(sid, row):
        calls.append(sid)
        return qualify(sid, row)

    result = capture(historical, context=context, read_sources=lambda: deepcopy(current),
                     verify_actors=lambda: 'd'*64, read_owner=lambda: deepcopy(owner),
                     persist=saved.append, qualify_ssh=verify)
    assert calls == ['c35', 'c35']
    assert result == saved[0] and result['baseline'] == current
    assert len(result['prebaseline_ssh']) == 1
    assert historical != current
    # Execution still compares the actual immutable baseline, not its history.
    changed = deepcopy(current)
    changed['candidates'][0]['names'].append('session-c36.scope')
    with pytest.raises(ValueError, match='entries changed'):
        capture(current, context=context, read_sources=lambda: changed,
                verify_actors=lambda: 'd'*64, read_owner=lambda: owner, persist=saved.append)
    assert len(saved) == 1


@pytest.mark.parametrize('change', ['no_verifier', 'foreign', 'removed', 'existing', 'wrong_proof', 'late'])
def test_ssh_does_not_admit_other_deltas_or_uncertain_qualifications(change):
    context, owner, historical, current, qualify = ssh_case()
    if change == 'foreign':
        current['candidates'][-1]['source_id'] = ROOT+'/foreign.scope'
    elif change == 'removed':
        current['candidates'].pop(1)
    elif change == 'existing':
        current['candidates'][1]['sha256'] = 'e'*64
    calls, saved = [], []

    def verify(sid, row):
        result = qualify(sid, row)
        calls.append(sid)
        if change == 'wrong_proof' or (change == 'late' and len(calls) == 2):
            result['context_sha256'] = '0'*64
        return result

    with pytest.raises(ValueError):
        capture(historical, context=context, read_sources=lambda: deepcopy(current),
                verify_actors=lambda: 'd'*64, read_owner=lambda: deepcopy(owner),
                persist=saved.append, qualify_ssh=None if change == 'no_verifier' else verify)
    assert len(saved) == (1 if change == 'late' else 0)


def test_rejected_read_keeps_its_actual_delta_in_exception_evidence():
    from cleanup_gate_diagnostics import exception_chain
    context, owner, historical, current, _ = ssh_case()
    with pytest.raises(BaselineComparisonError) as caught:
        capture(historical, context=context, read_sources=lambda: deepcopy(current),
                verify_actors=lambda: 'd'*64, read_owner=lambda: owner, persist=lambda _: None)
    evidence = exception_chain(caught.value)[0]['baseline_comparison']
    assert evidence['added'] == [ROOT+'/session-c35.scope']
    assert evidence['removed'] == [] and evidence['changed'] == [ROOT]
    current['candidates'].clear()
    assert exception_chain(caught.value)[0]['baseline_comparison'] == evidence
