"""Finite coordinator census with synthetic inventories and scheduled sources."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_census import CleanupCensus, candidate, processes, classify, process_groups
from cleanup_execution import canonical_digest


@pytest.fixture
def census():
    rows = [dict(pid=41, start_ticks='100', argv=['/usr/local/bin/dnlab-lab-cleanup', 'start']),
            dict(pid=42, start_ticks='200', argv=['python3.13', '/usr/local/bin/dnlab-multinode-api'])]
    sources = {'complete': True, 'candidates': [{'source_id': '/fixture/job', 'sha256': 'a' * 64}]}
    context = {'boot_id': 'synthetic', 'host_config_sha256': 'b' * 64}
    calls = []
    def read_rows():
        calls.append('processes')
        return deepcopy(rows)
    def read_sources():
        calls.append('sources')
        return deepcopy(sources)
    observer = CleanupCensus(context=context, expected_processes=processes(rows),
        scheduled_sha256=canonical_digest(sources), read_context=lambda: deepcopy(context),
        process_inventory=read_rows, sources=read_sources)
    return observer, rows, sources, context, calls


def test_fresh_double_census_preserves_scope_without_admitting_gate(census):
    observer, _, _, _, calls = census
    result = observer()
    assert result['unexpected_actors'] == [] and result['gate_allowed'] is False
    assert result['scope'] == 'declared-single-coordinator-recognized-entrypoints'
    assert calls == ['processes', 'sources'] * 2
    observer()
    assert calls == ['processes', 'sources'] * 4


@pytest.mark.parametrize('argv', [
    ['dnlab-multinode', 'status', '--json'],
    ['python3.13', '-B', '-I', '/venv/bin/dnlab-multinode', 'cleanup-labs'],
    ['python3', '-m', 'dnlab_multinode.lab_cleanup_cli', 'sync'],
])
def test_any_recognized_extra_cli_blocks_native_exclusion(census, argv):
    observer, rows, *_ = census
    rows.append(dict(pid=99, start_ticks='300', argv=argv))
    with pytest.raises(ValueError, match='process set differs'):
        observer()


@pytest.mark.parametrize('change', ['removed', 'restarted', 'command', 'duplicate'])
def test_original_process_conflicts_are_not_adopted(census, change):
    observer, rows, *_ = census
    if change == 'removed': rows.pop()
    elif change == 'restarted': rows[0]['start_ticks'] = '101'
    elif change == 'command': rows[0]['argv'].append('--different')
    else: rows.append(deepcopy(rows[0]))
    with pytest.raises(ValueError): observer()


@pytest.mark.parametrize('change', ['content', 'missing', 'incomplete', 'metadata'])
def test_scheduled_sources_require_original_qualification(census, change):
    observer, _, sources, *_ = census
    if change == 'content': sources['candidates'][0]['sha256'] = 'c' * 64
    elif change == 'missing': sources['candidates'] = []
    elif change == 'incomplete': sources['complete'] = False
    else: sources['candidates'][0]['metadata_sha256'] = 'd' * 64
    with pytest.raises(ValueError): observer()


def test_second_scan_and_context_recheck_are_required(census):
    observer, rows, _, context, calls = census
    original = observer._sources
    def change_context():
        result = original()
        if len(calls) == 4: context['boot_id'] = 'replacement'
        return result
    observer._sources = change_context
    with pytest.raises(ValueError, match='changed during observation'): observer()
    assert calls == ['processes', 'sources'] * 2


def test_second_scan_does_not_hide_new_actor(census):
    observer, rows, *_ = census
    original = observer._sources
    def add_cli():
        result = original()
        rows.append(dict(pid=99, start_ticks='300', argv=['dnlab-multinode', 'status']))
        return result
    observer._sources = add_cli
    with pytest.raises(ValueError, match='process set differs'): observer()


def test_payload_words_are_not_entrypoints_and_opaque_code_is_not_absence_proof():
    assert candidate(['printf', 'dnlab-lab-cleanup']) is False
    assert candidate(['python3', '-c', 'dnlab-lab-cleanup']) is False
    with pytest.raises(ValueError, match='incomplete Python'): candidate(['python3', '-m'])


@pytest.mark.parametrize('argv,expected', [
    (['dnlab-multinode', '', 'status'], True),
    (['python3', '-B', '/bin/dnlab-lab-cleanup', '', 'start'], True),
    (['printf', '', 'dnlab-lab-cleanup'], False),
])
def test_empty_arguments_after_program_are_legal(argv, expected):
    assert candidate(argv) is expected


@pytest.mark.parametrize('argv', [[], ['', 'dnlab-multinode'], ['dnlab-multinode', '\0'],
                                 ['dnlab-multinode', None], ['python3', '-m', '']])
def test_empty_program_invalid_words_or_missing_module_are_rejected(argv):
    with pytest.raises(ValueError): candidate(argv)


@pytest.mark.parametrize('entry,role', [
    ('/opt/dnlab-image-build/api.py', 'image_build'),
    ('/opt/dnlab-multinode/dnlab_multinode/api.py', 'cleanup'),
    ('/root/dnlab-multinode/dnlab_multinode/cli.py', 'cleanup'),
    ('/usr/local/lib/python3.13/site-packages/dnlab_multinode/lab_cleanup_cli.py', 'cleanup'),
    ('/other/api.py', 'unqualified_script'),
    ('/other/cli.py', 'unqualified_script'),
    ('api.py', 'unqualified_script'),
    ('/opt/dnlab-image-build/../dnlab-image-build/api.py', 'unqualified_script'),
])
def test_script_paths_distinguish_roles_without_dropping_unknowns(entry, role):
    assert classify(['python', '-B', entry]) == role
    assert candidate(['python', entry]) is True


def test_image_build_is_separate_but_blocks_gate_admission(census):
    observer, rows, *_ = census
    rows.append(dict(pid=99, start_ticks='300', argv=['python', '/opt/dnlab-image-build/api.py']))
    grouped = process_groups(rows)
    assert len(grouped['cleanup']) == 2 and len(grouped['image_build']) == 1
    assert len(processes(rows)) == 3
    with pytest.raises(ValueError, match='qualified hold required'): observer()


def test_unqualified_script_is_not_an_implicit_exemption(census):
    observer, rows, *_ = census
    rows.append(dict(pid=99, start_ticks='300', argv=['python', '/unknown/api.py']))
    with pytest.raises(ValueError, match='unqualified script'): observer()
