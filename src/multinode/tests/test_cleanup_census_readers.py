"""Readers use private synthetic proc/source trees, never the real host."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
import cleanup_census_readers as readers


def process(root, pid, argv):
    directory = root / str(pid)
    directory.mkdir()
    (directory / 'stat').write_text(str(pid) + ' (synthetic process) ' + ' '.join(['S'] + ['0'] * 18 + ['123']))
    (directory / 'cmdline').write_bytes(b'\0'.join(word.encode() for word in argv) + b'\0')
    return directory


def test_process_reader_retains_only_recognized_invocations(tmp_path):
    process(tmp_path, 42, ['python3', '-B', '/bin/dnlab-lab-cleanup', 'start'])
    process(tmp_path, 43, ['printf', 'dnlab-multinode'])
    process(tmp_path, 44, ['dnlab-multinode', 'status', '--json'])
    result = readers.process_inventory(tmp_path)
    assert [row['pid'] for row in result] == [42, 44]
    assert all(row['start_ticks'] == '123' for row in result)


def test_process_reader_preserves_legal_empty_arguments(tmp_path):
    process(tmp_path, 42, ['dnlab-multinode', '', 'status'])
    process(tmp_path, 43, ['printf', ''])
    rows = readers.process_inventory(tmp_path)
    assert rows == [{'pid': 42, 'start_ticks': '123', 'argv': ['dnlab-multinode', '', 'status']}]


def test_reader_retains_image_build_and_unknown_scripts(tmp_path):
    process(tmp_path, 42, ['python', '/opt/dnlab-image-build/api.py'])
    process(tmp_path, 43, ['python', '/unknown/api.py'])
    assert [row['pid'] for row in readers.process_inventory(tmp_path)] == [42, 43]


@pytest.mark.parametrize('raw,empty,terminated', [
    (b'\0private-argument\0', [0], True),
    (b'dnlab-multinode\0private-argument', [], False),
    (b'dnlab-multinode\0\xffprivate-argument\0', [], True),
])
def test_rejection_has_private_metadata_without_raw_arguments(tmp_path, raw, empty, terminated):
    import hashlib
    directory = process(tmp_path, 42, ['dnlab-multinode'])
    (directory / 'cmdline').write_bytes(raw)
    with pytest.raises(readers.CensusArgumentError) as caught:
        readers.process_inventory(tmp_path)
    evidence = caught.value.evidence
    assert evidence['pid'] == 42 and evidence['cmdline_sha256'] == hashlib.sha256(raw).hexdigest()
    assert evidence['empty_indices'] == empty and evidence['terminated'] is terminated
    assert 'private-argument' not in str(evidence) + str(caught.value)
    assert 'argv' not in evidence and 'raw' not in evidence


def test_candidate_command_change_is_rejected(tmp_path, monkeypatch):
    path = process(tmp_path, 42, ['dnlab-multinode', 'status'])
    original, calls = readers.read_regular, []
    def changing(source, limit):
        result = original(source, limit)
        if source == path / 'cmdline':
            calls.append(source)
            if len(calls) == 1: source.write_bytes(b'dnlab-multinode\0cleanup-labs\0')
        return result
    monkeypatch.setattr(readers, 'read_regular', changing)
    with pytest.raises(ValueError, match='changed during census'): readers.process_inventory(tmp_path)


def test_missing_field_of_present_process_is_not_absence(tmp_path):
    path = process(tmp_path, 42, ['dnlab-multinode'])
    (path / 'cmdline').unlink()
    with pytest.raises(ValueError, match='field missing'): readers.process_inventory(tmp_path)


def test_scheduled_reader_records_sources_and_symlinks_without_following(tmp_path):
    root = tmp_path / 'jobs'; root.mkdir()
    (root / 'job').write_bytes(b'opaque job data, never execute')
    (root / 'external').symlink_to('/not-followed-by-census')
    result = readers.scheduled_sources([str(root), str(tmp_path / 'absent')])
    rows = {row['source_id']: row for row in result['candidates']}
    assert result['complete'] is True
    assert rows[str(root / 'external')]['target'] == '/not-followed-by-census'
    assert rows[str(root / 'job')]['kind'] == 'file'
    assert rows[str(tmp_path / 'absent')]['kind'] == 'absent'
    assert len(rows) == 4


def test_source_limits_and_symlink_refusal(tmp_path):
    file = tmp_path / 'file'; file.write_bytes(b'oversized')
    alias = tmp_path / 'alias'; alias.symlink_to(file)
    with pytest.raises(ValueError, match='read bound'): readers.read_regular(file, 2)
    with pytest.raises(OSError): readers.read_regular(alias)
