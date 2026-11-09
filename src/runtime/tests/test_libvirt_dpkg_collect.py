"""Collector preparation with synthetic artifacts and a temporary filesystem."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools import libvirt_dpkg_collect as entry
from test_libvirt_dpkg_diagnosis import BASE, FACTS, digest, status


@pytest.fixture
def collection_request():
    return dict(context=dict(host_id='synthetic', boot_id='synthetic-boot', namespaces={}),
                expected_sha256=digest(BASE), observed_sha256=digest(BASE + status('other')),
                expected_packages=deepcopy(FACTS), nonce='a' * 32)


def reader(current, old=BASE):
    values = {entry.PATHS[0]: current, entry.PATHS[1]: old}
    return lambda path: None if values[path] is None else dict(raw=values[path], metadata=[1, 2, 3])


@pytest.mark.parametrize('old', [None, BASE, status('older')])
def test_candidate_requires_original_digest_and_never_qualifies(collection_request, old):
    saved = {}
    result = entry.collect(collection_request, read=reader(BASE + status('other'), old),
        context=lambda: deepcopy(collection_request['context']), persist=lambda name, raw: saved.setdefault(name, raw))
    assert result['qualified'] is False and result['passes'] == 2
    assert result['baseline_available'] is (old == BASE)
    assert result['changes'] is None if old != BASE else result['changes'][0]['change'] == 'added'
    assert saved['pass1-status.raw'] == saved['pass2-status.raw'] == BASE + status('other')


def test_context_conflict_prevents_status_reads(collection_request):
    saved = {}
    with pytest.raises(ValueError, match='context differs'):
        entry.collect(collection_request, read=lambda path: pytest.fail('unexpected read'),
                      context=lambda: {}, persist=lambda name, raw: saved.setdefault(name, raw))
    assert set(saved) == {'pass1-context-before.json'}
    assert json.loads(saved['pass1-context-before.json']) == dict(
        expected=collection_request['context'], observed={}, matches=False, pass_number=1, phase='before')


@pytest.mark.parametrize('position,reads', [(1, 0), (2, 2), (3, 2), (4, 4)])
def test_context_pairs_saved_at_each_boundary_without_additional_observations(collection_request, position, reads):
    saved = {}; observations = []; paths = []
    changed = deepcopy(collection_request['context']); changed['boot_id'] = 'different-synthetic-boot'
    def context():
        observations.append(1)
        return deepcopy(changed if len(observations) == position else collection_request['context'])
    def read(path):
        paths.append(path)
        return reader(BASE + status('other'))(path)
    with pytest.raises(ValueError, match='context'):
        entry.collect(collection_request, read=read, context=context,
                      persist=lambda name, raw: saved.setdefault(name, raw))
    number = (position + 1) // 2; phase = 'before' if position % 2 else 'after'
    pair = json.loads(saved[f'pass{number}-context-{phase}.json'])
    assert pair == dict(expected=collection_request['context'], observed=changed,
                        matches=False, pass_number=number, phase=phase)
    assert len(observations) == position and len(paths) == reads


def test_failed_context_artifact_write_does_not_continue_to_status_reads(collection_request):
    def persist(name, raw):
        assert name == 'pass1-context-before.json'
        raise OSError('synthetic report fsync failure')
    with pytest.raises(OSError, match='synthetic report fsync failure'):
        entry.collect(collection_request, read=lambda path: pytest.fail('unexpected read'),
                      context=lambda: deepcopy(collection_request['context']), persist=persist)


@pytest.mark.parametrize('fault', ['current', 'old', 'context'])
def test_between_pass_changes_preserve_captured_evidence(collection_request, fault):
    calls = []; saved = {}
    def read(path):
        calls.append(path)
        value = reader(BASE + status('other'))(path)
        if len(calls) > 2 and fault == ('current' if path == entry.PATHS[0] else 'old'):
            value['metadata'] = ['changed']
        return value
    spaces = []
    def context():
        spaces.append(1)
        return {} if fault == 'context' and len(spaces) == 4 else deepcopy(collection_request['context'])
    with pytest.raises(ValueError, match='changed'):
        entry.collect(collection_request, read=read, context=context, persist=lambda name, raw: saved.setdefault(name, raw))
    assert 'pass1-proof.json' in saved and 'pass2-proof.json' in saved


def test_unexpected_current_digest_preserves_both_raw_passes(collection_request):
    saved = {}
    with pytest.raises(ValueError, match='observed artifact digest differs'):
        entry.collect(collection_request, read=reader(BASE), context=lambda: collection_request['context'],
                      persist=lambda name, raw: saved.setdefault(name, raw))
    assert saved['pass1-status.raw'] == saved['pass2-status.raw'] == BASE


def test_flag_required_before_any_recipe_or_host_access(tmp_path):
    result = subprocess.run([sys.executable, '-B', '-I', '-S', str(Path(entry.__file__).resolve()),
        '--recipe', str(tmp_path / 'missing')], capture_output=True, timeout=10)
    assert result.returncode == 2 and b'requires --collect-host' in result.stderr
    assert not list(tmp_path.iterdir())


def test_source_or_input_drift_refused(tmp_path, monkeypatch):
    runtime = tmp_path / 'runtime'
    (runtime / 'tools').mkdir(parents=True); (runtime / 'dnlab_runtime').mkdir()
    source = runtime / 'tools/example.py'; source.write_text('# synthetic\n')
    monkeypatch.setattr(entry, 'RUNTIME', runtime)
    folder = tmp_path / 'recipe'; folder.mkdir()
    (folder / 'request.json').write_text('{}')
    receipt = dict(schema_version=1, runtime_root=str(runtime),
        source_sha256={'tools/example.py': digest(source.read_bytes())}, request_sha256=digest(b'{}'))
    (folder / 'receipt.json').write_text(json.dumps(receipt))
    assert entry.verify_recipe(folder)[1] == {}
    source.write_text('# changed\n')
    with pytest.raises(ValueError, match='frozen'): entry.verify_recipe(folder)
    receipt['source_sha256']['tools/example.py'] = digest(source.read_bytes())
    (folder / 'receipt.json').write_text(json.dumps(receipt))
    (folder / 'request.json').write_text('{"changed":true}')
    with pytest.raises(ValueError, match='frozen'): entry.verify_recipe(folder)


@pytest.mark.parametrize('fault', [None, 'symlink', 'writable', 'context'])
def test_native_transport_on_temporary_files_only(collection_request, tmp_path, monkeypatch, capsys, fault):
    import os
    import tools.libvirt_configuration_prepare as shared
    root = tmp_path / 'root'; directory = root / 'var/lib/dpkg'; directory.mkdir(parents=True)
    current = BASE + status('other')
    (directory / 'status').write_bytes(current); (directory / 'status-old').write_bytes(BASE)
    if fault == 'symlink':
        (directory / 'status').unlink(); (directory / 'status').symlink_to('status-old')
    elif fault == 'writable':
        (directory / 'status').chmod(0o666)
    output = tmp_path / 'output'; output.mkdir(mode=0o700)
    monkeypatch.setattr(entry, 'OUTPUT_PARENT', output)
    monkeypatch.setattr(entry, 'verify_recipe', lambda folder: (json.dumps(collection_request).encode(), deepcopy(collection_request)))
    observed_context = deepcopy(collection_request['context'])
    if fault == 'context':
        observed_context['boot_id'] = 'different-synthetic-boot'
    monkeypatch.setattr(shared, 'context', lambda value: deepcopy(observed_context))
    original_open = os.open
    def guarded_open(path, *args, **kwargs):
        if path == '/':
            path = root
        elif isinstance(path, (str, Path)) and Path(path).is_absolute():
            assert Path(path).is_relative_to(tmp_path)
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(os, 'open', guarded_open)
    assert entry.run(tmp_path / 'fake-recipe') == (0 if fault is None else 1)
    result = json.loads(capsys.readouterr().out)
    assert result['qualified'] is False
    folder = output / ('libvirt-dpkg-readonly-' + collection_request['nonce'][:12])
    assert (folder / 'intent.json').is_file() and (folder / 'result.json').is_file()
    if fault is None:
        assert (folder / 'pass1-status.raw').read_bytes() == current
        assert result['candidate']['matches_historical_digest'] is True
    elif fault == 'context':
        pair = json.loads((folder / 'pass1-context-before.json').read_text())
        assert pair['expected'] == collection_request['context'] and pair['observed'] == observed_context
        assert pair['matches'] is False
        assert not list(folder.glob('*.raw'))
