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
def request():
    return dict(context=dict(host_id='synthetic', boot_id='synthetic-boot', namespaces={}),
                expected_sha256=digest(BASE), observed_sha256=digest(BASE + status('other')),
                expected_packages=deepcopy(FACTS), nonce='a' * 32)


def reader(current, old=BASE):
    values = {entry.PATHS[0]: current, entry.PATHS[1]: old}
    return lambda path: None if values[path] is None else dict(raw=values[path], metadata=[1, 2, 3])


@pytest.mark.parametrize('old', [None, BASE, status('older')])
def test_candidate_requires_original_digest_and_never_qualifies(request, old):
    saved = {}
    result = entry.collect(request, read=reader(BASE + status('other'), old),
        context=lambda: deepcopy(request['context']), persist=lambda name, raw: saved.setdefault(name, raw))
    assert result['qualified'] is False and result['passes'] == 2
    assert result['baseline_available'] is (old == BASE)
    assert result['changes'] is None if old != BASE else result['changes'][0]['change'] == 'added'
    assert saved['pass1-status.raw'] == saved['pass2-status.raw'] == BASE + status('other')


def test_context_conflict_prevents_status_reads(request):
    with pytest.raises(ValueError, match='context differs'):
        entry.collect(request, read=lambda path: pytest.fail('unexpected read'),
                      context=lambda: {}, persist=lambda *args: pytest.fail('unexpected write'))


@pytest.mark.parametrize('fault', ['current', 'old', 'context'])
def test_between_pass_changes_preserve_captured_evidence(request, fault):
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
        return {} if fault == 'context' and len(spaces) == 4 else deepcopy(request['context'])
    with pytest.raises(ValueError, match='changed'):
        entry.collect(request, read=read, context=context, persist=lambda name, raw: saved.setdefault(name, raw))
    assert 'pass1-proof.json' in saved and 'pass2-proof.json' in saved


def test_unexpected_current_digest_preserves_both_raw_passes(request):
    saved = {}
    with pytest.raises(ValueError, match='observed artifact digest differs'):
        entry.collect(request, read=reader(BASE), context=lambda: request['context'],
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


@pytest.mark.parametrize('fault', [None, 'symlink', 'writable'])
def test_native_transport_on_temporary_files_only(request, tmp_path, monkeypatch, capsys, fault):
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
    monkeypatch.setattr(entry, 'verify_recipe', lambda folder: (json.dumps(request).encode(), deepcopy(request)))
    monkeypatch.setattr(shared, 'context', lambda value: deepcopy(request['context']))
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
    folder = output / ('libvirt-dpkg-readonly-' + request['nonce'][:12])
    assert (folder / 'intent.json').is_file() and (folder / 'result.json').is_file()
    if fault is None:
        assert (folder / 'pass1-status.raw').read_bytes() == current
        assert result['candidate']['matches_historical_digest'] is True
