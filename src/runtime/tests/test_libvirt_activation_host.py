"""Frozen native activation entry with all host operations simulated."""

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_activation import steps
from test_libvirt_activation_lineage import activation_files, successor, configured, install, request_profile
from tools import libvirt_activation_host as entry
from tools import libvirt_bus_inventory_host, libvirt_native_activation_inputs
from tools import libvirt_postboot_directories, libvirt_postboot_journal, libvirt_postboot_unit_revision
from dnlab_runtime import libvirt_account_runner, libvirt_account_worker


@pytest.fixture
def recipe(tmp_path, activation_files, monkeypatch):
    lineage, _, source, driver, adapter, _ = activation_files
    runtime = tmp_path / 'runtime'
    tools = runtime / 'tools'
    tools.mkdir(parents=True)
    script = tools / 'libvirt_activation_host.py'
    script.write_bytes(Path(entry.__file__).read_bytes())
    monkeypatch.setattr(entry, '__file__', str(script))
    monkeypatch.setattr(entry, 'RUNTIME', runtime)
    monkeypatch.setattr(entry, 'OUTPUT_PARENT', tmp_path)
    context = deepcopy(source['context'])
    window = dict(operation_id='native-activation', context=context,
                  targets=[step['key'] for step in steps(source['profile'])], nonce='a' * 32)
    binaries = dict(systemctl='/usr/bin/systemctl', virsh='/usr/bin/virsh', python='/usr/bin/python3.13',
                    reload=str(tools / 'libvirt_activation_worker_main.py'),
                    start=str(tools / 'libvirt_bus_worker_main.py'))
    installed = {'original': 'installation'}
    data = {name: {} for name in entry.INPUTS}
    data.update({
        'installed.json': installed, 'activation-source.json': source, 'activation-window.json': window,
        'bus-inventory.json': {'context': context}, 'unit-window.json': driver.window.receipt,
        'unit-reference.json': dict(lineage.reference, phase='prepared', proof=None),
        'postboot.json': dict(qualification_id='qualify', recovery_id='recover', run_parent={},
                              window=dict(window, operation_id='recover')),
        'journal-reference.json': dict(directory='/synthetic', identity='j' * 32, database_sha256='d' * 64),
        'journal-binding.json': {'original': True},
        'activation-binaries.json': {key: dict(path=path, sha256='b' * 64) for key, path in binaries.items()},
    })
    folder = tmp_path / 'recipe'
    entry.prepare_recipe(folder, data)
    calls = []
    state = dict(context=context, failed=False, mismatched_source=False)
    monkeypatch.setattr(libvirt_bus_inventory_host, 'host_context', lambda host: state['context'])

    @contextmanager
    def private_report(parent, name):
        output = parent / name
        output.mkdir()

        def write(filename, raw):
            with (output / filename).open('xb') as stream:
                stream.write(raw)

        yield write, output

    monkeypatch.setattr(libvirt_bus_inventory_host, 'private_report', private_report)

    @contextmanager
    def open_binary(path):
        calls.append(path)
        yield 44

    monkeypatch.setattr(libvirt_account_runner, 'open_resource', open_binary)
    monkeypatch.setattr(libvirt_account_runner, 'source_proof', lambda fd, digest: None)
    monkeypatch.setattr(libvirt_account_worker, 'binary_proof', lambda fd, digest: None)

    @contextmanager
    def open_journal(path, original, **kwargs):
        assert path == '/synthetic' and original == installed and kwargs['original_binding'] == {'original': True}
        kwargs['verify']()
        calls.append('original-journal')
        yield driver.journal, kwargs['original_binding']

    monkeypatch.setattr(libvirt_postboot_journal, 'open_postboot_journal', open_journal)
    monkeypatch.setattr(libvirt_postboot_directories, 'PostBootDirectoryAssembly', lambda *a, **kw: object())
    monkeypatch.setattr(libvirt_postboot_unit_revision, 'PostBootUnitRevision', lambda *a, **kw:
                        SimpleNamespace(view=lineage.view, revision=SimpleNamespace(driver=driver, adapter=adapter)))
    monkeypatch.setattr(libvirt_native_activation_inputs, 'ActivationHostInputs', lambda *a, **kw: object())
    original_read = driver.read
    def read(operation):
        result = original_read(operation)
        if state['mismatched_source']:
            result['phase'] = 'prepared'
        return result
    monkeypatch.setattr(driver, 'read', read)

    @contextmanager
    def open_activation(providers, *, operation, window, **kwargs):
        assert operation == 'native-activation'
        assert window.observe() == data['activation-window.json']
        calls.append('original-supervisor')
        reference = dict(id=operation, phase='prepared')
        class Controller:
            driver = SimpleNamespace(read=lambda op: dict(id=op, phase='activating' if state['failed'] else 'ready_empty'))

            def apply_original(self, original):
                assert original == reference
                calls.append('apply')
                if state['failed']:
                    raise OSError('original release response lost')
                return self.driver.read(operation)

        yield Controller(), reference

    monkeypatch.setattr(libvirt_native_activation_inputs, 'open_lineage_activation', open_activation)
    return folder, script, calls, state


def test_requires_explicit_flag_before_recipe_access(tmp_path, monkeypatch):
    monkeypatch.setattr(entry, 'verify_recipe', lambda *a: pytest.fail('recipe read without explicit flag'))
    with pytest.raises(SystemExit) as error:
        entry.main(['--recipe', str(tmp_path)])
    assert error.value.code == 2


@pytest.mark.parametrize('changed', ['source', 'input'])
def test_recipe_integrity_checked_before_host_access(recipe, changed):
    folder, script, calls, _ = recipe
    if changed == 'source':
        script.write_text('foreign source')
        (script.parent / 'unexpected.py').write_text('foreign source')
    else:
        (folder / 'activation-binaries.json').write_text('{}')
    with pytest.raises(ValueError, match='recipe differs|input differs'):
        entry.run(folder)
    assert calls == []


def test_one_shot_keeps_original_journal_and_qualified_result(recipe):
    folder, _, calls, _ = recipe
    result, output = entry.run(folder)
    assert result['status'] == 'ready_empty', result
    assert calls[-3:] == ['original-journal', 'original-supervisor', 'apply']
    assert json.loads((output / 'prepared.json').read_text())['phase'] == 'prepared'
    assert json.loads((output / 'journal-state.json').read_text())['phase'] == 'ready_empty'
    with pytest.raises(FileExistsError):
        entry.run(folder)
    assert calls.count('apply') == 1


def test_pending_release_preserves_original_journal_state(recipe):
    folder, _, calls, state = recipe
    state['failed'] = True
    result, output = entry.run(folder)
    assert result['status'] == 'failed' and result['error'] == 'original release response lost'
    assert json.loads((output / 'journal-state.json').read_text())['phase'] == 'activating'
    assert calls.count('apply') == 1


def test_context_conflict_precedes_binary_and_journal_access(recipe):
    folder, _, calls, state = recipe
    state['context'] = {'foreign': 'context'}
    result, output = entry.run(folder)
    assert result['status'] == 'failed'
    assert json.loads((output / 'context-conflict.json').read_text())['observed'] == state['context']
    assert calls == []


def test_uncompleted_revision_precedes_supervisor(recipe):
    folder, _, calls, state = recipe
    state['mismatched_source'] = True
    result, _ = entry.run(folder)
    assert result['status'] == 'failed'
    assert 'original-journal' in calls and 'original-supervisor' not in calls
