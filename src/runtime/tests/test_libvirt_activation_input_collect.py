"""Run the collector with a temporary filesystem and synthetic boot only."""

from copy import deepcopy
import hashlib
import json
import os

import pytest

from tools import libvirt_activation_input_collect as entry
from tools.libvirt_bus_inventory_host import prepare_recipe


@pytest.fixture
def collection(tmp_path):
    root = tmp_path / 'root'
    (root / 'run').mkdir(parents=True, mode=0o755)
    executable = root / 'usr/bin/virsh'
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b'\x7fELF synthetic binary')
    executable.chmod(0o755)
    context = dict(host_id='master-fixture', boot_id='synthetic-boot',
                   namespaces={name: dict(device=1, inode=index) for index, name in
                               enumerate(('pid', 'mnt', 'net', 'user'), 1)})
    recipe = tmp_path / 'recipe'
    prepare_recipe(recipe, dict(scope=entry.SCOPE, context=context, nonce='8' * 32), validate_request=entry.validate)
    output = tmp_path / 'reports'
    output.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield recipe, output, fd, context, executable
    finally:
        os.close(fd)


def test_two_passes_report_run_identity_and_virsh_hash(collection):
    recipe, output, fd, context, executable = collection

    def read(host):
        assert host == context['host_id']
        return deepcopy(context)

    result, folder = entry.run(recipe, root=fd, read_context=read, output_parent=output)
    assert result['status'] == 'collected' and result['context'] == context
    assert result['run_parent']['inode'] == (executable.parents[2] / 'run').stat().st_ino
    assert result['virsh']['sha256'] == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert json.loads((folder / 'pass1-proof.json').read_text()) == json.loads((folder / 'pass2-proof.json').read_text())
    with pytest.raises(FileExistsError):
        entry.run(recipe, root=fd, read_context=lambda host: pytest.fail('duplicate collection'), output_parent=output)


def test_foreign_boot_rejected_before_snapshot(collection, monkeypatch):
    recipe, output, fd, context, _ = collection
    monkeypatch.setattr(entry, 'snapshot', lambda root: pytest.fail('foreign boot reached filesystem'))
    result, folder = entry.run(recipe, root=fd, read_context=lambda host: dict(context, boot_id='foreign'),
                               output_parent=output)
    assert result['status'] == 'failed'
    evidence = json.loads((folder / 'pass1-context-before.json').read_text())
    assert evidence['expected'] == context and evidence['observed']['boot_id'] == 'foreign'


def test_changed_binary_between_passes_is_rejected(collection):
    recipe, output, fd, context, executable = collection
    contexts = iter(range(4))

    def read(host):
        if next(contexts) == 2:
            executable.write_bytes(b'\x7fELF replacement')
        return context

    result, folder = entry.run(recipe, root=fd, read_context=read, output_parent=output)
    assert result['status'] == 'failed' and 'changed' in result['error']
    assert (folder / 'pass1-proof.json').read_bytes() != (folder / 'pass2-proof.json').read_bytes()


@pytest.mark.parametrize('fault', ['run-symlink', 'binary-symlink', 'writable-binary', 'script'])
def test_rejects_unqualified_run_or_virsh(collection, fault):
    recipe, output, fd, context, executable = collection
    if fault == 'run-symlink':
        run = executable.parents[2] / 'run'
        run.rename(run.with_name('foreign'))
        run.symlink_to(run.with_name('foreign'))
    elif fault == 'binary-symlink':
        executable.rename(executable.with_name('foreign'))
        executable.symlink_to('foreign')
    elif fault == 'writable-binary':
        executable.chmod(0o777)
    else:
        executable.write_bytes(b'#!/bin/sh\n')
    result, _ = entry.run(recipe, root=fd, read_context=lambda host: context, output_parent=output)
    assert result['status'] == 'failed'


def test_explicit_host_flag_required_before_access(tmp_path):
    with pytest.raises(SystemExit) as error:
        entry.main(['--recipe', str(tmp_path / 'absent')])
    assert error.value.code == 2
