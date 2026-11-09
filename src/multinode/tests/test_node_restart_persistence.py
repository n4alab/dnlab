"""Restart must prepare the VD's persistent bind after an explicit wipe."""
from pathlib import Path
import shlex

import pytest

from tests.test_node_restart import _starting_controller


def persistent_controller(tmp_path, monkeypatch):
    controller, client, phases = _starting_controller(tmp_path, monkeypatch)
    controller.topo.persistence.root = str(tmp_path / 'persist')
    vd = controller.topo.nodes['R1']
    vd.image = 'vrnetlab/vendor_platform:fixture-dnlab'
    vd.persist_id = 'stable-r1'
    controller.state.node_runtime['R1'].image = vd.image
    directory = Path(controller.topo.persistence.root) / 'demo' / 'stable-r1'
    calls = []

    def command(text):
        args = shlex.split(text)
        assert args[:3] == ['mkdir', '-p', '--']
        Path(args[3]).mkdir(parents=True, exist_ok=True)
        calls.append(('prepare', str(args[3])))

    def deploy(*args, **kwargs):
        if not directory.is_dir():
            raise RuntimeError('persistent bind source missing after wipe')
        calls.append(('deploy', str(directory)))

    client.run = command
    client.deploy_clab = deploy
    return controller, client, directory, calls


def test_start_recreates_wiped_persistent_directory_before_deploy(tmp_path, monkeypatch):
    controller, client, directory, calls = persistent_controller(tmp_path, monkeypatch)
    assert not directory.exists()
    controller.start('R1')
    assert calls == [('prepare', str(directory)), ('deploy', str(directory))]
    assert controller.state.node_runtime['R1'].state == 'running'
    assert controller.state.node_runtime['R1'].host == 'master'


def test_restart_preserves_existing_overlay(tmp_path, monkeypatch):
    controller, client, directory, calls = persistent_controller(tmp_path, monkeypatch)
    directory.mkdir(parents=True)
    overlay = directory / 'overlay.qcow2'
    overlay.write_bytes(b'existing-overlay-sentinel')
    controller.state.node_runtime['R1'].state = 'running'
    controller.restart('R1')
    assert overlay.read_bytes() == b'existing-overlay-sentinel'
    assert len(client.destroyed) == 1
    assert calls == [('prepare', str(directory)), ('deploy', str(directory))]


def test_stop_wipe_start_restores_only_the_selected_vd(tmp_path, monkeypatch):
    import shutil
    controller, client, directory, calls = persistent_controller(tmp_path, monkeypatch)
    directory.mkdir(parents=True)
    (directory / 'overlay.qcow2').write_bytes(b'old-overlay')
    other = directory.parent / 'other-vd'
    other.mkdir()
    (other / 'overlay.qcow2').write_bytes(b'untouched')
    controller.state.node_runtime['R1'].state = 'running'
    controller.stop('R1')
    shutil.rmtree(directory)  # The successful wipe removes the full bind source.
    controller.start('R1')
    assert directory.is_dir() and list(directory.iterdir()) == []
    assert (other / 'overlay.qcow2').read_bytes() == b'untouched'
    assert calls == [('prepare', str(directory)), ('deploy', str(directory))]


def test_bind_source_prepare_failure_prevents_deploy(tmp_path, monkeypatch):
    controller, client, directory, calls = persistent_controller(tmp_path, monkeypatch)

    def fail(command):
        raise OSError('persistent storage unavailable')

    client.run = fail
    with pytest.raises(OSError, match='storage unavailable'):
        controller.start('R1')
    assert calls == [] and not directory.exists()
    assert controller.state.node_runtime['R1'].state == 'error'


def test_start_restores_persisted_feature_files_before_deploy(tmp_path, monkeypatch):
    controller, client, directory, calls = persistent_controller(tmp_path, monkeypatch)
    controller.topo.node_features = {'R1': {'fixture': {
        'state': {'enabled': True},
        'materialize': {'type': 'persist-key-value-bool-file', 'path': 'feature.conf'},
    }}}

    def upload(content, path):
        assert Path(path).parent.is_dir()
        Path(path).write_text(content)
        calls.append(('upload', path))

    client.upload_text = upload
    controller.start('R1')
    assert (directory / 'feature.conf').read_text() == 'enabled=yes\n'
    assert calls == [('prepare', str(directory)), ('upload', str(directory / 'feature.conf')),
                     ('deploy', str(directory))]


def test_wipe_restart_creates_fresh_qcow2_in_launcher_fixture(tmp_path, monkeypatch):
    """Real qcow2 files; deployment is a launcher fixture, not a vendor NOS."""
    import hashlib
    import json
    import shutil
    import subprocess
    image_tool = shutil.which('qemu-img')
    io_tool = shutil.which('qemu-io')
    if image_tool is None or io_tool is None:
        pytest.skip('qcow2 integration needs qemu-img and qemu-io')

    def command(args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout

    controller, client, directory, calls = persistent_controller(tmp_path, monkeypatch)
    base = tmp_path / 'base.qcow2'
    command([image_tool, 'create', '-f', 'qcow2', str(base), '16M'])
    original_base = hashlib.sha256(base.read_bytes()).hexdigest()
    overlay = directory / 'overlay.qcow2'
    births = []

    def launcher_fixture(*args, **kwargs):
        assert directory.is_dir(), 'Containerlab bind source must exist before launch'
        if not overlay.exists():
            command([image_tool, 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(overlay)])
            births.append(str(overlay))
        info = json.loads(command([image_tool, 'info', '--output=json', str(overlay)]))
        assert info['format'] == 'qcow2' and info['backing-filename'] == str(base)

    client.deploy_clab = launcher_fixture
    controller.start('R1')
    command([io_tool, '-f', 'qcow2', '-c', 'write -P 0xab 0 512', str(overlay)])
    saved = hashlib.sha256(overlay.read_bytes()).hexdigest()
    controller.restart('R1')
    assert hashlib.sha256(overlay.read_bytes()).hexdigest() == saved
    assert len(births) == 1
    controller.stop('R1')
    shutil.rmtree(directory)
    controller.start('R1')
    assert len(births) == 2
    command([io_tool, '-f', 'qcow2', '-c', 'read -P 0x00 0 512', str(overlay)])
    assert hashlib.sha256(base.read_bytes()).hexdigest() == original_base
