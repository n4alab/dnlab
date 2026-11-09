import os
from pathlib import Path

import pytest

from dnlab_runtime.backend import Linux
from dnlab_runtime.manifest import Conflict

BOOT = 'd28cbe4c-64f3-4768-8a89-dc1f526b5bf4'


def test_explicit_host_file_supplies_boot_without_changing_namespace(tmp_path, monkeypatch):
    path = tmp_path/'host-boot-id'
    path.write_text(BOOT+'\n')
    monkeypatch.setenv('DNLAB_RUNTIME_HOST_BOOT_ID_FILE', str(path))
    actual = Linux().network_identity()
    namespace = os.stat('/proc/self/ns/net')
    assert actual == {'boot_id': BOOT, 'device': namespace.st_dev, 'inode': namespace.st_ino}


def test_native_default_reads_host_proc(monkeypatch):
    monkeypatch.delenv('DNLAB_RUNTIME_HOST_BOOT_ID_FILE', raising=False)
    assert Linux().network_identity()['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def test_missing_explicit_file_does_not_fall_back_to_container_boot(tmp_path, monkeypatch):
    monkeypatch.setenv('DNLAB_RUNTIME_HOST_BOOT_ID_FILE', str(tmp_path/'missing'))
    with pytest.raises(Conflict, match='unavailable'):
        Linux().network_identity()


@pytest.mark.parametrize('value', ['', 'relative-boot-file'])
def test_empty_or_relative_explicit_path_rejected(monkeypatch, value):
    monkeypatch.setenv('DNLAB_RUNTIME_HOST_BOOT_ID_FILE', value)
    with pytest.raises(Conflict, match='absolute'):
        Linux().network_identity()


def test_invalid_boot_content_rejected(tmp_path, monkeypatch):
    path = tmp_path/'host-boot-id'
    path.write_text('not-a-boot-id')
    monkeypatch.setenv('DNLAB_RUNTIME_HOST_BOOT_ID_FILE', str(path))
    with pytest.raises(Conflict, match='invalid'):
        Linux().network_identity()
