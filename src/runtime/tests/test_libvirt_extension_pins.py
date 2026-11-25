"""Native loaders are simulated; only temporary file descriptors are real."""
import importlib.machinery
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import libvirt_loop_sdk as sdk


@pytest.fixture
def loader(monkeypatch):
    pins, paths, cache = {}, [], {}
    monkeypatch.setattr(sdk, '_EXTENSION_PINS', pins)

    class FakeExtension:
        def __init__(self, name, path):
            self.name, self.path = name, path

        def create_module(self, spec):
            paths.append(self.path)
            fd = int(self.path.rsplit('/', 1)[1])
            content = cache.setdefault(self.path, os.pread(fd, 32, 0))
            if content == b'failure':
                raise ValueError('synthetic initializer failed')
            module = ModuleType(spec.name)
            module.content = content
            return module

        def exec_module(self, module):
            pass

    monkeypatch.setattr(importlib.machinery, 'ExtensionFileLoader', FakeExtension)
    try:
        yield pins, paths
    finally:
        # Production pins have process lifetime. These are synthetic imports.
        for fd in pins.values():
            os.close(fd)


def test_distinct_extensions_keep_distinct_loader_paths_after_input_fd_reuse(tmp_path, loader):
    pins, paths = loader
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.write_bytes(b'first extension')
    second.write_bytes(b'second extension')
    original = os.open(first, os.O_RDONLY | os.O_CLOEXEC)
    try:
        a = sdk.extension_from_fd(original)
    finally:
        os.close(original)
    reused = os.open(second, os.O_RDONLY | os.O_CLOEXEC)
    try:
        assert reused == original
        b = sdk.extension_from_fd(reused, name='libvirtmod_qemu')
    finally:
        os.close(reused)
    assert a.content == b'first extension'
    assert b.content == b'second extension'
    assert len(paths) == len(set(paths)) == len(pins) == 2
    assert all(not os.get_inheritable(fd) for fd in pins.values())
    assert os.pread(pins['libvirtmod'], 32, 0) == b'first extension'
    with pytest.raises(Exception, match='already attempted'):
        sdk.extension_from_fd(-1)
    assert len(paths) == len(pins) == 2


def test_failed_initializer_keeps_its_path_reserved_without_retry(tmp_path, loader):
    pins, paths = loader
    path = tmp_path / 'failed'
    path.write_bytes(b'failure')
    original = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match='synthetic initializer failed'):
            sdk.extension_from_fd(original)
    finally:
        os.close(original)
    assert os.pread(pins['libvirtmod'], 32, 0) == b'failure'
    with pytest.raises(Exception, match='already attempted'):
        sdk.extension_from_fd(-1)
    assert len(paths) == len(pins) == 1


def test_unknown_extension_does_not_allocate_a_pin(loader):
    pins, paths = loader
    with pytest.raises(Exception, match='fixed libvirt extension'):
        sdk.extension_from_fd(-1, name='foreign')
    assert pins == {} and paths == []
