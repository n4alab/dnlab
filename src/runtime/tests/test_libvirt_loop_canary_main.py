"""Standalone bootstrap parsing and source-only loading; no child or SDK run."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from libvirt_loop_canary_main import VerifiedSources, read_bootstrap


@pytest.fixture
def sources(tmp_path):
    root=tmp_path/'runtime';(root/'dnlab_runtime').mkdir(parents=True)
    source=root/'dnlab_runtime'/'example.py';source.write_text('result = 42\n')
    source.chmod(0o644)
    manifest=dict(root=str(root),files={'dnlab_runtime/example.py':hashlib.sha256(source.read_bytes()).hexdigest()})
    return VerifiedSources(manifest),source


def test_source_loader_compiles_verified_bytes_without_reading_or_writing_pyc(sources):
    inventory,source=sources
    cache=source.parent/'__pycache__';cache.mkdir();pyc=cache/'example.cpython-313.pyc'
    pyc.write_bytes(b'synthetic unqualified bytecode remains opaque')
    before=pyc.read_bytes();assert inventory.verify()==inventory.expected
    spec=inventory.find_spec('dnlab_runtime.example')
    module=ModuleType(spec.name);spec.loader.exec_module(module)
    assert module.result==42 and module.__file__==str(source)
    assert pyc.read_bytes()==before and list(cache.iterdir())==[pyc]


@pytest.mark.parametrize('fault',['content','mode','symlink','manifest'])
def test_source_change_is_refused_before_exec(sources,fault):
    inventory,source=sources
    if fault=='content':source.write_text('result = 43\n')
    elif fault=='mode':source.chmod(0o666)
    elif fault=='symlink':
        other=source.with_name('other.py');source.rename(other);source.symlink_to(other)
    else:inventory.manifest['files']['dnlab_runtime/example.py']='0'*64
    with pytest.raises((ValueError,OSError)):inventory.verify()


def test_undeclared_runtime_import_does_not_fall_back_to_path_or_cache(sources):
    inventory,_=sources
    with pytest.raises(ValueError,match='undeclared runtime import'):inventory.find_spec('dnlab_runtime.foreign')
    with pytest.raises(ValueError,match='nested runtime'):inventory.find_spec('dnlab_runtime.foreign.child')
    assert inventory.find_spec('json') is None


@pytest.mark.parametrize('path',['../outside.py','tools/../../outside.py','/absolute.py','dnlab_runtime/a.pyc'])
def test_manifest_refuses_other_paths(sources,path):
    inventory,_=sources
    with pytest.raises(ValueError):VerifiedSources(dict(root=inventory.manifest['root'],files={path:'a'*64}))


def packet(raw,*,seal=True):
    fd=os.memfd_create('synthetic-loop-bootstrap',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    os.write(fd,raw)
    if seal:fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE)
    return fd


def test_bootstrap_requires_sealed_original_frame():
    value=dict(request=dict(nonce='a'*32),bootstrap=dict(synthetic=True))
    raw=json.dumps(value).encode();fd=packet(raw)
    try:assert read_bootstrap(fd)==value
    finally:os.close(fd)
    fd=packet(raw,seal=False)
    try:
        with pytest.raises(ValueError,match='sealed bootstrap'):read_bootstrap(fd)
    finally:os.close(fd)


@pytest.mark.parametrize('raw',[b'{"request":{},"request":{},"bootstrap":{}}',
    b'{"request":{},"bootstrap":{"value":NaN}}',b'[]',b'{}',b'x'*(1024*1024+1)])
def test_bootstrap_refuses_duplicate_nonfinite_foreign_and_oversized_packets(raw):
    fd=packet(raw)
    try:
        with pytest.raises(ValueError):read_bootstrap(fd)
    finally:os.close(fd)
