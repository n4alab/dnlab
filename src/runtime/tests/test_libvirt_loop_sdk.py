"""SDK Python source executes only from synthetic files; native load is fake."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from libvirt_loop_sdk import LoopSDK
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint

SOURCE=b'''import libvirtmod
def virEventRegisterDefaultImpl(): return 0
def virEventAddTimeout(*args): return 1
def virEventRunDefaultImpl(): return 0
'''


@pytest.fixture
def sdk_files(tmp_path):
    missing=object();original={key:sys.modules.pop(key,missing) for key in ('libvirt','libvirtmod')}
    journal=Journal(tmp_path/'journal');source=tmp_path/'sdk.py';extension=tmp_path/'sdk.so'
    source.write_bytes(SOURCE);extension.write_bytes(b'\x7fELF'+b'x'*64)
    source.chmod(0o644);extension.chmod(0o644)
    profile=dict(source=dict(path=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest()),
                 extension=dict(path=str(extension),sha256=hashlib.sha256(extension.read_bytes()).hexdigest()))
    state=dict(loads=0,opened=[],closed=[],scope=True,isolated=True,fault=None)
    @contextmanager
    def opener(path):
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);state['opened'].append(fd)
        try:yield fd
        finally:os.close(fd);state['closed'].append(fd)
    def load(fd):
        state['loads']+=1
        assert os.pread(fd,4,0)==b'\x7fELF'
        if state['fault']=='import':raise ValueError('synthetic native import failed')
        if state['fault']=='source':source.write_bytes(SOURCE+b'# changed\n')
        module=ModuleType('libvirtmod');module.__file__='/proc/self/fd/'+str(fd)
        return module
    def create():
        return LoopSDK(journal,profile,preflight=lambda:fingerprint(profile) if state['scope'] else None,
                       isolated=lambda:state['isolated'],opener=opener,load_extension=load)
    try:yield SimpleNamespace(journal=journal,source=source,extension=extension,profile=profile,
                             state=state,create=create)
    finally:
        for key,item in original.items():
            sys.modules.pop(key,None)
            if item is not missing:sys.modules[key]=item
        journal.close()


def test_loads_exact_source_with_original_native_binding_without_bytecode_cache(sdk_files):
    e=sdk_files;loader=e.create();sdk=loader.load()
    assert loader.check() is sdk and sdk.libvirtmod is sys.modules['libvirtmod']
    assert sdk.__file__==str(e.source) and e.state['loads']==1
    assert not list(e.source.parent.glob('__pycache__'))
    value=json.loads(e.journal.db.execute('SELECT payload FROM libvirt_loop_sdk_imports').fetchone()[0])
    assert value['phase']=='loaded' and value['assets']['source']['sha256']==e.profile['source']['sha256']
    assert len(e.state['opened'])==len(e.state['closed'])
    with pytest.raises(RuntimeErrorBase,match='cannot be repeated'):loader.load()
    assert e.state['loads']==1


@pytest.mark.parametrize('fault',['scope','isolated','foreign_python','foreign_native'])
def test_refuses_foreign_scope_or_modules_without_loading_native_code(sdk_files,fault):
    e=sdk_files;loader=e.create()
    if fault=='scope':e.state['scope']=False
    elif fault=='isolated':e.state['isolated']=False
    else:sys.modules['libvirt' if fault=='foreign_python' else 'libvirtmod']=ModuleType('foreign')
    with pytest.raises(RuntimeErrorBase):loader.load()
    assert e.state['loads']==0 and not e.state['opened']


@pytest.mark.parametrize('fault',['source_hash','extension_hash','source_mode','extension_mode'])
def test_refuses_changed_file_before_executing_any_initializer(sdk_files,fault):
    e=sdk_files;loader=e.create()
    path=e.source if fault.startswith('source') else e.extension
    if fault.endswith('hash'):path.write_bytes(path.read_bytes()+b'changed')
    else:path.chmod(0o666)
    with pytest.raises(RuntimeErrorBase):loader.load()
    assert e.state['loads']==0 and len(e.state['opened'])==len(e.state['closed'])
    value=json.loads(e.journal.db.execute('SELECT payload FROM libvirt_loop_sdk_imports').fetchone()[0])
    assert value['phase']=='pending'


@pytest.mark.parametrize('fault',['import','source'])
def test_uncertain_or_changed_import_is_pending_and_cannot_be_retried(sdk_files,fault):
    e=sdk_files;e.state['fault']=fault;loader=e.create()
    with pytest.raises((RuntimeErrorBase,ValueError)):loader.load()
    assert e.state['loads']==1 and len(e.state['opened'])==len(e.state['closed'])
    value=json.loads(e.journal.db.execute('SELECT payload FROM libvirt_loop_sdk_imports').fetchone()[0])
    assert value['phase']=='pending'
    e.state['fault']=None
    with pytest.raises(RuntimeErrorBase):loader.load()
    with pytest.raises(RuntimeErrorBase):e.create().load()
    assert e.state['loads']==1


@pytest.mark.parametrize('fault',['python','native','file','receipt','scope'])
def test_recheck_never_reimports_changed_module_or_provenance(sdk_files,fault):
    e=sdk_files;loader=e.create();loader.load()
    if fault=='python':sys.modules['libvirt']=ModuleType('substitute')
    elif fault=='native':sys.modules['libvirtmod']=ModuleType('substitute')
    elif fault=='file':e.source.write_bytes(SOURCE+b'# later change\n')
    elif fault=='scope':e.state['scope']=False
    else:
        with e.journal.transaction():e.journal.db.execute("UPDATE libvirt_loop_sdk_imports SET fingerprint=?",('0'*64,))
    with pytest.raises(RuntimeErrorBase):loader.check()
    assert e.state['loads']==1 and len(e.state['opened'])==len(e.state['closed'])


def test_failed_python_initializer_keeps_native_binding_and_original_failure(sdk_files):
    e=sdk_files;e.source.write_bytes(b'import libvirtmod\nraise ValueError("synthetic source refusal")\n')
    e.profile['source']['sha256']=hashlib.sha256(e.source.read_bytes()).hexdigest()
    loader=e.create()
    with pytest.raises(ValueError,match='synthetic source refusal'):loader.load()
    assert 'libvirtmod' in sys.modules and 'libvirt' in sys.modules
    row=e.journal.db.execute('SELECT payload FROM libvirt_loop_sdk_imports').fetchone()[0]
    assert json.loads(row)['error']['message']=='synthetic source refusal'
    with pytest.raises(RuntimeErrorBase):e.create().load()
    assert e.state['loads']==1
