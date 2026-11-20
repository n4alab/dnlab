"""Official-wrapper import contract with synthetic source and native loader."""
import hashlib
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from test_libvirt_loop_sdk import sdk_files
from libvirt_loop_sdk import QEMUSDK
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint

SOURCE=b'''import libvirt
import libvirtmod_qemu
VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT=0
def qemuMonitorCommand(*args): raise AssertionError('import must not query a domain')
'''


@pytest.fixture
def qemu_files(sdk_files):
    e=sdk_files;base=e.create();base.load()
    missing=object();previous={key:sys.modules.pop(key,missing) for key in ('libvirt_qemu','libvirtmod_qemu')}
    source=e.source.with_name('qemu.py');extension=e.extension.with_name('qemu.so')
    source.write_bytes(SOURCE);extension.write_bytes(b'\x7fELF'+b'q'*64)
    profile=dict(source=dict(path=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest()),
                 extension=dict(path=str(extension),sha256=hashlib.sha256(extension.read_bytes()).hexdigest()))
    state=dict(loads=0,fault=None)
    def load(fd):
        state['loads']+=1
        module=ModuleType('libvirtmod_qemu')
        if state['fault']=='foreign':sys.modules['libvirtmod_qemu']=ModuleType('foreign')
        if state['fault']=='self_register':sys.modules['libvirtmod_qemu']=module
        return module
    def create():
        return QEMUSDK(e.journal,profile,base=base,preflight=lambda:fingerprint(profile),
            isolated=lambda:True,load_extension=load)
    try:yield SimpleNamespace(base=base,source=source,extension=extension,profile=profile,state=state,create=create,e=e)
    finally:
        for key,original in previous.items():
            sys.modules.pop(key,None)
            if original is not missing:sys.modules[key]=original


def test_qemu_import_binds_original_main_sdk_without_monitor_calls(qemu_files):
    e=qemu_files;loader=e.create();sdk=loader.load()
    assert loader.check() is sdk and sdk.libvirt is e.base.sdk
    assert sdk.libvirtmod_qemu is sys.modules['libvirtmod_qemu']
    assert e.state['loads']==1 and e.e.state['loads']==1
    row=json.loads(e.e.journal.db.execute('SELECT payload FROM libvirt_qemu_sdk_imports').fetchone()[0])
    assert row['phase']=='loaded' and row['assets']['source']['sha256']==e.profile['source']['sha256']
    assert not list(e.source.parent.glob('__pycache__'))
    with pytest.raises(RuntimeErrorBase):loader.load()


@pytest.mark.parametrize('fault',['source','extension','main','binding','flags'])
def test_changed_assets_or_module_bindings_are_rejected_without_reimport(qemu_files,fault):
    e=qemu_files;loader=e.create();sdk=loader.load()
    if fault in ('source','extension'):
        path=getattr(e,fault);path.write_bytes(path.read_bytes()+b'changed')
    elif fault=='main':sys.modules['libvirt']=ModuleType('foreign')
    elif fault=='binding':sdk.libvirt=ModuleType('foreign')
    else:sdk.VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT=True
    with pytest.raises(RuntimeErrorBase):loader.check()
    assert e.state['loads']==e.e.state['loads']==1


def test_changed_main_sdk_blocks_extension_before_initializers(qemu_files):
    e=qemu_files;sys.modules['libvirt']=ModuleType('foreign')
    with pytest.raises(RuntimeErrorBase):e.create().load()
    assert e.state['loads']==0 and 'libvirtmod_qemu' not in sys.modules


@pytest.mark.parametrize('registration',['foreign','self_register'])
def test_native_initializer_registration_requires_same_original_object(qemu_files,registration):
    e=qemu_files;e.state['fault']=registration;loader=e.create()
    if registration=='foreign':
        with pytest.raises(RuntimeErrorBase):loader.load()
        assert sys.modules['libvirtmod_qemu'].__name__=='foreign'
        with pytest.raises(RuntimeErrorBase):e.create().load()
    else:assert loader.load().libvirtmod_qemu is sys.modules['libvirtmod_qemu']
    assert e.state['loads']==1


def test_failed_qemu_source_keeps_pending_receipt_without_second_import(qemu_files):
    e=qemu_files;e.source.write_bytes(SOURCE+b'raise ValueError("synthetic refusal")\n')
    e.profile['source']['sha256']=hashlib.sha256(e.source.read_bytes()).hexdigest()
    with pytest.raises(ValueError,match='synthetic refusal'):e.create().load()
    row=json.loads(e.e.journal.db.execute('SELECT payload FROM libvirt_qemu_sdk_imports').fetchone()[0])
    assert row['phase']=='pending' and row['error']['message']=='synthetic refusal'
    with pytest.raises(RuntimeErrorBase):e.create().load()
    assert e.state['loads']==1
