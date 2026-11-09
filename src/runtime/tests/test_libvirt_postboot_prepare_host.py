"""Frozen entry wiring on temporary SQLite with simulated host transports."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
from tools import libvirt_postboot_prepare_host as entry
from test_libvirt_postboot_session import assembly,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def native_recipe(assembly,tmp_path,monkeypatch):
    from dnlab_runtime import libvirt_account_runner,libvirt_account_worker
    from tools import libvirt_configuration_prepare,libvirt_postboot_assembly
    _,arguments,_,files,_,_,_=assembly
    directory=tmp_path/'original-journal';directory.mkdir(mode=0o700);database=directory/'journal.sqlite3'
    with sqlite3.connect(database) as copied:arguments['journal'].db.backup(copied)
    database.chmod(0o600)
    output=tmp_path/'outputs';output.mkdir(mode=0o700);monkeypatch.setattr(entry,'OUTPUT_PARENT',output)
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda installed:deepcopy(arguments['current']))
    executable=tmp_path/'synthetic-systemctl';executable.write_text('synthetic transport only')
    @contextmanager
    def resource(path):
        assert path=='/usr/bin/systemctl'
        fd=os.open(executable,os.O_RDONLY)
        try:yield fd
        finally:os.close(fd)
    monkeypatch.setattr(libvirt_account_runner,'open_resource',resource)
    proofs=[]
    monkeypatch.setattr(libvirt_account_worker,'binary_proof',lambda fd,digest:proofs.append((fd,digest)))
    commands=[]
    def run(argv,**kwargs):
        assert kwargs['timeout']==5 and kwargs['cwd']=='/' and kwargs['check'] is False
        assert argv[:3]==['/usr/bin/systemctl','show','--all']
        commands.append((argv,kwargs))
        return SimpleNamespace(returncode=0,stdout=b'synthetic query',stderr=b'')
    monkeypatch.setattr(entry.subprocess,'run',run)
    def build(journal,installed,current,**kwargs):
        assert kwargs['worker_profile']=={'synthetic':True}
        names=installed['profile']['service_order']+installed['profile']['forbidden_vendor_activation']
        kwargs['query'](['/usr/bin/systemctl','show','--all','--no-pager',
            '--property=Id,LoadState,ActiveState,Job','--',*names],env={'synthetic':'1'},timeout=5)
        files.journal=journal;files.readonly=True
        source=SessionInstaller(journal,None,readonly=True)
        session=PostBootRecoverySession(**{**arguments,'journal':journal,'source_reader':source.read},prepare_only=True)
        return SimpleNamespace(session=session,diagnostics={'synthetic':True})
    monkeypatch.setattr(libvirt_postboot_assembly,'PostBootPrepareAssembly',build)
    recipe=tmp_path/'recipe';recipe.mkdir(mode=0o700)
    request=dict(qualification_id=arguments['qualification_id'],recovery_id=arguments['recovery_id'],nonce='6'*32,
        window=arguments['window'].receipt,run_parent=arguments['run_parent'])
    values={'installed.json':arguments['installation'],
        'journal-reference.json':dict(directory=str(directory),identity=arguments['journal_identity'],
            database_sha256=hashlib.sha256(database.read_bytes()).hexdigest()),
        'expected-context.json':arguments['current'],'postboot.json':request,
        'expected-packages.json':{'synthetic':'1'},'approved-account-inputs.json':{'synthetic':True},
        'worker-profile.json':{'synthetic':True}}
    for name,value in values.items():(recipe/name).write_text(json.dumps(value))
    receipt=dict(schema_version=1,runtime_root=str(entry.RUNTIME),systemctl_sha256='a'*64,
        entry_sha256=hashlib.sha256(Path(entry.__file__).read_bytes()).hexdigest(),
        source_sha256={str(path.relative_to(entry.RUNTIME)):hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ('dnlab_runtime','tools') for path in (entry.RUNTIME/directory).glob('*.py')},
        input_sha256={name:hashlib.sha256((recipe/name).read_bytes()).hexdigest() for name in entry.INPUTS})
    (recipe/'receipt.json').write_text(json.dumps(receipt))
    return recipe,output/('libvirt-postboot-prepare-'+request['nonce'][:12]),database,commands,files,proofs


def test_host_flag_is_required_before_recipe_or_host_access(monkeypatch,tmp_path):
    monkeypatch.setattr(entry,'run',lambda *a,**kw:pytest.fail('host entry reached without flag'))
    with pytest.raises(SystemExit) as error:entry.main(['--recipe',str(tmp_path/'absent')])
    assert error.value.code==2


def test_native_entry_simulated_prepare_and_same_output_resume(native_recipe):
    recipe,output,_,commands,files,proofs=native_recipe
    assert entry.run(recipe)==0
    reference=(output/'prepared-reference.json').read_bytes();binding=(output/'journal-binding.json').read_bytes()
    assert entry.run(recipe,resume_output=output)==0
    assert (output/'prepared-reference.json').read_bytes()==reference
    assert (output/'journal-binding.json').read_bytes()==binding
    assert len(commands)==2 and proofs and files.calls==[]
    results=[json.loads(path.read_text()) for path in output.glob('result-*.json')]
    assert len(results)==2 and all(row['status']=='prepared' and row['qualified'] is False for row in results)


def test_context_mismatch_is_saved_and_blocks_before_journal_open(native_recipe,monkeypatch):
    from tools import libvirt_configuration_prepare
    recipe,output,database,commands,files,_=native_recipe;raw=database.read_bytes()
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda value:{'foreign':'context'})
    assert entry.run(recipe)==1 and database.read_bytes()==raw and commands==[] and files.calls==[]
    result=json.loads(next(output.glob('result-*.json')).read_text())
    assert result['contexts'][0]['observed']=={'foreign':'context'}
    assert not (output/'journal-binding.json').exists()


def test_lost_prepare_response_resumes_original_output(native_recipe,monkeypatch):
    from tools.libvirt_postboot_prepare import PrepareDelivery
    recipe,output,_,_,files,_=native_recipe;prepare=PrepareDelivery.prepare
    def lost(self,**kwargs):
        prepare(self,**kwargs)
        raise OSError('synthetic lost delivery response')
    monkeypatch.setattr(PrepareDelivery,'prepare',lost)
    assert entry.run(recipe)==1
    reference=(output/'prepared-reference.json').read_bytes()
    monkeypatch.setattr(PrepareDelivery,'prepare',prepare)
    assert entry.run(recipe,resume_output=output)==0
    assert (output/'prepared-reference.json').read_bytes()==reference and files.calls==[]


def test_changed_input_or_wrong_resume_path_never_starts_transport(native_recipe):
    recipe,output,_,commands,_,_=native_recipe
    with pytest.raises(RuntimeError,match='original prepare output'):
        entry.run(recipe,resume_output=output.with_name('foreign'))
    (recipe/'expected-packages.json').write_text('{}')
    with pytest.raises(RuntimeError,match='input changed'):entry.run(recipe)
    assert commands==[] and not output.exists()
