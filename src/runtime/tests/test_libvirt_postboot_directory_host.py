"""Directory host transport on temporary SQLite and simulated resource leaves."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from tools import libvirt_postboot_directory_host as entry
from tools.libvirt_postboot_journal import open_postboot_journal
from test_libvirt_postboot_directories import directories,wiring,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def host_recipe(directories,tmp_path,monkeypatch):
    from dnlab_runtime import libvirt_account_runner,libvirt_account_worker
    from tools import libvirt_configuration_prepare,libvirt_postboot_directories
    arguments,files,observed,_=directories
    directory=tmp_path/'transport-journal';directory.mkdir(mode=0o700);database=directory/'journal.sqlite3'
    with sqlite3.connect(database) as copied:arguments['journal'].db.backup(copied)
    database.chmod(0o600);retained=[]
    original=dict(directory=str(directory),identity=arguments['journal'].identity,
        database_sha256=hashlib.sha256(database.read_bytes()).hexdigest())
    with open_postboot_journal(directory,arguments['installation'],identity=original['identity'],
            initial_sha256=original['database_sha256'],retain=retained.append,verify=lambda:None) as (_,binding):pass
    output=tmp_path/'output';output.mkdir(mode=0o700);monkeypatch.setattr(entry,'OUTPUT_PARENT',output)
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda installed:deepcopy(arguments['current']))
    executable=tmp_path/'systemctl';executable.write_text('synthetic')
    @contextmanager
    def resource(path):
        assert path=='/usr/bin/systemctl';fd=os.open(executable,os.O_RDONLY)
        try:yield fd
        finally:os.close(fd)
    monkeypatch.setattr(libvirt_account_runner,'open_resource',resource)
    monkeypatch.setattr(libvirt_account_worker,'binary_proof',lambda fd,sha:None)
    commands=[]
    def transport(argv,**kwargs):
        assert kwargs['timeout']==5 and kwargs['check'] is False and kwargs['cwd']=='/'
        commands.append(argv)
        return SimpleNamespace(returncode=0,stdout=b'synthetic readonly query',stderr=b'')
    monkeypatch.setattr(entry.subprocess,'run',transport)
    real=libvirt_postboot_directories.PostBootDirectoryAssembly
    def build(journal,installed,current,**kwargs):
        names=installed['profile']['service_order']+installed['profile']['forbidden_vendor_activation']
        kwargs['query'](['/usr/bin/systemctl','show','--all','--no-pager',
            '--property=Id,LoadState,ActiveState,Job','--',*names],env={'synthetic':'1'},timeout=5)
        return real(journal,installed,current,**kwargs)
    monkeypatch.setattr(libvirt_postboot_directories,'PostBootDirectoryAssembly',build)
    recipe=tmp_path/'recipe';recipe.mkdir(mode=0o700)
    request=dict(qualification_id=arguments['qualification_id'],recovery_id=arguments['recovery_id'],nonce='8'*32,
        window=arguments['window'].receipt,run_parent=arguments['run_parent'])
    values={'installed.json':arguments['installation'],'journal-reference.json':original,
        'expected-context.json':arguments['current'],'postboot.json':request,
        'prepared-reference.json':arguments['prepared_reference'],'journal-binding.json':binding,
        'expected-packages.json':{'synthetic':'1'},'approved-account-inputs.json':{'synthetic':True},
        'worker-profile.json':{'synthetic':True}}
    for name,value in values.items():(recipe/name).write_text(json.dumps(value))
    def freeze():
        receipt=dict(schema_version=1,runtime_root=str(entry.RUNTIME),systemctl_sha256='a'*64,
            entry_sha256=hashlib.sha256(Path(entry.__file__).read_bytes()).hexdigest(),
            input_sha256={name:hashlib.sha256((recipe/name).read_bytes()).hexdigest() for name in entry.INPUTS},
            source_sha256={str(path.relative_to(entry.RUNTIME)):hashlib.sha256(path.read_bytes()).hexdigest()
                for directory in ('dnlab_runtime','tools') for path in (entry.RUNTIME/directory).glob('*.py')})
        (recipe/'receipt.json').write_text(json.dumps(receipt))
    freeze()
    return recipe,output,files,commands,freeze,observed


def test_explicit_mutually_exclusive_action_required(monkeypatch,tmp_path):
    monkeypatch.setattr(entry,'run',lambda *a,**kw:pytest.fail('operation entered without explicit action'))
    for flags in ([],['--apply-host','--recover-host']):
        with pytest.raises(SystemExit) as error:entry.main(['--recipe',str(tmp_path),*flags])
        assert error.value.code==2


def test_transport_applies_once_and_completed_resume_does_not_recreate(host_recipe):
    recipe,output,files,commands,_,_=host_recipe
    assert entry.run(recipe,action='apply')==0
    result=output/'libvirt-postboot-directories-apply-888888888888'
    original=(result/'effective.json').read_bytes()
    assert entry.run(recipe,action='apply',resume_output=result)==0
    assert len(files.calls)==2 and len(commands)==2 and (result/'effective.json').read_bytes()==original
    effective=json.loads(original)
    assert effective['daemon_ready'] is False and effective['scope']=='session-directories-only'


def test_lost_create_response_requires_explicit_recovery_of_original(host_recipe):
    recipe,output,files,_,_,_=host_recipe;files.lose_after=True
    assert entry.run(recipe,action='apply')==1 and len(files.calls)==1
    assert entry.run(recipe,action='recover')==0 and len(files.calls)==2
    effective=json.loads((output/'libvirt-postboot-directories-recover-888888888888/effective.json').read_text())
    assert effective['daemon_ready'] is False


def test_foreign_reference_blocks_all_directory_mutations(host_recipe):
    recipe,_,files,_,freeze,_=host_recipe
    reference=json.loads((recipe/'prepared-reference.json').read_text())
    reference['recovery']['items'][0]['nonce']='0'*32
    (recipe/'prepared-reference.json').write_text(json.dumps(reference));freeze()
    assert entry.run(recipe,action='apply')==1 and files.calls==[]


def test_context_conflict_is_saved_before_query_or_directory_action(host_recipe,monkeypatch):
    from tools import libvirt_configuration_prepare
    recipe,output,files,commands,_,_=host_recipe
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda value:{'foreign':'context'})
    assert entry.run(recipe,action='apply')==1 and files.calls==[] and commands==[]
    result=json.loads(next(output.glob('*/result-*.json')).read_text())
    assert result['contexts'][0]['observed']=={'foreign':'context'}
