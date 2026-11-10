"""Retirement host wiring: temporary journal/paths, simulated host observations."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from tools import libvirt_postboot_unit_retire_host as entry
from tools.libvirt_postboot_journal import open_postboot_journal
from test_libvirt_current_unit_retirement import current_retirement
from test_libvirt_postboot_unit_prepare import unit_prepare,directories,wiring,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def retirement_recipe(current_retirement,unit_prepare,tmp_path,monkeypatch):
    from dnlab_runtime import libvirt_account_runner,libvirt_account_worker
    from tools import libvirt_configuration_prepare,libvirt_postboot_directories
    _,reference,window,parent,files,observed,old=current_retirement
    built,source,_,_,_,_,_,installer=unit_prepare;installed=installer.read(source['id'])
    directory=tmp_path/'retirement-journal';directory.mkdir(mode=0o700);database=directory/'journal.sqlite3'
    with sqlite3.connect(database) as copied:built.session.journal.db.backup(copied)
    database.chmod(0o600);retained=[]
    original=dict(directory=str(directory),identity=built.session.journal.identity,
        database_sha256=hashlib.sha256(database.read_bytes()).hexdigest())
    with open_postboot_journal(directory,installed,identity=original['identity'],initial_sha256=original['database_sha256'],
            retain=retained.append,verify=lambda:None) as (_,binding):pass
    output=tmp_path/'retirement-outputs';output.mkdir(mode=0o700);monkeypatch.setattr(entry,'OUTPUT_PARENT',output)
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda value:deepcopy(source['context']))
    executable=tmp_path/'retirement-systemctl';executable.write_text('synthetic')
    @contextmanager
    def resource(path):
        assert path=='/usr/bin/systemctl';fd=os.open(executable,os.O_RDONLY)
        try:yield fd
        finally:os.close(fd)
    monkeypatch.setattr(libvirt_account_runner,'open_resource',resource)
    monkeypatch.setattr(libvirt_account_worker,'binary_proof',lambda fd,digest:None)
    commands=[]
    def transport(argv,**kwargs):
        assert kwargs['timeout']==5 and kwargs['cwd']=='/' and kwargs['check'] is False
        commands.append(argv);return SimpleNamespace(returncode=0,stdout=b'synthetic readonly query',stderr=b'')
    monkeypatch.setattr(entry.subprocess,'run',transport)
    real=libvirt_postboot_directories.PostBootDirectoryAssembly
    def forbidden(*a,**kw):pytest.fail('retirement cannot mutate directories')
    monkeypatch.setattr(real,'apply_original',forbidden);monkeypatch.setattr(real,'recover_original',forbidden)
    def construct(journal,installation,current,**kwargs):
        names=installation['profile']['service_order']+installation['profile']['forbidden_vendor_activation']
        kwargs['query'](['/usr/bin/systemctl','show','--all','--no-pager',
            '--property=Id,LoadState,ActiveState,Job','--',*names],env={'synthetic':'1'},timeout=5)
        return real(journal,installation,current,**kwargs,root=built.files.root)
    monkeypatch.setattr(libvirt_postboot_directories,'PostBootDirectoryAssembly',construct)
    recipe=tmp_path/'retirement-recipe';recipe.mkdir(mode=0o700)
    directory_reference=built.reference
    request=dict(qualification_id=directory_reference['qualification_id'],recovery_id=directory_reference['recovery']['id'],
        nonce='8'*32,window=built.session.window.receipt,run_parent=built.session.parent)
    values={'installed.json':installed,'journal-reference.json':original,'expected-context.json':source['context'],
        'postboot.json':request,'prepared-reference.json':directory_reference,'journal-binding.json':binding,
        'effective-source.json':source,'retirement-window.json':window.receipt,'unit-reference.json':reference,
        'expected-packages.json':{'synthetic':'1'},'approved-account-inputs.json':{'synthetic':True},'worker-profile.json':{'synthetic':True}}
    for name,value in values.items():(recipe/name).write_text(json.dumps(value))
    def freeze():
        receipt=dict(schema_version=1,runtime_root=str(entry.RUNTIME),systemctl_sha256='a'*64,
            entry_sha256=hashlib.sha256(Path(entry.__file__).read_bytes()).hexdigest(),
            input_sha256={name:hashlib.sha256((recipe/name).read_bytes()).hexdigest() for name in entry.INPUTS},
            source_sha256={str(path.relative_to(entry.RUNTIME)):hashlib.sha256(path.read_bytes()).hexdigest()
                for directory in ('dnlab_runtime','tools') for path in (entry.RUNTIME/directory).glob('*.py')})
        (recipe/'receipt.json').write_text(json.dumps(receipt))
    freeze()
    return recipe,output/'libvirt-current-unit-retire-333333333333',parent,files,commands,freeze,database,reference


def test_retire_flag_required_before_access(monkeypatch,tmp_path):
    monkeypatch.setattr(entry,'run',lambda *a,**kw:pytest.fail('retirement without flag'))
    with pytest.raises(SystemExit) as error:entry.main(['--recipe',str(tmp_path)])
    assert error.value.code==2


def test_real_metadata_retirement_and_output_replay(retirement_recipe):
    recipe,output,parent,files,commands,_,database,reference=retirement_recipe;calls=list(files.calls)
    assert entry.run(recipe)==0
    receipt=(output/'retirement-reference.json').read_bytes()
    assert entry.run(recipe,resume_output=output)==0
    assert (output/'retirement-reference.json').read_bytes()==receipt and len(commands)==2
    assert files.calls==calls and list(parent.iterdir())==[]
    with sqlite3.connect(database) as db:
        payload=db.execute('SELECT payload FROM libvirt_configuration_revisions WHERE id=?',(reference['id'],)).fetchone()[0]
        assert json.loads(payload)==reference
        assert db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM libvirt_configuration_generations').fetchone()[0]==0


def test_lost_response_resumes_same_retirement(retirement_recipe,monkeypatch):
    from tools.libvirt_postboot_unit_retire import PostBootUnitRetirement
    recipe,output,parent,files,_,_,database,_=retirement_recipe;calls=list(files.calls)
    retire=PostBootUnitRetirement.retire_original
    def lost(self):retire(self);raise OSError('synthetic lost retirement response')
    monkeypatch.setattr(PostBootUnitRetirement,'retire_original',lost)
    assert entry.run(recipe)==1 and not (output/'retirement-reference.json').exists()
    monkeypatch.setattr(PostBootUnitRetirement,'retire_original',retire)
    assert entry.run(recipe,resume_output=output)==0
    assert files.calls==calls and list(parent.iterdir())==[]
    with sqlite3.connect(database) as db:assert db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==1


def test_foreign_historical_reference_preserved_and_refused(retirement_recipe):
    recipe,output,parent,files,_,freeze,database,reference=retirement_recipe;calls=list(files.calls)
    reference=deepcopy(reference);reference['nonce']='0'*32
    (recipe/'unit-reference.json').write_text(json.dumps(reference));freeze()
    assert entry.run(recipe)==1 and not (output/'retirement-reference.json').exists()
    assert files.calls==calls and list(parent.iterdir())==[]
    with sqlite3.connect(database) as db:assert db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==0


def test_context_difference_saved_before_readonly_query(retirement_recipe,monkeypatch):
    from tools import libvirt_configuration_prepare
    recipe,output,parent,files,commands,_,database,_=retirement_recipe;raw=database.read_bytes();calls=list(files.calls)
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda value:{'foreign':'context'})
    assert entry.run(recipe)==1 and commands==[] and files.calls==calls and database.read_bytes()==raw
    result=json.loads(next(output.glob('result-*.json')).read_text())
    assert result['contexts'][0]['observed']=={'foreign':'context'} and list(parent.iterdir())==[]
