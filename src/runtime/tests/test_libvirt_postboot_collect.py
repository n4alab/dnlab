"""Collection protocol/entry tests; every host transport/identity reader is fake."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from tools import libvirt_postboot_collect as entry
from test_libvirt_postboot_observer import observed
from test_libvirt_postboot import postboot
from test_libvirt_install import install,request_profile


@pytest.fixture
def collection(observed,postboot):
    observer,value,root,proofs,snapshot=observed
    _,_,installer,history,_,_=postboot
    reader=entry.PostBootCollection(value['installation'],value['context'],source_reader=observer.source_reader,
        snapshot=observer.snapshot,identity=observer.identity,files=observer.files,directory_dependency=observer.directory_dependency,history=history)
    return reader,observer,value,root,proofs,snapshot,installer


def test_readonly_collection_never_prepares_qualification_or_claims_volatiles(collection):
    reader,_,value,_,_,_,installer=collection
    installer.journal.db.execute('PRAGMA query_only=ON');before=installer.journal.db.total_changes
    result=reader.collect()
    assert result['qualified'] is False and result['kind']=='postboot-readonly-observation-v1'
    assert result['pending_volatile']==value['plan']['volatile'] and result['prerequisite_differences']==[]
    assert len(reader.diagnostics['observations'])==2 and reader.diagnostics['status']=='collected'
    assert installer.journal.db.total_changes==before and installer.read(value['installation']['id'])==value['installation']


def test_static_delta_is_reported_without_qualification_or_adoption(collection):
    reader,_,_,_,_,snapshot,_=collection
    snapshot['prerequisites']['packages']='changed-synthetic-package-state'
    result=reader.collect()
    assert result['qualified'] is False
    assert result['prerequisite_differences']==[dict(path='prerequisites.packages',expected='unchanged-synthetic-packages',observed='changed-synthetic-package-state')]


def test_between_pass_transition_preserves_both_diagnostics(collection,monkeypatch):
    reader,_,_,_,_,snapshot,_=collection;calls=[]
    def changed():
        calls.append(1);result=deepcopy(snapshot)
        if len(calls)>=3:result['prerequisites']['packages']='different-second-pass'
        return result
    monkeypatch.setattr(reader.observer,'snapshot',changed)
    with pytest.raises(RuntimeError,match='between passes'):reader.collect()
    assert len(reader.diagnostics['observations'])==2 and reader.diagnostics['status']=='failed'


def test_missing_current_identity_keeps_original_failure(collection,monkeypatch):
    reader,_,_,_,_,_,_=collection
    monkeypatch.setattr(reader.observer,'identity',lambda request:None)
    with pytest.raises(Conflict,match='identity'):reader.collect()
    assert reader.diagnostics['error']['type']=='Conflict'
    assert reader.diagnostics['observations'][0]['status']=='failed'


def test_isolated_entry_refuses_before_loading_missing_recipe(tmp_path):
    result=entry.subprocess.run([sys.executable,'-B','-I','-S',str(Path(entry.__file__).resolve()),
        '--recipe',str(tmp_path/'missing')],capture_output=True,timeout=10,check=False)
    assert result.returncode==2 and result.stdout==b''
    assert b'native readonly collection requires --collect-host' in result.stderr
    assert not list(tmp_path.iterdir())


def test_explicit_flag_routes_to_single_collection(monkeypatch,tmp_path):
    calls=[];monkeypatch.setattr(entry,'run',lambda path:calls.append(path) or 0)
    assert entry.main(['--collect-host','--recipe',str(tmp_path)])==0 and calls==[tmp_path]


@pytest.fixture
def recipe(tmp_path,monkeypatch,install):
    installer,_,prepared,_=install;installed=installer.apply(prepared['id'])
    namespaces={name:dict(device=1,inode=index+10) for index,name in enumerate(('pid','mnt','net','user'))}
    installed['context']=dict(host_id='master',boot_id='old-synthetic-boot',namespaces=namespaces)
    installed['prerequisites']['profile_sha256']=installed['profile']['profile_sha256']
    installed['prerequisites']['account_inputs']={
        'usr/sbin/'+role:dict(sha256='a'*64) for role in ('useradd','groupadd')}
    with installer.journal.transaction():installer._save(installed)
    installer.journal.db.execute('CREATE TABLE libvirt_install_file_births (operation_id TEXT,nonce TEXT,payload TEXT,fingerprint TEXT)')
    dbpath=tmp_path/'original.sqlite3'
    with sqlite3.connect(dbpath) as destination:installer.journal.db.backup(destination)
    # Native entry has one fixed journal filename under the selected directory.
    directory=tmp_path/'journal-clone';directory.mkdir();dbpath.rename(directory/'journal.sqlite3')
    runtime=tmp_path/'runtime';(runtime/'dnlab_runtime').mkdir(parents=True);(runtime/'tools').mkdir()
    (runtime/'dnlab_runtime/__init__.py').write_text('# synthetic source\n');(runtime/'tools/tool.py').write_text('# synthetic tool\n')
    folder=tmp_path/'recipe';folder.mkdir();output=tmp_path/'outputs';output.mkdir(mode=0o700)
    monkeypatch.setattr(entry,'RUNTIME',runtime);monkeypatch.setattr(entry,'OUTPUT_PARENT',output)
    context=deepcopy(installed['context']);context['boot_id']='current-synthetic-boot'
    values={'installed.json':installed,'journal-reference.json':dict(directory=str(directory),identity=installer.journal.identity,database_sha256='e'*64),
        'expected-packages.json':installed['profile']['package_request']['roots'],'approved-account-inputs.json':{},
        'worker-profile.json':dict(python=dict(path='/synthetic/python',sha256='b'*64),worker=dict(path='/synthetic/worker',sha256='c'*64)),
        'expected-context.json':context,'collection.json':dict(id='postboot-observation',nonce='d'*32)}
    for name,value in values.items():(folder/name).write_text(json.dumps(value))
    digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    receipt=dict(schema_version=1,runtime_root=str(runtime),entry_sha256=digest(Path(entry.__file__)),systemctl_sha256='f'*64,
        source_sha256={str(p.relative_to(runtime)):digest(p) for dirname in ('dnlab_runtime','tools') for p in (runtime/dirname).glob('*.py')},
        input_sha256={name:digest(folder/name) for name in entry.INPUTS})
    (folder/'receipt.json').write_text(json.dumps(receipt))
    return folder,output,installed,values,receipt


@pytest.mark.parametrize('fault',[None,'source','input','missing-source'])
def test_recipe_is_frozen_before_any_host_call(recipe,fault):
    folder,_,_,_,receipt=recipe
    if fault=='source':(entry.RUNTIME/'tools/tool.py').write_text('# changed source')
    elif fault=='input':(folder/'expected-context.json').write_text('{}')
    elif fault=='missing-source':
        receipt['source_sha256'].pop('tools/tool.py');(folder/'receipt.json').write_text(json.dumps(receipt))
    if fault is None:assert entry.verify_recipe(folder)==receipt
    else:
        with pytest.raises(RuntimeError):entry.verify_recipe(folder)


@pytest.fixture
def native_fakes(recipe,monkeypatch):
    import tools.libvirt_configuration_prepare as shared
    import tools.libvirt_install_snapshot as snapshot_module
    import dnlab_runtime.libvirt_account_runner as account_runner
    import dnlab_runtime.libvirt_account_worker as account_worker
    folder,output,installed,values,_=recipe;calls=[]
    monkeypatch.setattr(sys,'path',list(sys.path))
    monkeypatch.setattr(shared,'context',lambda value:deepcopy(values['expected-context.json']))
    monkeypatch.setattr(shared,'original_journal',lambda *a:calls.append('original-journal-check'))
    @contextmanager
    def resource(path):
        assert path=='/usr/bin/systemctl';calls.append('pin-systemctl');yield 42
    monkeypatch.setattr(account_runner,'open_resource',resource)
    monkeypatch.setattr(account_worker,'binary_proof',lambda *a:calls.append('binary-proof'))
    monkeypatch.setattr(snapshot_module,'InstallationSnapshot',lambda *a,**kw:SimpleNamespace(services=kw['services']))
    class Collection:
        def __init__(self,*args,**kwargs):
            self.snapshot=kwargs['snapshot'];self.diagnostics={'synthetic':True}
            assert kwargs['files'].readonly is True
        def collect(self):
            calls.append('collect')
            profile=installed['profile'];argv=['/usr/bin/systemctl','show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',
                *profile['service_order'],*profile['forbidden_vendor_activation']]
            self.snapshot.services.query(argv,env={},timeout=5)
            return dict(kind='synthetic-entry-report',qualified=False,pending_volatile=['synthetic-runtime-directory'],prerequisite_differences=[])
    monkeypatch.setattr(entry,'PostBootCollection',Collection)
    def query(argv,**kwargs):
        assert argv[1]=='show' and kwargs['timeout']==5 and kwargs['stdin']==entry.subprocess.DEVNULL
        assert kwargs['executable']=='/proc/self/fd/42' and kwargs['pass_fds']==(42,)
        calls.append('readonly-query');return SimpleNamespace(returncode=0,stdout=b'synthetic raw properties',stderr=b'')
    monkeypatch.setattr(entry.subprocess,'run',query)
    return folder,output,values,calls


def test_native_wiring_keeps_original_sqlite_bytes_and_uses_only_readonly_query(native_fakes):
    folder,output,values,calls=native_fakes
    db=Path(values['journal-reference.json']['directory'])/'journal.sqlite3';before=db.read_bytes()
    assert entry.run(folder)==0
    generated=next(output.iterdir());result=json.loads((generated/'result.json').read_text())
    assert result['status']=='collected' and result['qualified'] is False
    assert calls.count('collect')==1 and calls.count('readonly-query')==1 and calls.count('original-journal-check')==2
    assert db.read_bytes()==before and not Path(str(db)+'-wal').exists() and not Path(str(db)+'-shm').exists()
    with pytest.raises(FileExistsError):entry.run(folder)


def test_native_context_refusal_precedes_original_journal_and_query(native_fakes,monkeypatch):
    import tools.libvirt_configuration_prepare as shared
    folder,output,_,calls=native_fakes
    monkeypatch.setattr(shared,'context',lambda value:{'unexpected':'context'})
    assert entry.run(folder)==1
    result=json.loads((next(output.iterdir())/'result.json').read_text())
    assert result['error']['message']=='explicit current collection context differs'
    assert 'original-journal-check' not in calls and 'readonly-query' not in calls
