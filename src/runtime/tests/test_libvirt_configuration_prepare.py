"""Recipe bootstrap and routing only; every host reader/executor is replaced."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from tools import libvirt_configuration_prepare as entry
from dnlab_runtime.libvirt_service_profile import render_profile
from test_libvirt_service_profile import request_profile


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def recipe(tmp_path,monkeypatch,request_profile):
    runtime=tmp_path/'runtime';(runtime/'dnlab_runtime').mkdir(parents=True);(runtime/'tools').mkdir()
    (runtime/'dnlab_runtime/__init__.py').write_text('# synthetic runtime source\n')
    (runtime/'tools/tool.py').write_text('# synthetic tool source\n')
    folder=tmp_path/'recipe';folder.mkdir();output=tmp_path/'outputs';output.mkdir(mode=0o700)
    monkeypatch.setattr(entry,'RUNTIME',runtime);monkeypatch.setattr(entry,'OUTPUT_PARENT',output)
    installed=dict(id='original-install',context=dict(host_id='master',boot_id='synthetic',namespaces={}),dependencies={})
    window=dict(operation_id='revision',context=deepcopy(installed['context']),targets=['file:/etc/systemd/system/dnlab-libvirtd.service'],nonce='d'*32)
    values={'request.json':request_profile,'baseline.json':{'snapshot':{'synthetic':'baseline'}},
        'installation-window.json':dict(window,operation_id=installed['id'],nonce='e'*32),
        'expected-packages.json':{},'approved-account-inputs.json':{},
        'worker-profile.json':dict(python=dict(path='/synthetic/python',sha256='a'*64),worker=dict(path='/synthetic/worker',sha256='b'*64)),
        'installed.json':installed,'journal-reference.json':dict(directory='/synthetic/journal',identity='c'*32,database_sha256='d'*64),
        'revision-window.json':window}
    for name,value in values.items():(folder/name).write_text(json.dumps(value))
    receipt=dict(schema_version=1,runtime_root=str(runtime),entry_sha256=digest(Path(entry.__file__)),systemctl_sha256='f'*64,
        source_sha256={str(p.relative_to(runtime)):digest(p) for directory in ('dnlab_runtime','tools') for p in (runtime/directory).glob('*.py')},
        input_sha256={name:digest(folder/name) for name in entry.INPUTS})
    (folder/'receipt.json').write_text(json.dumps(receipt))
    return folder,output,installed,values,receipt


def test_missing_flag_refuses_before_recipe_or_host_reads(monkeypatch,tmp_path):
    monkeypatch.setattr(entry,'run',lambda *args:pytest.fail('must reject before opening recipe'))
    with pytest.raises(SystemExit) as result:entry.main(['--recipe',str(tmp_path/'missing')])
    assert result.value.code==2 and not list(tmp_path.iterdir())


def test_explicit_flag_routes_only_to_prepare(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(entry,'run',lambda folder:calls.append(folder) or 0)
    assert entry.main(['--prepare-host','--recipe',str(tmp_path)])==0
    assert calls==[tmp_path]


def test_isolated_script_refuses_without_flag_before_loading_missing_recipe(tmp_path):
    result=entry.subprocess.run([sys.executable,'-B','-I','-S',str(Path(entry.__file__).resolve()),
        '--recipe',str(tmp_path/'missing-recipe')],capture_output=True,timeout=10,check=False)
    assert result.returncode==2 and result.stdout==b''
    assert b'native preparation requires --prepare-host' in result.stderr
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('fault',['input','source','missing-source','entry'])
def test_frozen_recipe_rejects_changed_binding(recipe,fault):
    folder,_,_,_,receipt=recipe
    if fault=='input':(folder/'installed.json').write_text('{}')
    elif fault=='source':(entry.RUNTIME/'tools/tool.py').write_text('# changed')
    elif fault=='missing-source':
        receipt['source_sha256'].pop('tools/tool.py');(folder/'receipt.json').write_text(json.dumps(receipt))
    else:
        receipt['entry_sha256']='0'*64;(folder/'receipt.json').write_text(json.dumps(receipt))
    with pytest.raises(RuntimeError):entry.verify_recipe(folder)


@pytest.fixture
def native_fakes(recipe,monkeypatch):
    import dnlab_runtime.journal as journal_module
    import dnlab_runtime.libvirt_account_identity as identity_module
    import dnlab_runtime.libvirt_account_runner as runner_module
    import dnlab_runtime.libvirt_account_process as process_module
    import dnlab_runtime.libvirt_account_worker as worker_module
    import dnlab_runtime.libvirt_configuration_session as revision_module
    import dnlab_runtime.libvirt_install_session as provisioning_module
    import tools.libvirt_install_activity as activity_module
    import tools.libvirt_install_snapshot as snapshot_module
    folder,output,installed,values,receipt=recipe
    calls=[];runners=[];activities=[]
    monkeypatch.setattr(sys,'path',list(sys.path))
    monkeypatch.setattr(entry,'context',lambda value:deepcopy(value['context']))
    monkeypatch.setattr(entry,'original_journal',lambda *args:calls.append('original-journal'))
    @contextmanager
    def resource(path):
        calls.append('pin:'+path);yield 42
    monkeypatch.setattr(runner_module,'open_resource',resource)
    monkeypatch.setattr(runner_module,'source_proof',lambda *args:calls.append('source-proof'))
    monkeypatch.setattr(worker_module,'binary_proof',lambda *args:calls.append('binary-proof'))
    class Journal:
        def __init__(self,path):self.identity=values['journal-reference.json']['identity'];calls.append('journal-open')
        def close(self):calls.append('journal-close')
    monkeypatch.setattr(journal_module,'Journal',Journal)
    class Observer:
        def __init__(self,journal):calls.append('observer-open')
        def close(self):calls.append('observer-close')
    monkeypatch.setattr(process_module,'AccountWorkerObserver',Observer)
    class Runner:
        def __init__(self,*args,**kwargs):runners.append(self)
    monkeypatch.setattr(runner_module,'AccountProcessRunner',Runner)
    monkeypatch.setattr(identity_module,'host_query',lambda *a:pytest.fail('fixture cannot perform NSS query'))
    class Activity:
        def __init__(self,profile,*,query):self.query=query;self.profile=profile;self.diagnostics=[];activities.append(self)
        def namespaces(self):return {}
        def __call__(self):
            profile=self.profile
            argv=['/usr/bin/systemctl','show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',
                *profile['service_order'],*profile['forbidden_vendor_activation']]
            result=self.query(argv,env={},timeout=5);self.diagnostics.append(result);return result
    monkeypatch.setattr(activity_module,'InstallationActivity',Activity)
    monkeypatch.setattr(snapshot_module,'InstallationSnapshot',lambda *a,**kw:object())
    class Provisioning:
        def __init__(self,*args,**kwargs):
            calls.append('provisioning-assembled');self.installer=SimpleNamespace(read=lambda operation:deepcopy(installed))
    monkeypatch.setattr(provisioning_module,'SessionProvisioning',Provisioning)
    class Revision:
        def __init__(self,*args,**kwargs):calls.append('revision-assembled')
        def prepare(self):
            calls.append('prepare');activities[0]()
            return dict(id='revision',phase='prepared')
        def apply_original(self,*a):pytest.fail('prepare cannot apply')
        def recover_original(self,*a):pytest.fail('prepare cannot recover')
    monkeypatch.setattr(revision_module,'ConfigurationSession',Revision)
    def query(argv,**kwargs):
        calls.append('query')
        assert argv[1]=='show' and kwargs['timeout']==5 and kwargs['executable']=='/proc/self/fd/42'
        assert kwargs['stdin']==entry.subprocess.DEVNULL and kwargs['pass_fds']==(42,)
        return SimpleNamespace(returncode=0,stdout=b'synthetic query output',stderr=b'')
    monkeypatch.setattr(entry.subprocess,'run',query)
    return folder,output,calls,runners


def test_native_prepare_route_records_intent_without_execution_capabilities(native_fakes):
    folder,output,calls,runners=native_fakes
    assert entry.run(folder)==0
    generated=list(output.iterdir());assert len(generated)==1
    result=json.loads((generated[0]/'result.json').read_text())
    assert result['status']=='prepared' and result['qualified'] is False and result['original_record_unchanged'] is True
    assert calls.count('prepare')==1 and calls.count('query')==1
    assert calls[-2:]==['observer-close','journal-close']
    for name in ('arm','release','outcome'):
        with pytest.raises(RuntimeError,match='prepare'):getattr(runners[0],name)({})
    with pytest.raises(FileExistsError):entry.run(folder)
    assert len(list(output.iterdir()))==1


def test_context_mismatch_preserves_diagnostics_without_opening_original_journal(native_fakes,monkeypatch):
    folder,output,calls,_=native_fakes
    monkeypatch.setattr(entry,'context',lambda value:{'changed':'context'})
    assert entry.run(folder)==1
    result=json.loads((next(output.iterdir())/'result.json').read_text())
    assert result['status']=='failed' and result['context_before']=={'changed':'context'}
    assert 'original-journal' not in calls and 'journal-open' not in calls and 'prepare' not in calls


def test_query_error_is_saved_with_original_cause_and_journal_closed(native_fakes,monkeypatch):
    folder,output,calls,_=native_fakes
    def fail(*args,**kwargs):raise entry.subprocess.TimeoutExpired('synthetic show',5)
    monkeypatch.setattr(entry.subprocess,'run',fail)
    assert entry.run(folder)==1
    result=json.loads((next(output.iterdir())/'result.json').read_text())
    assert result['error']['type']=='TimeoutExpired' and result['queries'][0]['status']=='failed'
    assert calls[-2:]==['observer-close','journal-close']


def test_close_error_cannot_hide_original_prepare_failure(native_fakes,monkeypatch):
    import dnlab_runtime.journal as module
    folder,output,calls,_=native_fakes
    def query(*args,**kwargs):raise entry.subprocess.TimeoutExpired('synthetic show',5)
    def close(self):
        calls.append('journal-close');raise OSError('synthetic close failure')
    monkeypatch.setattr(entry.subprocess,'run',query)
    monkeypatch.setattr(module.Journal,'close',close)
    assert entry.run(folder)==1
    result=json.loads((next(output.iterdir())/'result.json').read_text())
    assert result['error']['type']=='TimeoutExpired'
    assert result['cleanup_errors']==[dict(step='journal_close',type='OSError',message='synthetic close failure')]


@pytest.mark.parametrize('fault',[None,'hash','wal'])
def test_original_journal_read_checks_frozen_record_without_writes(tmp_path,fault):
    import sqlite3
    from dnlab_runtime.manifest import fingerprint
    from dnlab_runtime.vm_bundle import pinned_file
    database=tmp_path/'journal.sqlite3';installed={'id':'synthetic-install','phase':'installed_not_started'}
    db=sqlite3.connect(database)
    db.execute('CREATE TABLE journal_identity (identity TEXT)');db.execute('INSERT INTO journal_identity VALUES (?)',('c'*32,))
    db.execute('CREATE TABLE libvirt_install_intents (id TEXT,payload TEXT,fingerprint TEXT)')
    db.execute('INSERT INTO libvirt_install_intents VALUES (?,?,?)',(installed['id'],json.dumps(installed),fingerprint(installed)))
    db.commit();db.close()
    expected=database.read_bytes();reference=dict(directory=str(tmp_path),identity='c'*32,database_sha256=digest(database))
    if fault=='hash':reference['database_sha256']='0'*64
    elif fault=='wal':(tmp_path/'journal.sqlite3-wal').write_text('synthetic uncertain WAL')
    if fault is None:entry.original_journal(reference,installed,pinned_file,fingerprint)
    else:
        with pytest.raises(RuntimeError):entry.original_journal(reference,installed,pinned_file,fingerprint)
    assert database.read_bytes()==expected
