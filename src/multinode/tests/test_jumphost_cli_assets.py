"""Original output birth/recovery on an isolated filesystem, no Docker."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tools'))
import jumphost_cli_assets as module


class Root:
    def __init__(self,path):
        self.path=path
        self.owner={'container_id':'a'*64,'process':{'namespace':[11,22]}}

    def observe(self):return {'owner':deepcopy(self.owner),'exec_ids':[]}

    @contextmanager
    def open(self):
        fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
        try:yield fd
        finally:os.close(fd)


@pytest.fixture
def assets(tmp_path):
    root=tmp_path/'container';root.mkdir()
    for name in ('etc','run','usr/local/bin'):(root/name).mkdir(parents=True,exist_ok=True)
    (root/'etc/passwd').write_text('labuser:x:65534:65534:fixture:/home/labuser:/bin/bash\n')
    source=Path(__file__).resolve().parents[1]/'jumphost'
    for name in ('vd','vd-relay-client'):
        target=root/'usr/local/bin'/name;target.write_bytes((source/name).read_bytes());target.chmod(0o755)
    provider=Root(root)
    def open_asset():
        return module.Assets(tmp_path/'intent.json',provider,'b'*32,'connect','R1',b'first-command\n',b'nonce-response')
    return open_asset,provider,root


def complete(asset,root):
    path=root/asset.record['output'].lstrip('/')
    nonce=asset.record['nonce'];output=bytes.fromhex(asset.record['marker_hex'])+b'\n'
    birth=lambda pid:{'pid':pid,'start':'99','namespace':[11,22]}
    progress=lambda **kw:{'stdout_bytes':len(output),'stderr_bytes':0,'marker_seen':True,
                          'input_closed':False,'exit_code':None,**kw}
    result={'nonce':nonce,'output_hex':output.hex(),'exit_verified':True,'exit_code':0,
            'marker_seen_before_input_close':True}
    body=[('wrapper_birth',birth(10)),('client_birth',birth(11)),('progress',progress()),
          ('progress',progress(input_closed=True)),('progress',progress(input_closed=True,exit_code=0)),
          ('completed',result)]
    with path.open('ab') as stream:
        for kind,value in body:stream.write(module.encoded({'nonce':nonce,'kind':kind,'value':value})+b'\n')
        stream.flush();os.fsync(stream.fileno())
    return result


def test_asset_birth_and_result_are_bound_to_original_namespace_and_file(assets):
    open_asset,provider,root=assets;asset=open_asset();profile=asset.prepare()
    result=complete(asset,root)
    assert profile['identity']==asset.record['identity']
    observed=asset.result({'owner':provider.owner,'nonce':asset.record['nonce']},
                          {'Running':False,'ExitCode':0})
    assert {k:v for k,v in observed.items() if k!='journal_sha256'}==result
    captured=json.loads(asset.path.with_suffix('.output.json').read_text())
    assert captured['sha256']==observed['journal_sha256']
    assert bytes.fromhex(captured['raw_hex'])==(root/asset.record['output'].lstrip('/')).read_bytes()


def test_identity_checkpoint_loss_recovers_only_original_nonce_birth(assets,monkeypatch):
    open_asset,provider,root=assets;asset=open_asset();save=module.private_json
    def fail(path,record):
        if record['identity'] is not None:raise OSError('lost identity checkpoint')
        save(path,record)
    monkeypatch.setattr(module,'private_json',fail)
    with pytest.raises(OSError):asset.prepare()
    path=root/asset.record['output'].lstrip('/');before=path.stat();raw=path.read_bytes()
    monkeypatch.setattr(module,'private_json',save)
    recovered=open_asset();recovered.prepare()
    assert recovered.record['identity'][1]==before.st_ino and path.read_bytes()==raw


@pytest.mark.parametrize('conflict',['owner','account','source'])
def test_preflight_conflict_prevents_output_allocation(assets,conflict):
    open_asset,provider,root=assets;asset=open_asset()
    if conflict=='owner':provider.owner['container_id']='c'*64
    elif conflict=='account':(root/'etc/passwd').write_text('labuser:x:1000:1000:changed:/home/labuser:/bin/bash\n')
    else:(root/'usr/local/bin/vd').write_text('foreign code')
    with pytest.raises(RuntimeError):asset.prepare()
    assert not list((root/'run').iterdir())


def test_unbound_foreign_file_is_not_adopted_or_overwritten(assets):
    open_asset,provider,root=assets;asset=open_asset()
    path=root/asset.record['output'].lstrip('/');path.write_bytes(b'foreign')
    with pytest.raises(RuntimeError):asset.prepare()
    assert path.read_bytes()==b'foreign'


def test_replaced_qualified_output_is_refused(assets):
    open_asset,provider,root=assets;asset=open_asset();asset.prepare()
    path=root/asset.record['output'].lstrip('/');path.rename(path.with_suffix('.original'))
    path.write_bytes(asset.birth());path.chmod(0o600);os.chown(path,65534,65534)
    with pytest.raises(RuntimeError,match='output asset differs'):asset.prepare()


@pytest.mark.parametrize('conflict',['namespace','nonce','early-close','tail'])
def test_result_rejects_changed_or_incomplete_process_evidence(assets,conflict):
    open_asset,provider,root=assets;asset=open_asset();asset.prepare();complete(asset,root)
    path=root/asset.record['output'].lstrip('/');events=[json.loads(v) for v in path.read_bytes().splitlines()]
    if conflict=='namespace':events[2]['value']['namespace']=[33,44]
    elif conflict=='nonce':events[-1]['value']['nonce']='c'*32
    elif conflict=='early-close':events[3]['value']['input_closed']=True
    raw=b''.join(module.encoded(v)+b'\n' for v in events)
    if conflict=='tail':raw=raw[:-1]
    path.write_bytes(raw)
    with pytest.raises(RuntimeError):
        asset.result({'owner':provider.owner,'nonce':asset.record['nonce']},{'Running':False,'ExitCode':0})


def test_original_root_is_reobserved_and_descriptor_closes_on_conflict():
    ns=os.stat('/proc/self/ns/net')
    class Worker:
        record={'phase':'active','container_id':'a'*64,'nonce':'b'*32,'config':{},'image':{},
                'context':{'boot':'original'},'namespace':{'device':ns.st_dev,'inode':ns.st_ino}}
        def read(self):return deepcopy(self.record)
        def infrastructure(self,record):pass
        def verify_extensions(self,record):pass
        def container(self,record):
            return {'Id':'a'*64,'State':{'Pid':os.getpid(),'StartedAt':'original','Running':True},'ExecIDs':None}
        @contextmanager
        def namespace(self,record):
            fd=os.open('/proc/self/ns/net',os.O_RDONLY)
            try:yield fd
            finally:os.close(fd)
        def verify_attachment(self,record,fd):assert os.fstat(fd).st_ino==ns.st_ino
    worker=Worker();root=module.JumphostRoot(worker)
    assert root.observe()['exec_ids']==[]
    descriptor=None
    with pytest.raises(RuntimeError,match='root generation differs'):
        with root.open() as fd:
            descriptor=fd
            assert stat_is_directory(os.fstat(fd).st_mode)
            worker.record['context']={'boot':'replacement'}
    with pytest.raises(OSError):os.fstat(descriptor)


def stat_is_directory(mode):
    import stat
    return stat.S_ISDIR(mode)


@pytest.mark.parametrize('append_only',[False,True])
def test_live_journal_append_is_allowed_only_for_mutable_output(assets,monkeypatch,append_only):
    open_asset,provider,root=assets;asset=open_asset();asset.prepare()
    path=root/asset.record['output'].lstrip('/');before=path.read_bytes()
    original=os.fdopen
    class Reader:
        def __init__(self,fd,mode):self.stream=original(fd,mode)
        def __enter__(self):return self
        def __exit__(self,*args):self.stream.close()
        def fileno(self):return self.stream.fileno()
        def read(self,limit):
            data=self.stream.read(limit)
            fd=os.open(path,os.O_WRONLY|os.O_APPEND)
            try:os.write(fd,b'new-progress\n')
            finally:os.close(fd)
            return data
    monkeypatch.setattr(module.os,'fdopen',Reader)
    with provider.open() as fd:
        if append_only:
            assert module.read_file(fd,asset.record['output'],append_only=True)[1]==before
        else:
            with pytest.raises(RuntimeError,match='changed'):module.read_file(fd,asset.record['output'])


def test_readonly_asset_preflight_cannot_allocate_missing_output(assets):
    open_asset,provider,root=assets;asset=open_asset()
    before=asset.path.read_bytes()
    with pytest.raises(RuntimeError,match='birth unresolved'):asset.prepare(readonly=True)
    assert not list((root/'run').iterdir()) and asset.path.read_bytes()==before


def test_readonly_result_cannot_create_missing_capture(assets,monkeypatch):
    open_asset,provider,root=assets;asset=open_asset();asset.prepare();complete(asset,root)
    owner={'owner':provider.owner,'nonce':asset.record['nonce']};status={'Running':False,'ExitCode':0}
    with pytest.raises(RuntimeError,match='capture.*missing'):asset.result(owner,status,readonly=True)
    assert not asset.path.with_suffix('.output.json').exists()
    expected=asset.result(owner,status)
    before={p:p.read_bytes() for p in asset.path.parent.glob('*.json')}
    monkeypatch.setattr(module,'private_json',lambda *args:pytest.fail('readonly result wrote a file'))
    assert asset.result(owner,status,readonly=True)==expected
    assert all(p.read_bytes()==raw for p,raw in before.items())
