"""DNS journal with real filesystem and stateful Docker simulation."""
import copy
import json
import os
import pytest
from dnlab_multinode.services.dns_host import Worker, DNSError
from dnlab_multinode.services.jumphost_host import JumphostError
from tests.test_jumphost_host import World, config as jump_config


def config():
    return {'lab': 'breakout-alpha', 'generation': '2'*32, 'name': 'dnlab-breakout-alpha-dns',
            'image': 'dns:latest', 'network': {'name':'shared','bridge':'br-ext','subnet':'192.0.2.0/24','gateway':'192.0.2.1'},
            'ip':'192.0.2.2', 'upstream':['192.0.2.53']}


class DNSWorld(World):
    def __init__(self):
        c = jump_config(); c.update(config()); super().__init__(c)
    def run(self, argv, **kwargs):
        if argv[:4] == ['docker','kill','--signal','HUP']:
            self.calls.append(list(argv)); self.before(argv)
            if self.lost == 'hup': raise JumphostError('lost hup response')
            return ''
        try:
            return super().run(argv, **kwargs)
        finally:
            if argv[:2] == ['docker','create']:
                for value in self.values.values():
                    value['HostConfig']['CapAdd']=['NET_ADMIN']
                    value['HostConfig']['PortBindings']={}
    def worker(self, path):
        return Worker(config()['lab'],directory=path,run=self.run,host_context=lambda:{'boot_id':'boot','device':1,'inode':2})


@pytest.fixture
def world(tmp_path):
    w = DNSWorld(); return w, w.worker(tmp_path/'journal')


def test_birth_intent_before_create_and_id_before_start(world):
    w, worker = world
    def before(argv):
        r = worker.read()
        if argv[:2] == ['docker','create']:
            assert r['attempted'] and r['nonce'] and r['config'] == config()
            assert r['file']['content'] == '192.0.2.3 R1\n'
        if argv[:2] == ['docker','start']: assert r['container_id'] == argv[2]
    w.before = before
    r = worker.operate('ensure', config(), '192.0.2.3 R1\n')
    assert r['phase'] == 'active'
    assert worker.operate('ensure', config(), '192.0.2.3 R1\n') == r
    assert sum(c[:2]==['docker','create'] for c in w.calls)==1
    worker.operate('reload', content='192.0.2.4 R1\n')
    assert worker.read()['file']['content'] == '192.0.2.4 R1\n'
    assert sum(c[:4]==['docker','kill','--signal','HUP'] for c in w.calls)==1
    assert worker.operate('delete')['phase']=='cleaned'
    assert worker.operate('verify-cleaned')['cleanup_verified']
    assert not w.values
    assert not any('-f' in c for c in w.calls)


@pytest.mark.parametrize('failure', ['create','start','hup','rm'])
def test_recover_lost_responses(world,failure):
    w,worker=world
    if failure in ('hup','rm'): worker.operate('ensure',config(),'one')
    w.lost=failure
    with pytest.raises(JumphostError):
        if failure=='hup': worker.operate('reload',content='two')
        elif failure=='rm': worker.operate('delete')
        else: worker.operate('ensure',config(),'one')
    w.lost=None
    assert worker.operate('recover')['phase']==('cleaned' if failure=='rm' else 'active')
    assert sum(c[:2]==['docker','create'] for c in w.calls)==1


@pytest.mark.parametrize('replacement',['container','label','image','network','file','directory'])
def test_replaced_resources_preserved_before_any_mutation(world,replacement):
    w,worker=world;record=worker.operate('ensure',config(),'one')
    value=next(iter(w.values.values()));directory=worker.asset_directory(record)
    if replacement=='container':
        v=w.values.pop(record['container_id']);v['Id']='f'*64;w.values['f'*64]=v
    if replacement=='label': value['Config']['Labels']={}
    if replacement=='image': value['Image']='sha256:'+'f'*64
    if replacement=='network': w.network['Id']='f'*64
    if replacement=='file':
        (directory/'hosts').rename(directory/'foreign-old');(directory/'hosts').write_text('one');(directory/'hosts').chmod(0o600)
    if replacement=='directory':
        directory.rename(directory.with_name(directory.name+'-old'));directory.mkdir(mode=0o700)
    before=copy.deepcopy(w.values);calls=len(w.calls)
    with pytest.raises(DNSError): worker.operate('delete')
    assert w.values==before
    assert not any(c[:2] in (['docker','kill'],['docker','rm'],['docker','create']) for c in w.calls[calls:])


def test_foreign_initial_name_rejected_before_assets(world):
    w,worker=world;w.values['f'*64]={'Id':'f'*64,'Name':'/'+config()['name']}
    with pytest.raises(DNSError,match='occupied'): worker.operate('ensure',config(),'one')
    assert worker.read() is None
    assert not list(worker.directory.glob('*-*/hosts'))


def test_journal_failure_prevents_container_mutation(world,monkeypatch):
    w,worker=world
    monkeypatch.setattr(worker,'save',lambda record: (_ for _ in ()).throw(OSError('fsync failed')))
    with pytest.raises(OSError):worker.operate('ensure',config(),'one')
    assert not w.values


def test_recovery_after_atomic_file_replace_before_journal(world,monkeypatch):
    w,worker=world;worker.operate('ensure',config(),'one');save=worker.save
    def interrupted(record):
        if record['phase']=='reload_pending' and not record.get('file_operation'):
            raise OSError('lost file commit')
        save(record)
    with monkeypatch.context() as patch:
        patch.setattr(worker,'save',interrupted)
        with pytest.raises(OSError):worker.operate('reload',content='two')
    assert worker.operate('recover')['file']['content']=='two'


def test_recover_asset_cleanup_after_unlink(world,monkeypatch):
    w,worker=world;r=worker.operate('ensure',config(),'one');directory=worker.asset_directory(r)
    original=os.rmdir
    def interrupted(path,*args,**kwargs):
        if str(path)==str(directory): raise OSError('rmdir interrupted')
        return original(path,*args,**kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os,'rmdir',interrupted)
        with pytest.raises(OSError):worker.operate('delete')
    assert worker.read()['phase']=='assets_cleanup'
    assert worker.operate('recover')['phase']=='cleaned'


def test_new_generation_only_after_verified_cleanup(world):
    w,worker=world;old=worker.operate('ensure',config(),'one')
    worker.operate('delete');new=config();new['generation']='3'*32
    r=worker.operate('provision',new,'two');assert r['phase']=='active'
    assert r['nonce']!=old['nonce']
    with pytest.raises(DNSError,match='generation request differs'):
        worker.operate('delete',{'generation':old['config']['generation']})
    worker.operate('delete')
    with pytest.raises(DNSError,match='historical generation'):
        worker.operate('provision',config(),'one')


def test_unknown_file_blocks_cleanup_before_stop(world):
    w,worker=world;r=worker.operate('ensure',config(),'one')
    (worker.asset_directory(r)/'foreign').write_text('do not delete')
    before=len(w.calls)
    with pytest.raises(DNSError,match='unqualified files'):worker.operate('delete')
    assert not any(c[:2] in (['docker','kill'],['docker','rm']) for c in w.calls[before:])


def test_daemon_delegates_dns_and_preserves_legacy(topo_factory):
    from dnlab_multinode.services.lab_cleanup import CleanupArtifact, _action_for_artifact
    artifact=CleanupArtifact('container','dnlab-demo-dns','master','demo')
    action=_action_for_artifact(artifact,None)
    assert action.action=='cleanup-dns' and action.command==''


def test_hosts_readable_after_dnsmasq_privilege_drop(world):
    import subprocess
    import sys
    if os.getuid()!=0:pytest.skip('requires root to exercise unprivileged read')
    w,worker=world;r=worker.operate('ensure',config(),'one')
    directory=worker.asset_directory(r)
    value=subprocess.run([sys.executable,'-c',"print(open('hosts').read())"],cwd=directory,
                         preexec_fn=lambda:os.setuid(65534),capture_output=True,text=True)
    assert value.returncode==0,value.stderr
    assert value.stdout.strip()=='one'


def test_recovery_of_completed_cleanup_is_idempotent(world):
    w,worker=world;worker.operate('ensure',config(),'one');worker.operate('delete')
    assert worker.operate('recover')['cleanup_verified']


def test_daemon_preflight_allows_tracked_partial_asset_cleanup(world,monkeypatch):
    w,worker=world;r=worker.operate('ensure',config(),'one');directory=worker.asset_directory(r)
    original=os.rmdir
    def interrupted(path,*args,**kwargs):
        if str(path)==str(directory):raise OSError('crash')
        return original(path,*args,**kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os,'rmdir',interrupted)
        with pytest.raises(OSError):worker.operate('delete')
    assert worker.operate('preflight-delete')['phase']=='assets_cleanup'
    assert worker.operate('recover')['phase']=='cleaned'


def test_assets_are_readable_with_restrictive_host_umask(world):
    w,worker=world;old=os.umask(0o077)
    try:r=worker.operate('ensure',config(),'one')
    finally:os.umask(old)
    assert (worker.asset_directory(r).stat().st_mode & 0o777)==0o755
    assert ((worker.asset_directory(r)/'hosts').stat().st_mode & 0o777)==0o644


def test_cleanup_after_asset_directory_birth_before_file_creation(world,monkeypatch):
    w,worker=world
    with monkeypatch.context() as patch:
        patch.setattr(worker,'write_hosts',lambda record:(_ for _ in ()).throw(OSError('interrupted before hosts write')))
        with pytest.raises(OSError):worker.operate('ensure',config(),'one')
    assert worker.read()['asset_directory'] and not w.values
    assert worker.operate('preflight-delete')['phase']=='creating'
    assert worker.operate('delete')['cleanup_verified']


def test_stale_reload_generation_refused_before_file_or_signal(world):
    w,worker=world;r=worker.operate('ensure',config(),'one');before=len(w.calls)
    with pytest.raises(DNSError,match='reload generation differs'):
        worker.operate('reload',{'generation':'f'*32},content='two')
    assert worker.read()['file']==r['file']
    assert not any(c[:2]==['docker','kill'] for c in w.calls[before:])
