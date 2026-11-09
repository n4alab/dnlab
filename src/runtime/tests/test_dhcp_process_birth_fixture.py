"""Birth/cleanup guarantees of the network-isolated process qualification tool."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec=importlib.util.spec_from_file_location('birth_smoke',Path(__file__).resolve().parents[1]/'tools/dhcp_process_birth_smoke.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Docker:
    def __init__(self,lost=False):
        self.value=None;self.lost=lost;self.calls=[]

    def request(self,method,path,payload=None):
        self.calls.append((method,path))
        if path.startswith('/images/'):
            return {'Id':module.IMAGE,'Config':{'Labels':{'inherited.image':'original'}}}
        if path.startswith('/containers/json?'):
            return [{'Id':self.value['Id']}] if self.value else []
        if path.endswith('/start'):
            self.value['State']['Running']=True;return {}
        if '/kill?' in path:
            self.value['State']['Running']=False;return {}
        if path.endswith('/wait'):return {}
        if method=='DELETE':
            assert not self.value['State']['Running'];self.value=None;return {}
        raise AssertionError((method,path))

    def inspect(self,name):
        assert isinstance(name,str),'Docker ID must be extracted from the create response'
        return deepcopy(self.value)

    def create(self,name,cfg):
        assert cfg['Labels']['inherited.image']=='original'
        self.value={'Id':'a'*64,'Name':'/'+name,'Image':module.IMAGE,
            'Config':deepcopy(cfg),'HostConfig':deepcopy(cfg['HostConfig']),'State':{'Running':False,'Pid':123}}
        if self.lost:raise RuntimeError('lost create acknowledgement')
        return {'Id':self.value['Id'],'Warnings':[]}


@pytest.mark.parametrize('lost',[False,True])
def test_preflight_failure_or_lost_create_recovers_only_the_original_birth_and_cleans(tmp_path,monkeypatch,lost):
    docker=Docker(lost)
    monkeypatch.setattr(module,'Docker',lambda:docker)
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout='',stderr='synthetic preflight failure'))
    # The successful-create case reaches proc stat; use the current PID only to
    # supply a real namespace descriptor, without creating or signalling a process.
    import os
    original=docker.request
    def request(*args,**kwargs):
        value=original(*args,**kwargs)
        if args[1].endswith('/start'):docker.value['State']['Pid']=os.getpid()
        return value
    monkeypatch.setattr(docker,'request',request)
    root=tmp_path/'evidence'
    with pytest.raises(RuntimeError):module.run(root)
    report=json.loads((root/'report.json').read_text())
    assert report['cleanup_verified'] and report['status']=='failed'
    assert docker.value is None
    assert json.loads((root/'intent.json').read_text())['id']=='a'*64
    assert any(method=='DELETE' for method,path in docker.calls)
    if lost:assert not any('/kill?' in path for method,path in docker.calls)


def test_lost_create_does_not_adopt_or_remove_a_conflicting_container(tmp_path,monkeypatch):
    docker=Docker(True);create=docker.create
    def foreign(name,cfg):
        try:return create(name,cfg)
        finally:docker.value['Config']['Labels']['org.dnlab.dhcp-birth']='foreign'
    monkeypatch.setattr(docker,'create',foreign)
    monkeypatch.setattr(module,'Docker',lambda:docker)
    with pytest.raises(RuntimeError,match='birth differs'):module.run(tmp_path/'evidence')
    assert docker.value is not None
    assert not any(method=='DELETE' or '/kill?' in path for method,path in docker.calls)


def pending_birth():
    docker=Docker();nonce='a'*32;name='drsp-dhbirth-'+nonce[:12]
    cfg={'Labels':{'inherited.image':'original','org.dnlab.dhcp-birth':nonce},
         'Entrypoint':['python3','-c'],'Cmd':['import time;time.sleep(120)'],
         'HostConfig':{'NetworkMode':'none','Binds':[]}}
    docker.create(name,cfg)
    birth={'id':None,'name':name,'nonce':nonce,'image':module.IMAGE,'config':cfg,'create_status':'uncertain'}
    return docker,birth


def test_uncertain_create_absence_retains_pending_and_never_sends_another_create(tmp_path):
    docker,birth=pending_birth();late=docker.value;docker.value=None;saved=[]
    assert not module.cleanup_fixture(docker,birth,lambda:saved.append(deepcopy(birth)),wait_seconds=0)
    assert birth['cleanup_status']=='cleanup_pending' and birth['id'] is None
    assert all(method=='GET' for method,path in docker.calls)
    # Same journal resumes when the original birth finally becomes visible.
    birth=deepcopy(saved[-1]);docker.value=late
    assert module.cleanup_fixture(docker,birth,lambda:saved.append(deepcopy(birth)),wait_seconds=0)
    assert docker.value is None and birth['id']=='a'*64 and birth['cleanup_status']=='cleaned'
    bound=next(i for i,v in enumerate(saved) if v['id']=='a'*64)
    cleaned=next(i for i,v in enumerate(saved) if v['cleanup_status']=='cleaned')
    assert bound<cleaned
    assert not any(method=='POST' and '/create' in path for method,path in docker.calls)


def test_late_birth_within_bounded_poll_is_qualified_and_removed(monkeypatch):
    docker,birth=pending_birth();late=docker.value;docker.value=None;sleeps=[]
    def arrive(seconds):sleeps.append(seconds);docker.value=late
    monkeypatch.setattr(module.time,'sleep',arrive)
    assert module.cleanup_fixture(docker,birth,lambda:None,wait_seconds=5)
    assert sleeps==[.1] and birth['cleanup_id']=='a'*64 and docker.value is None


@pytest.mark.parametrize('change',['labels','id','image','command','mount','renamed'])
def test_uncertain_cleanup_preserves_conflicting_births(change):
    docker,birth=pending_birth()
    if change=='labels':docker.value['Config']['Labels']['org.dnlab.dhcp-birth']='foreign'
    if change=='id':birth['id']='b'*64
    if change=='image':docker.value['Image']='sha256:'+'f'*64
    if change=='command':docker.value['Config']['Cmd']=['foreign']
    if change=='mount':docker.value['HostConfig']['Binds']=['/foreign:/target']
    if change=='renamed':docker.value['Name']='/foreign'
    with pytest.raises(RuntimeError):module.cleanup_fixture(docker,birth,lambda:None,wait_seconds=0)
    assert birth['cleanup_status']=='cleanup_pending' and docker.value is not None
    assert all(method=='GET' for method,path in docker.calls)


def test_cleanup_recovers_lost_remove_reply_without_name_based_deletion():
    docker,birth=pending_birth();request=docker.request
    def lost(method,path,payload=None):
        result=request(method,path,payload)
        if method=='DELETE':raise TimeoutError('remove reply lost')
        return result
    docker.request=lost
    with pytest.raises(TimeoutError):module.cleanup_fixture(docker,birth,lambda:None,wait_seconds=0)
    assert birth['id']=='a'*64 and birth['cleanup_status']=='cleanup_pending'
    docker.request=request
    assert module.cleanup_fixture(docker,birth,lambda:None,wait_seconds=0)
    assert sum(method=='DELETE' for method,path in docker.calls)==1


def test_cleanup_save_failure_prevents_any_remote_mutation():
    docker,birth=pending_birth()
    def failed():raise OSError('directory fsync failed')
    with pytest.raises(OSError):module.cleanup_fixture(docker,birth,failed,wait_seconds=0)
    assert docker.calls==[] and docker.value is not None


def test_cleanup_recovery_command_never_runs_canary_or_creates_a_container(tmp_path,monkeypatch):
    docker,birth=pending_birth();root=tmp_path/'evidence';root.mkdir(mode=0o700)
    module.save_json(root/'intent.json',birth)
    monkeypatch.setattr(module,'Docker',lambda:docker)
    assert module.recover_cleanup(root)
    assert json.loads((root/'cleanup-recovery.json').read_text())['verified']
    assert docker.value is None and all('/create' not in path for method,path in docker.calls)


def test_recovery_does_not_trust_a_previous_verified_report_when_create_was_uncertain(tmp_path,monkeypatch):
    docker,birth=pending_birth();docker.value=None;root=tmp_path/'evidence';root.mkdir(mode=0o700)
    module.save_json(root/'intent.json',birth);module.save_json(root/'report.json',{'cleanup_verified':True})
    monkeypatch.setattr(module,'Docker',lambda:docker)
    cleanup=module.cleanup_fixture
    monkeypatch.setattr(module,'cleanup_fixture',lambda d,b,s:cleanup(d,b,s,wait_seconds=0))
    with pytest.raises(RuntimeError,match='still uncertain'):module.recover_cleanup(root)
    value=json.loads((root/'cleanup-recovery.json').read_text())
    assert value=={'verified':False,'status':'cleanup_pending','id':None}


def test_absence_snapshot_retains_pidfile_and_namespace_process_identity(monkeypatch):
    import os
    real_path=Path;process=real_path('/proc')/str(os.getpid());namespace=os.stat(process/'ns/pid')
    monkeypatch.setattr(module,'Path',lambda value:SimpleNamespace(iterdir=lambda:iter([process])) if value=='/proc' else real_path(value))
    expected={'lstat':{'regular':True,'uid':65534,'mode':'0o644'},'text':'26\n'}
    calls=[]
    def command(argv,check):
        calls.append((argv,check));return SimpleNamespace(returncode=0,stdout=json.dumps(expected))
    snapshot=module.absence_snapshot(command,namespace,{'host_pid':os.getpid()},{'matches':[],'daemons':[]})
    assert snapshot['pidfile_probe']['snapshot']==expected
    assert snapshot['processes'][0]['host_pid']==os.getpid()
    assert snapshot['processes'][0]['start']==(process/'stat').read_text().rsplit(')',1)[1].split()[19]
    assert snapshot['guard_observation']=={'matches':[],'daemons':[]}
    assert len(calls)==1 and calls[0][1] is False
    assert not any(key in snapshot['processes'][0] for key in ('environment','environ','cmdline'))


def test_absence_snapshot_preserves_read_failure_without_changing_guard_outcome(monkeypatch):
    import os
    namespace=os.stat('/proc/self/ns/pid')
    monkeypatch.setattr(module,'Path',lambda value:SimpleNamespace(iterdir=lambda:iter([])))
    def denied(*args,**kwargs):raise PermissionError('synthetic denied read')
    snapshot=module.absence_snapshot(denied,namespace,observed={'matches':[],'daemons':[]})
    assert snapshot['pidfile_probe']=={'error_type':'PermissionError'}
    assert snapshot['guard_observation']=={'matches':[],'daemons':[]} and snapshot['processes']==[]


def absence_proof():
    import select
    namespace={'device':4,'inode':123};container={'id':'c'*64,'pid_namespace':namespace,'started_at':'original'}
    service={'container':deepcopy(container),'host_pid':42,'pid':26,'start':'100','uids':['65534']*4,
             'binary_sha256':'b'*64,'executable':{'device':9,'inode':12}}
    file={'device':9,'inode':20,'uid':65534,'gid':65534,'mode':'0o644','regular':True,
          'directory':False,'symlink':False,'nlink':1}
    parent=dict(file,inode=19,uid=0,gid=0,mode='0o755',regular=False,directory=True)
    pidfile={'path':'/run/dnlab-dnsmasq.pid','lstat':deepcopy(file),'fstat':deepcopy(file),'parent':parent,'text':'26\n'}
    row={'host_pid':42,'namespace_pids':['42','26'],'state':'Z (zombie)','comm':'dnsmasq','start':'100'}
    inventory={'pid_namespace':namespace,'complete':True,'processes':[row]}
    return {'service':service,'container':container,'original_pidfile':pidfile,'current_pidfile':deepcopy(pidfile),
            'inventory':inventory,'events':[(9876,select.POLLIN)],'pidfd':9876}


@pytest.mark.parametrize('residual',['zombie','gone','file-removed'])
def test_original_pidfd_exit_qualifies_only_original_stale_pidfile_or_verified_removal(residual):
    values=absence_proof()
    if residual=='gone':values['inventory']['processes']=[]
    if residual=='file-removed':
        values['current_pidfile']={'path':values['original_pidfile']['path'],
            'parent':deepcopy(values['original_pidfile']['parent']),
            'read_error':{'error_type':'FileNotFoundError','errno':2}}
    original=deepcopy(values)
    result=module.qualify_fixture_absence(**values)
    assert result['original_exit_verified'] and result['live_dnsmasq_count']==0
    assert result['original_pidfile_retained']==(residual!='file-removed')
    assert values==original,'absence qualification must not mutate any evidence'


@pytest.mark.parametrize('change',['no-exit','poll-error','bad-fd','wrong-fd','container','namespace','incomplete',
    'pidfile-inode','pidfile-owner','pidfile-content','pidfile-symlink','parent','read-denied',
    'original-pidfile-invalid','live-original','reused-pid','reused-hostpid','new-daemon','renamed-daemon',
    'mapped-daemon','missing-executable','duplicate-row'])
def test_absence_refuses_replacement_new_daemon_or_incomplete_evidence(change):
    import select
    v=absence_proof();row=v['inventory']['processes'][0]
    if change=='no-exit':v['events']=[]
    if change=='poll-error':v['events']=[(9876,select.POLLIN|select.POLLERR)]
    if change=='bad-fd':v['events']=[(9876,select.POLLIN|select.POLLNVAL)]
    if change=='wrong-fd':v['events']=[(9877,select.POLLIN)]
    if change=='container':v['container']['id']='d'*64
    if change=='namespace':v['inventory']['pid_namespace']={'device':4,'inode':124}
    if change=='incomplete':v['inventory']['complete']=False
    if change=='pidfile-inode':v['current_pidfile']['fstat']['inode']+=1
    if change=='pidfile-owner':v['current_pidfile']['fstat']['uid']=0
    if change=='pidfile-content':v['current_pidfile']['text']='27\n'
    if change=='pidfile-symlink':v['current_pidfile']['lstat']['symlink']=True
    if change=='parent':v['current_pidfile']['parent']['inode']+=1
    if change=='read-denied':v['current_pidfile']={'read_error':{'error_type':'PermissionError','errno':13}}
    if change=='original-pidfile-invalid':v['original_pidfile']['fstat']['regular']=False
    if change=='live-original':row['state']='S (sleeping)'
    if change=='reused-pid':row.update(host_pid=43,start='new')
    if change=='reused-hostpid':row.update(namespace_pids=['42','27'],start='new')
    if change in ('new-daemon','renamed-daemon','mapped-daemon','missing-executable'):
        extra={'host_pid':43,'namespace_pids':['43','27'],'state':'S (sleeping)','comm':'python3','start':'new',
               'executable':{'device':9,'inode':99,'sha256':'e'*64}}
        if change=='new-daemon':extra['comm']='dnsmasq'
        if change=='renamed-daemon':extra['executable']['sha256']='b'*64
        if change=='mapped-daemon':extra['executable']['inode']=12
        if change=='missing-executable':extra.pop('executable')
        v['inventory']['processes'].append(extra)
    if change=='duplicate-row':v['inventory']['processes'].append(deepcopy(row))
    before=deepcopy(v)
    with pytest.raises(RuntimeError,match='unqualified'):module.qualify_fixture_absence(**v)
    assert v==before


def test_namespace_inventory_does_not_hide_permission_failures(monkeypatch):
    class Process:
        name='42'
        def __truediv__(self,name):return '/denied/'+name
    monkeypatch.setattr(module,'Path',lambda value:SimpleNamespace(iterdir=lambda:iter([Process()])))
    def denied(*args,**kwargs):raise PermissionError('denied namespace read')
    monkeypatch.setattr(module.os,'stat',denied)
    with pytest.raises(PermissionError):module.fixture_process_inventory(SimpleNamespace(st_dev=4,st_ino=123))


def test_structural_asset_mode_preserves_the_dedicated_fixture_container_name(tmp_path,monkeypatch):
    import os
    docker=Docker();created=[];create=docker.create;request=docker.request
    def capture(name,cfg):created.append(name);return create(name,cfg)
    def started(*args,**kwargs):
        value=request(*args,**kwargs)
        if args[1].endswith('/start'):docker.value['State']['Pid']=os.getpid()
        return value
    monkeypatch.setattr(docker,'create',capture);monkeypatch.setattr(docker,'request',started)
    monkeypatch.setattr(module,'Docker',lambda:docker)
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout='',stderr='synthetic syntax failure'))
    root=tmp_path/'fixture'
    with pytest.raises(RuntimeError):module.run(root,journaled_main=True,journaled_assets=True)
    assert docker.value is None and json.loads((root/'report.json').read_text())['cleanup_verified']
    assert len(created)==1 and created[0].startswith('drsp-dhbirth-'),created


@pytest.mark.parametrize('change',['asset-name','wrong-nonce','malformed-nonce','missing-name'])
def test_precreate_name_guard_refuses_non_dedicated_or_changed_identity(change):
    birth={'nonce':'a'*32,'name':'drsp-dhbirth-'+'a'*12}
    if change=='asset-name':birth['name']='options'
    if change=='wrong-nonce':birth['nonce']='b'*32
    if change=='malformed-nonce':birth['nonce']='z'*32
    if change=='missing-name':birth.pop('name')
    with pytest.raises(RuntimeError,match='before create'):module.validate_fixture_name(birth)


def test_precreate_name_guard_preserves_the_exact_original_nonce_identity():
    birth={'nonce':'a'*32,'name':'drsp-dhbirth-'+'a'*12}
    assert module.validate_fixture_name(birth)==birth['name']
