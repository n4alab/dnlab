"""Read-only host recovery probe, with simulated proc/namespace descriptors."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from dnlab_multinode.services import jumphost_host as module
from tests.test_dhcp_host_identity import proof


@pytest.fixture
def world(monkeypatch):
    expected=proof();main='original main\n';root,run,binary,log,pidfile,original,foreign,exe,otherexe=range(90001,90010)
    directories=[{'device':4,'inode':v,'uid':0,'gid':0,'mode':0o755,'directory':True} for v in (700,701)]
    logproof=dict(expected['pid_file'],inode=45,gid=0,mode=0o660,nlink=1)
    expected['log']={'directories':directories,'file':logproof,'configuration_sha256':hashlib.sha256(main.encode()).hexdigest()}
    infos={root:directories[0],run:directories[1],binary:expected['binary'],exe:expected['binary'],
           log:logproof,pidfile:expected['pid_file'],otherexe:dict(expected['binary'],inode=99)}
    processes={original:{'state':'Z','start':expected['start'],'host':123,'local':36,'comm':'dnsmasq'},
               foreign:{'state':'S','start':'9999','host':999,'local':99,'comm':'dnsmasq'}}
    state={'gone':False,'pidfile_missing':False,'foreign':False,'foreign_namespace':False,'permission':False,'text':'36\n'}
    worker=SimpleNamespace(dhcp_preflight=Mock())
    service=module.DHCPHostService(worker,{'dhcp_assets':{'files':{'main':{'content':main}}}},10)
    service.root=root;service.run_dir=run;service.container_proof=deepcopy(expected['container'])
    service.recheck_container=Mock();service.observe=Mock(return_value=expected)
    def opened(path,*,parent=None,directory=False,nofollow=True):
        if path=='dnsmasq':return binary
        if path=='dnlab-dhcp.log':return log
        if path=='dnlab-dnsmasq.pid':
            if state['pidfile_missing']:raise FileNotFoundError()
            return pidfile
        if path=='/proc/123':
            if state['gone']:raise FileNotFoundError()
            return original
        if path=='/proc/999':
            if state['permission']:raise PermissionError()
            return foreign
        if path=='exe':return exe if parent==original else otherexe
        raise AssertionError((path,parent))
    service.open=opened;service.root_directory=lambda parts:90010
    service.ns=lambda fd,name:deepcopy(expected['pid_namespace'])
    def read(path,parent):
        row=processes[parent]
        if path=='status':return f"State:\t{row['state']}\nNSpid:\t{row['host']} {row['local']}\n"
        if path=='stat':return str(row['host'])+' (dnsmasq) '+' '.join([row['state']]+['0']*18+[row['start']])
        if path=='comm':return row['comm']+'\n'
        raise AssertionError(path)
    service.read=read
    real_fstat=os.fstat;real_read=os.read;real_stat=os.stat
    def fstat(fd):
        if fd not in infos:return real_fstat(fd)
        v=infos[fd]
        return SimpleNamespace(st_dev=v['device'],st_ino=v['inode'],st_uid=v['uid'],st_gid=v['gid'],
            st_mode=(stat.S_IFDIR if v.get('directory') else stat.S_IFREG)|v['mode'],st_nlink=v.get('nlink',1))
    def procstat(path,*args,**kwargs):
        if str(path).startswith('/proc/'):
            ns=deepcopy(expected['pid_namespace'])
            if state['foreign_namespace'] and str(path).startswith('/proc/999/'):ns['inode']+=1
            return SimpleNamespace(st_dev=ns['device'],st_ino=ns['inode'])
        return real_stat(path,*args,**kwargs)
    monkeypatch.setattr(module.os,'fstat',fstat)
    monkeypatch.setattr(module.os,'stat',procstat)
    monkeypatch.setattr(module.os,'read',lambda fd,count:state['text'].encode() if fd==pidfile else real_read(fd,count))
    monkeypatch.setattr(module,'hash_descriptor',lambda fd:'f'*64 if fd==otherexe else expected['binary_sha256'])
    def paths():
        result=[] if state['gone'] else [Path('/proc/123')]
        if state['foreign']:result.append(Path('/proc/999'))
        return iter(result)
    monkeypatch.setattr(module,'Path',lambda path:SimpleNamespace(iterdir=paths))
    signal=Mock(side_effect=AssertionError('read-only probe attempted a signal'))
    monkeypatch.setattr(module.signal,'pidfd_send_signal',signal)
    return SimpleNamespace(service=service,expected=expected,infos=infos,state=state,processes=processes,signal=signal,
        root=root,binary=binary,log=log,pidfile=pidfile,original=original,otherexe=otherexe)


@pytest.mark.parametrize('outcome',['zombie','gone','live','file-removed','other-namespace'])
def test_read_only_probe_qualifies_original_generation_and_preserves_every_resource(world,outcome):
    w=world
    if outcome=='gone':w.state['gone']=True
    if outcome=='live':w.processes[w.original]['state']='S'
    if outcome=='file-removed':w.state['pidfile_missing']=True
    if outcome=='other-namespace':w.state.update(foreign=True,foreign_namespace=True)
    result=w.service.shutdown_status(w.expected)
    assert result['state']==('running' if outcome=='live' else 'stopped')
    assert result['service']==w.expected
    if outcome!='live':assert result['exit_verified'] and not w.service.observe.called
    else:w.service.observe.assert_called_once_with(w.expected)
    w.signal.assert_not_called();w.service.worker.dhcp_preflight.assert_called_once_with(w.service.record)


@pytest.mark.parametrize('change',['container','root','configuration','binary','log','pidfile','pidfile-content',
    'pid-reuse','namespace-reuse','foreign-daemon','renamed-daemon','mapped-daemon','permission'])
def test_recovery_refuses_changed_proofs_and_foreign_services_without_signals(world,change,monkeypatch):
    w=world
    if change=='container':w.service.container_proof['id']='f'*64
    if change=='root':w.infos[w.root]=dict(w.infos[w.root],inode=999)
    if change=='configuration':w.service.record['dhcp_assets']['files']['main']['content']='foreign'
    if change=='binary':w.infos[w.binary]=dict(w.infos[w.binary],inode=999)
    if change=='log':w.infos[w.log]=dict(w.infos[w.log],inode=999)
    if change=='pidfile':w.infos[w.pidfile]=dict(w.infos[w.pidfile],inode=999)
    if change=='pidfile-content':w.state['text']='37\n'
    if change=='pid-reuse':w.processes[w.original]['start']='new'
    if change=='namespace-reuse':w.processes[w.original]['local']=37
    if change in ('foreign-daemon','renamed-daemon','mapped-daemon','permission'):w.state['foreign']=True
    if change=='permission':w.state['permission']=True
    if change=='renamed-daemon':
        w.processes[90007]['comm']='other';monkeypatch.setattr(module,'hash_descriptor',lambda fd:w.expected['binary_sha256'])
    if change=='mapped-daemon':w.processes[90007]['comm']='other';w.infos[w.otherexe]=deepcopy(w.expected['binary'])
    with pytest.raises((module.JumphostError,PermissionError)):w.service.shutdown_status(w.expected)
    w.signal.assert_not_called()
