"""Readonly numeric inventory: synthetic responses, pinned-FD transport checked."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

from dnlab_runtime import vm_tap_inventory as inventory
from dnlab_runtime.manifest import RuntimeErrorBase


@pytest.fixture
def dump():
    link=dict(ifname='dtp-test',ifindex=40,address='02:00:00:00:00:fe',mtu=1500,
        flags=['BROADCAST','MULTICAST'],linkinfo=dict(info_kind='tun',info_data=dict(
            type='tap',pi=False,vnet_hdr=True,multi_queue=False,persist=True,user='dnlab-libvirt',group='dnlab-libvirt')))
    row=dict(ifname='dtp-test',flags=['tap','persist','vnet_hdr'],user=1001,group=1002)
    return [link],[row]


def test_names_are_diagnostic_and_numeric_credentials_authoritative(dump):
    links,rows=dump;original=deepcopy(links)
    result=inventory.correlate(links,rows,list(reversed(rows)))
    assert result[0]['linkinfo']['info_data']['user']==1001
    assert result[0]['linkinfo']['info_data']['group']==1002
    assert links==original


def test_empty_tun_inventory_still_requires_real_link_inventory():
    lo=dict(ifname='lo',ifindex=1)
    assert inventory.correlate([lo],[],[])==[lo]
    with pytest.raises(RuntimeErrorBase):inventory.correlate([],[],[])


@pytest.mark.parametrize('fault',['name','index','uid','gid','mode','persist','pi','vnet','missing','duplicate','duplicate-link','duplicate-index'])
def test_incomplete_ambiguous_or_changed_inventory_is_refused(dump,fault):
    links,before=dump;after=deepcopy(before)
    if fault=='name':after[0]['ifname']='foreign'
    elif fault=='index':links[0]['ifindex']=True
    elif fault=='uid':after[0]['user']=1003
    elif fault=='gid':before[0]['group']=after[0]['group']='dnlab-libvirt'
    elif fault=='mode':links[0]['linkinfo']['info_data']['type']='tun'
    elif fault in ('persist','pi','vnet'):
        key={'vnet':'vnet_hdr'}.get(fault,fault);links[0]['linkinfo']['info_data'][key]=not links[0]['linkinfo']['info_data'][key]
    elif fault=='missing':before.clear();after.clear()
    elif fault=='duplicate':before.append(deepcopy(before[0]));after=deepcopy(before)
    elif fault=='duplicate-link':links.append(deepcopy(links[0]))
    else:links.append(dict(ifname='other',ifindex=links[0]['ifindex']))
    with pytest.raises(RuntimeErrorBase):inventory.correlate(links,before,after)


@pytest.fixture
def transport(dump,monkeypatch):
    links,rows=dump;info=os.stat('/proc/thread-self/ns/net')
    scope=dict(boot_id='12345678-1234-4234-8234-123456789abc',device=info.st_dev,inode=info.st_ino)
    profile=dict(path='/usr/bin/ip',sha256='a'*64,identity=[1792,42,stat.S_IFREG|0o755,0,0,1234,15,16])
    state=dict(calls=[],scope=deepcopy(scope),binary=profile['identity'][:],responses=[rows,links,rows],exit=0,stderr=b'')
    @contextmanager
    def opener(path):
        assert path=='/usr/bin/ip';yield 77
    def proof(fd,sha):
        assert (fd,sha)==(77,profile['sha256']);return tuple(state['binary'])
    monkeypatch.setattr(inventory,'binary_proof',proof)
    def run(argv,**options):
        index=len(state['calls']);state['calls'].append((argv,options))
        if state.get('timeout'):raise subprocess.TimeoutExpired(argv,5)
        body=json.dumps(state['responses'][index]).encode()
        if state.get('json'):body=state['json']
        if state.get('drift'):state['scope']['inode']+=1
        return SimpleNamespace(returncode=state['exit'],stdout=body,stderr=state['stderr'])
    source=inventory.TapInventory(profile,scope,read_context=lambda:deepcopy(state['scope']),run=run,opener=opener)
    return source,state,scope,profile


def test_transport_uses_only_original_fd_and_fixed_queries(transport):
    source,state,_,_=transport;result=source()
    assert result[0]['linkinfo']['info_data']['user']==1001
    assert [argv[1:] for argv,_ in state['calls']]==[list(inventory.NUMERIC),list(inventory.LINKS),list(inventory.NUMERIC)]
    for argv,options in state['calls']:
        assert argv[0]=='/usr/bin/ip' and options['executable']=='/proc/self/fd/77'
        assert options['pass_fds']==(77,) and options['stdin']==subprocess.DEVNULL
        assert options['timeout']==5 and options['close_fds'] is True and options['cwd']=='/'
        assert options['env']==inventory.ENVIRONMENT


@pytest.mark.parametrize('fault',['inode','context','thread','exit','stderr','json','duplicate-key','timeout','during'])
def test_failed_queries_do_not_retry_or_return_partial_inventory(transport,monkeypatch,fault):
    source,state,scope,_=transport
    if fault=='inode':state['binary'][1]+=1
    elif fault=='context':state['scope']['inode']+=1
    elif fault=='thread':
        original=os.stat
        def wrong(path,*args,**kwargs):
            if path=='/proc/thread-self/ns/net':return SimpleNamespace(st_dev=scope['device'],st_ino=scope['inode']+1)
            return original(path,*args,**kwargs)
        monkeypatch.setattr(inventory.os,'stat',wrong)
    elif fault=='exit':state['exit']=1
    elif fault=='stderr':state['stderr']=b'unexpected'
    elif fault=='json':state['json']=b'not-json'
    elif fault=='duplicate-key':state['json']=b'[{"ifname":"a","ifname":"b","flags":["tap"]}]'
    elif fault=='timeout':state['timeout']=True
    else:state['drift']=True
    with pytest.raises((RuntimeErrorBase,subprocess.TimeoutExpired)):source()
    assert len(state['calls'])<=1
