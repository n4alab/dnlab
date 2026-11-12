"""Exclusive TAP ioctl protocol with /dev/null FDs and a synthetic kernel."""
from copy import deepcopy
import errno
import os
from types import SimpleNamespace
import stat
import struct

import pytest

from dnlab_runtime import vm_tap_device as tap
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase


@pytest.fixture
def kernel(monkeypatch):
    original_open, original_close, original_fstat = os.open,os.close,os.fstat
    info=os.stat('/proc/self/ns/net')
    namespace=dict(boot_id='12345678-1234-4234-8234-123456789abc',device=info.st_dev,inode=info.st_ino)
    spec=dict(nonce='a'*32,name='dtp-synthetic',ifindex=12001,vnet_header=False)
    state=dict(links={},fds={},calls=[],records=[],scope=deepcopy(namespace),features=0x5002)
    def opened(path,flags,*args,**kwargs):
        if path!='/dev/net/tun':return original_open(path,flags,*args,**kwargs)
        fd=original_open('/dev/null',os.O_RDWR|os.O_CLOEXEC)
        state['fds'][fd]=dict(index=0,link=None,flags=0)
        return fd
    def closed(fd):
        record=state['fds'].pop(fd,None)
        if record and record['link'] is not None and not record['flags']&0x800:
            link=record['link']
            if state['links'].get(link['ifname']) is link:state['links'].pop(link['ifname'])
        original_close(fd)
    def fstat(fd):
        if fd in state['fds']:
            return SimpleNamespace(st_mode=stat.S_IFCHR|0o666,st_rdev=os.makedev(10,200),
                st_uid=0,st_gid=0,st_dev=7,st_ino=99)
        return original_fstat(fd)
    def ioctl(fd,command,arg=None):
        state['calls'].append(command);record=state['fds'][fd]
        if command in (0x400454cc,0x400454ce,0x400454cb):
            assert type(arg) is int
            if state.get('before_change')==command:raise OSError('uncertain change')
            data=record['link']['linkinfo']['info_data']
            if command==0x400454cc:data['user']=arg
            elif command==0x400454ce:data['group']=arg
            else:
                record['flags']=(record['flags']|0x800) if arg else (record['flags']&~0x800)
                data['persist']=bool(arg)
            if state.get('lost_change')==command:raise OSError('lost change response')
            return 0
        if command==tap.TUNGETFEATURES:return struct.pack('=I',state['features'])
        if command==tap.TUNSETIFINDEX:
            record['index']=struct.unpack('=I',arg)[0]
            if state.get('race'):
                state['links'][spec['name']]=dict(ifname=spec['name'],ifindex=999,foreign=True)
            return arg
        if command==tap.TUNSETIFF:
            name,flags=tap.IFREQ.unpack(arg);name=name.split(b'\0')[0].decode()
            assert flags&tap.IFF_TUN_EXCL
            if name in state['links']:raise OSError(errno.EBUSY,'exclusive name occupied')
            if any(link['ifindex']==record['index'] for link in state['links'].values()):
                raise OSError(errno.EEXIST,'ifindex occupied')
            link=dict(ifname=name,ifindex=record['index'],address='02:00:00:00:00:fe',mtu=1500,
                flags=['BROADCAST','MULTICAST'],linkinfo={'info_kind':'tun','info_data':{
                    'type':'tap','pi':not bool(flags&tap.IFF_NO_PI),'vnet_hdr':bool(flags&tap.IFF_VNET_HDR),
                    'multi_queue':False,'persist':False}})
            state['links'][name]=link;record.update(link=link,flags=flags&~tap.IFF_TUN_EXCL)
            return arg
        if command==tap.TUNGETIFF:
            if record['link'] is None:raise OSError(errno.EBADFD,'not attached')
            return tap.IFREQ.pack(record['link']['ifname'].encode(),record['flags'])
        if command==tap.TUNGETDEVNETNS:return original_open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        pytest.fail('unexpected ioctl')
    def inventory():return deepcopy(list(state['links'].values()))
    def save(value):
        state['records'].append(deepcopy(value))
        if state.get('fail_record')==value['phase']:raise OSError('synthetic durability failure')
        if value['phase']=='create_requested' and state.get('checkpoint_conflict'):
            state['links'][spec['name']]=dict(ifname=spec['name'],ifindex=999,foreign=True)
    def device(cls=tap.EphemeralTap):return cls(spec,namespace,read_context=lambda:deepcopy(state['scope']),
        inventory=inventory,record=save,ioctl=ioctl)
    monkeypatch.setattr(tap.os,'open',opened);monkeypatch.setattr(tap.os,'close',closed);monkeypatch.setattr(tap.os,'fstat',fstat)
    return spec,namespace,state,device


@pytest.mark.parametrize('vnet_header',[False,True])
def test_exclusive_ephemeral_birth_and_original_fd_close(kernel,vnet_header):
    spec,namespace,state,device=kernel;spec['vnet_header']=vnet_header
    with device() as original:
        proof=original.create()
        assert proof['context']==namespace and proof['link']['ifindex']==spec['ifindex']
        assert original.capture()==proof
        assert state['calls'].index(tap.TUNSETIFINDEX)<state['calls'].index(tap.TUNSETIFF)
        assert [r['phase'] for r in state['records']]==['opened','create_requested','created']
        with pytest.raises(RuntimeErrorBase,match='repeated'):original.create()
    assert state['links']=={} and state['fds']=={}
    with pytest.raises(RuntimeErrorBase,match='reopened'):
        with original:pass


def test_existing_foreign_link_refused_before_kernel_mutation(kernel):
    spec,_,state,device=kernel;state['links'][spec['name']]=dict(ifname=spec['name'],ifindex=55,foreign=True)
    with device() as original:
        with pytest.raises(Conflict,match='occupied'):original.create()
    assert tap.TUNSETIFF not in state['calls'] and state['links'][spec['name']]['foreign']


def test_kernel_exclusive_flag_catches_race_without_foreign_cleanup(kernel):
    spec,_,state,device=kernel;state['race']=True
    with device() as original:
        with pytest.raises(OSError) as error:original.create()
        assert error.value.errno==errno.EBUSY
        with pytest.raises(RuntimeErrorBase,match='repeated'):original.create()
    assert state['links'][spec['name']]['ifindex']==999


def test_checkpoint_collision_stops_before_create_ioctl(kernel):
    spec,_,state,device=kernel;state['checkpoint_conflict']=True
    with device() as original:
        with pytest.raises(Conflict,match='checkpoint'):original.create()
    assert tap.TUNSETIFF not in state['calls'] and state['links'][spec['name']]['foreign']


@pytest.mark.parametrize('phase',['opened','create_requested','created'])
def test_record_failure_closes_only_original_ephemeral_fd(kernel,phase):
    _,_,state,device=kernel;state['fail_record']=phase
    with pytest.raises(OSError,match='durability'):
        with device() as original:original.create()
    assert state['links']=={} and state['fds']=={}
    if phase!='created':assert tap.TUNSETIFF not in state['calls']


def test_namespace_drift_refused_before_create(kernel):
    _,_,state,device=kernel
    with device() as original:
        state['scope']['inode']+=1
        with pytest.raises(Conflict,match='namespace'):original.create()
    assert tap.TUNSETIFF not in state['calls'] and state['links']=={}


@pytest.mark.parametrize('fault',['index','alias','bridge','up','kind','persistent'])
def test_changed_created_link_is_not_accepted(kernel,fault):
    spec,_,state,device=kernel
    with device() as original:
        original.create();link=state['links'][spec['name']]
        if fault=='index':link['ifindex']+=1
        elif fault=='alias':link['ifalias']='foreign'
        elif fault=='bridge':link['master']='foreign'
        elif fault=='up':link['flags'].append('UP')
        elif fault=='kind':link['linkinfo']['info_kind']='veth'
        else:next(iter(state['fds'].values()))['flags']|=0x800
        with pytest.raises(RuntimeErrorBase):original.capture()
    assert state['fds']=={}


def test_unavailable_requested_feature_refused_without_creation(kernel):
    spec,_,state,device=kernel;spec['vnet_header']=True;state['features']&=~tap.IFF_VNET_HDR
    with device() as original:
        with pytest.raises(RuntimeErrorBase,match='features'):original.create()
    assert tap.TUNSETIFF not in state['calls']


def test_leader_context_cannot_hide_foreign_current_thread_namespace(kernel,monkeypatch):
    _,namespace,state,device=kernel;original=os.stat
    def stat(path,*args,**kwargs):
        if path=='/proc/thread-self/ns/net':return SimpleNamespace(st_dev=namespace['device'],st_ino=namespace['inode']+1)
        return original(path,*args,**kwargs)
    monkeypatch.setattr(tap.os,'stat',stat)
    with pytest.raises(Conflict,match='thread belongs'):
        with device():pytest.fail('device opened in another thread namespace')
    assert state['fds']=={} and state['calls']==[]
