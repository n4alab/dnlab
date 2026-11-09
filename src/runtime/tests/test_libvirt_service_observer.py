"""Typed synthetic daemon acknowledgements; no host process or socket reads."""
from copy import deepcopy
import stat

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_service_observer import ServiceGenerationObserver
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_install import install, request_profile


@pytest.fixture
def service(install):
    installer,_,prepared,_=install
    installation=installer.apply(prepared['id'])
    # This descriptor is fixture data, not a qualified host installation.
    installation['context']=dict(boot_id='synthetic-boot',namespaces={
        name:dict(device=1,inode=i+10) for i,name in enumerate(('pid','mnt','net','user'))})
    profile=installation['profile'];session=profile['session']
    def make(role='libvirtd'):
        unit='dnlab-'+role+'.service';path='/etc/systemd/system/'+unit
        socket_path=session['runtime_root']+'/libvirt/'+('libvirt' if role=='libvirtd' else role)+'-sock'
        environment=deepcopy(profile['client_environment']);environment.pop('LIBVIRT_DEFAULT_URI')
        environment['HOME']=session['state_root']
        value=dict(unit=dict(name=unit,fragment_path=path,fragment_sha256=profile['files'][path]['sha256'],
            dropins=[],restart='no',active='active',job=0,pid=1234,invocation_id='a'*32),
            process=dict(pid=1234,start_ticks=5678,boot_id='synthetic-boot',uids=[1001]*4,gids=[1002]*4,
                groups=[1002,108] if role=='libvirtd' else [1002],namespaces=deepcopy(installation['context']['namespaces']),
                executable_sha256=profile['binaries'][role]['sha256'],argv=[profile['binaries'][role]['path'],
                    '--config','/etc/dnlab/libvirt/'+role+'.conf','--pid-file',session['runtime_root']+'/libvirt/'+role+'.pid'],
                environment=environment,pidfd_alive=True),
            socket=dict(path=socket_path,device=2,inode=100,mode=stat.S_IFSOCK|0o700,
                uid=1001,gid=1002,peer_pid=1234,peer_uid=1001,peer_gid=1002),
            files={item['spec']['path']:deepcopy(item['proof']) for item in installation['items'] if item['spec']['kind']=='file'})
        item=dict(spec=next(s for s in steps(profile) if s.get('role')==role),nonce='b'*32)
        receipt=dict(activation_id='activation',nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
            identity=dict(command=dict(sha256='c'*64,exit_code=0,process_reference_sha256='d'*64),service=deepcopy(value)))
        observer=ServiceGenerationObserver(installation,item,'activation',receipt,socket_path=socket_path,
            command_sha256='c'*64,read=lambda:deepcopy(value))
        return observer,value,receipt,item,socket_path
    return installation,make


@pytest.mark.parametrize('role',['libvirtd','virtlogd','virtlockd'])
def test_original_nonroot_service_generation_is_read_twice(service,role):
    _,make=service;observer,value,_,_,_=make(role)
    calls=[]
    def read():calls.append(True);return deepcopy(value)
    observer.read=read
    assert observer()==value and len(calls)==2


@pytest.mark.parametrize('fault',['root','executable','dropin','file','peer','socket_mode','pidfd','namespace','environment','loader','groups','invocation','ticks'])
def test_changed_service_proof_is_rejected_without_discovery(service,fault):
    _,make=service;observer,value,_,_,_=make()
    if fault=='root':value['process']['uids']=[0]*4
    elif fault=='executable':value['process']['executable_sha256']='f'*64
    elif fault=='dropin':value['unit']['dropins']=['foreign.conf']
    elif fault=='file':next(iter(value['files'].values()))['identity']={'foreign':'preserve'}
    elif fault=='peer':value['socket']['peer_pid']=9999
    elif fault=='socket_mode':value['socket']['mode']=stat.S_IFSOCK|0o777
    elif fault=='pidfd':value['process']['pidfd_alive']=False
    elif fault=='namespace':value['process']['namespaces']['pid']['inode']+=1
    elif fault=='environment':value['process']['environment']['XDG_CONFIG_HOME']='/foreign'
    elif fault=='loader':value['process']['environment']['LD_PRELOAD']='/foreign.so'
    elif fault=='groups':value['process']['groups']=[0,108]
    elif fault=='invocation':value['unit']['invocation_id']='e'*32
    else:value['process']['start_ticks']+=1
    with pytest.raises(Conflict):observer()


def test_replacement_between_observations_is_refused(service):
    _,make=service;observer,value,_,_,_=make();calls=[]
    def read():
        result=deepcopy(value)
        if calls:result['process']['start_ticks']+=1
        calls.append(True);return result
    observer.read=read
    with pytest.raises(Conflict,match='generation replaced'):observer()


@pytest.mark.parametrize('fault',['nonce','command','exit','socket_path'])
def test_current_matching_unit_cannot_replace_original_start_acknowledgement(service,fault):
    installation,make=service;_,value,receipt,item,path=make()
    if fault=='nonce':receipt['nonce']='f'*32
    elif fault=='command':receipt['identity']['command']['sha256']='f'*64
    elif fault=='exit':receipt['identity']['command']['exit_code']=1
    else:path='/run/foreign.sock'
    with pytest.raises(Conflict):ServiceGenerationObserver(installation,item,'activation',receipt,
        socket_path=path,command_sha256='c'*64,read=lambda:pytest.fail('no discovery before valid original acknowledgement'))
