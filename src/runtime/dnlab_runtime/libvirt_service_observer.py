"""Typed observation of an originally acknowledged dedicated daemon generation.

Providers remain explicit: native systemd, pinned process and socket-peer readers
must be qualified before host use. This module neither discovers a generation nor
creates an acknowledgement from a currently matching unit. The root command
completion must already have been durably qualified by its owning executor.
"""
import configparser
from copy import deepcopy
from pathlib import PurePosixPath
import re
import shlex
import stat

from .manifest import Conflict, fingerprint


def require(value,message):
    if not value:raise Conflict(message)


def digest(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None


def qualify_service(installation,unit_name,socket_path,value):
    profile=installation['profile'];session=profile['session']
    require(unit_name in profile['service_order'],'original dedicated unit required')
    unit_path='/etc/systemd/system/'+unit_name
    config=configparser.ConfigParser(interpolation=None,strict=False)
    config.read_string(profile['files'][unit_path]['content'])
    service=config['Service'];argv=shlex.split(service['ExecStart'])
    role=unit_name.removeprefix('dnlab-').removesuffix('.service')
    expected_environment=dict(line[len('Environment='):].split('=',1)
        for line in profile['files'][unit_path]['content'].splitlines() if line.startswith('Environment='))
    expected_environment['HOME']=session['state_root']
    require(isinstance(socket_path,str) and str(PurePosixPath(socket_path))==socket_path
        and '..' not in PurePosixPath(socket_path).parts
        and PurePosixPath(socket_path).is_relative_to(session['runtime_root'])
        and socket_path!=session['runtime_root'],'explicit private service socket path required')
    if role=='libvirtd':require(socket_path==session['socket'],'original libvirt socket path required')
    require(isinstance(value,dict) and set(value)=={'unit','process','socket','files'},'complete daemon observation required')
    expected_files={item['spec']['path']:item['proof'] for item in installation['items'] if item['spec']['kind']=='file'}
    require(value['files']==expected_files,'original installed service files differ')
    unit=value['unit'];process=value['process'];socket=value['socket']
    require(isinstance(unit,dict) and set(unit)=={'name','fragment_path','fragment_sha256','dropins','restart','active','job','pid','invocation_id'},
        'complete original unit observation required')
    require(unit['name']==unit_name and unit['fragment_path']==unit_path
        and unit['fragment_sha256']==profile['files'][unit_path]['sha256'] and unit['dropins']==[]
        and unit['restart']=='no' and unit['active']=='active' and type(unit['job']) is int and unit['job']==0
        and isinstance(unit['invocation_id'],str) and re.fullmatch('[0-9a-f]{32}',unit['invocation_id'])
        and unit['invocation_id']!='0'*32,'original service unit configuration/generation differs')
    require(isinstance(process,dict) and set(process)=={'pid','start_ticks','boot_id','uids','gids','groups','namespaces',
        'executable_sha256','argv','environment','pidfd_alive'},'complete pinned daemon process observation required')
    require(type(process['pid']) is int and process['pid']>0 and process['pid']==unit['pid']
        and type(process['start_ticks']) is int and process['start_ticks']>0
        and process['boot_id']==installation['context']['boot_id']
        and process['uids']==[session['uid']]*4 and process['gids']==[session['gid']]*4
        and process['namespaces']==installation['context']['namespaces']
        and process['executable_sha256']==profile['binaries'][role]['sha256']
        and process['argv']==argv and process['pidfd_alive'] is True,
        'original nonroot daemon process generation/configuration differs')
    required_groups={int(n) for n in service.get('SupplementaryGroups','').split()}
    require(isinstance(process['groups'],list) and all(type(n) is int and n>0 for n in process['groups'])
        and len(set(process['groups']))==len(process['groups'])
        and required_groups<=set(process['groups'])<=required_groups|{session['gid']},'daemon supplementary groups differ')
    environment=process['environment']
    require(isinstance(environment,dict) and all(environment.get(k)==v for k,v in expected_environment.items())
        and all(isinstance(k,str) and isinstance(v,str) for k,v in environment.items())
        and not any(k.startswith('LD_') or k.startswith(('LIBVIRT_','XDG_')) and k not in expected_environment for k in environment),
        'original daemon environment differs')
    require(isinstance(socket,dict) and set(socket)=={'path','device','inode','mode','uid','gid','peer_pid','peer_uid','peer_gid'},
        'complete private socket and peer observation required')
    require(socket['path']==socket_path and all(type(socket[k]) is int for k in socket if k!='path')
        and socket['device']>=0 and socket['inode']>0 and stat.S_ISSOCK(socket['mode']) and not socket['mode']&0o077
        and socket['uid']==socket['peer_uid']==session['uid'] and socket['gid']==socket['peer_gid']==session['gid']
        and socket['peer_pid']==process['pid'],'private service socket ownership/peer differs')
    return deepcopy(value)


class ServiceGenerationObserver:
    def __init__(self,installation,item,activation_id,receipt,*,socket_path,command_sha256,read):
        require(callable(read) and digest(command_sha256),'explicit service observer and command reference required')
        require(isinstance(receipt,dict) and set(receipt)=={'activation_id','nonce','spec_sha256','identity'}
            and receipt['activation_id']==activation_id and receipt['nonce']==item['nonce']
            and receipt['spec_sha256']==fingerprint(item['spec']) and item['spec']['kind']=='start',
            'original service start acknowledgement required')
        identity=receipt['identity']
        require(isinstance(identity,dict) and set(identity)=={'command','service'},'original command and daemon proofs required')
        command=identity['command']
        require(isinstance(command,dict) and set(command)=={'sha256','exit_code','process_reference_sha256'}
            and command['sha256']==command_sha256 and type(command['exit_code']) is int and command['exit_code']==0
            and digest(command['process_reference_sha256']),'original successful command completion required')
        self.installation,self.unit,self.socket_path=deepcopy(installation),item['spec']['unit'],socket_path
        self.reference=qualify_service(installation,self.unit,socket_path,identity['service'])
        self.read=read

    def __call__(self):
        for _ in range(2):
            current=qualify_service(self.installation,self.unit,self.socket_path,self.read())
            if current!=self.reference:raise Conflict('original acknowledged service generation replaced')
        return deepcopy(self.reference)
