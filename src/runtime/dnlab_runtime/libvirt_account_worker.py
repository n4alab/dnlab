"""Blocked account worker protocol. Import and tests do not launch a process.

An authorized parent must pin the binary FD, worker source/interpreter and
original process before releasing. This worker is not a standalone installer.
"""
import hashlib
import json
import os
import re
import stat

from .manifest import Conflict, canonical, fingerprint

ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/','LANG':'C','LC_ALL':'C'}
MAX_FRAME=16384


def require(value,message):
    if not value:raise Conflict(message)


def validate_command(command):
    require(isinstance(command,dict) and set(command)=={'request_sha256','binary','argv','environment'},'fixed account worker command required')
    binary=command['binary'];argv=command['argv']
    require(isinstance(binary,dict) and set(binary)=={'path','sha256'}
        and binary['path'] in ('/usr/sbin/useradd','/usr/sbin/groupadd')
        and isinstance(binary['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',binary['sha256'])
        and isinstance(command['request_sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',command['request_sha256'])
        and command['environment']==ENVIRONMENT,'original account binary and environment required')
    require(isinstance(argv,list) and all(isinstance(v,str) and '\0' not in v for v in argv), 'account argv must be strings')
    require(len(argv)==(6 if binary['path'].endswith('/groupadd') else 21),'fixed account argv length required')
    name=argv[-1]
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name) and name!='root','dedicated account name required')
    def numeric(value):return value.isdecimal() and 0<int(value)<2**31 and str(int(value))==value
    if binary['path'].endswith('/groupadd'):
        require(numeric(argv[3]) and argv==[binary['path'],'--system','--gid',argv[3],'--',name], 'fixed group command required')
    else:
        require(numeric(argv[3]) and numeric(argv[5])
            and re.fullmatch(r'/[A-Za-z0-9_./-]+',argv[7]) and '..' not in argv[7].split('/')
            and re.fullmatch(r'dnlab-v1-[0-9a-f]{64}',argv[18]),'safe account IDs, home and marker required')
        expected=[binary['path'],'--system','--uid',argv[3],'--gid',argv[5],'--home-dir',argv[7],
            '--no-create-home','--no-user-group','--no-log-init','--groups','','--shell','/usr/sbin/nologin',
            '--password','!','--comment',argv[18],'--',name]
        require(argv==expected,'fixed locked noninteractive user command required')
    return command


def binary_proof(fd,expected_sha256):
    before=os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022
        and 4<=before.st_size<=128*1024*1024,'pinned root-owned immutable-mode ELF required')
    os.lseek(fd,0,os.SEEK_SET);digest=hashlib.sha256();total=0;header=b''
    while total<=before.st_size:
        block=os.read(fd,min(65536,before.st_size+1-total))
        if not block:break
        if not header:header=block[:4]
        total+=len(block);digest.update(block)
    require(header==b'\x7fELF' and total==before.st_size and digest.hexdigest()==expected_sha256,'original account executable content differs')
    after=os.fstat(fd)
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
    require(all(getattr(before,k)==getattr(after,k) for k in fields),'account executable changed during read')
    os.lseek(fd,0,os.SEEK_SET)
    return tuple(getattr(before,k) for k in fields)


def frame(stream):
    line=stream.readline(MAX_FRAME+1)
    require(isinstance(line,str) and len(line.encode())<=MAX_FRAME and line.endswith('\n'),'bounded complete worker frame required')
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'duplicate worker frame key');value[key]=item
        return value
    return json.loads(line,object_pairs_hook=unique)


def serve(source,sink,binary_fd,*,execute):
    """No account mutation before the exact release. execute must replace this PID."""
    request=frame(source)
    require(isinstance(request,dict) and set(request)=={'token','command'}
        and isinstance(request['token'],str) and re.fullmatch(r'[0-9a-f]{32}',request['token']), 'original worker token required')
    command=validate_command(request['command'])
    require(os.geteuid()==0,'privileged provisioning worker required')
    original=binary_proof(binary_fd,command['binary']['sha256'])
    command_sha256=fingerprint(command)
    sink.write(canonical(dict(ready=request['token'],command_sha256=command_sha256))+'\n');sink.flush()
    release=frame(source)
    require(release==dict(release=request['token'],command_sha256=command_sha256),'original worker release differs')
    require(binary_proof(binary_fd,command['binary']['sha256'])==original,'original executable FD identity differs')
    execute(binary_fd,command['argv'],command['environment'])
    raise Conflict('account worker exec unexpectedly returned')
