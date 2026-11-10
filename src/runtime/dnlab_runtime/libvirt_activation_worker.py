"""Blocked systemctl worker protocol; native launch requires explicit ownership.

The parent must pin the binary FD, interpreter/source and original worker before
release. Account worker validation is neither changed nor used for these verbs.
"""
import os
import re

from .libvirt_account_worker import binary_proof,frame,require
from .libvirt_activation_commands import ENVIRONMENT
from .manifest import Conflict,canonical,fingerprint

UNITS=('dnlab-virtlogd.service','dnlab-virtlockd.service','dnlab-libvirtd.service')


def validate_command(command):
    require(isinstance(command,dict) and set(command)=={'request_sha256','binary','argv','environment'},
        'fixed activation worker command required')
    binary=command['binary'];argv=command['argv']
    require(isinstance(binary,dict) and set(binary)=={'path','sha256'} and binary['path']=='/usr/bin/systemctl'
        and isinstance(binary['sha256'],str) and re.fullmatch('[0-9a-f]{64}',binary['sha256'])
        and isinstance(command['request_sha256'],str) and re.fullmatch('[0-9a-f]{64}',command['request_sha256'])
        and command['environment']==ENVIRONMENT,'original activation binary and environment required')
    require(isinstance(argv,list) and all(isinstance(value,str) and '\0' not in value for value in argv),
        'activation argv must be fixed strings')
    require(argv==['/usr/bin/systemctl','daemon-reload']
        or len(argv)==4 and argv[:3]==['/usr/bin/systemctl','start','--'] and argv[3] in UNITS,
        'only original reload and individual dedicated starts permitted')
    return command


def serve(source,sink,binary_fd,*,execute):
    request=frame(source)
    require(isinstance(request,dict) and set(request)=={'token','command'}
        and isinstance(request['token'],str) and re.fullmatch('[0-9a-f]{32}',request['token']),
        'original activation worker token required')
    command=validate_command(request['command'])
    require(os.geteuid()==0,'privileged activation worker required')
    original=binary_proof(binary_fd,command['binary']['sha256'])
    command_sha256=fingerprint(command)
    sink.write(canonical(dict(ready=request['token'],command_sha256=command_sha256))+'\n');sink.flush()
    release=frame(source)
    require(release==dict(release=request['token'],command_sha256=command_sha256),
        'original activation worker release differs')
    require(binary_proof(binary_fd,command['binary']['sha256'])==original,'original activation executable FD identity differs')
    execute(binary_fd,command['argv'],command['environment'])
    raise Conflict('activation worker exec unexpectedly returned')
