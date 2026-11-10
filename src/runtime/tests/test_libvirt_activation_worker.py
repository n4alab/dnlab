"""Memory streams, fixture ELF bytes and mocked exec; no worker process starts."""
from copy import deepcopy
import hashlib
import io
import json
import os

import pytest

from dnlab_runtime.libvirt_activation_commands import command_plan
from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_worker import serve,validate_command
from dnlab_runtime.libvirt_account_worker import validate_command as account_command
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_profile import request_profile


@pytest.fixture
def worker(tmp_path,request_profile):
    request=dict(deepcopy(request_profile),activation_policy='requisite-after-v1')
    source=dict(request=request,profile=render_profile(**request),context=dict(boot_id='synthetic',namespaces={'pid':{'device':1,'inode':2}}))
    path=tmp_path/'synthetic-elf';data=b'\x7fELFsynthetic activation executable; never executed';path.write_bytes(data);path.chmod(0o755)
    binary=dict(path='/usr/bin/systemctl',sha256=hashlib.sha256(data).hexdigest())
    commands=[command_plan(source,dict(spec=spec,nonce='a'*32),'activation',binary) for spec in steps(source['profile'])]
    fd=os.open(path,os.O_RDONLY)
    try:yield commands,fd,path
    finally:os.close(fd)


def frames(command,*,token='b'*32,release=None):
    request=dict(token=token,command=command)
    if release is None:release=dict(release=token,command_sha256=fingerprint(command))
    return io.StringIO(json.dumps(request)+'\n'+json.dumps(release)+'\n')


@pytest.mark.parametrize('index',range(4))
def test_fixed_command_executes_only_after_matching_release(worker,index):
    commands,fd,_=worker;command=commands[index];sink=io.StringIO();calls=[]
    class Executed(Exception):pass
    def execute(*args):calls.append(args);raise Executed
    with pytest.raises(Executed):serve(frames(command),sink,fd,execute=execute)
    assert calls==[(fd,command['argv'],command['environment'])]
    assert json.loads(sink.getvalue())==dict(ready='b'*32,command_sha256=fingerprint(command))
    with pytest.raises(Conflict):account_command(command)


@pytest.mark.parametrize('fault',['token','hash','eof','truncated'])
def test_missing_or_changed_release_never_executes(worker,fault):
    commands,fd,_=worker;command=commands[0];release=dict(release='b'*32,command_sha256=fingerprint(command))
    if fault=='token':release['release']='c'*32
    elif fault=='hash':release['command_sha256']='d'*64
    source=frames(command,release=release)
    if fault=='eof':source=io.StringIO(json.dumps(dict(token='b'*32,command=command))+'\n')
    elif fault=='truncated':source=io.StringIO(source.getvalue().rstrip('\n'))
    with pytest.raises(Conflict):serve(source,io.StringIO(),fd,execute=lambda *a:pytest.fail('must not execute'))


@pytest.mark.parametrize('fault',['environment','binary','stop','restart','force','foreign_unit'])
def test_arbitrary_command_is_rejected_before_ready(worker,fault):
    commands,fd,_=worker;command=deepcopy(commands[1])
    if fault=='environment':command['environment']['LD_PRELOAD']='foreign'
    elif fault=='binary':command['binary']['path']='/bin/sh'
    elif fault in ('stop','restart'):command['argv'][1]=fault
    elif fault=='force':command['argv'].insert(1,'--force')
    else:command['argv'][-1]='foreign.service'
    sink=io.StringIO()
    with pytest.raises(Conflict):serve(frames(command),sink,fd,execute=lambda *a:pytest.fail('must not execute'))
    assert sink.getvalue()==''


def test_binary_changed_after_ready_cannot_execute(worker):
    commands,fd,path=worker
    class Changed(io.StringIO):
        def flush(self):path.write_bytes(b'\x7fELFchanged')
    with pytest.raises(Conflict,match='executable content differs'):
        serve(frames(commands[0]),Changed(),fd,execute=lambda *a:pytest.fail('must not execute'))


def test_writable_binary_refused_before_ready(worker):
    commands,fd,path=worker;path.chmod(0o777);sink=io.StringIO()
    with pytest.raises(Conflict,match='immutable-mode'):
        serve(frames(commands[0]),sink,fd,execute=lambda *a:pytest.fail('must not execute'))
    assert sink.getvalue()==''
