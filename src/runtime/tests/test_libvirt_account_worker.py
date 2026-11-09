"""Memory streams, synthetic ELF bytes and mocked exec only; no process starts."""
from copy import deepcopy
import hashlib
import io
import json
import os

import pytest

from dnlab_runtime.libvirt_account_commands import command_plan
from dnlab_runtime.libvirt_account_worker import serve
from dnlab_runtime.libvirt_install import targets
from dnlab_runtime.libvirt_provisioning import account_request
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_profile import request_profile


@pytest.fixture(params=['group','account'])
def worker(tmp_path,request_profile,request):
    spec=next(i for i in targets(render_profile(**request_profile)) if i['kind']==request.param)
    value=account_request(dict(spec=spec,nonce='a'*32),'install')
    binary=tmp_path/'synthetic-elf';data=b'\x7fELFsynthetic executable bytes, never executed';binary.write_bytes(data);binary.chmod(0o755)
    role='groupadd' if request.param=='group' else 'useradd'
    command=command_plan(value,{role:dict(path='/usr/sbin/'+role,sha256=hashlib.sha256(data).hexdigest())})
    token='b'*32;ready=dict(token=token,command=command)
    release=dict(release=token,command_sha256=fingerprint(command))
    fd=os.open(binary,os.O_RDONLY)
    yield ready,release,fd,binary
    os.close(fd)


def stream(ready,release):return io.StringIO(json.dumps(ready)+'\n'+json.dumps(release)+'\n')


def test_exec_is_only_called_after_matching_release_on_the_same_fd(worker):
    ready,release,fd,_=worker;sink=io.StringIO();calls=[]
    class Executed(Exception):pass
    def execute(*args):calls.append(args);raise Executed
    with pytest.raises(Executed):serve(stream(ready,release),sink,fd,execute=execute)
    assert calls==[(fd,ready['command']['argv'],ready['command']['environment'])]
    assert json.loads(sink.getvalue())==dict(ready=ready['token'],command_sha256=fingerprint(ready['command']))


@pytest.mark.parametrize('fault',['token','hash','eof','truncated'])
def test_no_release_or_changed_release_never_executes(worker,fault):
    ready,release,fd,_=worker
    if fault=='token':release['release']='c'*32
    elif fault=='hash':release['command_sha256']='d'*64
    source=stream(ready,release)
    if fault=='eof':source=io.StringIO(json.dumps(ready)+'\n')
    elif fault=='truncated':source=io.StringIO(json.dumps(ready)+'\n'+json.dumps(release))
    with pytest.raises(Conflict):serve(source,io.StringIO(),fd,execute=lambda *a:pytest.fail('must not exec'))


@pytest.mark.parametrize('fault',['environment','extra-option','binary','uid-or-gid','name'])
def test_unqualified_command_is_rejected_before_ready(worker,fault):
    ready,release,fd,_=worker;command=ready['command']
    if fault=='environment':command['environment']['LD_PRELOAD']='foreign'
    elif fault=='extra-option':command['argv'].insert(1,'--force')
    elif fault=='binary':command['binary']['path']='/bin/sh'
    elif fault=='uid-or-gid':command['argv'][3]='0'
    else:command['argv'][-1]='root'
    sink=io.StringIO()
    with pytest.raises(Conflict):serve(stream(ready,release),sink,fd,execute=lambda *a:pytest.fail('must not exec'))
    assert sink.getvalue()==''


def test_changed_binary_after_ready_is_rejected(worker):
    ready,release,fd,path=worker
    class Sink(io.StringIO):
        def flush(self):path.write_bytes(b'\x7fELFchanged')
    with pytest.raises(Conflict,match='executable content differs'):
        serve(stream(ready,release),Sink(),fd,execute=lambda *a:pytest.fail('must not exec'))


def test_writable_binary_is_rejected_before_ready(worker):
    ready,release,fd,path=worker;path.chmod(0o777);sink=io.StringIO()
    with pytest.raises(Conflict,match='immutable-mode'):
        serve(stream(ready,release),sink,fd,execute=lambda *a:pytest.fail('must not exec'))
    assert sink.getvalue()==''
