"""Real command/worker/process journals with fake Popen, procfs and pidfd."""
from contextlib import contextmanager
from copy import deepcopy
import os
import select

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_commands import ActivationCommands
from dnlab_runtime.libvirt_activation_runner import ActivationProcessRunner,ActivationWorkerObserver
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_account_runner import runner,request_profile
from test_libvirt_account_process import observed


@pytest.fixture
def pipeline(observed,runner,request_profile):
    original,_,_,kernel,root,boot,_,_,tmp=observed
    base,account,parent,_=runner
    provider=ActivationWorkerObserver(base.journal,proc_root=original.proc_root,pidfd_open=original.pidfd_open,
        poll_factory=original.poll_factory,pid_namespace=original.pid_namespace)
    @contextmanager
    def opener(path):
        with base.opener('/usr/sbin/useradd' if path=='/usr/bin/systemctl' else path) as fd:yield fd
    def spawn(argv,**options):
        child=base.spawn(argv,**options);child.args=deepcopy(argv);child.poll=lambda:kernel['status']
        (root/'cmdline').write_bytes(b'\0'.join(os.fsencode(v) for v in argv)+b'\0')
        close=child.stdin.close
        def released():
            close()
            (root/'exe').unlink();(root/'exe').symlink_to(tmp/'useradd')
            (root/'cmdline').write_bytes(b'/usr/bin/systemctl\0start\0--\0dnlab-virtlogd.service\0')
            kernel.update(status=0,events=[('original',select.POLLIN|select.POLLHUP)])
        child.stdin.close=released;return child
    transport=ActivationProcessRunner(base.journal,profile=base.profile,observer=provider,spawn=spawn,opener=opener,
        read_ready=base.read_ready,read_output=base.read_output)
    namespaces={}
    for name in ('pid','mnt','net','user'):
        info=(root/'ns'/name).stat();namespaces[name]=dict(device=info.st_dev,inode=info.st_ino)
    request=dict(deepcopy(request_profile),activation_policy='requisite-after-v1')
    installation=dict(id='synthetic-installation',phase='installed_not_started',request=request,profile=render_profile(**request),
        context=dict(host_id='master',boot_id=boot.read_text().strip(),namespaces=namespaces))
    value=dict(id='activation',installation=installation,installation_sha256=fingerprint(installation),
        items=[dict(spec=spec,nonce=str(index+1)*32,phase='prepared',proof=None) for index,spec in enumerate(steps(installation['profile']))])
    item=value['items'][1];item['phase']='requested'
    def preflight(command):return dict(qualified=True,command_sha256=fingerprint(command),installation_sha256=value['installation_sha256'],
        context_sha256=fingerprint(installation['context']),inputs_sha256=fingerprint(installation['profile']['files']))
    helper=ActivationCommands(base.journal,binary=dict(path='/usr/bin/systemctl',sha256=account['binary']['sha256']),
        runner=transport,activation_reader=lambda operation:deepcopy(value),preflight=preflight)
    try:yield helper,item,value['id'],transport,provider,parent,kernel
    finally:provider.close()


def test_composed_original_worker_exit_and_readonly_proof(pipeline):
    helper,item,operation,transport,provider,parent,kernel=pipeline
    proof=helper.execute(item,operation)
    assert helper.original_completion(item,operation)==proof and helper.completion(item,operation)==proof
    assert helper._read(item,operation)['phase']=='completed'
    assert len(parent['spawns'])==1 and not transport.live and not provider.live
    assert parent['process'].stdout.closed and parent['process'].stderr.closed
    for fd in kernel['fds']:
        with pytest.raises(OSError):os.fstat(fd)
    assert helper.journal.db.execute('SELECT count(*) FROM libvirt_activation_commands').fetchone()[0]==1
    assert helper.journal.db.execute('SELECT count(*) FROM libvirt_activation_workers').fetchone()[0]==1
    assert helper.journal.db.execute('SELECT count(*) FROM libvirt_activation_processes').fetchone()[0]==1


def test_composed_release_reply_lost_recovers_same_exit_without_second_spawn(pipeline,monkeypatch):
    helper,item,operation,transport,_,parent,_=pipeline;save=transport._save
    def lost(value):
        save(value)
        if value['phase']=='released':raise OSError('synthetic composed release reply lost')
    monkeypatch.setattr(transport,'_save',lost)
    with pytest.raises(OSError):helper.execute(item,operation)
    assert helper._read(item,operation)['phase']=='release_requested'
    proof=helper.recover(item,operation)
    assert helper.original_completion(item,operation)==proof and len(parent['spawns'])==1
    assert len(parent['process'].stdin.getvalue().splitlines())==2


def test_composed_pending_output_keeps_original_waiter_and_release(pipeline):
    helper,item,operation,transport,_,parent,_=pipeline;parent['output_pending']=True
    with pytest.raises(Conflict,match='pending'):helper.execute(item,operation)
    assert helper.original_completion(item,operation) is None and len(parent['spawns'])==1
    parent['output_pending']=False
    assert helper.recover(item,operation)['exit_code']==0 and len(parent['spawns'])==1
    assert not transport.live
