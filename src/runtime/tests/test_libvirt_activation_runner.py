"""Fake child and synthetic procfs only; no real process or service starts."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import os
import select

import pytest

from dnlab_runtime.libvirt_activation_commands import ENVIRONMENT
from dnlab_runtime.libvirt_activation_runner import ActivationProcessRunner,ActivationWorkerObserver
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_account_runner import runner,request_profile
from test_libvirt_account_process import observed


@pytest.fixture
def activation_runner(runner):
    base,account,state,_=runner
    command=dict(request_sha256='a'*64,binary=dict(path='/usr/bin/systemctl',sha256=account['binary']['sha256']),
        argv=['/usr/bin/systemctl','start','--','dnlab-virtlogd.service'],environment=deepcopy(ENVIRONMENT))
    @contextmanager
    def opener(path):
        with base.opener('/usr/sbin/useradd' if path=='/usr/bin/systemctl' else path) as fd:yield fd
    def make():
        return ActivationProcessRunner(base.journal,profile=base.profile,observer=base.observer,
            spawn=base.spawn,opener=opener,read_ready=base.read_ready,read_output=base.read_output)
    return make(),command,state,make,base,account


def test_separate_journal_and_unchanged_account_validator(activation_runner):
    driver,command,state,make,base,account=activation_runner
    with pytest.raises(Conflict):base.arm(command)
    with pytest.raises(Conflict):driver.arm(account)
    reference=driver.arm(command);driver.release(reference);outcome=driver.outcome(reference)
    assert outcome['exit_code']==0 and make().completed_outcome(reference)==outcome
    assert len(state['spawns'])==1
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_activation_workers').fetchone()[0]==1
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_account_workers').fetchone()[0]==0


def test_release_reply_loss_never_releases_again(activation_runner,monkeypatch):
    driver,command,state,_,_,_=activation_runner;reference=driver.arm(command);save=driver._save
    def lost(value):
        save(value)
        if value['phase']=='released':raise OSError('synthetic activation release reply lost')
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError):driver.release(reference)
    assert driver.outcome(reference)['exit_code']==0
    with pytest.raises(Conflict,match='not repeated'):driver.release(reference)
    assert len(state['spawns'])==1 and len(state['process'].stdin.getvalue().splitlines())==2


def test_missing_waiter_cannot_be_adopted_from_pid(activation_runner):
    driver,command,state,make,_,_=activation_runner;reference=driver.arm(command);driver.release(reference)
    with pytest.raises(Conflict,match='waiter unavailable'):make().outcome(reference)
    assert len(state['spawns'])==1


@pytest.fixture
def activation_process(observed):
    base,process,_,state,root,boot,_,_,tmp=observed
    target=tmp/'systemctl';data=b'\x7fELFfake activation target';target.write_bytes(data);target.chmod(0o755)
    command=dict(request_sha256='a'*64,binary=dict(path='/usr/bin/systemctl',sha256=hashlib.sha256(data).hexdigest()),
        argv=['/usr/bin/systemctl','start','--','dnlab-virtlogd.service'],environment=deepcopy(ENVIRONMENT))
    def make():return ActivationWorkerObserver(base.journal,proc_root=base.proc_root,pidfd_open=base.pidfd_open,
        poll_factory=base.poll_factory,pid_namespace=base.pid_namespace)
    provider=make();record=provider.capture(process)
    reference=dict(token='a'*32,command_sha256=fingerprint(command),process_record=record)
    provider.bind(reference,process,command)
    def execute(argv=None):
        (root/'exe').unlink();(root/'exe').symlink_to(target)
        (root/'cmdline').write_bytes(b'\0'.join(os.fsencode(v) for v in (command['argv'] if argv is None else argv))+b'\0')
    try:yield provider,process,command,state,root,reference,make,execute
    finally:provider.close()


def test_original_exact_exec_and_durable_exit_on_separate_process_table(activation_process):
    provider,process,command,state,_,reference,make,execute=activation_process
    assert provider.verify(reference,process,command,'armed')
    execute();assert provider.verify(reference,process,command,'released')
    state.update(status=0,events=[('original',select.POLLIN|select.POLLHUP)])
    assert provider.exit(process,reference);provider.retire(reference)
    reopened=make()
    try:assert reopened.verify(reference,None,command,'completed')
    finally:reopened.close()
    assert provider.journal.db.execute('SELECT count(*) FROM libvirt_activation_processes').fetchone()[0]==1
    assert provider.journal.db.execute('SELECT count(*) FROM libvirt_account_processes').fetchone()[0]==0


@pytest.mark.parametrize('fault',['argv','ticks','credentials','namespace'])
def test_target_process_substitution_refused(activation_process,fault):
    provider,process,command,_,root,reference,_,execute=activation_process
    execute()
    if fault=='argv':(root/'cmdline').write_bytes(b'/usr/bin/systemctl\0stop\0foreign.service\0')
    elif fault=='ticks':(root/'stat').write_bytes(b'123 (systemctl) S '+b'0 '*18+b'457\n')
    elif fault=='credentials':(root/'status').write_bytes(b'Uid:\t0\t1\t0\t0\nGid:\t0\t0\t0\t0\n')
    else:
        path=root/'ns/net';path.rename(root/'ns/old-net');path.write_bytes(b'foreign namespace')
    with pytest.raises(Conflict):provider.verify(reference,process,command,'released')
    assert provider._read(reference)['exit'] is None
