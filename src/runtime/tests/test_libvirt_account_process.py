"""Synthetic procfs, fake waiter/pidfd/poll; never inspect or start host processes."""
from copy import deepcopy
import os
import select

import pytest

from dnlab_runtime.libvirt_account_process import AccountWorkerObserver
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_account_runner import runner,request_profile


@pytest.fixture
def observed(tmp_path,runner):
    driver,command,_,_=runner
    proc=tmp_path/'proc';root=proc/'123'
    (root/'ns').mkdir(parents=True)
    boot=proc/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_text('synthetic-boot\n')
    (root/'stat').write_bytes(b'123 (blocked worker) S '+b'0 '*18+b'456\n')
    (root/'status').write_bytes(b'Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
    binary=tmp_path/'python';(root/'exe').symlink_to(binary)
    spaces={}
    for name in ('pid','mnt','net','user'):
        path=root/'ns'/name;path.write_bytes(b'synthetic namespace')
        info=path.stat();spaces[name]=dict(device=info.st_dev,inode=info.st_ino)
    state=dict(status=None,events=[],fds=[],pid_namespace=deepcopy(spaces['pid']))
    class Process:
        pid=123
        args=['/qualified/python','-B','-I','-S','/qualified/worker']
        def poll(self):return state['status']
    process=Process()
    (root/'cmdline').write_bytes(b'\0'.join(v.encode() for v in process.args)+b'\0')
    inert=tmp_path/'inert';inert.write_bytes(b'not a pidfd')
    def pidfd_open(pid,flags):
        assert (pid,flags)==(123,0)
        fd=os.open(inert,os.O_RDONLY);state['fds'].append(fd);return fd
    class Poll:
        def register(self,fd,flags):self.fd=fd;assert flags==select.POLLIN
        def poll(self,timeout):
            assert timeout==0
            return [(self.fd if fd=='original' else fd,mask) for fd,mask in state['events']]
    def make():return AccountWorkerObserver(driver.journal,proc_root=proc,pidfd_open=pidfd_open,
        poll_factory=Poll,pid_namespace=lambda:deepcopy(state['pid_namespace']))
    provider=make()
    def bind():
        record=provider.capture(process)
        reference=dict(token='a'*32,command_sha256=fingerprint(command),process_record=record)
        provider.bind(reference,process,command)
        return reference
    yield provider,process,command,state,root,boot,bind,make,tmp_path
    provider.close()


def test_original_interpreter_target_exec_and_durable_exit(observed):
    provider,process,command,state,root,_,bind,make,tmp=observed
    reference=bind()
    assert provider.verify(reference,process,command,'armed') is True
    (root/'exe').unlink();(root/'exe').symlink_to(tmp/'useradd')
    (root/'cmdline').write_bytes(b'useradd\0scrubbed password\0')
    assert provider.verify(reference,process,command,'released') is True
    with pytest.raises(Conflict):provider.verify(reference,process,command,'armed')
    state['status']=0;state['events']=[('original',select.POLLIN|select.POLLHUP)]
    assert provider.exit(process,reference)
    provider.retire(reference)
    for fd in state['fds']:
        with pytest.raises(OSError):os.fstat(fd)
    reopened=make()
    try:assert reopened.verify(reference,None,command,'completed')
    finally:reopened.close()


@pytest.mark.parametrize('fault',['ticks','uid','gid','command','executable','namespace','boot','directory','caller_namespace'])
def test_substitutions_rejected_with_original_binding_retained(observed,fault):
    provider,process,command,state,root,boot,bind,_,tmp=observed
    reference=bind();original=provider._read(reference)
    if fault=='ticks':(root/'stat').write_bytes(b'123 (worker) S '+b'0 '*18+b'457\n')
    elif fault in ('uid','gid'):
        path=root/'status';key=b'Uid' if fault=='uid' else b'Gid'
        path.write_bytes(path.read_bytes().replace(key+b':\t0',key+b':\t1'))
    elif fault=='command':(root/'cmdline').write_bytes(b'foreign\0')
    elif fault=='executable':(tmp/'python').write_bytes(b'replacement executable')
    elif fault=='namespace':
        path=root/'ns/net';path.rename(root/'ns/old-net');path.write_bytes(b'foreign')
    elif fault=='boot':boot.write_text('another-boot\n')
    elif fault=='directory':root.rename(root.parent/'old-123');root.mkdir()
    else:state['pid_namespace']['inode']+=1
    with pytest.raises((Conflict,OSError)):provider.verify(reference,process,command,'armed')
    # Binding is never rewritten while observing a conflict.
    with provider.journal.lock:
        row=provider.journal.db.execute('SELECT payload FROM libvirt_account_processes').fetchone()
    from dnlab_runtime.manifest import canonical
    assert row['payload']==canonical(original)


def test_same_pid_new_waiter_is_not_adopted(observed):
    provider,process,command,_,_,_,bind,make,_=observed;reference=bind()
    replacement=type(process)()
    with pytest.raises(Conflict,match='waiter unavailable'):provider.verify(reference,replacement,command,'released')
    reopened=make()
    try:
        with pytest.raises(Conflict,match='waiter unavailable'):reopened.verify(reference,process,command,'released')
    finally:reopened.close()


@pytest.mark.parametrize('mask',[select.POLLERR,select.POLLNVAL,select.POLLIN|select.POLLERR,select.POLLOUT,0])
def test_error_or_ambiguous_pidfd_never_proves_exit(observed,mask):
    provider,process,_,state,_,_,bind,_,_=observed;reference=bind()
    state['status']=0;state['events']=[('original',mask)]
    with pytest.raises(Conflict,match='pidfd'):provider.exit(process,reference)
    assert provider._read(reference)['exit'] is None


@pytest.mark.parametrize('status,events',[(None,[('original',select.POLLIN)]),(0,[]),(0,[(999,select.POLLIN)])])
def test_exit_requires_both_original_waiter_and_original_pidfd(observed,status,events):
    provider,process,_,state,_,_,bind,_,_=observed;reference=bind()
    state.update(status=status,events=events)
    with pytest.raises(Conflict):provider.exit(process,reference)
    assert provider._read(reference)['exit'] is None


def test_capture_failure_closes_only_owned_pidfd(observed):
    provider,process,_,state,root,_,_,_,_=observed
    (root/'cmdline').write_bytes(b'foreign\0')
    with pytest.raises(Conflict,match='Popen command'):provider.capture(process)
    assert len(state['fds'])==1
    with pytest.raises(OSError):os.fstat(state['fds'][0])
    assert not provider.live


def test_namespace_conflict_before_pidfd_open(observed):
    provider,process,_,state,_,_,_,_,_=observed;state['pid_namespace']['inode']+=1
    with pytest.raises(Conflict,match='PID namespace'):provider.capture(process)
    assert state['fds']==[]


def test_binding_is_immutable_and_exit_not_inferred_from_absence(observed):
    provider,process,command,_,_,_,bind,_,_=observed;reference=bind()
    with pytest.raises(Conflict,match='captured helper'):provider.bind(reference,process,command)
    with pytest.raises(Conflict,match='exit receipt'):provider.retire(reference)
    provider.close()
    with pytest.raises(Conflict,match='waiter unavailable'):provider.verify(reference,process,command,'released')


def test_exit_after_release_can_be_observed_without_proc_pid_reopening(observed):
    provider,process,command,state,root,_,bind,_,_=observed;reference=bind()
    root.rename(root.parent/'old-123')
    state.update(status=0,events=[('original',select.POLLHUP)])
    assert provider.verify(reference,process,command,'released')
    assert provider._read(reference)['exit']['exit_code']==0


@pytest.fixture
def composed(observed,runner):
    """The real parent and observer share one journal; only the child is fake."""
    provider,_,command,kernel,root,boot,_,make_observer,tmp=observed
    driver,_,parent,make_runner=runner
    driver.observer=provider
    spawn=driver.spawn
    def start(argv,**options):
        child=spawn(argv,**options)
        child.args=deepcopy(argv)
        child.poll=lambda:kernel['status']
        (root/'cmdline').write_bytes(b'\0'.join(os.fsencode(v) for v in argv)+b'\0')
        close=child.stdin.close
        def released():
            close()
            # Simulate the same original PID exec followed by a zero exit.
            (root/'exe').unlink();(root/'exe').symlink_to(tmp/'useradd')
            (root/'cmdline').write_bytes(b'useradd\0scrubbed\0')
            kernel.update(status=0,events=[('original',select.POLLIN|select.POLLHUP)])
        child.stdin.close=released
        return child
    driver.spawn=start
    yield driver,command,parent,kernel,root,make_runner,make_observer


def test_parent_and_observer_commit_same_original_process_and_retire(composed):
    driver,command,parent,kernel,_,make_runner,make_observer=composed
    reference=driver.arm(command)
    assert driver.verify(reference,command)
    driver.release(reference)
    result=driver.outcome(reference)
    assert result['exit_code']==0 and result['reference']==reference
    assert driver.observer._read(reference)['exit']['process_record']==reference['process_record']
    assert not driver.live and not driver.observer.live
    assert parent['process'].stdout.closed and parent['process'].stderr.closed
    for fd in kernel['fds']:
        with pytest.raises(OSError):os.fstat(fd)
    reopened=make_runner();reopened.observer=make_observer()
    try:assert reopened.outcome(reference)==result
    finally:reopened.observer.close()
    assert len(parent['spawns'])==1


def test_parent_response_lost_after_release_uses_same_exit_receipt(composed,monkeypatch):
    driver,command,parent,_,_,_,_=composed;reference=driver.arm(command)
    save=driver._save
    def lost(value):
        save(value)
        if value['phase']=='released':raise OSError('synthetic release acknowledgement lost')
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError):driver.release(reference)
    assert driver.outcome(reference)['exit_code']==0
    assert len(parent['spawns'])==1
    assert len(parent['process'].stdin.getvalue().splitlines())==2


def test_parent_response_lost_after_outcome_commit_retires_on_replay(composed,monkeypatch):
    driver,command,parent,_,_,_,_=composed;reference=driver.arm(command);driver.release(reference)
    save=driver._save
    def lost(value):
        save(value)
        if value['phase']=='completed':raise OSError('synthetic outcome acknowledgement lost')
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError):driver.outcome(reference)
    assert driver._read(reference)['phase']=='completed' and driver.live
    assert driver.outcome(reference)['exit_code']==0
    assert not driver.live and not driver.observer.live and len(parent['spawns'])==1


def test_parent_keeps_original_pending_when_owned_waiter_is_lost(composed):
    driver,command,parent,_,_,make_runner,make_observer=composed
    reference=driver.arm(command);driver.release(reference)
    reopened=make_runner();reopened.observer=make_observer()
    try:
        with pytest.raises(Conflict,match='waiter unavailable'):reopened.outcome(reference)
    finally:reopened.observer.close()
    assert driver._read(reference)['phase']=='released' and len(parent['spawns'])==1
    assert driver.outcome(reference)['exit_code']==0


def test_parent_refuses_kernel_generation_change_at_release_checkpoint(composed,monkeypatch):
    driver,command,parent,kernel,root,_,_=composed;reference=driver.arm(command)
    save=driver._save
    def replaced(value):
        save(value)
        if value['phase']=='release_requested':
            (root/'stat').write_bytes(b'123 (foreign) S '+b'0 '*18+b'457\n')
    monkeypatch.setattr(driver,'_save',replaced)
    with pytest.raises(Conflict):driver.release(reference)
    assert len(parent['process'].stdin.getvalue().splitlines())==1
    assert driver._read(reference)['phase']=='release_requested' and kernel['status'] is None
