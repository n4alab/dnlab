"""Synthetic procfs files; pidfd and poll never address a real process."""
from copy import deepcopy
import hashlib
import os
import select

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.qemu_process import PinnedQEMUProcess, stat_start
from test_libvirt_observer import observer, template, instance


@pytest.fixture
def process(tmp_path, observer):
    _, birth, _, _ = observer
    proc = tmp_path/'proc'; root = proc/'1234'
    (root/'ns').mkdir(parents=True)
    boot = proc/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_text('synthetic-boot\n')
    original_stat = b'1234 (qemu (VM) worker) S ' + b'0 '*18 + b'5678\n'
    (root/'stat').write_bytes(original_stat)
    (root/'status').write_text('Name:\tqemu\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n')
    command = b'qemu-system-x86_64\0-uuid\0' + birth['uuid'].encode() + b'\0'
    (root/'cmdline').write_bytes(command)
    binary = tmp_path/'qemu';binary.write_bytes(b'synthetic executable, never run')
    (root/'exe').symlink_to(binary)
    spaces = {}
    for name in ('pid','mnt','net','user'):
        path=root/'ns'/name;path.write_bytes(b'namespace marker')
        info=path.stat();spaces[name]={'device':info.st_dev,'inode':info.st_ino}
    original = dict(boot_id='synthetic-boot',pid=1234,start_ticks=5678,
                    executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    record = dict(birth=birth,process=original,uid=1001,gid=1002,
                  cmdline_sha256=hashlib.sha256(command).hexdigest(),namespaces=spaces)
    state={'events':[],'fds':[],'calls':[],'pid_namespace':deepcopy(spaces['pid'])}
    inert = tmp_path/'inert-pidfd';inert.write_bytes(b'not a real pidfd')
    def pidfd_open(pid, flags):
        assert (pid,flags)==(1234,0)
        fd=os.open(inert,os.O_RDONLY);state['fds'].append(fd);return fd
    class Poll:
        def register(self,fd,flags):state['calls'].append((fd,flags))
        def poll(self,timeout):assert timeout==0;return list(state['events'])
    provider=PinnedQEMUProcess(record,proc_root=proc,pidfd_open=pidfd_open,poll_factory=Poll,
                              pid_namespace=lambda:deepcopy(state['pid_namespace']))
    return provider,record,state,root,binary,boot,observer


def closed(state):
    for fd in state['fds']:
        with pytest.raises(OSError):os.fstat(fd)


def test_original_process_is_pinned_and_readonly_without_adoption(process):
    provider,record,state,root,_,_,_=process
    before={path.name:path.read_bytes() for path in root.iterdir() if path.is_file()}
    with provider.capture(record['birth']) as proof:
        assert proof==record['process']
        os.fstat(state['fds'][-1])
        proof['pid']=999
    assert provider.record==record
    assert {path.name:path.read_bytes() for path in root.iterdir() if path.is_file()}==before
    closed(state)


@pytest.mark.parametrize('fault',['ticks','zombie','uid','gid','uuid','command','executable','namespace','boot'])
@pytest.mark.parametrize('when',['before','during'])
def test_changed_identity_is_refused_and_original_record_retained(process,fault,when):
    provider,record,state,root,binary,boot,_=process
    def change():
        if fault=='ticks':(root/'stat').write_bytes((root/'stat').read_bytes().replace(b'5678',b'5679'))
        elif fault=='zombie':(root/'stat').write_bytes((root/'stat').read_bytes().replace(b') S ',b') Z '))
        elif fault in ('uid','gid'):
            path=root/'status';path.write_text(path.read_text().replace('1001' if fault=='uid' else '1002','0'))
        elif fault=='uuid':
            path=root/'cmdline';path.write_bytes(path.read_bytes().replace(record['birth']['uuid'].encode(),b'foreign'))
        elif fault=='command':
            path=root/'cmdline';path.write_bytes(path.read_bytes()+b'-incoming\0defer\0')
        elif fault=='executable':binary.write_bytes(b'replacement executable')
        elif fault=='namespace':
            path=root/'ns/net';path.rename(root/'ns/original-net');path.write_bytes(b'foreign namespace')
        else:boot.write_text('new-boot\n')
    with pytest.raises(Conflict):
        if when=='before':change()
        with provider.capture(record['birth']):
            if when=='during':change()
    assert provider.record==record
    closed(state)


@pytest.mark.parametrize('flags',[select.POLLIN,select.POLLHUP,select.POLLERR,select.POLLNVAL])
def test_pidfd_exit_and_error_events_never_prove_a_live_process(process,flags):
    provider,record,state,_,_,_,_=process
    state['events']=[(999,flags)]
    with pytest.raises(Conflict,match='pidfd'):
        with provider.capture(record['birth']):pytest.fail('unqualified pidfd entered')
    closed(state)


def test_replaced_proc_directory_after_first_observation_is_refused(process):
    provider,record,state,root,_,_,_=process
    with pytest.raises(Conflict,match='directory replaced'):
        with provider.capture(record['birth']):
            root.rename(root.parent/'original-1234');root.mkdir()
    closed(state)


def test_observer_uses_pinned_process_around_domain_configuration_reads(process):
    provider,record,state,_,_,_,observer=process
    value,birth,observed,calls=observer
    value.reference['process_sha256']=fingerprint(record['process'])
    value.process=provider
    assert value(birth)['process']==record['process']
    assert calls.count(('XMLDesc',0))==calls.count(('XMLDesc',2))==2
    closed(state)


def test_foreign_birth_is_rejected_before_pidfd_open(process):
    provider,record,state,_,_,_,_=process
    foreign=deepcopy(record['birth']);foreign['nonce']='a'*32
    with pytest.raises(Conflict,match='birth'):
        with provider.capture(foreign):pytest.fail('foreign birth entered')
    assert not state['fds']


def test_foreign_caller_pid_namespace_is_rejected_before_pidfd_open(process):
    provider,record,state,_,_,_,_=process
    state['pid_namespace']['inode']+=1
    with pytest.raises(Conflict,match='PID namespace'):
        with provider.capture(record['birth']):pytest.fail('foreign namespace entered')
    assert not state['fds']


def test_caller_namespace_is_rechecked_after_observer_body(process):
    provider,record,state,_,_,_,_=process
    with pytest.raises(Conflict,match='PID namespace'):
        with provider.capture(record['birth']):state['pid_namespace']['inode']+=1
    closed(state)


@pytest.mark.parametrize('raw',[b'',b'1234 (qemu) S 0',b'1234 qemu S '+b'0 '*20])
def test_malformed_stat_is_not_a_process_proof(raw):
    with pytest.raises(Conflict):stat_start(raw,1234)
