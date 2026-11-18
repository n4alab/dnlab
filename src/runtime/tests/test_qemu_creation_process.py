"""CPU TID -> leader correlation on synthetic proc files and inert pidfds."""
from copy import deepcopy
from types import SimpleNamespace
import os
import select

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.qemu_creation_process import QEMUCreationProcess
from test_qemu_process import process, observer, template, instance, closed


@pytest.fixture
def creation(process):
    provider,record,state,leader,binary,boot,_=process
    proc=leader.parent
    status=leader/'status';status.write_text('Pid:\t1234\nTgid:\t1234\n'+status.read_text())
    caller=proc/'self';caller.mkdir();(caller/'status').write_text('Pid:\t77\nTgid:\t77\nNSpid:\t77\n')
    tasks={}
    for index,tid in enumerate((901,902)):
        text=f'Pid:\t{tid}\nTgid:\t1234\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n'
        raw=f'{tid} (CPU {index}/KVM) S '.encode()+b'0 '*18+str(5680+index).encode()+b'\n'
        for root in (proc/str(tid),leader/'task'/str(tid)):
            (root/'ns').mkdir(parents=True)
            (root/'status').write_text(text);(root/'stat').write_bytes(raw)
            for name in ('pid','mnt','net','user'):(root/'ns'/name).symlink_to(leader/'ns'/name)
        tasks[tid]=proc/str(tid)
    identity=proc.stat()
    policy=dict(uid=1001,gid=1002,boot_id=record['process']['boot_id'],executable_sha256=record['process']['executable_sha256'],
                proc_identity=dict(device=identity.st_dev,inode=identity.st_ino),minimum_start_ticks=5670,
                shared_namespaces={key:deepcopy(record['namespaces'][key]) for key in ('pid','net','user')})
    request=dict(birth=deepcopy(record['birth']),expected_cpus=2)
    receipt=dict(id='f'*32,birth=deepcopy(record['birth']),request=deepcopy(request),phase='completed',
                 cpus=[dict(index=0,thread_id=901),dict(index=1,thread_id=902)])
    reads=[];control=dict(after=None)
    def read(expected):
        assert expected==request;reads.append(True)
        if len(reads)==2 and control['after']:control['after']()
        return deepcopy(receipt)
    value=QEMUCreationProcess(SimpleNamespace(read_completed=read),request,policy,proc_root=proc,
                              pidfd_open=provider.pidfd_open,poll_factory=provider.poll_factory,
                              pid_namespace=provider.pid_namespace,process_id=lambda:77)
    return SimpleNamespace(value=value,record=record,state=state,leader=leader,tasks=tasks,binary=binary,
                           boot=boot,request=request,receipt=receipt,policy=policy,reads=reads,control=control)


def test_all_vcpus_correlate_to_original_nonroot_leader_without_query_or_signal(creation):
    e=creation;before={path:path.read_bytes() for path in e.leader.parent.rglob('*') if path.is_file()}
    result=e.value.correlate()
    assert result['record']==e.record and len(result['tasks'])==2
    assert {task['tgid'] for task in result['tasks']}=={1234}
    assert {task['thread_id'] for task in result['tasks']}=={901,902}
    assert len(e.reads)==2 and len(e.state['fds'])==1
    assert {path:path.read_bytes() for path in before}==before
    closed(e.state)


@pytest.mark.parametrize('fault',['tgid','member','root_uid','uuid','executable','old_leader','namespace','proc_mount','caller','proc_view','missing_task'])
def test_foreign_or_inconsistent_kernel_mapping_never_returns_creation_record(creation,fault):
    e=creation
    if fault=='tgid':
        path=e.tasks[902]/'status';path.write_text(path.read_text().replace('Tgid:\t1234','Tgid:\t9999'))
    elif fault=='member':
        path=e.leader/'task/901/stat';path.write_bytes(path.read_bytes().replace(b'5680',b'5689'))
    elif fault=='root_uid':
        path=e.tasks[901]/'status';path.write_text(path.read_text().replace('1001','0'))
    elif fault=='uuid':
        path=e.leader/'cmdline';path.write_bytes(path.read_bytes().replace(e.record['birth']['uuid'].encode(),b'foreign'))
    elif fault=='executable':e.binary.write_bytes(b'foreign QEMU executable')
    elif fault=='old_leader':e.value.policy['minimum_start_ticks']=5679
    elif fault=='namespace':
        path=e.tasks[901]/'ns/net';path.unlink();path.write_bytes(b'foreign namespace')
    elif fault=='proc_mount':e.value.policy['proc_identity']['inode']+=1
    elif fault=='caller':e.state['pid_namespace']['inode']+=1
    elif fault=='proc_view':
        path=e.leader.parent/'self/status';path.write_text(path.read_text().replace('NSpid:\t77','NSpid:\t999 77'))
    else:(e.leader/'task/901/stat').unlink()
    with pytest.raises((RuntimeErrorBase,OSError)):e.value.correlate()
    closed(e.state)


@pytest.mark.parametrize('flags',[select.POLLIN,select.POLLERR,select.POLLHUP,select.POLLNVAL,select.POLLIN|select.POLLERR])
def test_pidfd_exit_or_error_is_never_a_live_creation_proof(creation,flags):
    e=creation;e.state['events']=[(e.state['fds'][0] if e.state['fds'] else 999,flags)]
    with pytest.raises(RuntimeErrorBase,match='pidfd'):e.value.correlate()
    closed(e.state)


@pytest.mark.parametrize('fault',['task','exe','pid_directory'])
def test_identity_is_rechecked_after_final_creation_receipt_observation(creation,fault):
    e=creation
    def changed():
        if fault=='task':
            path=e.tasks[901]/'stat';path.write_bytes(path.read_bytes().replace(b'5680',b'5689'))
        elif fault=='exe':e.binary.write_bytes(b'replaced while observing the original domain')
        else:
            e.leader.rename(e.leader.parent/'previous-leader');e.leader.mkdir()
    e.control['after']=changed
    with pytest.raises((RuntimeErrorBase,OSError)):e.value.correlate()
    closed(e.state)
