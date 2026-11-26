"""Original gate retirement with synthetic procfs and pidfd providers."""
from copy import deepcopy
import os
import select
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_admin_owner import GateOwnerRetirement, idle_tasks


@pytest.fixture
def task_tree(tmp_path):
    root=tmp_path/'42/task/42';root.mkdir(parents=True)
    (root/'children').write_text('')
    (root/'status').write_text('SigCgt:\t00000000\nSigIgn:\t00000001\n')
    (root/'syscall').write_text('0 0x0 0x100 0x200')
    return tmp_path,root


def test_only_idle_original_terminal_without_children_is_accepted(task_tree):
    proc,_=task_tree
    assert idle_tasks(42,proc_root=proc)==dict(tids=[42],children_absent=True,main_reading_stdin=True,default_term=True)


@pytest.mark.parametrize('name,content',[('children','999'),('status','SigCgt: 4000\nSigIgn: 0'),
    ('status','SigCgt: 0\nSigIgn: 4000'),('syscall','1 0x0'),('syscall','0 0x1')])
def test_child_handler_or_active_main_refuses_retirement(task_tree,name,content):
    proc,root=task_tree;(root/name).write_text(content)
    with pytest.raises(TemplateError):idle_tasks(42,proc_root=proc)


@pytest.fixture
def owner():
    snapshot=dict(record=dict(pid=42,boot_id='boot'),namespaces={})
    epoch=dict(snapshot=snapshot,profile=dict(host_id='master',sources_sha256='a'*64))
    state=dict(snapshot=deepcopy(snapshot),exited=False,events=None,signals=[],checks=0)
    class Poll:
        def register(self,fd,events):self.fd=fd;assert events==select.POLLIN
        def poll(self,timeout):
            if state['events'] is not None:return [(self.fd,state['events'])]
            return [(self.fd,select.POLLIN)] if state['exited'] else []
    def send(fd,number,info,flags):
        state['signals'].append((number,info,flags));state['exited']=True
    reader=SimpleNamespace(read_process=lambda pid:deepcopy(state['snapshot']))
    driver=GateOwnerRetirement(epoch,reader=reader,verify_sources=lambda:'a'*64,
        read_context=lambda:dict(host_id='master',boot_id='boot',namespaces={}),tasks=lambda pid:dict(idle=True),
        pidfd_open=lambda pid,flags:os.open('/dev/null',os.O_RDONLY),poll_factory=Poll,send_signal=send)
    yield driver,dict(owner_sha256=fingerprint(snapshot)),state
    driver.close()


def test_single_pinned_term_and_verified_exit_only(owner):
    driver,request,state=owner
    result=driver.terminate(request,check=lambda:None)
    assert result==dict(owner_sha256=request['owner_sha256'],pidfd_exit_verified=True,term_count=1,force_used=False)
    assert state['signals']==[(15,None,0)]
    with pytest.raises(TemplateError,match='single TERM'):driver.terminate(request,check=lambda:None)
    assert len(state['signals'])==1


@pytest.mark.parametrize('fault',['process','preflight','pidfd'])
def test_conflicts_prevent_signal(owner,fault):
    driver,request,state=owner
    if fault=='process':state['snapshot']['record']['pid']=99
    elif fault=='pidfd':state['events']=select.POLLERR
    def check():
        if fault=='preflight':raise TemplateError('original preflight changed')
    with pytest.raises(TemplateError):driver.terminate(request,check=check)
    assert state['signals']==[]
