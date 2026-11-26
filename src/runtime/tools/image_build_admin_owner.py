"""Pin and retire only the original idle gate process, never a service daemon.

The caller holds the original journal execution lock and persists the TERM
intent before calling terminate. All event-loop threads die with this process;
any child, custom TERM handler or non-idle main thread refuses retirement.
"""
from copy import deepcopy
import os
from pathlib import Path
import select
import signal

from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import require


def idle_tasks(pid, *, proc_root='/proc'):
    root=Path(proc_root)/str(pid)/'task'
    before=sorted(os.listdir(root))
    require(1<=len(before)<=128 and all(name.isascii() and name.isdecimal() for name in before)
            and str(pid) in before, 'bounded original gate thread inventory required')
    for name in before:
        path=root/name
        require(not (path/'children').read_text().strip(), 'original gate has a child; separate qualification required')
    status={}
    for line in (root/str(pid)/'status').read_text().splitlines():
        key,sep,value=line.partition(':')
        if sep:
            require(key not in status, 'duplicate original gate process status')
            status[key]=value.strip()
    require(not (int(status['SigCgt'],16)|int(status['SigIgn'],16))&(1<<(signal.SIGTERM-1)),
            'original gate TERM disposition differs')
    call=(root/str(pid)/'syscall').read_text().split()
    # The qualified host is x86_64. syscall 0/read on fd 0 is the frozen
    # entry's synchronous terminal command loop, not a native action in flight.
    require(len(call)>=2 and call[0]=='0' and int(call[1],0)==0,
            'original gate main thread is not idle on its terminal')
    require(sorted(os.listdir(root))==before, 'original gate threads changed during observation')
    return dict(tids=[int(name) for name in before],children_absent=True,main_reading_stdin=True,default_term=True)


class GateOwnerRetirement:
    def __init__(self, epoch, *, reader, verify_sources, read_context, tasks=idle_tasks,
                 pidfd_open=os.pidfd_open, poll_factory=select.poll, send_signal=signal.pidfd_send_signal):
        self.epoch=deepcopy(epoch);self.reader,self.verify_sources,self.read_context,self.tasks=(
            reader,verify_sources,read_context,tasks)
        self.send_signal=send_signal;self.fd=None;self.sent=False
        self.check()
        self.fd=pidfd_open(epoch['snapshot']['record']['pid'],0)
        try:
            self.poll=poll_factory();self.poll.register(self.fd,select.POLLIN)
            require(not self.exited(), 'original gate already exited before pinning')
            self.check()
        except BaseException:
            self.close();raise

    def _context(self):
        snapshot=self.epoch['snapshot']
        return dict(host_id=self.epoch['profile']['host_id'],boot_id=snapshot['record']['boot_id'],
                    namespaces=snapshot['namespaces'])

    def check(self):
        require(self.read_context()==self._context()
                and self.verify_sources()==self.epoch['profile']['sources_sha256'],
                'original gate source/context differs')
        pid=self.epoch['snapshot']['record']['pid']
        require(self.reader.read_process(pid)==self.epoch['snapshot'], 'original gate process replaced')
        proof=self.tasks(pid)
        require(self.reader.read_process(pid)==self.epoch['snapshot']
                and self.read_context()==self._context(), 'original gate changed during idle observation')
        if self.fd is not None:require(not self.exited(), 'original gate exited during idle observation')
        return proof

    def exited(self, *, timeout=0):
        events=self.poll.poll(timeout)
        if not events:return False
        require(len(events)==1 and events[0][0]==self.fd and type(events[0][1]) is int
                and events[0][1] and not events[0][1]&~(select.POLLIN|select.POLLHUP),
                'original gate pidfd exit/error ambiguous')
        return True

    def terminate(self, request, *, check):
        require(not self.sent and request['owner_sha256']==fingerprint(self.epoch['snapshot']),
                'original gate single TERM intent required')
        check();self.check();check()
        self.sent=True
        self.send_signal(self.fd,signal.SIGTERM,None,0)
        require(self.exited(timeout=5000), 'original gate exit timed out; no resend or force')
        require(self.read_context()==self._context(), 'gate exit context changed')
        return dict(owner_sha256=request['owner_sha256'],pidfd_exit_verified=True,term_count=1,force_used=False)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
