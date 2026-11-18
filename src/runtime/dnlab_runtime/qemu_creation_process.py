"""Kernel correlation of an original completed paused-creation CPU query.

Only explicitly returned TIDs are read; no process inventory/name/pidfile is
used. The shared PID namespace and procfs mount must be qualified by the creator.
The returned record is first-creation evidence, not an authority to adopt a VM
on retry. The caller must persist it in the original creation operation and use
PinnedQEMUProcess thereafter. No signals, commands or monitor queries are sent.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import select

from .manifest import Conflict, fingerprint
from .qemu_process import QEMUProcFiles, PinnedQEMUProcess, stat_start, validate_process_record
from .vm_template import digest, fields, require


class QEMUCreationProcess(QEMUProcFiles):
    def __init__(self,queries,request,policy,*,proc_root='/proc',pidfd_open=os.pidfd_open,
                 poll_factory=select.poll,pid_namespace=PinnedQEMUProcess._local_pid_namespace,process_id=os.getpid):
        fields(policy,('uid','gid','boot_id','executable_sha256','proc_identity','shared_namespaces','minimum_start_ticks'),
               'original QEMU creation process policy')
        require(all(type(policy[key]) is int and policy[key]>0 for key in ('uid','gid','minimum_start_ticks'))
                and isinstance(policy['boot_id'],str) and policy['boot_id'] and digest(policy['executable_sha256']),
                'original non-root creation policy required')
        fields(policy['proc_identity'],('device','inode'),'original procfs mount identity')
        fields(policy['shared_namespaces'],('pid','net','user'),'qualified shared QEMU namespaces')
        for identity in [policy['proc_identity'],*policy['shared_namespaces'].values()]:
            fields(identity,('device','inode'),'original kernel identity')
            require(all(type(v) is int and v>0 for v in identity.values()), 'original kernel identity differs')
        require(callable(getattr(queries,'read_completed',None)) and all(callable(fn) for fn in (pidfd_open,poll_factory,pid_namespace,process_id)),
                'original query receipt and kernel providers required')
        self.queries,self.request,self.policy=queries,deepcopy(request),deepcopy(policy)
        self.proc_root,self.pidfd_open,self.poll_factory,self.pid_namespace=Path(proc_root),pidfd_open,poll_factory,pid_namespace
        self.process_id=process_id

    @staticmethod
    def _identity(info):return dict(device=info.st_dev,inode=info.st_ino)

    def _status(self,root,pid):
        value={}
        for line in self._read('status',root,65536).splitlines():
            key,sep,data=line.partition(b':')
            if sep and key in (b'Pid',b'Tgid',b'Uid',b'Gid'):
                require(key not in value, 'duplicate QEMU task status field')
                try:value[key]=[int(v) for v in data.split()]
                except ValueError as error:raise Conflict('malformed QEMU task status') from error
        require(set(value)=={b'Pid',b'Tgid',b'Uid',b'Gid'} and value[b'Pid']==[pid]
                and len(value[b'Tgid'])==1 and 0<value[b'Tgid'][0]<2**31
                and value[b'Uid']==[self.policy['uid']]*4 and value[b'Gid']==[self.policy['gid']]*4,
                'original QEMU task credentials or PID mapping differs')
        return value[b'Tgid'][0]

    def _task(self,fd,tid):
        ticks=stat_start(self._read('stat',fd,16384),tid)
        tgid=self._status(fd,tid)
        spaces={name:self._identity(os.stat('ns/'+name,dir_fd=fd)) for name in ('pid','mnt','net','user')}
        require(all(spaces[name]==expected for name,expected in self.policy['shared_namespaces'].items()),
                'original QEMU shared namespace differs')
        return dict(thread_id=tid,tgid=tgid,start_ticks=ticks,namespaces=spaces)

    def _path(self,parent,name,fd):
        require(self._identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==self._identity(os.fstat(fd)),
                'original QEMU proc/task path replaced')

    def _self_map(self,proc):
        # Fixed procfs magic self link only. NSpid has one entry exactly when
        # this procfs view uses the caller's active PID namespace.
        value={}
        for line in self._read('self/status',proc,65536).splitlines():
            key,sep,data=line.partition(b':')
            if sep and key in (b'Pid',b'Tgid',b'NSpid'):
                require(key not in value, 'duplicate caller proc mapping')
                try:value[key]=[int(v) for v in data.split()]
                except ValueError as error:raise Conflict('malformed caller proc mapping') from error
        pid=self.process_id()
        require(type(pid) is int and pid>0 and value=={b'Pid':[pid],b'Tgid':[pid],b'NSpid':[pid]},
                'procfs and pidfd caller PID namespace views differ')

    def correlate(self):
        receipt=self.queries.read_completed(deepcopy(self.request))
        require(receipt['birth']==self.request['birth'] and receipt['request']==self.request
                and receipt['phase']=='completed', 'original paused CPU query required')
        cpus=receipt['cpus']
        require(type(self.request['expected_cpus']) is int and 1<=self.request['expected_cpus']<=256
                and type(cpus) is list and len(cpus)==self.request['expected_cpus'],
                'complete original CPU thread mapping required')
        with ExitStack() as stack:
            require(self.pid_namespace()==self.policy['shared_namespaces']['pid'], 'caller and QEMU PID namespaces differ')
            proc=self._open(str(self.proc_root),None,stack,directory=True)
            require(self._identity(os.fstat(proc))==self.policy['proc_identity'], 'qualified procfs mount differs')
            self._self_map(proc)
            boot=self._read('sys/kernel/random/boot_id',proc,128).decode('ascii').strip()
            require(boot==self.policy['boot_id'], 'original QEMU creation boot differs')
            tasks=[]
            for index,cpu in enumerate(cpus):
                fields(cpu,('index','thread_id'),'original queried CPU')
                tid=cpu['thread_id']
                require(type(cpu['index']) is int and cpu['index']==index and type(tid) is int and 0<tid<2**31,
                        'original CPU indexes or thread IDs differ')
                fd=self._open(str(tid),proc,stack,directory=True)
                tasks.append(dict(fd=fd,original=self._task(fd,tid)))
            tgids={task['original']['tgid'] for task in tasks}
            require(len(tgids)==1 and len({task['original']['thread_id'] for task in tasks})==len(tasks),
                    'CPU threads do not belong to one original QEMU process')
            pid=tgids.pop();leader=self._open(str(pid),proc,stack,directory=True)
            pidfd=self.pidfd_open(pid,0)
            require(type(pidfd) is int and pidfd>=0, 'original leader pidfd required')
            stack.callback(os.close,pidfd)
            poll=self.poll_factory();poll.register(pidfd,select.POLLIN)
            def alive():
                require(self.pid_namespace()==self.policy['shared_namespaces']['pid'] and not poll.poll(0),
                        'original QEMU pidfd exit/error or caller namespace changed')
                self._path(None,str(self.proc_root),proc)
                self._path(proc,str(pid),leader)
                self._self_map(proc)
            alive()
            original=self._task(leader,pid)
            require(original['tgid']==pid and original['start_ticks']>=self.policy['minimum_start_ticks'],
                    'QEMU leader predates original creation or is not a leader')
            for task in tasks:
                tid=task['original']['thread_id']
                fd=self._open('task/'+str(tid),leader,stack,directory=True)
                require(self._task(fd,tid)==task['original'] and task['original']['start_ticks']>=original['start_ticks'],
                        'queried CPU is not the same original kernel task under the leader')
                task['member']=fd
            command=self._read('cmdline',leader,1024*1024)
            record=dict(birth=deepcopy(receipt['birth']),process=dict(boot_id=boot,pid=pid,
                        start_ticks=original['start_ticks'],executable_sha256=self.policy['executable_sha256']),
                        uid=self.policy['uid'],gid=self.policy['gid'],cmdline_sha256=hashlib.sha256(command).hexdigest(),
                        namespaces=deepcopy(original['namespaces']))
            validate_process_record(record)
            verifier=PinnedQEMUProcess(record)
            require(verifier._observe(leader,proc)==record['process'], 'original QEMU leader differs from creation policy')
            require(self.queries.read_completed(deepcopy(self.request))==receipt,
                    'original creation query changed during kernel correlation')
            evidence=[]
            for task in tasks:
                tid=task['original']['thread_id']
                self._path(proc,str(tid),task['fd']);self._path(leader,'task/'+str(tid),task['member'])
                require(self._task(task['fd'],tid)==task['original'] and self._task(task['member'],tid)==task['original'],
                        'original queried CPU task changed during correlation')
                evidence.append(dict(**deepcopy(task['original']),proc_identity=self._identity(os.fstat(task['fd'])),
                                     member_identity=self._identity(os.fstat(task['member']))))
            alive()
            require(self._task(leader,pid)==original and verifier._observe(leader,proc)==record['process'],
                    'original creation or query changed during kernel correlation')
            alive()
            return dict(record=record,query_sha256=fingerprint(receipt),policy_sha256=fingerprint(self.policy),tasks=evidence)
