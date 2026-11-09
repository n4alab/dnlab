"""Original account-worker observation; no discovery, signals or process starts.

The parent owns the Popen waiter. A pidfd remains pinned until a durable exit
receipt exists. Losing the waiter before that receipt leaves recovery pending.
Host use still requires qualification of procfs, interpreter and worker sources.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import select
import stat

from .libvirt_account_commands import reference_proof
from .manifest import Conflict,canonical,fingerprint
from .qemu_process import stat_start


class AccountWorkerObserver:
    def __init__(self,journal,*,proc_root='/proc',pidfd_open=os.pidfd_open,
                 poll_factory=select.poll,pid_namespace=None):
        self.journal,self.proc_root=journal,Path(proc_root)
        self.pidfd_open,self.poll_factory=pidfd_open,poll_factory
        self.pid_namespace=pid_namespace or self._local_namespace
        self.live={}
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_account_processes '
                '(token TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @staticmethod
    def _local_namespace():
        info=os.stat('/proc/self/ns/pid')
        return dict(device=info.st_dev,inode=info.st_ino)

    @staticmethod
    def _identity(info):return [info.st_dev,info.st_ino]

    @staticmethod
    def _read_file(root,name,limit):
        fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):raise Conflict('regular worker observation required')
            data=b''
            while len(data)<=limit:
                block=os.read(fd,min(65536,limit+1-len(data)))
                if not block:break
                data+=block
            if len(data)>limit:raise Conflict('worker observation exceeds bound')
            return data
        finally:os.close(fd)

    def _snapshot(self,process):
        with ExitStack() as stack:
            proc=os.open(self.proc_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            stack.callback(os.close,proc)
            root=os.open(str(process.pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=proc)
            stack.callback(os.close,root)
            first=self._read_file(root,'stat',16384)
            ticks=stat_start(first,process.pid)
            credentials={}
            for line in self._read_file(root,'status',65536).splitlines():
                key,sep,value=line.partition(b':')
                if sep and key in (b'Uid',b'Gid'):
                    if key in credentials:raise Conflict('duplicate worker credentials')
                    try:credentials[key]=[int(v) for v in value.split()]
                    except ValueError as error:raise Conflict('malformed worker credentials') from error
            if credentials!={b'Uid':[0]*4,b'Gid':[0]*4}:raise Conflict('original root helper credentials differ')
            spaces={}
            for name in ('pid','mnt','net','user'):
                info=os.stat('ns/'+name,dir_fd=root)
                spaces[name]=dict(device=info.st_dev,inode=info.st_ino)
            if spaces['pid']!=self.pid_namespace():raise Conflict('helper and caller PID namespace differ')
            # Only the magic exe link below the pinned original proc directory is followed.
            fd=os.open('exe',os.O_RDONLY|os.O_CLOEXEC,dir_fd=root);stack.callback(os.close,fd)
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not 0<info.st_size<=128*1024*1024:
                raise Conflict('bounded root-controlled helper executable required')
            hashed=hashlib.sha256();remaining=info.st_size
            while remaining:
                block=os.read(fd,min(remaining,65536))
                if not block:raise Conflict('helper executable truncated')
                hashed.update(block);remaining-=len(block)
            after=os.fstat(fd)
            keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
            if os.read(fd,1) or any(getattr(info,k)!=getattr(after,k) for k in keys):
                raise Conflict('helper executable changed during read')
            command=self._read_file(root,'cmdline',1024*1024)
            if not command.endswith(b'\0') or not command.split(b'\0')[0]:raise Conflict('helper command malformed')
            boot=self._read_file(proc,'sys/kernel/random/boot_id',128).decode('ascii').strip()
            if not boot:raise Conflict('helper boot identity missing')
            identity=self._identity(os.fstat(root))
            if (self._identity(os.stat(str(process.pid),dir_fd=proc,follow_symlinks=False))!=identity
                    or stat_start(self._read_file(root,'stat',16384),process.pid)!=ticks):
                raise Conflict('original helper proc incarnation changed')
            return dict(record=dict(boot_id=boot,pid=process.pid,start_ticks=ticks,uid=0,gid=0,
                executable_sha256=hashed.hexdigest(),namespace_sha256=fingerprint(spaces)),
                namespaces=spaces,proc_identity=identity,cmdline_sha256=hashlib.sha256(command).hexdigest())

    @staticmethod
    def _events(live):
        events=live['poll'].poll(0)
        if not events:return False
        if (len(events)!=1 or events[0][0]!=live['fd'] or type(events[0][1]) is not int
                or not events[0][1] or events[0][1]&~(select.POLLIN|select.POLLHUP)):
            raise Conflict('helper pidfd events are not qualified')
        return True

    def capture(self,process):
        with self.journal.execution_lock:
            if id(process) in self.live:raise Conflict('helper process already captured')
            if process.poll() is not None:raise Conflict('helper already exited before capture')
            first=self._snapshot(process)
            fd=self.pidfd_open(process.pid,0)
            try:
                poll=self.poll_factory();poll.register(fd,select.POLLIN)
                live=dict(process=process,fd=fd,poll=poll,snapshot=first,token=None)
                if self._events(live) or process.poll() is not None or self._snapshot(process)!=first:
                    raise Conflict('helper changed during capture')
                argv=process.args
                if not isinstance(argv,(list,tuple)) or not argv or any(not isinstance(v,str) or '\0' in v for v in argv):
                    raise Conflict('original Popen argument vector required')
                expected=b'\0'.join(os.fsencode(v) for v in argv)+b'\0'
                if hashlib.sha256(expected).hexdigest()!=first['cmdline_sha256']:
                    raise Conflict('original Popen command differs')
                self.live[id(process)]=live
                return deepcopy(first['record'])
            except BaseException:
                os.close(fd);raise

    def bind(self,reference,process,command):
        reference_proof(reference,command)
        with self.journal.execution_lock:
            live=self.live.get(id(process))
            if live is None or live['process'] is not process or live['token'] is not None or live['snapshot']['record']!=reference['process_record']:
                raise Conflict('original captured helper required for binding')
            self._verify_live(live,command,'armed')
            value=dict(reference=deepcopy(reference),command_sha256=fingerprint(command),
                snapshot=deepcopy(live['snapshot']),exit=None)
            with self.journal.transaction():
                if self.journal.db.execute('SELECT token FROM libvirt_account_processes WHERE token=?',(reference['token'],)).fetchone():
                    raise Conflict('original helper binding is immutable')
                self.journal.db.execute('INSERT INTO libvirt_account_processes VALUES(?,?,?)',
                    (reference['token'],canonical(value),fingerprint(value)))
            live['token']=reference['token']

    def _read(self,reference):
        with self.journal.lock:
            row=self.journal.db.execute('SELECT * FROM libvirt_account_processes WHERE token=?',(reference['token'],)).fetchone()
        if row is None:raise Conflict('original helper binding missing')
        value=json.loads(row['payload'])
        if fingerprint(value)!=row['fingerprint'] or value['reference']!=reference:
            raise Conflict('original helper binding differs')
        # Durable exit may be read without a waiter, but never across a new boot/namespace.
        proc=os.open(self.proc_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:boot=self._read_file(proc,'sys/kernel/random/boot_id',128).decode('ascii').strip()
        finally:os.close(proc)
        if boot!=reference['process_record']['boot_id'] or self.pid_namespace()!=value['snapshot']['namespaces']['pid']:
            raise Conflict('original helper observation context differs')
        return value

    def _verify_live(self,live,command,phase):
        if self._events(live) or live['process'].poll() is not None:raise Conflict('helper is no longer live')
        observed=self._snapshot(live['process']);original=live['snapshot']
        executable=observed['record']['executable_sha256']
        allowed={original['record']['executable_sha256']}
        if phase in ('release_requested','released'):allowed.add(command['binary']['sha256'])
        if executable not in allowed:raise Conflict('original helper executable differs')
        expected=deepcopy(original);expected['record']['executable_sha256']=executable
        # useradd may scrub its argv; only the blocked interpreter must retain its exact argv.
        if executable!=original['record']['executable_sha256']:expected['cmdline_sha256']=observed['cmdline_sha256']
        if observed!=expected or self._events(live) or live['process'].poll() is not None:
            raise Conflict('original helper process differs')
        return True

    def verify(self,reference,process,command,phase):
        reference_proof(reference,command)
        with self.journal.execution_lock:
            value=self._read(reference)
            if value['command_sha256']!=fingerprint(command):raise Conflict('original helper command differs')
            if value['exit'] is not None:
                if phase not in ('release_requested','released','completed'):raise Conflict('helper exited before release')
                return True
            live=self.live.get(id(process))
            if live is None or live['process'] is not process or live['token']!=reference['token']:
                raise Conflict('original helper waiter unavailable; no PID adoption')
            if phase in ('release_requested','released') and process.poll() is not None:
                return self.exit(process,reference)
            return self._verify_live(live,command,phase)

    def exit(self,process,reference):
        with self.journal.execution_lock:
            value=self._read(reference)
            live=self.live.get(id(process))
            if live is None or live['process'] is not process or live['token']!=reference['token']:
                raise Conflict('original helper waiter required for exit')
            status=process.poll()
            if type(status) is not int or not self._events(live):raise Conflict('original helper exit is not qualified')
            proof=dict(exit_code=status,process_record=deepcopy(reference['process_record']))
            if value['exit'] is not None and value['exit']!=proof:raise Conflict('original helper exit differs')
            value['exit']=proof
            with self.journal.transaction():
                self.journal.db.execute('UPDATE libvirt_account_processes SET payload=?,fingerprint=? WHERE token=?',
                    (canonical(value),fingerprint(value),reference['token']))
            return True

    def retire(self,reference):
        with self.journal.execution_lock:
            value=self._read(reference)
            if value['exit'] is None:raise Conflict('helper exit receipt required before retire')
            for key,live in list(self.live.items()):
                if live['token']==reference['token']:
                    os.close(live['fd']);del self.live[key]

    def close(self):
        for key,live in list(self.live.items()):
            os.close(live['fd']);del self.live[key]
