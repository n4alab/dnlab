"""Parent runner for the blocked account worker, without signals or respawns.

The observer is mandatory: it must capture/verify the original local process,
its namespace and its exit. Production use is disabled until that observer and
worker/interpreter/config profiles are qualified. Tests inject a fake spawner.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
import select
import stat
import subprocess
import time
import uuid

from .libvirt_account_commands import reference_proof
from .libvirt_account_worker import ENVIRONMENT,MAX_FRAME,binary_proof,validate_command
from .manifest import Conflict,canonical,fingerprint
from .vm_bundle import pinned_file


@contextmanager
def open_resource(path):
    if not isinstance(path,str) or not path.startswith('/') or '..' in path.split('/'):
        raise Conflict('absolute qualified worker resource required')
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        with pinned_file(root,path.lstrip('/')) as (fd,_):yield fd
    finally:os.close(root)


def source_proof(fd,expected):
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not 0<info.st_size<=1024*1024:
        raise Conflict('original root-controlled worker source required')
    os.lseek(fd,0,os.SEEK_SET);data=b''
    while len(data)<=info.st_size:
        block=os.read(fd,min(65536,info.st_size+1-len(data)))
        if not block:break
        data+=block
    if len(data)!=info.st_size or hashlib.sha256(data).hexdigest()!=expected:
        raise Conflict('original worker source hash differs')
    os.lseek(fd,0,os.SEEK_SET)


def worker_argv(profile,binary,python,worker):
    """Share the inherited-FD bootstrap with the non-mutating qualification recipe."""
    return [profile['python']['path'],'-B','-I','-S','/proc/self/fd/'+str(worker),
        '--binary-fd',str(binary),'--close-on-exec-fd',str(python),'--close-on-exec-fd',str(worker)]


def ready_line(process,timeout=10):
    deadline=time.monotonic()+timeout;value=b''
    while time.monotonic()<deadline and len(value)<=16384:
        readable,_,_=select.select([process.stdout],[],[],max(0,deadline-time.monotonic()))
        if not readable:break
        block=os.read(process.stdout.fileno(),min(4096,16385-len(value)))
        if not block:break
        value+=block
        if b'\n' in value:
            line,tail=value.split(b'\n',1)
            if tail:raise Conflict('unexpected output before worker release')
            return json.loads(line)
    raise Conflict('original blocked worker readiness not observed')


def collect_output(process,state,timeout=10):
    """Bound each stream; retain partial bytes for a later observation."""
    deadline=time.monotonic()+timeout
    for stream in (process.stdout,process.stderr):os.set_blocking(stream.fileno(),False)
    while time.monotonic()<deadline:
        streams=[getattr(process,key) for key in ('stdout','stderr') if key not in state['eof']]
        if not streams:
            status=process.poll()
            if status is not None:
                return dict(exit_code=status,stdout=state['stdout'].decode('utf-8','replace'),
                    stderr=state['stderr'].decode('utf-8','replace'))
        readable,_,_=select.select(streams,[],[],min(0.05,max(0,deadline-time.monotonic())))
        for stream in readable:
            key='stdout' if stream is process.stdout else 'stderr'
            block=os.read(stream.fileno(),min(4096,65537-len(state[key])))
            if not block:state['eof'].add(key)
            else:
                state[key]+=block
                if len(state[key])>65536:raise Conflict('account worker output exceeds bound')
    return None


class AccountProcessRunner:
    worker_table='libvirt_account_workers'
    command_validator=staticmethod(validate_command)

    def __init__(self,journal,*,profile,observer,spawn=subprocess.Popen,opener=open_resource,
                 read_ready=ready_line,read_output=collect_output):
        if set(profile)!={'python','worker'} or any(set(v)!={'path','sha256'} for v in profile.values()):
            raise Conflict('explicit interpreter and worker profiles required')
        self.journal,self.profile,self.observer=journal,deepcopy(profile),observer
        self.spawn,self.opener,self.read_ready,self.read_output=spawn,opener,read_ready,read_output
        self.live={}
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS '+self.worker_table+' '
                '(token TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _save(self,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE '+self.worker_table+' SET payload=?,fingerprint=? WHERE token=?',
                (canonical(value),fingerprint(value),value['token']))

    def _read(self,reference):
        with self.journal.lock:
            row=self.journal.db.execute('SELECT * FROM '+self.worker_table+' WHERE token=?',(reference['token'],)).fetchone()
        if row is None:raise Conflict('original account worker journal missing')
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['reference']!=reference
                or value['profile']!=self.profile or value['token']!=row['token']):
            raise Conflict('original account worker journal differs')
        reference_proof(reference,value['command'])
        return value

    def arm(self,command):
        self.command_validator(command)
        with self.journal.execution_lock:
            token=uuid.uuid4().hex
            packet=(canonical(dict(token=token,command=command))+'\n').encode()
            if len(packet)>MAX_FRAME:raise Conflict('account worker request exceeds frame bound')
            value=dict(token=token,command=deepcopy(command),profile=deepcopy(self.profile),
                phase='launch_requested',reference=None,outcome=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO '+self.worker_table+' VALUES(?,?,?)',
                    (token,canonical(value),fingerprint(value)))
            with self.opener(command['binary']['path']) as binary, self.opener(self.profile['python']['path']) as python, self.opener(self.profile['worker']['path']) as worker:
                binary_proof(binary,command['binary']['sha256'])
                binary_proof(python,self.profile['python']['sha256'])
                source_proof(worker,self.profile['worker']['sha256'])
                argv=worker_argv(self.profile,binary,python,worker)
                process=self.spawn(argv,executable='/proc/self/fd/'+str(python),pass_fds=(binary,python,worker),
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=deepcopy(ENVIRONMENT),cwd='/',close_fds=True)
                self.live[token]=dict(process=process,stdout=b'',stderr=b'',eof=set())
                process.stdin.write(packet);process.stdin.flush()
                ready=self.read_ready(process)
                if ready!=dict(ready=token,command_sha256=fingerprint(command)):
                    raise Conflict('original account worker ready differs')
                record=self.observer.capture(process)
                reference=dict(token=token,command_sha256=fingerprint(command),process_record=record)
                reference_proof(reference,command)
                if record['pid']!=process.pid or record['executable_sha256']!=self.profile['python']['sha256'] :
                    raise Conflict('original blocked worker process differs')
                self.observer.bind(reference,process,command)
                if self.observer.verify(reference,process,command,'armed') is not True:
                    raise Conflict('original blocked worker process differs')
                value.update(reference=reference,phase='armed');self._save(value)
                return deepcopy(reference)

    def verify(self,reference,command):
        with self.journal.execution_lock:
            value=self._read(reference)
            if value['command']!=command:raise Conflict('original account worker command differs')
            live=self.live.get(reference['token'])
            process=live['process'] if live else None
            if value['phase']!='completed' and process is None:
                raise Conflict('original account worker waiter unavailable; no PID adoption')
            return self.observer.verify(reference,process,command,value['phase']) is True

    def release(self,reference):
        with self.journal.execution_lock:
            value=self._read(reference)
            if value['phase']!='armed':raise Conflict('original worker release is not repeated')
            if not self.verify(reference,value['command']):raise Conflict('original account worker differs before release')
            value['phase']='release_requested';self._save(value)
            if not self.verify(reference,value['command']):raise Conflict('original account worker differs at release boundary')
            process=self.live[reference['token']]['process']
            if self.observer.verify(reference,process,value['command'],'armed') is not True:
                raise Conflict('original blocked worker differs before release write')
            process.stdin.write((canonical(dict(release=reference['token'],command_sha256=reference['command_sha256']))+'\n').encode())
            process.stdin.flush();process.stdin.close()
            value['phase']='released';self._save(value)

    def outcome(self,reference):
        with self.journal.execution_lock:
            value=self._read(reference)
            if value['phase']=='completed':
                if not self.verify(reference,value['command']):raise Conflict('original completed worker proof differs')
                self._retire(reference)
                return deepcopy(value['outcome'])
            if value['phase'] not in ('release_requested','released'):return None
            if not self.verify(reference,value['command']):raise Conflict('original account worker outcome is unqualified')
            live=self.live[reference['token']];process=live['process']
            result=self.read_output(process,live)
            if result is None:return None
            if self.observer.exit(process,reference) is not True:
                raise Conflict('original worker exit is not qualified')
            if set(result)!={'exit_code','stdout','stderr'} or type(result['exit_code']) is not int:
                raise Conflict('bounded original worker output required')
            if any(not isinstance(result[k],str) or len(result[k].encode())>65536 for k in ('stdout','stderr')):
                raise Conflict('worker output is malformed or exceeds bound')
            value.update(phase='completed',outcome=dict(reference=deepcopy(reference),**result));self._save(value)
            self._retire(reference)
            return deepcopy(value['outcome'])

    def completed_outcome(self,reference):
        """Read only an already committed outcome; never collect or retire here."""
        with self.journal.execution_lock:
            value=self._read(reference)
            if value['phase']!='completed':return None
            if not self.verify(reference,value['command']):
                raise Conflict('original completed worker proof differs')
            return deepcopy(value['outcome'])

    def _retire(self,reference):
        self.observer.retire(reference)
        live=self.live.get(reference['token'])
        if live is not None:
            for key in ('stdin','stdout','stderr'):getattr(live['process'],key).close()
            del self.live[reference['token']]
