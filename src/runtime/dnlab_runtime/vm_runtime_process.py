"""Current runtime-process epoch; never discover or adopt an external worker.

Capture is explicit before VM mutations. A live pidfd, original full snapshot
and qualified source profile anchor per-command references in this process.
Closing the witness records no process exit; another instance cannot reopen it.
"""
from copy import deepcopy
import json
import os
import select
import uuid

from .libvirt_account_commands import reference_proof
from .libvirt_account_process import AccountWorkerObserver
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_events import validate_birth
from .vm_template import digest, fields, require


class RuntimeProcess:
    def __init__(self, journal, profile, *, verify_sources, reader=None,
                 pidfd_open=os.pidfd_open, poll_factory=select.poll, process_id=os.getpid,
                 thread_namespaces=None):
        fields(profile,('host_id','executable_sha256','cmdline_sha256','namespaces','sources_sha256'), 'runtime process profile')
        identifier(profile['host_id'],'runtime host')
        require(all(digest(profile[key]) for key in ('executable_sha256','cmdline_sha256','sources_sha256'))
            and all(callable(fn) for fn in (verify_sources,pidfd_open,poll_factory,process_id)),
            'qualified runtime source/process providers required')
        fields(profile['namespaces'],('pid','mnt','net','user'),'runtime namespaces')
        for namespace in profile['namespaces'].values():
            fields(namespace,('device','inode'),'runtime namespace')
            require(all(type(v) is int and v>0 for v in namespace.values()), 'original runtime namespace required')
        self.journal,self.profile=journal,deepcopy(profile)
        self.verify_sources,self.process_id=verify_sources,process_id
        self.thread_namespaces=self._thread_namespaces if thread_namespaces is None else thread_namespaces
        require(callable(self.thread_namespaces), 'original runtime thread namespace reader required')
        self.reader=AccountWorkerObserver(journal) if reader is None else reader
        require(callable(getattr(self.reader,'read_process',None)), 'readonly runtime process reader required')
        self.pidfd_open,self.poll_factory=pidfd_open,poll_factory
        self.fd,self.poll,self.epoch=None,None,None
        self.started=False
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_runtime_epochs '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_runtime_references '
                '(id TEXT PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,domain_uuid TEXT UNIQUE NOT NULL, '
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @staticmethod
    def _thread_namespaces():
        result={}
        for name in ('pid','mnt','net','user'):
            info=os.stat('/proc/thread-self/ns/'+name)
            result[name]=dict(device=info.st_dev,inode=info.st_ino)
        return result

    def _thread(self):
        require(self.thread_namespaces()==self.profile['namespaces'], 'runtime calling thread namespace changed')

    def _sources(self):
        require(self.verify_sources()==self.profile['sources_sha256'], 'qualified runtime sources changed')

    def _snapshot(self, pid):
        value=self.reader.read_process(pid)
        fields(value,('record','namespaces','proc_identity','cmdline_sha256'),'runtime process snapshot')
        record=value['record']
        require(value['namespaces']==self.profile['namespaces']
            and value['cmdline_sha256']==self.profile['cmdline_sha256']
            and record['pid']==pid and record['executable_sha256']==self.profile['executable_sha256']
            and record['namespace_sha256']==fingerprint(value['namespaces'])
            and type(value['proc_identity']) is list and len(value['proc_identity'])==2
            and all(type(v) is int and v>0 for v in value['proc_identity']), 'original runtime process/profile differs')
        # Reuse the typed privileged-process contract without claiming a child
        # Popen or inferring an external process birth from a matching PID.
        reference_proof(dict(token='0'*32,command_sha256=fingerprint({}),process_record=record),{})
        require(str(uuid.UUID(record['boot_id']))==record['boot_id'], 'canonical runtime boot identity required')
        self._sources()
        return deepcopy(value)

    def _alive(self):
        require(self.fd is not None and self.poll is not None, 'original runtime pidfd unavailable')
        if self.poll.poll(0):raise Conflict('runtime pidfd exit/error/ambiguous event; original epoch unavailable')

    def start(self):
        with self.journal.execution_lock:
            if self.epoch is not None:return self.check()
            require(not self.started, 'runtime process epoch cannot be reopened')
            self.started=True;pid=self.process_id()
            require(type(pid) is int and pid>0, 'current original runtime PID required')
            self._thread()
            snapshot=self._snapshot(pid)
            fd=self.pidfd_open(pid,0)
            require(type(fd) is int and fd>=0, 'original runtime pidfd required')
            self.fd=fd
            try:
                self.poll=self.poll_factory();self.poll.register(fd,select.POLLIN)
                self._alive()
                if self.process_id()!=pid or self._snapshot(pid)!=snapshot:
                    raise Conflict('runtime process changed during capture')
                epoch=dict(id=uuid.uuid4().hex,profile=deepcopy(self.profile),snapshot=snapshot)
                with self.journal.transaction():
                    self._alive()
                    if self._snapshot(pid)!=snapshot or self.process_id()!=pid:
                        raise Conflict('runtime process changed before epoch commit')
                    self.journal.db.execute('INSERT INTO vm_runtime_epochs VALUES(?,?,?)',
                        (epoch['id'],canonical(epoch),fingerprint(epoch)))
                self.epoch=epoch
                return self.check()
            except BaseException:
                self.close();raise

    def check(self):
        require(self.epoch is not None, 'original runtime epoch not captured')
        require(self.profile==self.epoch['profile'], 'original runtime profile changed')
        self._thread()
        self._alive();pid=self.epoch['snapshot']['record']['pid']
        if self.process_id()!=pid or self._snapshot(pid)!=self.epoch['snapshot']:
            raise Conflict('original runtime process incarnation changed')
        row=self.journal.db.execute('SELECT * FROM vm_runtime_epochs WHERE id=?',(self.epoch['id'],)).fetchone()
        if row is None or row['payload']!=canonical(self.epoch) or row['fingerprint']!=fingerprint(self.epoch):
            raise Conflict('original runtime epoch journal changed')
        self._alive();self._sources();self._thread()
        if self.process_id()!=pid:raise Conflict('original runtime process changed after source verification')
        return deepcopy(self.epoch)

    def _command(self, command):
        fields(command,('action','operation_id','birth','definition_sha256','context','specs'),'runtime TAP command')
        validate_birth(command['birth']);context=command['context']
        fields(context,('boot_id','device','inode'),'runtime TAP namespace')
        snapshot=self.check()['snapshot']
        require(command['action']=='vm-tap-lease' and command['operation_id']==command['birth']['creator_operation_id']
            and command['birth']['host_id']==self.profile['host_id'] and digest(command['definition_sha256'])
            and context==dict(boot_id=snapshot['record']['boot_id'],**snapshot['namespaces']['net'])
            and type(command['specs']) is list and 1<=len(command['specs'])<=256,
            'original runtime TAP command host/context differs')

    def _read(self, token):
        row=self.journal.db.execute('SELECT * FROM vm_runtime_references WHERE id=?',(token,)).fetchone()
        if row is None:raise Conflict('original runtime command reference missing')
        value=json.loads(row['payload'])
        fields(value,('id','birth','epoch_id','epoch_sha256','command','reference'),'runtime command reference')
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=token or value['reference']['token']!=token
                or value['birth']!=value['command']['birth'] or row['operation_id']!=value['command']['operation_id']
                or row['operation_id']!=value['birth']['creator_operation_id'] or row['domain_uuid']!=value['birth']['uuid']):
            raise Conflict('original runtime command journal differs')
        reference_proof(value['reference'],value['command'])
        return value

    def reference(self, command):
        with self.journal.execution_lock:
            self._command(command)
            row=self.journal.db.execute('SELECT id FROM vm_runtime_references WHERE operation_id=?',
                (command['operation_id'],)).fetchone()
            if row:
                value=self._read(row['id'])
                if value['command']!=command:raise Conflict('original runtime command cannot change')
                self.verify(value['reference'],command);return deepcopy(value['reference'])
            reference=dict(token=uuid.uuid4().hex,command_sha256=fingerprint(command),
                process_record=deepcopy(self.epoch['snapshot']['record']))
            value=dict(id=reference['token'],birth=deepcopy(command['birth']),epoch_id=self.epoch['id'],
                epoch_sha256=fingerprint(self.epoch),command=deepcopy(command),reference=reference)
            with self.journal.transaction():
                self._command(command)
                self.journal.db.execute('INSERT INTO vm_runtime_references VALUES(?,?,?,?,?)',
                    (value['id'],command['operation_id'],value['birth']['uuid'],canonical(value),fingerprint(value)))
            self.verify(reference,command)
            return deepcopy(reference)

    def verify(self, reference, command):
        with self.journal.execution_lock:
            self._command(command);value=self._read(reference['token'])
            if (value['reference']!=reference or value['command']!=command or value['epoch_id']!=self.epoch['id']
                    or value['epoch_sha256']!=fingerprint(self.epoch)
                    or reference['process_record']!=self.epoch['snapshot']['record']):
                raise Conflict('original runtime reference belongs to another epoch/process')
            self.check();return True

    def close(self):
        if self.fd is not None:
            fd,self.fd=self.fd,None
            os.close(fd)
        self.poll=None
