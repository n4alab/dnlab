"""Pinned inherited-FD launcher for one original loop-only child.

Preparation opens files and seals a bootstrap memfd; it starts no process.
The parent protocol owns release and exit proof. Launch uncertainty is never
permission to repeat Popen, and launcher descriptors remain owned until the
original parent has saved a qualified exit receipt.
"""
from contextlib import ExitStack
from copy import deepcopy
import fcntl
import json
import os
import subprocess

from dnlab_runtime.libvirt_account_runner import open_resource, source_proof
from dnlab_runtime.libvirt_account_worker import binary_proof
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_bundle import metadata
from dnlab_runtime.vm_template import digest, fields, require

ENVIRONMENT=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',LIBVIRT_AUTOSTART='0')
SEALS=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE


class FDLoopLauncher:
    def __init__(self,journal,profile,*,preflight,opener=open_resource,spawn=subprocess.Popen):
        fields(profile,('python','worker'),'loop launcher profile')
        for asset in profile.values():
            fields(asset,('path','sha256'),'loop launcher asset')
            require(isinstance(asset['path'],str) and asset['path'].startswith('/')
                    and '..' not in asset['path'].split('/') and digest(asset['sha256']),
                    'explicit original interpreter/source required')
        require(all(callable(fn) for fn in (preflight,opener,spawn)), 'qualified loop launcher providers required')
        self.journal,self.profile=journal,deepcopy(profile)
        self.preflight,self.opener,self.spawner=preflight,opener,spawn
        self.stack=ExitStack();self.files={};self.assets={};self.packet=None;self.value=None
        self.process=None;self.attempted=False;self.closed=False
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_loop_fd_launchers '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _save(self):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_loop_fd_launchers SET payload=?,fingerprint=? WHERE id=?',
                (canonical(self.value),fingerprint(self.value),self.value['id']))

    def _scope(self):
        scope=dict(profile=self.profile,bootstrap=self.value['bootstrap'])
        require(self.preflight(deepcopy(scope))==fingerprint(scope), 'original launcher scope differs')

    def prepare(self,nonce,bootstrap):
        with self.journal.execution_lock:
            require(self.value is None and not self.closed and isinstance(nonce,str) and len(nonce)==32
                    and all(c in '0123456789abcdef' for c in nonce) and type(bootstrap) is dict,
                    'new original loop launcher intent required')
            value=dict(id=nonce,profile=deepcopy(self.profile),bootstrap=deepcopy(bootstrap),
                       phase='preparing',request=None,bootstrap_sha256=None,error=None)
            scope=dict(profile=self.profile,bootstrap=value['bootstrap'])
            require(self.preflight(deepcopy(scope))==fingerprint(scope), 'original launcher scope differs')
            with self.journal.transaction():
                require(self.journal.db.execute('SELECT 1 FROM libvirt_loop_fd_launchers').fetchone() is None,
                        'launcher journal is one-shot; no replacement child')
                self.journal.db.execute('INSERT INTO libvirt_loop_fd_launchers VALUES(?,?,?)',
                    (nonce,canonical(value),fingerprint(value)))
            self.value=value
            try:
                for name,asset in self.profile.items():
                    fd=self.stack.enter_context(self.opener(asset['path']));self.files[name]=fd
                    (binary_proof if name=='python' else source_proof)(fd,asset['sha256'])
                    self.assets[name]=list(metadata(os.fstat(fd)))
                fd=os.memfd_create('dnlab-loop-bootstrap',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
                self.stack.callback(os.close,fd);self.files['bootstrap']=fd
                argv=[self.profile['python']['path'],'-B','-I','-S','/proc/self/fd/'+str(self.files['worker']),
                      '--bootstrap-fd',str(fd)]
                request=dict(nonce=nonce,command=dict(binary=deepcopy(self.profile['python']),
                                                    argv=argv,environment=deepcopy(ENVIRONMENT)))
                self.packet=(canonical(dict(request=request,bootstrap=bootstrap))+'\n').encode()
                require(len(self.packet)<=1024*1024, 'bounded inherited bootstrap required')
                remaining=self.packet
                while remaining:
                    count=os.write(fd,remaining)
                    require(count>0, 'original bootstrap write incomplete');remaining=remaining[count:]
                fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
                os.lseek(fd,0,os.SEEK_SET)
                self.value.update(phase='prepared',request=request,
                                  bootstrap_sha256=fingerprint(dict(request=request,bootstrap=bootstrap)))
                self._save();self.check(request)
                return deepcopy(request)
            except BaseException as error:
                self.value.update(phase='pending',error=dict(type=type(error).__name__,message=str(error)))
                self._save();self.stack.close();self.closed=True
                raise

    def check(self,request):
        require(not self.closed and self.value is not None and request==self.value['request']
                and self.profile==self.value['profile'], 'original prepared launcher required')
        self._scope()
        row=self.journal.db.execute('SELECT payload,fingerprint FROM libvirt_loop_fd_launchers WHERE id=?',
            (self.value['id'],)).fetchone()
        require(row is not None and json.loads(row['payload'])==self.value
                and row['fingerprint']==fingerprint(self.value), 'original launcher journal differs')
        for name,asset in self.profile.items():
            fd=self.files[name]
            require(list(metadata(os.fstat(fd)))==self.assets[name], 'original launcher asset identity differs')
            (binary_proof if name=='python' else source_proof)(fd,asset['sha256'])
        fd=self.files['bootstrap']
        require(fcntl.fcntl(fd,fcntl.F_GET_SEALS)==SEALS
                and os.pread(fd,len(self.packet)+1,0)==self.packet, 'original sealed bootstrap differs')
        self._scope()
        return fingerprint(request)

    def spawn(self,command):
        with self.journal.execution_lock:
            require(not self.attempted and not self.closed and self.value is not None
                    and self.value['phase']=='prepared' and command==self.value['request']['command'],
                    'original loop launch cannot be repeated or changed')
            self.check(self.value['request'])
            self.attempted=True;self.value['phase']='launch_requested';self._save()
            self.check(self.value['request'])
            try:
                # Return the waiter immediately: a failing post-launch check
                # must never hide the original child from its parent protocol.
                self.process=self.spawner(command['argv'],executable='/proc/self/fd/'+str(self.files['python']),
                    pass_fds=tuple(self.files.values()),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,env=deepcopy(ENVIRONMENT),cwd='/',close_fds=True)
                return self.process
            except BaseException as error:
                self.value.update(phase='pending',error=dict(type=type(error).__name__,message=str(error)))
                self._save()
                raise

    def close(self,*,parent=None):
        """Release own FDs only before launch or after original-parent exit."""
        with self.journal.execution_lock:
            require(not self.closed and self.value is not None, 'original open launcher required')
            if self.attempted:
                require(self.process is not None and parent is not None and parent.journal is self.journal
                        and parent.process is self.process and parent.request==self.value['request'],
                        'original child waiter and parent receipt required')
                result=parent._read()
                require(result['phase'] in ('completed','failed') and result['cleanup_verified'] is True
                        and type(result['exit_code']) is int and self.process.poll()==result['exit_code'],
                        'original qualified process exit required before releasing launcher files')
            self.stack.close();self.closed=True
            self.value['phase']='closed';self._save()
