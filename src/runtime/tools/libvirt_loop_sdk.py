"""One-shot SDK import from qualified files for a dedicated canary child.

No sys.path changes, site hooks, bytecode cache, connection or event dispatch.
The Debian loader still resolves native shared-library dependencies; package
compatibility is not reimplemented here. File/source provenance is checked, not
claimed as introspection of native library memory.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import types
import uuid

from dnlab_runtime.libvirt_account_runner import open_resource
from dnlab_runtime.libvirt_account_worker import binary_proof
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_bundle import metadata
from dnlab_runtime.vm_template import digest, fields, require


def isolated_interpreter():
    return bool(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)


def extension_from_fd(fd):
    path='/proc/self/fd/'+str(fd)
    loader=importlib.machinery.ExtensionFileLoader('libvirtmod',path)
    spec=importlib.util.spec_from_file_location('libvirtmod',path,loader=loader)
    require(spec is not None, 'original libvirt extension spec required')
    module=importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class LoopSDK:
    def __init__(self,journal,profile,*,preflight,isolated=isolated_interpreter,
                 opener=open_resource,load_extension=extension_from_fd):
        fields(profile,('source','extension'),'loop SDK profile')
        for asset in profile.values():
            fields(asset,('path','sha256'),'loop SDK asset')
            require(isinstance(asset['path'],str) and asset['path'].startswith('/')
                    and '..' not in asset['path'].split('/') and digest(asset['sha256']),
                    'explicit qualified SDK file required')
        require(profile['source']['path']!=profile['extension']['path']
                and all(callable(fn) for fn in (preflight,isolated,opener,load_extension)),
                'qualified SDK import providers required')
        self.journal,self.profile=journal,deepcopy(profile)
        self.preflight,self.isolated,self.opener,self.load_extension=preflight,isolated,opener,load_extension
        self.attempted=False;self.sdk=None;self.native=None;self.receipt=None
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_loop_sdk_imports '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _guard(self):
        require(self.isolated() is True and self.preflight()==fingerprint(self.profile),
                'original isolated interpreter/SDK scope differs')

    def _save(self,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_loop_sdk_imports SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    def _files(self,stack):
        files={};proofs={};source=None
        for name,asset in self.profile.items():
            fd=stack.enter_context(self.opener(asset['path']));files[name]=fd
            info=os.fstat(fd)
            if name=='extension':binary_proof(fd,asset['sha256'])
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
                        and 0<info.st_size<=4*1024*1024, 'bounded root-controlled libvirt source required')
                os.lseek(fd,0,os.SEEK_SET);parts=[];total=0
                while total<=info.st_size:
                    block=os.read(fd,min(65536,info.st_size+1-total))
                    if not block:break
                    total+=len(block);parts.append(block)
                source=b''.join(parts)
                require(total==info.st_size and hashlib.sha256(source).hexdigest()==asset['sha256'],
                        'original libvirt source hash differs')
            require(metadata(info)==metadata(os.fstat(fd)), 'original SDK asset changed while reading')
            proofs[name]=dict(path=asset['path'],sha256=asset['sha256'],metadata=list(metadata(info)))
        return files,proofs,source

    def load(self):
        with self.journal.execution_lock:
            require(not self.attempted, 'original SDK import cannot be repeated')
            self.attempted=True;self._guard()
            require('libvirt' not in sys.modules and 'libvirtmod' not in sys.modules,
                    'fresh child required; existing SDK modules cannot be adopted')
            value=dict(id=uuid.uuid4().hex,profile=deepcopy(self.profile),phase='import_requested',
                       assets=None,error=None)
            with self.journal.transaction():
                require(self.journal.db.execute('SELECT 1 FROM libvirt_loop_sdk_imports').fetchone() is None,
                        'SDK journal is one-shot; no replacement import')
                self.journal.db.execute('INSERT INTO libvirt_loop_sdk_imports VALUES(?,?,?)',
                    (value['id'],canonical(value),fingerprint(value)))
            try:
                with ExitStack() as stack:
                    files,proofs,source=self._files(stack)
                    value['assets']=proofs;self._save(value);self._guard()
                    native=self.load_extension(files['extension'])
                    require(isinstance(native,types.ModuleType) and native.__name__=='libvirtmod'
                            and ('libvirtmod' not in sys.modules or sys.modules['libvirtmod'] is native)
                            and 'libvirt' not in sys.modules,
                            'original freshly loaded native SDK module required')
                    sys.modules['libvirtmod']=native
                    self._guard()
                    sdk=types.ModuleType('libvirt');sdk.__file__=self.profile['source']['path']
                    sdk.__package__='';sys.modules['libvirt']=sdk
                    exec(compile(source,self.profile['source']['path'],'exec',dont_inherit=True),sdk.__dict__)
                    self.sdk,self.native=sdk,native
                    require(sdk.libvirtmod is native and all(callable(getattr(sdk,name,None)) for name in
                        ('virEventRegisterDefaultImpl','virEventAddTimeout','virEventRunDefaultImpl')),
                        'original SDK event API required')
                    self._guard()
                # Reopen and hash after executing both initializers; path/content
                # changes never become the accepted provenance of this import.
                with ExitStack() as stack:
                    _,after,_=self._files(stack)
                    require(after==proofs, 'original SDK files changed during import')
                self._guard()
                value['phase']='loaded';self._save(value);self.receipt=deepcopy(value)
                return self.check()
            except BaseException as error:
                value.update(phase='pending',error=dict(type=type(error).__name__,message=str(error)))
                self._save(value)
                # Initializers may already have executed. Never remove their
                # modules to make a second import appear fresh.
                raise

    def check(self):
        require(self.receipt is not None and self.sdk is not None and self.native is not None,
                'original completed SDK import required')
        self._guard()
        require(sys.modules.get('libvirt') is self.sdk and sys.modules.get('libvirtmod') is self.native
                and self.sdk.libvirtmod is self.native, 'original SDK module binding changed')
        row=self.journal.db.execute('SELECT payload,fingerprint FROM libvirt_loop_sdk_imports WHERE id=?',
            (self.receipt['id'],)).fetchone()
        require(row is not None and json.loads(row['payload'])==self.receipt
                and row['fingerprint']==fingerprint(self.receipt), 'original SDK import journal differs')
        with ExitStack() as stack:
            _,proofs,_=self._files(stack)
            require(proofs==self.receipt['assets'], 'original SDK file provenance changed')
        self._guard()
        return self.sdk
