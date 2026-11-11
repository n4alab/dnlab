"""Readonly post-boot observation, never ownership adoption or qualification.

Snapshot, current identity and original journal readers remain explicit. Volatile
paths are inspected without following symlinks and never read as old births.
The caller retains diagnostics and separately validates persistent qualification.
"""
from copy import deepcopy
import os
from pathlib import Path
import stat

from dnlab_runtime.libvirt_postboot import context,plan
from dnlab_runtime.libvirt_configuration import UNIT
from dnlab_runtime.libvirt_provisioning import account_request
from dnlab_runtime.manifest import Conflict,fingerprint


class PostBootObserver:
    def __init__(self,root,installation,current,*,source_reader,snapshot,identity,files,directory_dependency,
                 completed_revision=None):
        self.root=Path(root);self.installation=deepcopy(installation);self.context=context(current)
        self.layout=plan(installation,current)
        if (not self.root.is_absolute() or not all(callable(fn) for fn in (source_reader,snapshot,identity,directory_dependency))
                or getattr(files,'readonly',False) is not True or Path(files.root)!=self.root):
            raise Conflict('explicit readonly post-boot observers required')
        self.source_reader,self.snapshot,self.identity,self.files,self.directory_dependency=source_reader,snapshot,identity,files,directory_dependency
        self.completed_revision=completed_revision
        self.diagnostics=None

    def _source(self):
        if self.source_reader(self.installation['id'])!=self.installation:
            raise Conflict('original post-boot observation source changed')

    def _snapshot(self):
        self.diagnostics['stage']='snapshot'
        value=self.snapshot()
        self.diagnostics['snapshot']=deepcopy(value)
        if (not isinstance(value,dict) or set(value)!={'context','prerequisites'}
                or context(value['context'])!=self.context or not isinstance(value['prerequisites'],dict)):
            raise Conflict('explicit current post-boot snapshot differs')
        return deepcopy(value)

    def _volatile(self,item,entry):
        try:
            with self.files._parent(item['spec']['path']) as (parent,name):
                observed=os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            entry['state']='absent';return dict(state='absent')
        entry.update(state='present_unqualified',metadata=dict(device=observed.st_dev,inode=observed.st_ino,
            uid=observed.st_uid,gid=observed.st_gid,mode=stat.S_IMODE(observed.st_mode),
            kind='directory' if stat.S_ISDIR(observed.st_mode) else 'symlink' if stat.S_ISLNK(observed.st_mode) else 'other'))
        return dict(state='present_unqualified')

    def __call__(self,value):
        if (value['installation']!=self.installation or value['context']!=self.context
                or value['source_sha256']!=fingerprint(self.installation) or value['plan']!=self.layout):
            raise Conflict('original post-boot collection binding differs')
        binding=(self.completed_revision.binding(self.installation,self.context)
                 if self.completed_revision is not None else None)
        if binding!=value.get('completed_revision'):
            raise Conflict('original post-boot revision observation binding differs')
        self.diagnostics=dict(stage='source',status='requested',targets=[])
        try:
            self._source();before=self._snapshot();persistent={};volatile={}
            self.diagnostics['stage']='targets'
            for item in self.installation['items']:
                spec=item['spec'];key=spec['key']
                entry=dict(key=key,kind=spec['kind'],status='requested');self.diagnostics['targets'].append(entry)
                if key in self.layout['volatile']:
                    volatile[key]=self._volatile(item,entry)
                else:
                    if item['phase']=='dependency':current=self.directory_dependency(deepcopy(spec))
                    elif spec['kind'] in ('group','account'):
                        request=account_request(item,self.installation['id']);identity=self.identity(deepcopy(request))
                        entry['identity']=deepcopy(identity)
                        if identity!=request['expected'] or item['proof']['identity']!=request['expected']:
                            raise Conflict('current account identity differs: '+key)
                        current=deepcopy(item['proof'])
                    elif binding is not None and spec.get('path')==UNIT:
                        current=self.completed_revision.observe(self.installation,self.context)['replacement']
                        persistent[key]=current
                        entry.update(proof=deepcopy(current),status='observed')
                        continue
                    else:current=self.files.observe(deepcopy(item),self.installation['id'])
                    entry['proof']=deepcopy(current)
                    if current!=item['proof']:raise Conflict('original persistent post-boot resource differs: '+key)
                    persistent[key]=current
                entry['status']='observed'
            self._source()
            if self._snapshot()!=before:raise Conflict('post-boot snapshot changed during observation')
            self._source();self.diagnostics.update(stage='completed',status='collected')
            return dict(context=before['context'],prerequisites=before['prerequisites'],persistent=persistent,volatile=volatile)
        except BaseException as error:
            self.diagnostics.update(status='failed',error=dict(type=type(error).__name__,message=str(error)))
            raise
