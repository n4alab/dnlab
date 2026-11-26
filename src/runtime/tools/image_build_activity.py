"""Readonly process activity for one original image-build container.

All container cgroup members are retained. Host detection covers the declared
builder entrypoints/roots, not arbitrary opaque automation or future requests.
The operator window, original process observer and shutdown/drain remain separate.
No process is adopted, signalled or started by this provider.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
import posixpath
from pathlib import PurePosixPath
import re

from dnlab_runtime.libvirt_account_process import AccountWorkerObserver
from dnlab_runtime.libvirt_xml import absolute
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.procfs_context import check as check_procfs
from dnlab_runtime.vm_template import TemplateError, require
from cleanup_container_observer import config_digest
from image_build_healthcheck import KIND as HEALTHCHECK_KIND

DIRECTORY = os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC


class ActivityChanged(TemplateError):
    def __init__(self, pid, changes, *, container, reason, command, observed_command,
                 observed_container=None, observed_reason=None):
        self.diagnostic=dict(pid=pid,changed_fields=changes,original_container_member=container,
            original_builder_reason=reason,command_sha256=hashlib.sha256(command).hexdigest(),
            observed_command_sha256=hashlib.sha256(observed_command).hexdigest(),
            observed_container_member=observed_container,observed_builder_reason=observed_reason)
        super().__init__('process changed during activity census '
            f'(pid={pid}, fields={",".join(changes)}, container={container}, builder={reason is not None})')


def _under(path, roots, cwd=None):
    if not isinstance(path,str):return False
    path=path.removesuffix(' (deleted)')
    if not path.startswith('/'):
        if not cwd or not cwd.startswith('/'):return False
        path=posixpath.join(cwd.removesuffix(' (deleted)'),path)
    path=posixpath.normpath(path)
    return path.startswith('/') and any(PurePosixPath(path).is_relative_to(root) for root in roots)


def builder_reason(argv, cwd, roots):
    """Classify only executable/option positions; never run or parse shell text."""
    if not argv:return None
    name=PurePosixPath(argv[0]).name;args=list(argv[1:])
    if re.fullmatch(r'python(?:[23](?:\.[0-9]+)*)?',name):
        while args and args[0] in ('-B','-I','-S','-s','-u','-E'):args.pop(0)
        if args and not args[0].startswith('-') and PurePosixPath(args[0]).name=='build_image.py':return 'image-build-script'
        if len(args)>=2 and args[0]=='-m' and args[1] in ('build_image','dnlab_image_build.build_image'):return 'image-build-script'
    if name in ('make','gmake','ninja'):
        directories=[cwd]
        for index,arg in enumerate(args):
            if arg in ('-C','--directory') and index+1<len(args):
                path=args[index+1];directories.append(path if path.startswith('/') else str(PurePosixPath(cwd or '/')/path))
            elif arg.startswith('--directory='):directories.append(arg.partition('=')[2])
            elif arg.startswith('-C') and len(arg)>2:directories.append(arg[2:])
        if any(_under(path,roots,cwd) for path in directories):return 'scoped-make'
    if name=='qemu-img' and args and args[0] in ('create','convert','resize','rebase','amend','commit'):
        if _under(cwd,roots) or any(_under(arg.rsplit('=',1)[-1],roots,cwd) for arg in args[1:]):return 'scoped-image-write'
    if name=='docker':
        values={'--host','-H','--context','--config','--log-level','-l','--tlscacert','--tlscert','--tlskey'}
        flags={'--debug','-D','--tls','--tlsverify','--help','-h','--version','-v'}
        while args and args[0].startswith('-'):
            option=args.pop(0)
            if option in values:
                if not args:return 'ambiguous-docker-options'
                args.pop(0)
            elif '=' not in option and option not in flags:return 'ambiguous-docker-options'
        if args and args[0]=='build':return 'docker-build'
        if args and args[0] in ('buildx','builder'):
            args.pop(0)
            while args and args[0].startswith('-'):
                option=args.pop(0)
                if option=='--builder' and args:args.pop(0)
                elif '=' not in option:return 'ambiguous-docker-builder-options'
            if args and args[0]=='build':return 'docker-build'
    if name in ('buildctl','buildctl-daemonless.sh') and args and args[0]=='build':return 'buildkit-client'
    return None


def _stat(raw,pid):
    try:
        head,tail=raw.rsplit(b')',1);parts=tail.split()
        observed=int(head.split(b'(',1)[0]);ppid=int(parts[1]);ticks=int(parts[19])
    except (ValueError,IndexError) as error:raise RuntimeError('activity process stat malformed') from error
    require(observed==pid and ppid>=0 and ticks>0, 'activity process generation differs')
    return str(ticks)


class ImageBuildActivity:
    def __init__(self, api, *, context, read_context, proc_identity, roots, proc_root='/proc', record=None,
                 qualify_healthcheck=None):
        require(callable(read_context) and type(roots) is list and roots, 'qualified activity context and build roots required')
        for path in roots:absolute(path)
        self.api,self.context,self.read_context=api,deepcopy(context),read_context
        self.proc_identity,self.roots,self.proc_root=deepcopy(proc_identity),list(roots),proc_root
        require(record is None or callable(record), 'private activity diagnostic writer required')
        self.record,self.diagnostics=record,[]
        require(qualify_healthcheck is None or callable(qualify_healthcheck), 'qualified original healthcheck provider required')
        self.qualify_healthcheck=qualify_healthcheck

    def _classify(self, command, cgroup, root, cid):
        require(not command or command.endswith(b'\0') and command[0]!=0, 'complete activity argv required')
        argv=[os.fsdecode(part) for part in command[:-1].split(b'\0')] if command else []
        belongs=re.search(rb'(?<![0-9a-f])'+cid.encode('ascii')+rb'(?![0-9a-f])',cgroup) is not None
        cwd=None
        if argv and (PurePosixPath(argv[0]).name in ('make','gmake','ninja')
                or PurePosixPath(argv[0]).name=='qemu-img' and len(argv)>1
                and argv[1] in ('create','convert','resize','rebase','amend','commit')):
            cwd=os.readlink('cwd',dir_fd=root)
            require(len(os.fsencode(cwd))<=4096, 'bounded activity cwd required')
        return belongs,builder_reason(argv,cwd,self.roots),cwd

    def _record(self, diagnostic):
        require(len(self.diagnostics)<1024, 'activity transition diagnostic bound exceeded')
        self.diagnostics.append(deepcopy(diagnostic))
        if self.record is not None:self.record(deepcopy(diagnostic))

    def _healthchecks(self, value, inspected, rows):
        if not inspected['State']['Running'] or self.qualify_healthcheck is None:return rows
        members=[row for row in rows if row['container']]
        main=[row for row in members if row['pid']==inspected['State']['Pid']]
        extra=[row for row in members if row not in main]
        if not extra:return rows
        require(len(main)==1, 'original main API missing; no healthcheck exemption')
        proof=self.qualify_healthcheck(deepcopy(value),deepcopy(inspected),deepcopy(members))
        require(type(proof) is dict and set(proof)=={'kind','container_id','image_id','config_sha256',
                'generation_sha256','main_process','processes','evidence_sha256'}
                and proof['kind']==HEALTHCHECK_KIND and proof['container_id']==inspected['Id']
                and proof['image_id']==inspected['Image'] and proof['config_sha256']==config_digest(inspected)
                and proof['main_process']==main[0] and proof['processes']==extra
                and all(type(proof[key]) is str and re.fullmatch('[0-9a-f]{64}',proof[key])
                    for key in ('generation_sha256','evidence_sha256')), 'original qualified healthcheck evidence differs')
        self._record(proof)
        return [row for row in rows if row not in extra]

    def _context(self,proc):
        check_procfs(proc,context=self.context,read_context=self.read_context,
                     proc_identity=self.proc_identity,proc_root=self.proc_root)

    def _scan(self,cid):
        with ExitStack() as stack:
            proc=os.open(self.proc_root,DIRECTORY);stack.callback(os.close,proc);self._context(proc)
            names=os.listdir(proc);require(len(names)<=65536, 'bounded image-build process inventory required')
            selected=[];total=0
            for name in sorted(names):
                if not name.isascii() or not name.isdecimal() or not 0<int(name)<2**31:continue
                try:root=os.open(name,DIRECTORY,dir_fd=proc)
                except FileNotFoundError:continue
                try:
                    def read(path,limit):
                        nonlocal total
                        data=AccountWorkerObserver._read_file(root,path,limit);total+=len(data)
                        require(total<=16*1024*1024, 'image-build process census byte bound exceeded')
                        return data
                    pid=int(name);before=read('stat',16384);ticks=_stat(before,pid)
                    command=read('cmdline',1024*1024);cgroup=read('cgroup',65536)
                    belongs,reason,cwd=self._classify(command,cgroup,root,cid)
                    again=read('stat',16384);next_command=read('cmdline',1024*1024);next_cgroup=read('cgroup',65536)
                    next_belongs,next_reason,next_cwd=self._classify(next_command,next_cgroup,root,cid)
                    changes=[name for name,changed in (('stat',_stat(again,pid)!=ticks),
                             ('cmdline',next_command!=command),('cgroup',next_cgroup!=cgroup),('cwd',next_cwd!=cwd)) if changed]
                    if next_cwd is not None:
                        require(os.readlink('cwd',dir_fd=root)==next_cwd, 'process cwd changed during activity census')
                    original=os.fstat(root);visible=os.stat(name,dir_fd=proc,follow_symlinks=False)
                    require((original.st_dev,original.st_ino)==(visible.st_dev,visible.st_ino), 'activity proc directory replaced')
                    if changes:
                        error=ActivityChanged(pid,changes,container=belongs,reason=reason,command=command,
                            observed_command=next_command,observed_container=next_belongs,observed_reason=next_reason)
                        unrelated=not (belongs or next_belongs or reason or next_reason) and 'stat' not in changes
                        self._record(dict(kind='unrelated-transition' if unrelated else 'candidate-conflict',**error.diagnostic))
                        if not unrelated:raise error
                    if belongs or reason:
                        selected.append(dict(pid=pid,start_ticks=ticks,command_sha256=hashlib.sha256(command).hexdigest(),
                            cgroup_sha256=hashlib.sha256(cgroup).hexdigest(),container=belongs,reason=reason))
                except FileNotFoundError:
                    try:os.stat(name,dir_fd=proc,follow_symlinks=False)
                    except FileNotFoundError:continue
                    raise RuntimeError('live process activity observation incomplete') from None
                finally:os.close(root)
            self._context(proc)
            return sorted(selected,key=lambda value:value['pid'])

    def __call__(self,value):
        self.diagnostics=[]
        actor=value['actor'];cid=actor['container_id']
        require(re.fullmatch('[0-9a-f]{64}',cid) and actor['context_sha256']==fingerprint(self.context)
                and value['scope']['host_id']==self.context['host_id'] and value['scope']['boot_id']==self.context['boot_id'],
                'original image-build activity owner/context differs')
        before=self.api.inspect(cid)
        require(type(before) is dict and before.get('Id')==cid and before.get('Image')==actor['image_id'],
                'original image-build activity container missing/replaced')
        first=self._healthchecks(value,before,self._scan(cid))
        second=self._healthchecks(value,before,self._scan(cid))
        require(first==second, 'image-build processes changed between activity observations')
        container_pids=[row['pid'] for row in first if row['container']]
        if before['State']['Running']:
            require(before['State']['Pid'] in container_pids, 'running image-build API absent from qualified procfs census')
        after=self.api.inspect(cid)
        require(type(after) is dict and after.get('Id')==cid and after.get('Image')==actor['image_id']
                and after['RestartCount']==before['RestartCount'] and all(after['State'][key]==before['State'][key]
                    for key in ('Pid','Running','Status','StartedAt')), 'image-build lifecycle changed during activity census')
        return dict(container_pids=container_pids,
                    host_build_processes=[row for row in first if row['reason'] and not row['container']],complete=True)
