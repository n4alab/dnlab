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
from dnlab_runtime.vm_template import require

DIRECTORY = os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC


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
    def __init__(self, api, *, context, read_context, proc_identity, roots, proc_root='/proc'):
        require(callable(read_context) and type(roots) is list and roots, 'qualified activity context and build roots required')
        for path in roots:absolute(path)
        self.api,self.context,self.read_context=api,deepcopy(context),read_context
        self.proc_identity,self.roots,self.proc_root=deepcopy(proc_identity),list(roots),proc_root

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
                    require(not command or command.endswith(b'\0') and command[0]!=0, 'complete activity argv required')
                    argv=[os.fsdecode(part) for part in command[:-1].split(b'\0')] if command else []
                    belongs=re.search(rb'(?<![0-9a-f])'+cid.encode('ascii')+rb'(?![0-9a-f])',cgroup) is not None
                    cwd=None
                    needs_cwd=bool(argv) and (PurePosixPath(argv[0]).name in ('make','gmake','ninja')
                        or PurePosixPath(argv[0]).name=='qemu-img' and len(argv)>1
                        and argv[1] in ('create','convert','resize','rebase','amend','commit'))
                    if needs_cwd:
                        cwd=os.readlink('cwd',dir_fd=root);require(len(os.fsencode(cwd))<=4096, 'bounded activity cwd required')
                    reason=builder_reason(argv,cwd,self.roots)
                    again=read('stat',16384)
                    require(_stat(again,pid)==ticks and read('cmdline',1024*1024)==command and read('cgroup',65536)==cgroup,
                            'process changed during activity census')
                    if needs_cwd:require(os.readlink('cwd',dir_fd=root)==cwd, 'process cwd changed during activity census')
                    original=os.fstat(root);visible=os.stat(name,dir_fd=proc,follow_symlinks=False)
                    require((original.st_dev,original.st_ino)==(visible.st_dev,visible.st_ino), 'activity proc directory replaced')
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
        actor=value['actor'];cid=actor['container_id']
        require(re.fullmatch('[0-9a-f]{64}',cid) and actor['context_sha256']==fingerprint(self.context)
                and value['scope']['host_id']==self.context['host_id'] and value['scope']['boot_id']==self.context['boot_id'],
                'original image-build activity owner/context differs')
        before=self.api.inspect(cid)
        require(type(before) is dict and before.get('Id')==cid and before.get('Image')==actor['image_id'],
                'original image-build activity container missing/replaced')
        first=self._scan(cid);second=self._scan(cid)
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
