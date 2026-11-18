"""Standalone inherited-FD entry; stdlib only until sources are authenticated."""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


def require(value,message):
    if not value:raise ValueError(message)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def metadata(info):
    return (*identity(info),info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def directory(stack,path):
    require(isinstance(path,str) and path.startswith('/') and '..' not in path.split('/'),
            'absolute original source directory required')
    current=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);stack.callback(os.close,current)
    for part in PurePosixPath(path).parts[1:]:
        parent=current
        current=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        stack.callback(os.close,current)
        info=os.fstat(current)
        require(info.st_uid==0 and (not info.st_mode&0o022 or info.st_mode&stat.S_ISVTX),
                'root-controlled source directory required')
        require(identity(info)==identity(os.stat(part,dir_fd=parent,follow_symlinks=False)),
                'original source directory changed')
    return current


class VerifiedSources:
    """Explicit source-only finder. No pyc/site/path fallback for runtime modules."""
    tools={'libvirt_loop_canary_child','libvirt_loop_sdk','libvirt_event_loop_canary'}
    def __init__(self,manifest):
        require(type(manifest) is dict and set(manifest)=={'root','files'}
                and type(manifest['files']) is dict and 1<=len(manifest['files'])<=256,
                'bounded original source manifest required')
        for path,digest in manifest['files'].items():
            require(isinstance(path,str) and re.fullmatch(r'(dnlab_runtime|tools)/[A-Za-z0-9_]+\.py',path)
                    and isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest),
                    'explicit flat runtime source/hash required')
        self.manifest=json.loads(json.dumps(manifest));self.expected=fingerprint(self.manifest)

    def read(self,path):
        require(path in self.manifest['files'], 'undeclared runtime source refused')
        with ExitStack() as stack:
            root=directory(stack,self.manifest['root'])
            part,name=path.split('/')
            parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
            stack.callback(os.close,parent);info=os.fstat(parent)
            require(info.st_uid==0 and not info.st_mode&0o022, 'root-controlled runtime package required')
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
            stack.callback(os.close,fd);before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022
                    and 0<before.st_size<=4*1024*1024, 'bounded root-controlled runtime source required')
            raw=os.pread(fd,before.st_size+1,0)
            require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==self.manifest['files'][path],
                    'original runtime source hash differs')
            require(metadata(before)==metadata(os.fstat(fd))==metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))
                    and identity(info)==identity(os.stat(part,dir_fd=root,follow_symlinks=False)),
                    'original runtime source changed during read')
            return raw

    def verify(self):
        require(fingerprint(self.manifest)==self.expected, 'original source manifest changed')
        for path in self.manifest['files']:self.read(path)
        return self.expected

    def find_spec(self,fullname,path=None,target=None):
        if fullname=='dnlab_runtime':relative='dnlab_runtime/__init__.py';package=True
        elif fullname.startswith('dnlab_runtime.'):
            suffix=fullname[len('dnlab_runtime.'):]
            require(re.fullmatch(r'[A-Za-z0-9_]+',suffix), 'undeclared nested runtime package refused')
            relative='dnlab_runtime/'+suffix+'.py';package=False
        elif fullname in self.tools:relative='tools/'+fullname+'.py';package=False
        else:return None
        require(relative in self.manifest['files'], 'undeclared runtime import refused')
        source=self
        class Loader:
            def create_module(self,spec):return None
            def exec_module(self,module):
                filename=source.manifest['root']+'/'+relative
                module.__file__=filename
                exec(compile(source.read(relative),filename,'exec',dont_inherit=True),module.__dict__)
        return importlib.util.spec_from_loader(fullname,Loader(),is_package=package)


def read_bootstrap(fd):
    require(type(fd) is int and fd>=3, 'private inherited bootstrap descriptor required')
    before=os.fstat(fd)
    seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
    require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and 0<before.st_size<=1024*1024
            and fcntl.fcntl(fd,fcntl.F_GET_SEALS)==seals, 'original sealed bootstrap required')
    raw=os.pread(fd,before.st_size+1,0)
    require(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd)), 'bootstrap changed during read')
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result, 'duplicate bootstrap field');result[key]=value
        return result
    def constant(value):raise ValueError('nonfinite bootstrap value')
    packet=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    require(type(packet) is dict and set(packet)=={'request','bootstrap'}, 'original bootstrap fields required')
    return packet


def context():
    with open('/proc/sys/kernel/random/boot_id',encoding='ascii') as stream:boot=stream.read(128).strip()
    spaces={}
    for name in ('pid','mnt','net','user'):
        info=os.stat('/proc/thread-self/ns/'+name);spaces[name]=dict(device=info.st_dev,inode=info.st_ino)
    return dict(boot_id=boot,namespaces=spaces)


def execute(packet):
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.geteuid()==0 and os.getegid()==0, 'original isolated root canary interpreter required')
    request=packet['request'];data=packet['bootstrap']
    require(type(data) is dict and set(data)=={'host_id','context','sources','sdk','journal_directory'},
            'explicit loop child scope required')
    require(context()==data['context'], 'original child context differs')
    command=request['command']
    require(command['argv'][1:4]==['-B','-I','-S'] and command['argv'][4:]==sys.argv,
            'original inherited child argv differs')
    sources=VerifiedSources(data['sources']);sources.verify()
    main='tools/libvirt_loop_canary_main.py'
    require(main in sources.manifest['files'] and sys.argv[0].startswith('/proc/self/fd/'),
            'original inherited worker source required')
    fd=int(sys.argv[0][len('/proc/self/fd/'):])
    require(hashlib.sha256(os.pread(fd,1024*1024+1,0)).hexdigest()==sources.manifest['files'][main],
            'inherited worker/source manifest differs')
    require(not any(name=='dnlab_runtime' or name.startswith('dnlab_runtime.') or name in sources.tools
                    for name in sys.modules), 'fresh child source modules required')
    sys.meta_path.insert(0,sources)
    from dnlab_runtime.journal import Journal
    from libvirt_loop_canary_child import ChildFrames, run_child
    from libvirt_loop_sdk import LoopSDK
    def verify_sources():
        require(context()==data['context'], 'original child context changed')
        return sources.verify()
    profile=dict(host_id=data['host_id'],executable_sha256=command['binary']['sha256'],
        cmdline_sha256=hashlib.sha256(b'\0'.join(value.encode() for value in command['argv'])+b'\0').hexdigest(),
        namespaces=data['context']['namespaces'],sources_sha256=sources.expected)
    path=PurePosixPath(data['journal_directory'])
    require(path.is_absolute() and '..' not in path.parts, 'private child journal path required')
    with ExitStack() as stack:
        parent=directory(stack,str(path.parent));before=os.fstat(parent)
        require(stat.S_IMODE(before.st_mode)==0o700, 'original private output directory required')
        os.mkdir(path.name,mode=0o700,dir_fd=parent);os.fsync(parent)
        created=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        child=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        stack.callback(os.close,child)
        require(identity(created)==identity(os.fstat(child)), 'original child journal directory differs')
        journal=Journal(Path('/proc/self/fd/'+str(child)))
        try:
            require(identity(created)==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                    'original child journal directory changed')
            with journal.transaction():
                journal.db.execute('CREATE TABLE libvirt_loop_child_bootstrap (payload TEXT NOT NULL)')
                journal.db.execute('INSERT INTO libvirt_loop_child_bootstrap VALUES(?)',
                    (json.dumps(dict(request_sha256=fingerprint(request),context=data['context'],
                        sources_sha256=sources.expected,directory=list(identity(created))),sort_keys=True),))
            def sdk_scope():verify_sources();return fingerprint(data['sdk'])
            sdk=LoopSDK(journal,data['sdk'],preflight=sdk_scope)
            frames=ChildFrames(0,1)
            return run_child(request,profile,journal,verify_sources=verify_sources,
                load_sdk=sdk.load,check_sdk=sdk.check,read_frame=frames.receive,write_frame=frames.send)
        finally:journal.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-fd',required=True,type=int)
    args=parser.parse_args()
    return execute(read_bootstrap(args.bootstrap_fd))


if __name__=='__main__':raise SystemExit(main())
