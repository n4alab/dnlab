"""Readonly original runtime lock and local checkout binding, without Git.

Only the release repository/branch/commit and dedicated local remote are parsed.
Other Git settings remain opaque bytes, used only to detect concurrent changes.
No config hook, include, command or credential helper is evaluated.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import PurePosixPath
import re

from image_build_ledger import _file, identity
from dnlab_runtime.image_build_hold import actor
from dnlab_runtime.libvirt_xml import absolute
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_bundle import metadata, unique_pairs
from dnlab_runtime.vm_template import digest, fields, require

DIRECTORY=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
REMOTES=('https://github.com/n4alab/vrnetlab.git','git@github.com:n4alab/vrnetlab.git')


def _directory(stack, path):
    fd=os.open('/',DIRECTORY);stack.callback(os.close,fd)
    for part in PurePosixPath(path).parts[1:]:
        fd=os.open(part,DIRECTORY,dir_fd=fd);stack.callback(os.close,fd)
        info=os.fstat(fd)
        require(info.st_uid==0 and not info.st_mode&0o022, 'root-controlled checkout ancestors required')
    return fd


def remote_url(raw):
    selected=False;sections=0;urls=[]
    for line in raw.decode('utf-8').splitlines():
        text=line.strip()
        if not text or text.startswith(('#',';')):continue
        if text.startswith('['):
            selected=re.fullmatch(r'\[remote\s+"dnlab"\]\s*(?:[#;].*)?',text,re.IGNORECASE) is not None
            if selected:sections+=1
        elif selected:
            match=re.fullmatch(r'url\s*=\s*(.+)',text,re.IGNORECASE)
            if match:
                value=match[1].strip()
                if value.startswith('"'):value=json.loads(value)
                urls.append(value)
    require(sections==1 and len(urls)==1 and urls[0] in REMOTES, 'one corresponding local dnlab remote required')
    return urls[0]


def _scan(profile, read_context, read_lock):
    require(read_context()==profile['context'], 'original binding context differs')
    expected=profile['binding'];raw=read_lock(profile['lock_sha256'])
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==profile['lock_sha256'],
            'original runtime lock bytes required')
    lock=json.loads(raw,object_pairs_hook=unique_pairs)
    fields(lock,('schema_version','repository','branch','commit'),'runtime vrnetlab lock')
    require(type(lock['schema_version']) is int and lock['schema_version']==1
            and lock['repository']==expected['repository'] and lock['branch']==expected['branch']
            and lock['commit']==expected['current_commit'], 'original runtime lock binding differs')
    with ExitStack() as stack:
        root=_directory(stack,profile['checkout']);git=os.open('.git',DIRECTORY,dir_fd=root);stack.callback(os.close,git)
        require(os.fstat(git).st_uid==0 and not os.fstat(git).st_mode&0o022, 'root-controlled Git directory required')
        directories=dict(checkout=identity(os.fstat(root)),git=identity(os.fstat(git)))
        assets={}
        def read(name,limit=1024*1024):
            proof,data=_file(git,name,limit,content=True);assets[name]=proof;return data
        head=read('HEAD',4096).decode('ascii').strip();config=read('config');remote=remote_url(config)
        if head.startswith('ref: '):
            reference=head[5:]
            require(reference=='refs/heads/'+expected['branch'], 'checkout points to another local branch')
            # Traverse each parent without following symlinks, including refs.
            parent=git;parts=reference.split('/')
            try:
                for part in parts[:-1]:
                    parent=os.open(part,DIRECTORY,dir_fd=parent);stack.callback(os.close,parent)
                    require(os.fstat(parent).st_uid==0 and not os.fstat(parent).st_mode&0o022,
                            'root-controlled Git ref directory required')
                proof,data=_file(parent,parts[-1],4096,content=True)
                assets[reference]=proof;head=data.decode('ascii').strip()
            except FileNotFoundError:
                packed=read('packed-refs').decode('ascii').splitlines()
                matches=[line.split(' ')[0] for line in packed if line.endswith(' '+reference)]
                require(len(matches)==1, 'original unique packed branch ref required');head=matches[0]
        require(re.fullmatch('[0-9a-f]{40}',head) is not None and head==expected['current_commit'],
                'original checkout commit differs')
        # No file/config path is followed from its contents except the fixed
        # original branch reference, whose components are traversed above.
        visible=_directory(stack,profile['checkout'])
        require(identity(os.fstat(visible))==directories['checkout']
                and identity(os.stat('.git',dir_fd=visible,follow_symlinks=False))==directories['git'],
                'original checkout path changed during read')
        require(read_context()==profile['context'] and read_lock(profile['lock_sha256'])==raw,
                'runtime lock/context changed during checkout observation')
        return dict(directories=directories,assets=assets,head=head,remote=remote)


def capture_binding(*, checkout, binding, original_actor, lock_sha256, context, read_context, read_lock):
    absolute(checkout);actor(original_actor)
    fields(binding,('state','repository','branch','requested_commit','current_commit','detail'),'original API binding')
    require(binding['state']=='aligned' and binding['detail'] is None and binding['repository'] in REMOTES
            and binding['branch']=='dnlab' and re.fullmatch('[0-9a-f]{40}',binding['current_commit']) is not None
            and binding['requested_commit']==binding['current_commit'] and digest(lock_sha256)
            and original_actor['context_sha256']==fingerprint(context), 'original aligned dnlab binding required')
    profile=dict(checkout=checkout,binding=deepcopy(binding),lock_sha256=lock_sha256,
                 actor_sha256=fingerprint(original_actor),context=deepcopy(context))
    first=_scan(profile,read_context,read_lock);second=_scan(profile,read_context,read_lock)
    require(first==second, 'checkout changed during binding capture')
    return dict(profile=profile,evidence=first)


class ImageBuildBinding:
    def __init__(self, receipt, *, expected_sha256, read_context, read_lock):
        require(digest(expected_sha256) and fingerprint(receipt)==expected_sha256
                and callable(read_context) and callable(read_lock), 'original binding receipt/providers required')
        self.receipt,self.sha256=deepcopy(receipt),expected_sha256
        self.read_context,self.read_lock=read_context,read_lock

    def __call__(self, value):
        require(fingerprint(self.receipt)==self.sha256 and fingerprint(value['actor'])==self.receipt['profile']['actor_sha256'],
                'original binding owner/receipt differs')
        first=_scan(self.receipt['profile'],self.read_context,self.read_lock)
        require(first==self.receipt['evidence'] and _scan(self.receipt['profile'],self.read_context,self.read_lock)==first,
                'original checkout binding evidence changed')
        return deepcopy(self.receipt['profile']['binding'])
