"""Bounded readonly account-tool profile collection, never account execution.

Only fixed binaries/configuration and useradd hook directories are inventoried.
Symlinks are reported without following them. Collection is not qualification
of NSS results, linked libraries, hooks or permission to provision an account.
"""
import argparse
import json
import os
from pathlib import Path
import sys

if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.manifest import Conflict,fingerprint
from dnlab_runtime.vm_bundle import metadata
from tools.vm_host_inventory import entry,probe,regular

BINARIES=('usr/sbin/useradd','usr/sbin/groupadd')
CONFIGS=('etc/nsswitch.conf','etc/login.defs','etc/default/useradd')
DATABASES=('etc/passwd','etc/group','etc/subuid','etc/subgid')
HOOKS=('etc/shadow-maint/useradd-pre.d','etc/shadow-maint/useradd-post.d')


def hook_directory(root,path):
    result=probe(root,path)
    if result.get('kind')!='directory':return result
    with entry(root,path) as (parent,name,info):
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            if metadata(os.fstat(fd))!=metadata(info):raise Conflict('hook directory changed before read')
            names=sorted(os.listdir(fd))
            if len(names)>128:raise Conflict('hook directory exceeds entry bound')
            result['entries']={name:probe(fd,name,content=True,limit=1024*1024) for name in names}
            if names!=sorted(os.listdir(fd)) or metadata(os.fstat(fd))!=metadata(info):
                raise Conflict('hook directory changed during read')
        finally:os.close(fd)
    return result


def collect(root):
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    def snapshot():
        boot=regular(fd,'proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        if not boot:raise Conflict('account inventory boot identity missing')
        paths={path:probe(fd,path,content=True,limit=128*1024*1024) for path in BINARIES}
        for path in CONFIGS+DATABASES:paths[path]=probe(fd,path,content=True,limit=1024*1024)
        configs={path:regular(fd,path,1024*1024).decode('utf-8')
            for path in CONFIGS if paths[path].get('kind')=='regular'}
        for path in HOOKS:paths[path]=hook_directory(fd,path)
        return dict(boot_id=boot,paths=paths,configuration_text=configs)
    try:
        first=snapshot();second=snapshot()
        if first!=second:raise Conflict('account inventory changed between observations')
    finally:os.close(fd)
    return dict(status='collected',qualified=False,observation_sha256=fingerprint(first),observed=first,
        limitations=['No account binaries, commands, hooks or NSS lookup executed',
            'No shadow/gshadow contents collected; passwd/group/subids are hash/metadata only',
            'Symlinks and nested hook directories not followed; contents require explicit review',
            'No linked-library qualification, account allocation or provisioning window'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--collect-host',action='store_true')
    source.add_argument('--fixture-root',type=Path)
    args=parser.parse_args()
    root=Path('/') if args.collect_host else args.fixture_root
    if not args.collect_host and root.resolve()==Path('/'):
        parser.error('host collection requires --collect-host')
    print(json.dumps(collect(root),sort_keys=True))


if __name__=='__main__':main()
