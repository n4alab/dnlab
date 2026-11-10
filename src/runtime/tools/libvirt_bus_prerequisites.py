"""Two-pass readonly library/socket inventory; no load, open-bus or commands.

Only the fixed amd64 library alias, a constrained sibling target and bus socket
metadata are inspected. Context and private persistence are explicit providers.
There is no CLI/native default or permission to qualify a daemon from this report.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat

from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vm_bundle import metadata,pinned_file
from tools.vm_host_inventory import probe

LIBRARY='usr/lib/x86_64-linux-gnu/libsystemd.so.0'
SOCKET='run/dbus/system_bus_socket'
PARENTS=('usr','usr/lib','usr/lib/x86_64-linux-gnu','run','run/dbus')
LIMIT=16*1024*1024


def require(condition,message):
    if not condition:raise Conflict(message)


def library_path(alias):
    require(alias['status']=='present' and alias['metadata'][3]==0,'original library alias metadata differs')
    path=LIBRARY
    if alias['kind']=='symlink':
        target=alias['target']
        require(isinstance(target,str) and re.fullmatch(r'libsystemd\.so\.[0-9]+(?:\.[0-9]+)*',target) is not None,
            'library target must be a constrained sibling')
        path=str(PurePosixPath(LIBRARY).parent/target)
    else:require(alias['kind']=='regular','library alias must be regular or one symlink')
    return path


def hash_library(fd, info):
    require(info.st_uid==0 and not info.st_mode&0o022 and 4<=info.st_size<=LIMIT,'bounded root-controlled library required')
    digest=hashlib.sha256();total=0;header=b''
    while total<=info.st_size:
        block=os.read(fd,min(65536,info.st_size+1-total))
        if not block:break
        if not header:header=block[:4]
        total+=len(block);digest.update(block)
    require(total==info.st_size and header==b'\x7fELF','bounded ELF library bytes required')
    return dict(metadata=list(metadata(info)),sha256=digest.hexdigest(),bytes=total)


def library(root,persist):
    alias=probe(root,LIBRARY);persist('library-alias.json',json.dumps(alias,sort_keys=True).encode())
    if alias['status']=='absent':return dict(alias=alias,object=None,path=None)
    path=library_path(alias)
    with pinned_file(root,path) as (fd,info):
        value=hash_library(fd,info)
    require(probe(root,LIBRARY)==alias,'library alias changed during read')
    return dict(alias=alias,object=value,path=path)


def collect(root,expected,*,context,persist,socket_probe=probe):
    """root is an already opened directory FD, never followed or opened here."""
    require(callable(context) and callable(persist) and callable(socket_probe),'explicit inventory providers required')
    expected=deepcopy(expected);snapshots=[]
    def check(index,phase):
        observed=context()
        persist(f'pass{index}-context-{phase}.json',json.dumps(dict(expected=expected,observed=observed,matches=observed==expected),sort_keys=True).encode())
        require(observed==expected,'bus prerequisite context differs')
    for index in (1,2):
        check(index,'before')
        parents={path:probe(root,path) for path in PARENTS}
        persist(f'pass{index}-parents.json',json.dumps(parents,sort_keys=True).encode())
        for path,row in parents.items():
            require(row['status']=='present' and row['kind']=='directory' and row['metadata'][3]==0
                and not row['metadata'][2]&0o022,'bus prerequisite parent differs: '+path)
        lib=library(root,lambda name,raw:persist(f'pass{index}-'+name,raw))
        sock=socket_probe(root,SOCKET)
        persist(f'pass{index}-socket.json',json.dumps(sock,sort_keys=True).encode())
        require(sock['status']=='present' and sock['kind']=='socket' and sock['metadata'][3]==0
            and stat.S_ISSOCK(sock['metadata'][2]),'root-owned system bus socket metadata required')
        snapshot=dict(parents=parents,library=lib,socket=sock)
        persist(f'pass{index}-proof.json',json.dumps(snapshot,sort_keys=True).encode())
        snapshots.append(snapshot);check(index,'after')
    require(snapshots[0]==snapshots[1],'bus prerequisites changed between passes')
    return dict(status='collected',qualified=False,context=expected,passes=2,proof=snapshots[0],
        library_present=snapshots[0]['library']['object'] is not None,
        limitations=['No CDLL, ELF execution, symbol lookup, socket open/connect or service query',
            'No package database, account/NSS, original journal or service mutation',
            'This inventory is not library ABI, peer, manager or daemon readiness qualification'])
