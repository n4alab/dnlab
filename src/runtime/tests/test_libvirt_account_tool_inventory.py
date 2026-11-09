"""Synthetic filesystem only; no account binaries, hooks or host NSS queried."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from dnlab_runtime.manifest import Conflict,fingerprint
from tools import libvirt_account_tool_inventory as module


@pytest.fixture
def inventory(tmp_path):
    root=tmp_path/'root';root.mkdir()
    def write(name,data):
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(data);return path
    write('proc/sys/kernel/random/boot_id','synthetic-boot\n')
    for path in module.BINARIES:write(path,'synthetic executable, never run')
    write('etc/nsswitch.conf','passwd: files\ngroup: files\n')
    write('etc/login.defs','CREATE_HOME yes\n')
    write('etc/default/useradd','HOME=/home\n')
    write('etc/passwd','root:x:0:0:private-gecos:/root:/bin/sh\n')
    write('etc/group','root:x:0:\n')
    for path in module.HOOKS:(root/path).mkdir(parents=True)
    return root,write


def test_collection_is_readonly_and_never_authorizes_provisioning(inventory,monkeypatch):
    root,_=inventory
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('no subprocess allowed'))
    before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    result=module.collect(root)
    assert result['qualified'] is False and result['status']=='collected'
    assert result['observation_sha256']==fingerprint(result['observed'])
    assert 'private-gecos' not in json.dumps(result)
    assert result['observed']['configuration_text']['etc/nsswitch.conf']=='passwd: files\ngroup: files\n'
    assert before=={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_hook_bytes_are_hashed_without_execution_or_recursion(inventory):
    root,write=inventory;path=module.HOOKS[0]
    hook=write(path+'/audit','do not execute\n');hook.chmod(0o755)
    write(path+'/nested/secret','never traverse')
    entries=module.collect(root)['observed']['paths'][path]['entries']
    assert entries['audit']['kind']=='regular' and entries['audit']['sha256']
    assert entries['nested']['kind']=='directory' and 'entries' not in entries['nested']
    assert 'never traverse' not in json.dumps(entries)


@pytest.mark.parametrize('target',[module.BINARIES[0],module.CONFIGS[0],module.HOOKS[0]])
def test_symlinks_are_reported_without_following(inventory,target):
    root,write=inventory;foreign=write('outside','preserve')
    path=root/target
    if path.is_dir():path.rmdir()
    else:path.unlink()
    path.symlink_to(foreign)
    value=module.collect(root)['observed']['paths'][target]
    assert value['kind']=='symlink' and value['followed'] is False and 'sha256' not in value
    assert foreign.read_text()=='preserve'


def test_change_between_reads_is_refused(inventory,monkeypatch):
    root,write=inventory;probe=module.probe;changed=[]
    def changing(fd,path,**kwargs):
        value=probe(fd,path,**kwargs)
        if path=='etc/group' and not changed:
            changed.append(True);write('etc/group','foreign:x:123:\n')
        return value
    monkeypatch.setattr(module,'probe',changing)
    with pytest.raises(Conflict,match='between observations'):module.collect(root)


def test_hook_listing_is_bounded(inventory):
    root,write=inventory
    for index in range(129):write(module.HOOKS[0]+'/'+str(index),'inert')
    with pytest.raises(Conflict,match='entry bound'):module.collect(root)


def test_host_root_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(sys,'argv',['inventory','--fixture-root','/'])
    with pytest.raises(SystemExit) as error:module.main()
    assert error.value.code==2
