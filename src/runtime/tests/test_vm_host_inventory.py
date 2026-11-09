"""Inventory a synthetic filesystem; no host collector invocation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from dnlab_runtime.manifest import Conflict

SCRIPT = Path(__file__).resolve().parents[1]/'tools/vm_host_inventory.py'
spec = importlib.util.spec_from_file_location('vm_host_inventory', SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


@pytest.fixture
def root(tmp_path):
    tree=tmp_path/'synthetic-root'
    for name in ('proc/sys/kernel/random','etc','usr/bin','dev/net'):(tree/name).mkdir(parents=True,exist_ok=True)
    (tree/'proc/sys/kernel/random/boot_id').write_text('11111111-2222-4333-8444-555555555555\n')
    (tree/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
    (tree/'usr/bin/qemu-img').write_text('#!/bin/sh\ntouch should-never-exist\n')
    (tree/'dev/kvm').write_text('synthetic regular file, not KVM')
    return tree


def test_presence_is_only_inventory_and_never_execution_or_device_access(root,monkeypatch):
    open_original=os.open
    def opened(path,*args,**kwargs):
        assert str(path) not in ('kvm','tun'), 'device nodes must never be opened'
        return open_original(path,*args,**kwargs)
    monkeypatch.setattr(os,'open',opened)
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('binary execution prohibited'))
    result=inventory.collect(root,host_id='master',account='dnlab-libvirt')
    assert result['status']=='collected' and result['qualified'] is False
    assert result['local_account'] is None
    assert result['paths']['dev/kvm']['kind']=='regular'
    assert result['paths']['dev/net/tun']['status']=='absent'
    assert result['paths']['usr/bin/qemu-img']['sha256']
    assert not (root/'should-never-exist').exists()


def test_local_account_projection_omits_other_users_and_password_fields(root):
    (root/'etc/passwd').write_text('root:opaque-root-value:0:0:root:/root:/bin/sh\n'
        'dnlab-libvirt:opaque-secret:1001:1002:comment:/var/lib/dnlab-libvirt:/usr/sbin/nologin\n')
    result=inventory.collect(root,host_id='worker-1',account='dnlab-libvirt')
    assert result['local_account']==dict(name='dnlab-libvirt',uid=1001,gid=1002,
        home='/var/lib/dnlab-libvirt',shell='/usr/sbin/nologin')
    assert 'opaque' not in json.dumps(result) and 'comment' not in json.dumps(result)
    assert result['paths']['run/user/1001/libvirt/libvirt-sock']['status']=='absent'


def test_final_and_parent_symlinks_are_reported_without_following(root,tmp_path):
    foreign=tmp_path/'foreign';foreign.mkdir();(foreign/'qemu.conf').write_text('secret-outside-root')
    (root/'usr/bin/virsh').symlink_to(foreign/'qemu.conf')
    (root/'etc/libvirt').symlink_to(foreign,target_is_directory=True)
    result=inventory.collect(root,host_id='master',account='dnlab-libvirt')
    assert result['paths']['usr/bin/virsh']['followed'] is False
    assert 'sha256' not in result['paths']['usr/bin/virsh']
    assert result['paths']['etc/libvirt/qemu.conf']['status']=='unresolved'
    assert 'secret-outside-root' not in json.dumps(result)


def test_fifo_is_not_opened_or_hashed(root):
    os.mkfifo(root/'usr/bin/virsh')
    result=inventory.collect(root,host_id='master',account='dnlab-libvirt')
    assert result['paths']['usr/bin/virsh']['kind']=='unsupported'


def test_changed_boot_is_not_reported_as_a_completed_inventory(root,monkeypatch):
    read=inventory.regular;calls=[]
    def changed(fd,path,limit):
        result=read(fd,path,limit)
        if path=='proc/sys/kernel/random/boot_id':
            calls.append(True)
            if len(calls)>1:return b'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n'
        return result
    monkeypatch.setattr(inventory,'regular',changed)
    with pytest.raises(Conflict,match='boot changed'):inventory.collect(root,host_id='master',account='dnlab-libvirt')


def test_ambiguous_account_and_oversized_config_are_rejected(root):
    item='dnlab-libvirt:x:1001:1002::/nonexistent:/bin/false\n'
    (root/'etc/passwd').write_text(item*2)
    with pytest.raises(Conflict,match='ambiguous'):inventory.collect(root,host_id='master',account='dnlab-libvirt')
    (root/'etc/passwd').write_text(item)
    path=root/'etc/os-release'
    with path.open('wb') as stream:stream.truncate(1024*1024+1)
    with pytest.raises(Conflict,match='bound'):inventory.collect(root,host_id='master',account='dnlab-libvirt')


def test_cli_isolated_bootstrap_uses_only_synthetic_root_and_no_cache(root,tmp_path):
    result=subprocess.run([sys.executable,'-B','-I','-S',str(SCRIPT),'--fixture-root',str(root),
        '--host-id','synthetic-master'],capture_output=True,text=True,timeout=10,cwd=tmp_path)
    assert result.returncode==0,result.stderr
    report=json.loads(result.stdout)
    assert report['qualified'] is False and report['host_id']=='synthetic-master'
    assert not result.stderr and not list(root.rglob('__pycache__'))


def test_cli_requires_explicit_host_collection_flag():
    with pytest.raises(SystemExit) as error:inventory.main(['--fixture-root','/','--host-id','master'])
    assert error.value.code==2
