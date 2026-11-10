"""Temporary library/link files and synthetic socket stat; no socket created."""
from copy import deepcopy
import hashlib
import json
import os
import stat
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict
from tools.libvirt_bus_prerequisites import collect,LIBRARY,SOCKET


@pytest.fixture
def inventory(tmp_path,monkeypatch):
    root=tmp_path/'fixture';root.mkdir()
    (root/'usr/lib/x86_64-linux-gnu').mkdir(parents=True)
    (root/'run/dbus').mkdir(parents=True)
    target=root/'usr/lib/x86_64-linux-gnu/libsystemd.so.0.39.0';target.write_bytes(b'\x7fELFsynthetic-library');target.chmod(0o644)
    alias=root/LIBRARY;alias.symlink_to(target.name)
    socket=SimpleNamespace(st_dev=1,st_ino=42,st_mode=stat.S_IFSOCK|0o666,st_uid=0,st_gid=0,st_size=0,st_mtime_ns=0,st_ctime_ns=0)
    original_stat=os.stat;original_open=os.open;outputs={}
    expected=dict(host_id='synthetic',boot_id='fixture-boot',namespaces={'pid':dict(device=1,inode=2)})
    def fake_stat(path,*args,**kwargs):
        if path=='system_bus_socket' and kwargs.get('dir_fd') is not None:return socket
        return original_stat(path,*args,**kwargs)
    def no_socket_open(path,*args,**kwargs):
        assert path not in ('system_bus_socket',SOCKET,str(root/SOCKET)),'socket must never be opened'
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(os,'stat',fake_stat);monkeypatch.setattr(os,'open',no_socket_open)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:yield fd,expected,outputs,alias,target,socket
    finally:os.close(fd)


def run(inventory,context=None):
    fd,expected,outputs,_,_,_=inventory
    return collect(fd,expected,context=context or (lambda:deepcopy(expected)),persist=lambda name,raw:outputs.__setitem__(name,raw))


def test_two_stable_passes_hash_library_and_stat_socket_without_qualification(inventory):
    result=run(inventory);_,expected,outputs,_,target,_=inventory
    assert result['context']==expected and result['passes']==2 and result['qualified'] is False
    assert result['library_present'] and result['proof']['socket']['kind']=='socket'
    assert result['proof']['library']['object']['sha256']==hashlib.sha256(target.read_bytes()).hexdigest()
    assert json.loads(outputs['pass1-proof.json'])==json.loads(outputs['pass2-proof.json'])


@pytest.mark.parametrize('target',['../../outside','/usr/lib/foreign.so','foreign.so','libsystemd.so.0/child'])
def test_unqualified_symlink_target_is_not_followed(inventory,target):
    _,_,outputs,alias,_,_=inventory;alias.unlink();alias.symlink_to(target)
    with pytest.raises(Conflict,match='constrained sibling'):run(inventory)
    assert json.loads(outputs['pass1-library-alias.json'])['target']==target


def test_non_elf_and_writable_library_are_rejected(inventory):
    _,_,_,_,target,_=inventory;target.write_bytes(b'not an ELF')
    with pytest.raises(Conflict,match='ELF'):run(inventory)
    target.write_bytes(b'\x7fELFsynthetic');target.chmod(0o666)
    with pytest.raises(Conflict,match='root-controlled'):run(inventory)


def test_context_mismatch_is_saved_before_any_path_read(inventory):
    _,expected,outputs,_,_,_=inventory
    with pytest.raises(Conflict,match='context differs'):run(inventory,lambda:dict(expected,boot_id='foreign'))
    assert set(outputs)=={'pass1-context-before.json'}
    assert json.loads(outputs['pass1-context-before.json'])['matches'] is False


def test_changed_library_between_passes_preserves_both_proofs_and_refuses(inventory):
    _,expected,outputs,_,target,_=inventory;calls=[]
    def context():
        calls.append(True)
        if len(calls)==2:target.write_bytes(b'\x7fELFsynthetic-changed')
        return deepcopy(expected)
    with pytest.raises(Conflict,match='changed between passes'):run(inventory,context)
    assert json.loads(outputs['pass1-proof.json'])!=json.loads(outputs['pass2-proof.json'])


def test_missing_library_is_diagnostic_not_permission_to_install(inventory):
    _,_,_,alias,target,_=inventory;alias.unlink();target.unlink()
    result=run(inventory)
    assert result['qualified'] is False and result['library_present'] is False


def test_non_socket_path_is_saved_and_rejected_without_open(inventory):
    _,_,outputs,_,_,socket=inventory;socket.st_mode=stat.S_IFREG|0o644
    with pytest.raises(Conflict,match='socket metadata'):run(inventory)
    assert json.loads(outputs['pass1-socket.json'])['kind']=='regular'
