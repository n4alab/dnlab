"""Original boot/observer under test; sockets and credentials are synthetic."""
from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import PurePosixPath
import socket
import stat
import struct
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime import vm_console
from dnlab_runtime.manifest import RuntimeErrorBase
from test_vm_boot import boot, definition, template, instance


@pytest.fixture
def console(boot, tmp_path, monkeypatch):
    driver, operation, state, process, _ = boot
    original = driver.apply(operation)
    path = PurePosixPath(ET.fromstring(original['xml']).find('devices/serial/source').get('path'))
    parent = dict(device=4, inode=9, uid=1001, gid=1001, mode=0o700)
    directory = dict(phase='ready', birth=deepcopy(original['birth']),
        definition_sha256=original['request_fingerprint'], spec=dict(path=str(path.parent)),
        proof=dict(identity=dict(parent, kind='directory')))
    observed = dict(endpoint=dict(device=4, inode=10, uid=1001, gid=1001, mode=stat.S_IFSOCK|0o600),
                    peer=(process['pid'],1001,1001), connects=[], sends=[], closed=0, pinned=0,
                    hook=None, send_error=None)
    directories = SimpleNamespace(definitions=driver.definitions, journal=driver.journal,
                                  observe=lambda op:deepcopy(directory))
    @contextmanager
    def pin():
        fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
        observed['pinned']+=1
        try:yield fd
        finally:observed['pinned']-=1;os.close(fd)
    monkeypatch.setattr(vm_console,'directory_identity',lambda fd:deepcopy(parent))
    monkeypatch.setattr(vm_console,'socket_identity',lambda fd,name:deepcopy(observed['endpoint']))
    class Socket:
        def __init__(self,family,kind):assert (family,kind)==(socket.AF_UNIX,socket.SOCK_STREAM)
        def settimeout(self,timeout):assert timeout==1
        def connect(self,name):
            assert observed['pinned']==1 and name.startswith('/proc/self/fd/') and name.endswith('/'+path.name)
            observed['connects'].append(name)
            if observed['hook']:observed['hook']()
        def getsockopt(self,level,key,size):
            assert (level,key,size)==(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            return struct.pack('3i',*observed['peer'])
        def recv(self,size):return b'guest prompt'
        def send(self,data):
            observed['sends'].append(data)
            if observed['send_error']:raise observed['send_error']
            return min(2,len(data))
        def close(self):observed['closed']+=1
    value=vm_console.VMConsole(driver,directories,operation,pin_directory=pin,socket_factory=Socket)
    return value,observed,directory,process,state


def test_original_console_reads_and_returns_short_write_without_replay(console):
    value,observed,_,_,state=console
    with value.connect() as stream:
        assert stream.recv()==b'guest prompt'
        assert stream.send(b'command')==2
        assert observed['sends']==[b'command'] and observed['pinned']==1
    assert observed['closed']==1 and observed['pinned']==0
    assert state['starts']==state['resumes']==1
    with pytest.raises(RuntimeErrorBase,match='closed'):stream.send(b'again')


@pytest.mark.parametrize('fault',['pid','uid','gid','socket','process'])
def test_connect_rejects_peer_or_generation_change_without_guest_io(console,fault):
    value,observed,_,process,_=console
    def change():
        if fault in ('pid','uid','gid'):
            peer=list(observed['peer']);peer[('pid','uid','gid').index(fault)]+=1;observed['peer']=tuple(peer)
        elif fault=='socket':observed['endpoint']['inode']+=1
        else:process['start_ticks']+=1
    observed['hook']=change
    with pytest.raises(RuntimeErrorBase):
        with value.connect():pytest.fail('foreign console was exposed')
    assert observed['closed']==1 and observed['pinned']==0 and not observed['sends']


def test_replacement_after_connect_is_rejected_before_write(console):
    value,observed,_,_,_=console
    with value.connect() as stream:
        observed['endpoint']['inode']+=1
        with pytest.raises(RuntimeErrorBase):stream.send(b'never sent')
    assert not observed['sends'] and observed['closed']==1


def test_uncertain_send_cannot_be_replayed_on_original_stream(console):
    value,observed,_,_,_=console
    observed['send_error']=TimeoutError('unknown written prefix')
    with value.connect() as stream:
        with pytest.raises(TimeoutError):stream.send(b'one command')
        with pytest.raises(RuntimeErrorBase,match='closed'):stream.send(b'one command')
    assert observed['sends']==[b'one command'] and observed['closed']==1


def test_lost_monitor_rejects_console_without_restarting_guest(console):
    value,observed,_,_,state=console;state['monitor_alive']=False
    with pytest.raises(RuntimeErrorBase):
        with value.connect():pytest.fail('lost monitor admitted')
    assert not observed['connects'] and state['starts']==state['resumes']==1
