"""An unrelated local listener cannot establish SSH tunnel readiness."""
from contextlib import contextmanager
import select
import socket
import subprocess
import sys
import pytest
from app.services.webui_service import _wait_for_bind, WebUITunnelError


@contextmanager
def inert_child(listener=False):
    source='import sys; print("ready",flush=True); sys.stdin.buffer.read()'
    if listener:
        source='import socket,sys; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); print(s.getsockname()[1],flush=True); sys.stdin.buffer.read(); s.close()'
    proc=subprocess.Popen([sys.executable,'-u','-c',source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        assert select.select([proc.stdout],[],[],3)[0], 'inert child did not reach readiness'
        line=proc.stdout.readline().decode().strip()
        assert proc.poll() is None
        yield proc,line
    finally:
        proc.stdin.close()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=3)
        proc.stdout.close();proc.stderr.close()


def test_listener_owned_by_original_process_satisfies_bind_wait():
    with inert_child(listener=True) as (proc,port):
        _wait_for_bind('127.0.0.1',int(port),proc,timeout=.3)


def test_unrelated_listener_does_not_establish_tunnel_readiness():
    with socket.socket() as foreign:
        foreign.bind(('127.0.0.1',0));foreign.listen()
        with inert_child() as (proc,ready):
            assert ready=='ready'
            with pytest.raises(WebUITunnelError,match="not owned"):
                _wait_for_bind('127.0.0.1',foreign.getsockname()[1],proc,timeout=.3)


def test_original_process_exit_is_refused_and_pinned_descriptors_close():
    import os
    from app.services.webui_listener import Listener,ListenerError
    with inert_child(listener=True) as (proc,port):
        with Listener(proc) as proof:
            held=(proof.pidfd,proof.directory,proof.namespace)
            proc.stdin.close();proc.wait(timeout=3)
            with pytest.raises(ListenerError,match='exited'):proof.proof('127.0.0.1',int(port))
        for fd in held:
            with pytest.raises(OSError):os.fstat(fd)


@pytest.mark.parametrize('change',['foreign','fd-disappeared','multiple','wildcard','ipv6-wildcard','table-changed','process-changed'])
def test_ambiguous_or_changed_proofs_are_refused(change):
    from unittest.mock import Mock
    from app.services.webui_listener import Listener,ListenerError
    proof=object.__new__(Listener);proof.identity={'pid':1,'start':'original'};proof.recheck=Mock()
    row={'table':'tcp','address':Listener.encoded('127.0.0.1'),'port':32001,'inode':123}
    rows=[row];proof.inodes=Mock(return_value={123})
    if change=='foreign':proof.inodes.return_value={456}
    if change=='fd-disappeared':proof.inodes.side_effect=[{123},set()]
    if change=='multiple':rows=[row,dict(row,inode=456)]
    if change=='wildcard':rows=[dict(row,address='0'*8)]
    if change=='ipv6-wildcard':rows=[dict(row,table='tcp6',address='0'*32)]
    proof.candidates=Mock(return_value=rows)
    if change=='table-changed':proof.candidates.side_effect=[[row],[dict(row,inode=456)]]
    if change=='process-changed':proof.recheck.side_effect=[None,ListenerError('original process generation changed')]
    with pytest.raises(ListenerError):proof.proof('127.0.0.1',32001)


def test_no_listener_remains_pending_without_accepting_socket_from_other_port():
    from unittest.mock import Mock
    from app.services.webui_listener import Listener
    proof=object.__new__(Listener);proof.identity={};proof.recheck=Mock()
    proof.inodes=Mock(return_value={123});proof.candidates=Mock(return_value=[])
    assert proof.proof('127.0.0.1',32001) is None
    assert proof.recheck.call_count==2


@pytest.mark.parametrize('bad',['header','row','address','inode','remote','permission'])
def test_bad_or_unreadable_kernel_tables_cannot_qualify(bad):
    from app.services.webui_listener import Listener,ListenerError
    proof=object.__new__(Listener)
    header='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
    row='0: 0100007F:7D01 00000000:0000 0A 0:0 00:0 0 0 0 123 0\n'
    if bad=='header':header='unqualified table\n'
    if bad=='row':row='incomplete\n'
    if bad=='address':row=row.replace('0100007F','bad')
    if bad=='inode':row=row.replace(' 123 ',' invalid ')
    if bad=='remote':row=row.replace('00000000:0000','0100007F:1234')
    def read(name):
        if bad=='permission':raise PermissionError('denied')
        return header+row if name=='net/tcp' else header.replace('rem_address','remote_address')
    proof.read=read
    with pytest.raises((ListenerError,PermissionError)):proof.candidates('127.0.0.1',32001)


def test_owned_listener_changed_after_connect_is_not_accepted(monkeypatch):
    from unittest.mock import Mock
    from app.services import webui_service as service
    fake=Mock();fake.__enter__=Mock(return_value=fake);fake.__exit__=Mock(return_value=False)
    fake.proof.side_effect=[{'inode':123},{'inode':456}]
    monkeypatch.setattr(service,'Listener',lambda proc:fake)
    # Connect only to this test's owned loopback socket, never an external service.
    with socket.socket() as server:
        server.bind(('127.0.0.1',0));server.listen()
        with pytest.raises(WebUITunnelError,match='changed during local connection'):
            _wait_for_bind('127.0.0.1',server.getsockname()[1],Mock(),timeout=.3)


def test_listener_appearing_during_startup_requires_later_stable_proof():
    from unittest.mock import Mock
    from app.services.webui_listener import Listener
    proof=object.__new__(Listener);proof.identity={'pid':1,'start':'original'};proof.recheck=Mock()
    row={'table':'tcp','address':Listener.encoded('127.0.0.1'),'port':32001,'inode':123}
    proof.inodes=Mock(side_effect=[set(),{123},{123},{123}])
    proof.candidates=Mock(side_effect=[[],[row],[row],[row]])
    assert proof.proof('127.0.0.1',32001) is None
    assert proof.recheck.call_count==2
    assert proof.proof('127.0.0.1',32001)==dict(row,process=proof.identity)
    assert proof.recheck.call_count==4


@pytest.mark.parametrize('change',['foreign','wildcard','ipv6','multiple','generation','namespace','read-error','wrong-port','non-loopback','replacement','disappearance'])
def test_startup_transition_preserves_conflict_and_identity_failures(change):
    from unittest.mock import Mock
    from app.services.webui_listener import Listener,ListenerError
    proof=object.__new__(Listener);proof.identity={};proof.recheck=Mock()
    host='192.0.2.1' if change=='non-loopback' else '127.0.0.1'
    row={'table':'tcp','address':Listener.encoded(host),'port':32001,'inode':123}
    latest=[row];before=[];proof.inodes=Mock(side_effect=[set(),{123}])
    if change=='foreign':proof.inodes.side_effect=[set(),{456}]
    if change=='wildcard':latest=[dict(row,address='0'*8)]
    if change=='ipv6':latest=[dict(row,table='tcp6')]
    if change=='multiple':latest=[row,dict(row,inode=456)]
    if change=='wrong-port':latest=[dict(row,port=32002)]
    if change in ('generation','namespace'):proof.recheck.side_effect=[None,ListenerError(change+' changed')]
    if change=='replacement':before=[dict(row,inode=456)]
    if change=='disappearance':before=[row];latest=[]
    proof.candidates=Mock(side_effect=[before,PermissionError('denied') if change=='read-error' else latest])
    with pytest.raises((ListenerError,PermissionError)):proof.proof(host,32001)
