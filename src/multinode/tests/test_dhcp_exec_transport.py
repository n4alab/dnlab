"""Only a structured Docker 404 establishes absence; errors hide exec payloads."""
from types import SimpleNamespace

import pytest

from dnlab_multinode.services import jumphost_host as module


def connection(monkeypatch,status,body):
    calls=[]
    sock=SimpleNamespace(settimeout=lambda v:None,connect=lambda path:calls.append(('connect',path)))
    conn=SimpleNamespace(sock=None,request=lambda *a:calls.append(('request',a)),
        getresponse=lambda:SimpleNamespace(status=status,read=lambda:body),close=lambda:calls.append(('close',)))
    monkeypatch.setattr(module.socket,'socket',lambda *a:sock)
    monkeypatch.setattr(module.http.client,'HTTPConnection',lambda *a,**kw:conn)
    return calls


@pytest.mark.parametrize('status,body,expected',[(201,b'{"Id":"original"}',{'Id':'original'}),(200,b'',{}),(404,b'{"message":"not found"}',None)])
def test_exec_transport_returns_json_empty_success_and_only_qualified_absence(monkeypatch,status,body,expected):
    calls=connection(monkeypatch,status,body)
    assert module.DockerExecHTTP('/tmp/docker-test.sock').call('GET','/exec/id/json',missing=True)==expected
    assert calls[-1]==('close',)


@pytest.mark.parametrize('status',[400,401,403,409,500])
def test_exec_failure_keeps_status_without_leaking_daemon_message(monkeypatch,status):
    connection(monkeypatch,status,b'{"message":"SECRET daemon command"}')
    with pytest.raises(module.DockerExecError) as error:
        module.DockerExecHTTP().call('POST','/exec/id/start',{'Env':['SECRET=value']},missing=True)
    assert error.value.status==status and 'SECRET' not in str(error.value)


@pytest.mark.parametrize('status,body',[(200,b'broken'),(404,b'broken'),(404,b'{}')])
def test_malformed_success_or_absence_never_authorizes_recovery(monkeypatch,status,body):
    connection(monkeypatch,status,body)
    with pytest.raises(module.JumphostError):module.DockerExecHTTP().call('GET','/exec/id/json',missing=True)


def test_socket_failure_is_uncertain_and_connection_is_closed(monkeypatch):
    calls=connection(monkeypatch,200,b'{}')
    sock=SimpleNamespace(settimeout=lambda v:None,connect=lambda p:(_ for _ in ()).throw(PermissionError('SECRET')))
    monkeypatch.setattr(module.socket,'socket',lambda *a:sock)
    with pytest.raises(module.JumphostError,match='uncertain') as error:
        module.DockerExecHTTP().call('GET','/exec/id/json',missing=True)
    assert 'SECRET' not in str(error.value) and calls[-1]==('close',)
