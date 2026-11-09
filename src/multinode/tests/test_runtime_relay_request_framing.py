"""Inert console framing: the request line must not consume shell input."""
from types import SimpleNamespace
import pytest
from tests.runtime_relay_import import load_runtime_relay_module

relay=load_runtime_relay_module()


class Stream:
    def __init__(self,data):self.buffer=data;self.sent=[]
    def recv(self,size):
        result=self.buffer[:size];self.buffer=self.buffer[size:];return result
    def sendall(self,data):self.sent.append(data)
    def __enter__(self):return self
    def __exit__(self,*args):pass


@pytest.mark.parametrize('action',['CONNECT','CONNECT_ID'])
def test_console_request_preserves_input_arriving_in_the_same_read(monkeypatch,action):
    name='clab-dnlab-demo-R1-R1';identity='a'*64
    command=b'printf "first-console-command"\n'
    suffix=' '+identity if action=='CONNECT_ID' else ''
    stream=Stream(f'{action} key {name}{suffix}\n'.encode()+command)
    received=[]
    monkeypatch.setattr(relay,'API_KEY','key');monkeypatch.setattr(relay,'ALLOWED',{name})
    monkeypatch.setattr(relay,'_resolve_target',lambda container,expected_id=None:expected_id or container)
    monkeypatch.setattr(relay,'_get_console_broker',lambda target:SimpleNamespace(attach=lambda sock:received.append(sock.recv(4096))))
    relay._handle(stream,None)
    assert received==[command],'request parsing discarded the first console input'
    assert not stream.sent


@pytest.mark.parametrize('wire',[b'CONNECT key container\n',b'CONNECT_ID key container '+b'a'*64+b'\n',b'CONNECT "two words" container\r\n'])
def test_parser_leaves_binary_and_multiline_console_input_untouched(wire):
    data=b'\x00\xff\r\nfirst\nsecond\n'
    stream=Stream(wire+data)
    assert relay._read_request(stream)
    assert stream.buffer==data


def test_parser_accepts_complete_request_at_limit_and_preserves_following_input():
    token=b'a'*(relay.MAX_REQUEST_BYTES-1);stream=Stream(token+b'\ncommand\n')
    assert relay._read_request(stream)==[token.decode()]
    assert stream.buffer==b'command\n'


def test_parser_rejects_oversized_request_without_reading_past_limit():
    stream=Stream(b'a'*relay.MAX_REQUEST_BYTES+b'\ncommand\n')
    with pytest.raises(ValueError,match='size limit'):relay._read_request(stream)
    assert stream.buffer==b'\ncommand\n'


@pytest.mark.parametrize('data',[b'',b'CONNECT key container',b'\n'])
def test_incomplete_or_empty_request_is_not_accepted(data):
    assert relay._read_request(Stream(data)) is None


@pytest.mark.parametrize('wire',[b'CONNECT wrong container\n',b'CONNECT_ID wrong container '+b'a'*64+b'\n'])
def test_auth_rejection_cannot_consume_or_forward_console_input(monkeypatch,wire):
    stream=Stream(wire+b'command\n')
    monkeypatch.setattr(relay,'API_KEY','key');monkeypatch.setattr(relay,'ALLOWED',{'container'})
    monkeypatch.setattr(relay,'_resolve_target',lambda *a:pytest.fail('unauthorized inspection'))
    monkeypatch.setattr(relay,'_get_console_broker',lambda *a:pytest.fail('unauthorized console'))
    relay._handle(stream,None)
    assert stream.sent==[b'ERR unauthorized\n'] and stream.buffer==b'command\n'


def test_invalid_qualified_id_is_rejected_without_docker_or_console(monkeypatch):
    stream=Stream(b'CONNECT_ID key container short\ncommand\n')
    monkeypatch.setattr(relay,'API_KEY','key');monkeypatch.setattr(relay,'ALLOWED',{'container'})
    monkeypatch.setattr(relay.subprocess,'run',lambda *a,**kw:pytest.fail('unexpected Docker'))
    monkeypatch.setattr(relay,'_get_console_broker',lambda *a:pytest.fail('unqualified console'))
    relay._handle(stream,None)
    assert b'invalid container identity' in b''.join(stream.sent) and stream.buffer==b'command\n'


def test_malformed_quoting_is_rejected_without_consuming_input(monkeypatch):
    stream=Stream(b'CONNECT "unterminated\ncommand\n')
    monkeypatch.setattr(relay,'_resolve_target',lambda *a:pytest.fail('unexpected inspection'))
    relay._handle(stream,None)
    assert b'ERR ' in b''.join(stream.sent) and stream.buffer==b'command\n'


@pytest.mark.parametrize('action',['CONNECT','CONNECT_ID'])
def test_local_unix_stream_keeps_early_console_command_without_prompt(monkeypatch,action):
    import socket
    name='clab-dnlab-demo-R1-R1';identity='a'*64
    command=b'first\nsecond\r\n\x00\xff'
    suffix=' '+identity if action=='CONNECT_ID' else ''
    monkeypatch.setattr(relay,'API_KEY','key');monkeypatch.setattr(relay,'ALLOWED',{name})
    monkeypatch.setattr(relay,'_resolve_target',lambda container,expected_id=None:expected_id or container)
    received=[]
    def attach(sock):
        data=b''
        while len(data)<len(command):
            chunk=sock.recv(len(command)-len(data))
            if not chunk:break
            data+=chunk
        received.append(data)
    monkeypatch.setattr(relay,'_get_console_broker',lambda target:SimpleNamespace(attach=attach))
    client,server=socket.socketpair()
    with client,server:
        client.settimeout(1);server.settimeout(1)
        client.sendall(f'{action} key {name}{suffix}\n'.encode()+command)
        relay._handle(server,None)
    assert received==[command]
