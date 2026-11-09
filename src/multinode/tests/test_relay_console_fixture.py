"""Bounded relay probes and listener qualification without Docker or host networking."""
from pathlib import Path
import json
import socket
import subprocess
import sys

import pytest

TOOLS=Path(__file__).resolve().parents[2]/'runtime/tools'
if str(TOOLS) not in sys.path:sys.path.insert(0,str(TOOLS))
import relay_console_smoke as fixture


class Stream:
    def __init__(self,chunks):self.chunks=list(chunks);self.sent=[];self.closed=False
    def settimeout(self,value):assert 0<value<=1 or value==5
    def recv(self,size):
        value=self.chunks.pop(0) if self.chunks else b''
        if isinstance(value,Exception):raise value
        assert len(value)<=size
        return value
    def sendall(self,value):self.sent.append(value)
    def __enter__(self):return self
    def __exit__(self,*args):self.closed=True


def test_receive_retains_partial_proof_and_records_it():
    seen=[];sock=Stream([b'O',socket.timeout(),b'K\nnonce'])
    assert fixture.receive(sock,lambda v:b'nonce' in v,observe=seen.append)==b'OK\nnonce'
    assert seen==[b'O',b'OK\nnonce']


@pytest.mark.parametrize('chunks',[[b'OK\n',b''],[b'ERR unauthorized\n']])
def test_receive_never_accepts_ack_or_error_as_proof(chunks):
    with pytest.raises(RuntimeError,match='ended before expected proof'):
        fixture.receive(Stream(chunks),lambda v:b'nonce' in v)


def test_receive_is_bounded():
    with pytest.raises(RuntimeError,match='exceeded bound'):
        fixture.receive(Stream([b'1234']),lambda v:False,limit=4)


def test_console_nonce_is_actual_shell_output_and_cannot_match_echo():
    command,marker=fixture.console_command('a'*32)
    assert marker not in command
    result=subprocess.run(['sh','-c',command.decode()],capture_output=True,check=True,timeout=3)
    assert result.stdout==marker+b'\n'


@pytest.mark.parametrize('nonce',['','a'*31,'a'*33,'g'*32,"'; exit #"])
def test_probe_nonce_validation_rejects_unqualified_input(nonce):
    with pytest.raises(ValueError):fixture.console_command(nonce)


def test_protocol_probes_require_log_and_console_nonces_and_close_connections(tmp_path,monkeypatch):
    nonce='b'*32;command,marker=fixture.console_command(nonce)
    streams=[Stream([b'OK\nrelay-log-'+nonce.encode()]),Stream([b'# ',command,marker+b'\n'])]
    queue=list(streams)
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:queue.pop(0))
    result=fixture.probe('127.0.0.1',18080,'key','qualified',nonce,tmp_path/'probe.json')
    assert all(result.values()) and all(s.closed for s in streams) and not queue
    assert streams[1].sent==[b'CONNECT key qualified\n'+command]


def test_probe_rejects_console_echo_without_output(tmp_path,monkeypatch):
    nonce='b'*32;command,_=fixture.console_command(nonce)
    streams=[Stream([b'OK\nrelay-log-'+nonce.encode()]),Stream([b'# ',command,b''])]
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:streams.pop(0))
    with pytest.raises(RuntimeError,match='ended before expected proof'):
        fixture.probe('127.0.0.1',18080,'key','qualified',nonce,tmp_path/'probe.json')


@pytest.fixture
def listener(tmp_path,monkeypatch):
    real_path=Path
    def mapped(value):
        value=str(value)
        return tmp_path/value.lstrip('/') if value.startswith('/proc') else real_path(value)
    proc=tmp_path/'proc/4242';(proc/'net').mkdir(parents=True);(proc/'fd').mkdir();(proc/'ns').mkdir()
    (tmp_path/'proc/self/ns').mkdir(parents=True)
    namespace=tmp_path/'namespace';namespace.write_text('fixture')
    (proc/'ns/net').symlink_to(namespace);(tmp_path/'proc/self/ns/net').symlink_to(namespace)
    (proc/'stat').write_text('4242 (relay fixture) '+' '.join(['S']+['0']*18+['99','0','0']))
    (proc/'fd/3').symlink_to('socket:[17]')
    line='0: 0100007F:'+format(18080,'04X')+' 00000000:0000 0A 0:0 00:0 0 0 0 17 1\n'
    (proc/'net/tcp').write_text('header\n'+line);(proc/'net/tcp6').write_text('header\n')
    monkeypatch.setattr(fixture,'Path',mapped)
    class API:
        def request(self,*args):return {'Id':'c'*64,'State':{'Pid':4242,'StartedAt':'fixture','Running':True}}
    return API(),proc,tmp_path/'observations.json'


def test_listener_requires_original_process_socket_inode_and_namespace(listener):
    api,proc,output=listener
    result=fixture.listener_proof(api,'c'*64,18080,output)
    assert result['socket_inode']=='17' and result['pid']==4242


def test_foreign_listener_is_not_readiness(listener):
    api,proc,output=listener
    (proc/'fd/3').unlink();(proc/'fd/3').symlink_to('socket:[25]')
    with pytest.raises(RuntimeError,match='another process'):
        fixture.listener_proof(api,'c'*64,18080,output)


def test_wildcard_listener_is_not_exact_loopback_readiness(listener):
    api,proc,output=listener
    path=proc/'net/tcp';path.write_text(path.read_text().replace('0100007F','00000000'))
    with pytest.raises(RuntimeError,match='exact loopback bind'):
        fixture.listener_proof(api,'c'*64,18080,output)


def test_container_diagnostic_preserves_difference_without_secret_values():
    record={'nonce':'a'*32,'container_id':'b'*64,'config':{'lab':'demo','host':'master','bind_ip':'127.0.0.1',
            'port':18080,'api_key':'expected-secret','allowed':['owned'],'prefix':'clab-dnlab-demo-'},
            'image':{'Id':'sha256:'+'c'*64,'Config':{'Env':['PATH=/bin'],'Entrypoint':['relay'],'Cmd':None}}}
    value={'Id':'b'*64,'Config':{'Env':['PATH=/bin','RELAY_API_KEY=foreign-secret','EXTRA=other-secret'],
                                'Entrypoint':['foreign-secret'],'Cmd':['other-secret'],'Labels':{}},'HostConfig':{}}
    snapshot=fixture.container_diagnostic(record,value);text=json.dumps(snapshot)
    assert not any(secret in text for secret in ('expected-secret','foreign-secret','other-secret'))
    assert snapshot['env_matches']['PATH'] is True and snapshot['env_matches']['RELAY_API_KEY'] is False
    assert snapshot['unexpected_env_keys']==['EXTRA'] and not snapshot['entrypoint_matches']


def test_foreign_container_diagnostic_never_dumps_environment_or_command():
    value={'Id':'f'*64,'Name':'/foreign','Config':{'Env':['KEY=secret'],'Cmd':['secret']}}
    assert 'secret' not in json.dumps(fixture.container_diagnostic(None,value))


def test_relay_host_executes_real_bootstrap_over_stdin_with_timeout(monkeypatch):
    import shlex
    original=subprocess.run;seen=[]
    def observed(argv,**kwargs):
        seen.append((argv,kwargs))
        return original(argv,**kwargs)
    monkeypatch.setattr(fixture.subprocess,'run',observed)
    source="import json,sys\nprint(json.dumps({'phase':json.load(sys.stdin)['action']}))"
    payload=json.dumps({'source':source,'request':{'action':'inert'}})
    command=shlex.join(['python3','-c',fixture.relays._WORKER_BOOTSTRAP])
    assert json.loads(fixture.RelayHost().run_input(command,payload,timeout=7))=={'phase':'inert'}
    assert len(seen)==1 and seen[0][1]['timeout']==7 and seen[0][1]['input']==payload
    assert payload not in seen[0][0] and source not in seen[0][0]


@pytest.mark.parametrize('timeout',[0,-1,True,float('inf'),float('nan')])
def test_relay_host_refuses_invalid_timeout_before_subprocess(timeout,monkeypatch):
    import shlex
    monkeypatch.setattr(fixture.subprocess,'run',lambda *a,**kw:pytest.fail('unexpected subprocess'))
    command=shlex.join(['python3','-c',fixture.relays._WORKER_BOOTSTRAP])
    with pytest.raises(ValueError):fixture.RelayHost().run_input(command,'{}',timeout=timeout)


def test_relay_host_rejects_unexpected_command_and_preserves_worker_failure(monkeypatch):
    import shlex
    with pytest.raises(ValueError):fixture.RelayHost().run_input('sh -c true','{}')
    monkeypatch.setattr(fixture.subprocess,'run',lambda *a,**kw:subprocess.CompletedProcess(a[0],1,'','original worker failure'))
    command=shlex.join(['python3','-c',fixture.relays._WORKER_BOOTSTRAP])
    with pytest.raises(RuntimeError,match='original worker failure'):
        fixture.RelayHost().run_input(command,'{}',timeout=3)


def test_relay_host_does_not_retry_after_timeout(monkeypatch):
    import shlex
    calls=[]
    def expired(argv,**kwargs):
        calls.append(kwargs['timeout'])
        raise subprocess.TimeoutExpired(argv,kwargs['timeout'])
    monkeypatch.setattr(fixture.subprocess,'run',expired)
    command=shlex.join(['python3','-c',fixture.relays._WORKER_BOOTSTRAP])
    with pytest.raises(subprocess.TimeoutExpired):fixture.RelayHost().run_input(command,'{}',timeout=3)
    assert calls==[3]


@pytest.mark.parametrize('reply',[[b'ERR unauthorized\n'],[b'E',b'RR unauthorized\n']])
def test_console_stream_rejects_errors_even_when_split(tmp_path,monkeypatch,reply):
    nonce='c'*32
    streams=[Stream([b'OK\nrelay-log-'+nonce.encode()]),Stream(reply)]
    queue=list(streams)
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:queue.pop(0))
    with pytest.raises(RuntimeError,match='console rejected'):
        fixture.probe('127.0.0.1',18080,'key','qualified',nonce,tmp_path/'probe.json')
    assert all(s.closed for s in streams)


def test_console_prompt_alone_is_not_proof(tmp_path,monkeypatch):
    nonce='c'*32
    streams=[Stream([b'OK\nrelay-log-'+nonce.encode()]),Stream([b'# ',b''])]
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:streams.pop(0))
    with pytest.raises(RuntimeError,match='ended before expected proof'):
        fixture.probe('127.0.0.1',18080,'key','qualified',nonce,tmp_path/'probe.json')


def test_native_probe_sends_original_id_for_logs_and_console(tmp_path,monkeypatch):
    nonce='b'*32;command,marker=fixture.console_command(nonce);identity='a'*64
    streams=[Stream([b'OK\nrelay-log-'+nonce.encode()]),Stream([b'# ',marker+b'\n'])]
    queue=list(streams)
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:queue.pop(0))
    assert all(fixture.probe('127.0.0.1',18080,'key','qualified',nonce,tmp_path/'probe.json',identity).values())
    assert streams[0].sent==[f'LOG_ID key qualified {identity} all 0\n'.encode()]
    assert streams[1].sent==[f'CONNECT_ID key qualified {identity}\n'.encode()+command]


def test_native_probe_refuses_malformed_id_before_connection(tmp_path,monkeypatch):
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:pytest.fail('unexpected connection'))
    with pytest.raises(ValueError):fixture.probe('127.0.0.1',18080,'key','qualified','b'*32,tmp_path/'probe.json','short')


def test_probe_sends_command_with_request_without_waiting_for_prompt(tmp_path,monkeypatch):
    nonce='b'*32;command,marker=fixture.console_command(nonce);identity='a'*64
    streams=[Stream([b'OK\nrelay-log-'+nonce.encode()]),Stream([marker+b'\n'])]
    queue=list(streams)
    monkeypatch.setattr(fixture.socket,'create_connection',lambda *a,**kw:queue.pop(0))
    result=fixture.probe('127.0.0.1',18080,'key','qualified',nonce,tmp_path/'probe.json',identity)
    assert result['console_early_input_verified'] is True
    assert streams[1].sent==[f'CONNECT_ID key qualified {identity}\n'.encode()+command]
    assert marker not in streams[1].sent[0]
