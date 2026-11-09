"""No Docker: immutable target selection at the relay consumption boundary."""
from copy import deepcopy
import json
import subprocess
from types import SimpleNamespace
import pytest
from tests.runtime_relay_import import load_runtime_relay_module

relay=load_runtime_relay_module()
NAME='clab-dnlab-demo-R1-R1';IDENTITY='a'*64


@pytest.fixture
def inspected(monkeypatch):
    value={'Id':IDENTITY,'Name':'/'+NAME,'State':{'Running':True},'Config':{'Labels':{'org.dnlab.runtime':'v1'}}}
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv);assert argv==['docker','inspect','--type','container',NAME]
        return subprocess.CompletedProcess(argv,0,json.dumps([deepcopy(value)]),'')
    monkeypatch.setattr(relay.subprocess,'run',run)
    return value,calls


def test_qualified_target_is_full_original_id(inspected):
    value,calls=inspected
    assert relay._resolve_target(NAME,IDENTITY)==IDENTITY
    assert len(calls)==1


@pytest.mark.parametrize('conflict',['id','name','state','legacy-native','short-id'])
def test_conflicting_or_unqualified_target_is_rejected(inspected,conflict):
    value,calls=inspected;expected=IDENTITY
    if conflict=='id':value['Id']='b'*64
    if conflict=='name':value['Name']='/different'
    if conflict=='state':value['State']['Running']=False
    if conflict=='legacy-native':expected=None
    if conflict=='short-id':expected='a'*12
    with pytest.raises(RuntimeError):relay._resolve_target(NAME,expected)


def test_containerlab_name_protocol_stays_compatible(inspected):
    value,calls=inspected;value['Config']['Labels']={'containerlab':'demo'}
    assert relay._resolve_target(NAME)==NAME


class Socket:
    def __init__(self,request):self.request=request;self.sent=[]
    def recv(self,size):data=self.request[:size];self.request=self.request[size:];return data
    def sendall(self,data):self.sent.append(data)
    def __enter__(self):return self
    def __exit__(self,*args):pass


@pytest.mark.parametrize('action',['CONNECT_ID','LOG_ID'])
def test_handler_consumes_original_id_even_if_name_is_replaced(inspected,monkeypatch,action):
    value,calls=inspected;opened=[]
    monkeypatch.setattr(relay,'API_KEY','key');monkeypatch.setattr(relay,'ALLOWED',{NAME})
    def attach(sock):
        value['Id']='b'*64  # Concurrent replacement after the qualified read.
        opened.append(('console',IDENTITY))
    def broker(target):
        assert target==IDENTITY
        return SimpleNamespace(attach=attach)
    def logs(sock,target,tail,follow):
        value['Id']='b'*64
        opened.append(('logs',target));assert (tail,follow)==('200','0')
    monkeypatch.setattr(relay,'_get_console_broker',broker);monkeypatch.setattr(relay,'_stream_logs',logs)
    suffix=' 200 0' if action=='LOG_ID' else ''
    sock=Socket(f'{action} key {NAME} {IDENTITY}{suffix}\n'.encode())
    relay._handle(sock,None)
    assert opened==[('console' if action=='CONNECT_ID' else 'logs',IDENTITY)] and not sock.sent


@pytest.mark.parametrize('action',['CONNECT_ID','LOG_ID'])
def test_handler_never_opens_replaced_generation(inspected,monkeypatch,action):
    value,calls=inspected;value['Id']='b'*64
    monkeypatch.setattr(relay,'API_KEY','key');monkeypatch.setattr(relay,'ALLOWED',{NAME})
    monkeypatch.setattr(relay,'_get_console_broker',lambda *a:pytest.fail('unexpected console'))
    monkeypatch.setattr(relay,'_stream_logs',lambda *a:pytest.fail('unexpected logs'))
    suffix=' 200 0' if action=='LOG_ID' else ''
    sock=Socket(f'{action} key {NAME} {IDENTITY}{suffix}\n'.encode());relay._handle(sock,None)
    assert b'container generation differs' in b''.join(sock.sent)


@pytest.mark.parametrize('response',['[]','{}','[{},{}]','invalid'])
def test_inspect_errors_never_fall_back_to_name(monkeypatch,response):
    monkeypatch.setattr(relay.subprocess,'run',lambda *a,**kw:subprocess.CompletedProcess(a[0],0,response,''))
    with pytest.raises((RuntimeError,ValueError)):relay._resolve_target(NAME,IDENTITY)
