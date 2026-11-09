"""Relay request encoding preserves qualified native IDs without fallback."""
import asyncio
from types import SimpleNamespace
from uuid import uuid4
import pytest
from app.services import runtime_relay_client as module
from app.services.runtime_relay_client import RuntimeRelayClient,RuntimeRelayError


class Writer:
    def __init__(self):self.sent=[];self.closed=False
    def write(self,value):self.sent.append(value)
    async def drain(self):pass
    def close(self):self.closed=True
    async def wait_closed(self):pass


@pytest.mark.parametrize('action',['CONNECT','LOG'])
@pytest.mark.parametrize('native',[True,False])
def test_relay_wire_uses_id_only_for_qualified_native_context(monkeypatch,action,native):
    writer=Writer();calls=[]
    class Reader:
        async def readline(self):
            assert action=='LOG'
            return b'OK\n'
    async def connect(host,port):calls.append((host,port));return Reader(),writer
    monkeypatch.setattr(module.asyncio,'open_connection',connect)
    relay={'host':'127.0.0.1','port':19000,'api_key':'key','container':'qualified-name'}
    if native:relay.update(runtime_backend='custom',container_id='a'*64)
    extra=('200','0') if action=='LOG' else ()
    asyncio.run(RuntimeRelayClient()._open(relay,action,*extra))
    expected=[action+'_ID' if native else action,'key','qualified-name']
    if native:expected.append('a'*64)
    assert writer.sent==[(' '.join([*expected,*extra])+'\n').encode()]
    assert calls==[('127.0.0.1',19000)]


@pytest.mark.parametrize('context',[{'runtime_backend':'custom'},
    {'runtime_backend':'custom','container_id':'short'},
    {'runtime_backend':'custom','container_id':None},
    {'runtime_backend':'custom','container_id':'A'*64},
    {'container_id':'a'*64},{'runtime_backend':'unknown'}])
def test_bad_identity_never_opens_connection(monkeypatch,context):
    async def forbidden(*a):pytest.fail('unexpected connection')
    monkeypatch.setattr(module.asyncio,'open_connection',forbidden)
    with pytest.raises(RuntimeRelayError):asyncio.run(RuntimeRelayClient()._open(context,'CONNECT'))


def test_relay_rejection_never_retries_name_protocol(monkeypatch):
    writer=Writer();calls=[]
    class Reader:
        async def readline(self):return b'ERR unknown action\n'
    async def connect(*args):calls.append(args);return Reader(),writer
    monkeypatch.setattr(module.asyncio,'open_connection',connect)
    relay={'host':'127.0.0.1','port':19000,'api_key':'key','container':'name','runtime_backend':'custom','container_id':'a'*64}
    with pytest.raises(RuntimeRelayError,match='unknown action'):
        asyncio.run(RuntimeRelayClient()._open(relay,'LOG','200','0'))
    assert len(calls)==1 and writer.closed and writer.sent[0].startswith(b'LOG_ID ')


def test_local_gui_resolution_uses_shared_qualified_resolver(tmp_path,monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'multinode'))
    from dnlab_multinode.services import relay_resolution,state as state_svc
    from app.services.multinode_service import MultinodeService
    path=tmp_path/'lab.yml';path.write_text('name: demo\n')
    lab=SimpleNamespace(netname='demo',yaml_path=path,id=uuid4())
    state=SimpleNamespace(node_runtime={'R1':object()});seen=[]
    monkeypatch.setattr(state_svc,'load_state',lambda *args:state)
    expected={'runtime_backend':'custom','container_id':'a'*64}
    def resolve(*args):seen.append(args);return expected
    monkeypatch.setattr(relay_resolution,'resolve',resolve)
    monkeypatch.setattr(MultinodeService,'_use_api',property(lambda self:False))
    service=MultinodeService()
    assert asyncio.run(service.resolve_runtime_relay(lab,'R1'))==expected
    assert seen==[(state,'R1',tmp_path,service._hosts_file)]
