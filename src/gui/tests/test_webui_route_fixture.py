"""Real ASGI WebUI opening with controlled fixture identity and status inputs."""
import sys
from pathlib import Path
from unittest.mock import Mock
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tools'))
from gui_route_fixture import route_client
from app.config import settings
from app.services import webui_service as module
from app.views.api import webui_routes as routes


def test_real_router_uses_configured_host_live_port_and_restores_fixture_inputs(monkeypatch):
    monkeypatch.setattr(settings,'JUMPHOST_HOST','127.0.0.2')
    commands=[];ports=iter([32001,32002])
    def spawn(command,**kwargs):
        commands.append(command);process=Mock();process.poll.return_value=None;return process
    monkeypatch.setattr(module.subprocess,'Popen',spawn)
    monkeypatch.setattr(module,'_pick_free_port',lambda:next(ports))
    monkeypatch.setattr(module,'_wait_for_bind',lambda *a,**kw:None)
    service=module.WebUIService()
    targets=[{'role':'default','ip':'198.19.233.1'},{'role':'blue','ip':'198.19.234.1'}]
    profile={'lab':'fixture','host':'127.0.0.2','port':2200,'targets':targets}
    before=(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)
    try:
        with route_client(profile,service) as client:
            first=client.open(targets[0]);assert client.open(targets[0]) is first
            second=client.open(targets[1]);assert second.token!=first.token
            assert service.get(first.token) is None
            assert len(client.evidence['http_requests'])==3
            assert client.evidence['production_authentication_verified'] is False
            assert client.evidence['vd_http_verified'] is False
            assert all(command[-1]=='labuser@127.0.0.2' for command in commands)
            assert all(command[command.index('-p')+1]=='2200' for command in commands)
            with pytest.raises(RuntimeError,match='outside original'):client.open({'role':'foreign','ip':'192.0.2.1'})
        assert before==(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)
    finally:service.shutdown()


def test_fixture_refuses_wrong_connect_configuration_before_installing_overrides(monkeypatch):
    monkeypatch.setattr(settings,'JUMPHOST_HOST','127.0.0.1')
    before=(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)
    with pytest.raises(RuntimeError,match='configured connect host'):
        with route_client({'host':'127.0.0.2'},Mock()):pytest.fail('must not reach API request')
    assert before==(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)


def test_fixture_restores_original_routes_after_exception(monkeypatch):
    monkeypatch.setattr(settings,'JUMPHOST_HOST','127.0.0.2')
    before=(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)
    with pytest.raises(ValueError,match='interrupted'):
        with route_client({'host':'127.0.0.2','lab':'fixture','port':2200,'targets':[]},Mock()):
            raise ValueError('interrupted')
    assert before==(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)


@pytest.mark.parametrize('fault',[None,'nonce','header','status'])
def test_real_http_proxy_preserves_original_workload_response(monkeypatch,fault):
    import httpx
    monkeypatch.setattr(settings,'JUMPHOST_HOST','127.0.0.2')
    process=Mock();process.poll.return_value=None
    monkeypatch.setattr(module.subprocess,'Popen',lambda *a,**kw:process)
    monkeypatch.setattr(module,'_pick_free_port',lambda:32001)
    monkeypatch.setattr(module,'_wait_for_bind',lambda *a,**kw:None)
    original_client=httpx.AsyncClient;requests=[];nonce='a'*32
    def upstream(request):
        requests.append(request)
        return httpx.Response(503 if fault=='status' else 200,
            json={'nonce':'b'*32 if fault=='nonce' else nonce,'role':'dnlab-native-http'},
            headers={'X-Dnlab-Fixture':'b'*32 if fault=='header' else nonce})
    def client(*a,**kw):
        if 'transport' not in kw:kw['transport']=httpx.MockTransport(upstream)
        return original_client(*a,**kw)
    monkeypatch.setattr(httpx,'AsyncClient',client)
    target={'node':'http-vd','ip':'198.19.233.11','vd_port':8080,'nonce':nonce,'path':'/dnlab-probe/'+nonce}
    profile={'lab':'fixture','host':'127.0.0.2','port':2200,'targets':[],'http_target':target}
    service=module.WebUIService()
    try:
        with route_client(profile,service) as api:
            if fault:
                with pytest.raises(RuntimeError,match='proxy response differs'):api.http_get(target)
                assert api.evidence['vd_http_verified'] is False
            else:
                tunnel,proof=api.http_get(target)
                assert tunnel.vd_port==8080 and proof['nonce']==nonce
                assert api.evidence['vd_http_verified'] is True
            assert len(requests)==1
            assert str(requests[0].url)=='http://127.0.0.1:32001'+target['path']
    finally:service.shutdown()
