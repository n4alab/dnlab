"""A new open after a management move must target the requested endpoint."""
from unittest.mock import Mock
import pytest
from app.services import webui_service as module


@pytest.fixture
def opened(monkeypatch):
    processes=[]
    def spawn(*args,**kwargs):
        process=Mock();process.poll.return_value=None;process.wait.return_value=0
        processes.append(process);return process
    monkeypatch.setattr(module.subprocess,'Popen',spawn)
    monkeypatch.setattr(module,'_pick_free_port',lambda:31000+len(processes))
    monkeypatch.setattr(module,'_wait_for_bind',lambda *args,**kwargs:None)
    service=module.WebUIService()
    request=dict(lab_id='fixture-lab',lab_name='fixture',node_name='vd',vd_ip='198.18.1.20',
                 vd_port=443,scheme='https',user_id=1,jh_host='127.0.0.1',jh_port=32000)
    original=service.open(**request)
    yield service,request,original,processes
    service.shutdown()


def test_same_original_target_reuses_the_original_process(opened):
    service,request,original,processes=opened
    assert service.open(**request) is original and len(processes)==1


@pytest.mark.parametrize('change',['management-ip','jumphost-port'])
def test_changed_endpoint_does_not_reuse_tunnel_to_old_target(opened,change):
    service,request,original,processes=opened
    if change=='management-ip':request['vd_ip']='198.18.2.20'
    else:request['jh_port']=32001
    current=service.open(**request)
    assert current is not original, 'open reused an SSH tunnel bound to the previous endpoint'
    assert current.vd_ip==request['vd_ip'] and len(processes)==2


@pytest.mark.parametrize('field,value',[('jh_host','127.0.0.2'),('scheme','http'),('user_id',2),('lab_name','renamed')])
def test_other_effective_destination_changes_replace_original(opened,field,value):
    service,request,original,processes=opened;request[field]=value
    current=service.open(**request)
    assert current is not original and len(processes)==2
    assert service.get(original.token) is None
    processes[0].terminate.assert_called_once()
    assert current.upstream_authorization is None


def test_resolved_defaults_are_compared_before_reuse(opened,monkeypatch):
    service,request,original,processes=opened
    request['jh_host']=None
    monkeypatch.setattr(module.settings,'JUMPHOST_HOST','127.0.0.1')
    assert service.open(**request) is original
    monkeypatch.setattr(module.settings,'JUMPHOST_HOST','127.0.0.2')
    current=service.open(**request)
    assert current is not original and current.ssh_host=='127.0.0.2' and len(processes)==2


def test_legacy_name_endpoint_uses_effective_port22_and_ignores_unused_host(opened):
    service,request,original,processes=opened
    request.update(jh_port=None,jh_host='ignored')
    legacy=service.open(**request)
    assert legacy is not original and legacy.ssh_host=='dnlab-fixture-jumphost' and legacy.ssh_port==22
    request['jh_host']='also-ignored'
    assert service.open(**request) is legacy and len(processes)==2
    request.update(jh_host=legacy.ssh_host,jh_port=22)
    assert service.open(**request) is legacy


@pytest.mark.parametrize('field',['JUMPHOST_USER','GUI_SSH_KEY'])
def test_changed_ssh_identity_settings_replace_original(opened,monkeypatch,field):
    service,request,original,processes=opened
    monkeypatch.setattr(module.settings,field,'changed-setting')
    assert service.open(**request) is not original and len(processes)==2


def test_reuse_updates_request_metadata_without_changing_connection(opened):
    service,request,original,processes=opened;request.update(path='/new-ui',label='Updated UI')
    assert service.open(**request) is original and len(processes)==1
    assert original.path=='/new-ui' and original.label=='Updated UI'


def test_failed_replacement_never_returns_or_registers_old_target(opened,monkeypatch):
    service,request,original,processes=opened;request['vd_ip']='198.18.2.20'
    def fail(*args,**kwargs):raise module.WebUITunnelError('replacement bind failed')
    monkeypatch.setattr(module,'_wait_for_bind',fail)
    with pytest.raises(module.WebUITunnelError,match='replacement bind failed'):service.open(**request)
    assert service.get(original.token) is None and not service.list()
    assert not service._by_key
    assert len(processes)==2
    for process in processes:process.terminate.assert_called_once()


def test_failed_replacement_spawn_reports_tunnel_error_without_old_fallback(opened,monkeypatch):
    service,request,original,processes=opened;request['jh_port']=32001
    def fail(*args,**kwargs):raise OSError('SSH executable unavailable')
    monkeypatch.setattr(module.subprocess,'Popen',fail)
    with pytest.raises(module.WebUITunnelError,match='avviare'):service.open(**request)
    assert service.get(original.token) is None and not service.list() and not service._by_key
    processes[0].terminate.assert_called_once()
