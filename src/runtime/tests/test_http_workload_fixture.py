"""The HTTP fixture has a nonce-bound response and cooperative PID1 stop."""
import io
import json
from pathlib import Path
import signal
import sys
from unittest.mock import Mock,patch
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from http_workload_fixture import program


@pytest.mark.parametrize('nonce',['','x'*32,'a'*31,'a'*33])
def test_program_refuses_non_original_nonce(nonce):
    with pytest.raises(ValueError):program(nonce)


def test_server_checks_original_path_and_closes_after_signal(capsys):
    namespace={};signals={};events=[];server=Mock()
    def make(address,handler):
        assert address==('0.0.0.0',8080)
        server.handler=handler;return server
    def request():signals[signal.SIGTERM]()
    server.handle_request.side_effect=request
    with patch('http.server.HTTPServer',make),patch('signal.signal',lambda kind,fn:signals.update({kind:fn})):
        exec(program('a'*32),namespace)
    server.server_close.assert_called_once()
    assert 'READY:'+'a'*32 in capsys.readouterr().out
    good=Mock();good.path='/dnlab-probe/'+'a'*32;good.wfile=io.BytesIO()
    server.handler.do_GET(good)
    assert json.loads(good.wfile.getvalue())=={'nonce':'a'*32,'role':'dnlab-native-http'}
    good.send_response.assert_called_once_with(200)
    assert ('X-Dnlab-Fixture','a'*32) in [c.args for c in good.send_header.call_args_list]
    foreign=Mock();foreign.path='/dnlab-probe/'+'b'*32
    server.handler.do_GET(foreign)
    foreign.send_error.assert_called_once_with(404);foreign.wfile.write.assert_not_called()


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    import http_workload_fixture as module
    api=Mock();driver=Mock();driver.advance.return_value={'phase':'completed'}
    monkeypatch.setattr(module,'Docker',lambda:api)
    monkeypatch.setattr(module,'OperationDriver',lambda *a:driver)
    runtime=Mock(expected_journal_id='1'*32);store=Mock();store.contains.return_value=True
    args=(tmp_path,'lab','http-vd','sha256:'+'b'*64,{'network':'owned','ipv4':'198.19.233.11'},
          {'host':'master','socket_path':'/owned/runtime.sock','container_name':None},runtime,store)
    owner=module.Workload(*args)
    return module,owner,args,api,driver,runtime


def test_retry_cannot_overwrite_sealed_source_or_runtime_journal(fixture):
    module,owner,args,api,driver,runtime=fixture
    record=json.loads(owner.path.read_text());record['spec']['command']=['foreign']
    owner.path.write_text(json.dumps(record));before=owner.path.read_bytes()
    with pytest.raises(RuntimeError,match='source or original request'):module.Workload(*args)
    assert owner.path.read_bytes()==before
    record['spec']=owner.spec;owner.path.write_text(json.dumps(record));before=owner.path.read_bytes()
    runtime.expected_journal_id='2'*32
    with pytest.raises(RuntimeError,match='original intent'):module.Workload(*args)
    assert owner.path.read_bytes()==before
    api.request.assert_not_called();driver.prepare.assert_not_called()


def test_uncertain_start_preserves_resources_and_original_intent(fixture):
    module,owner,args,api,driver,runtime=fixture
    runtime.inspect_node.return_value={'operation':{'phase':'recovery_required'}}
    with pytest.raises(RuntimeError,match='tracked recovery'):owner.cleanup()
    assert json.loads(owner.path.read_text())['phase']=='cleanup_pending'
    assert json.loads(owner.path.read_text())['cleanup_verified'] is False
    api.inspect.assert_not_called();driver.prepare.assert_not_called()


def test_cleanup_uses_coordinator_stop_without_force_and_checks_absence(fixture):
    module,owner,args,api,driver,runtime=fixture
    owner.record.update(container_id='a'*64,revision=1);owner.save()
    runtime.inspect_node.side_effect=[{'operation':None,'container_id':'a'*64,'revision':1,'committed_state':'running'},
                                     {'operation':None,'container_id':None,'committed_state':'stopped','container_state':'absent'}]
    api.inspect.return_value=None;owner.cleanup()
    request=driver.prepare.call_args.args[0]
    assert request['action']=='stop' and request['expected_revision']==1 and 'force' not in request
    assert request['lab_id']=='lab' and request['node_id']=='http-vd'
    assert json.loads(owner.path.read_text())['cleanup_verified'] is True
    api.inspect.assert_called_once_with('a'*64)


def test_cleanup_refuses_replaced_container(fixture):
    module,owner,args,api,driver,runtime=fixture
    owner.record['container_id']='a'*64;owner.save()
    runtime.inspect_node.return_value={'operation':None,'container_id':'c'*64}
    with pytest.raises(RuntimeError,match='generation differs'):owner.cleanup()
    driver.prepare.assert_not_called();api.inspect.assert_not_called()


def test_workload_identity_is_rechecked_after_http_response(fixture):
    module,owner,args,api,driver,runtime=fixture
    owner.record.update(container_id='a'*64,revision=1,workload={'generation':1})
    view={'operation':None,'container_id':'a'*64,'revision':1,'committed_state':'running','container_state':'running','workload':{'generation':1}}
    runtime.inspect_node.return_value=view
    assert owner.verify()==view
    runtime.inspect_node.return_value={**view,'revision':2}
    with pytest.raises(RuntimeError,match='changed during proxy'):owner.verify()
    api.request.assert_not_called();driver.prepare.assert_not_called()
