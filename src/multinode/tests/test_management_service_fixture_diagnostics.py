"""Capture original fixture failures durably, before cleanup changes journals."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

TOOLS=Path(__file__).resolve().parents[2]/'runtime/tools'
for path in (TOOLS,TOOLS.parent):
    if str(path) not in sys.path:sys.path.insert(0,str(path))
import management_service_diagnostics as diagnostics
from tests.test_jumphost_network_guard import fixture


def test_comparison_saves_original_types_and_nested_difference_before_raising(tmp_path):
    expected={'dns':{'records':(('name','address'),)},'binding':{'container_id':'original'}}
    actual={'dns':{'records':[['name','address']]},'binding':{'container_id':'foreign'}}
    with pytest.raises(RuntimeError,match='fixture comparison publication-replay differs'):
        diagnostics.compare_snapshot(tmp_path,'publication-replay',expected,actual)
    saved=json.loads((tmp_path/'publication-replay.json').read_text())
    assert saved['matches'] is False and expected['dns']['records']==(('name','address'),)
    assert saved['differences']==[
        {'path':'/binding/container_id','expected':'original','actual':'foreign'},
        {'path':'/dns/records','expected_type':'tuple','actual_type':'list',
         'expected':[['name','address']],'actual':[['name','address']]}]
    assert (tmp_path/'publication-replay.json').stat().st_mode & 0o777==0o600


def test_equal_comparison_keeps_original_equality_and_redacts_tuple_secrets(tmp_path):
    diagnostics.compare_snapshot(tmp_path,'publication-binding',{'values':('secret-marker',)},
                                 {'values':('secret-marker',)},['secret-marker'])
    text=(tmp_path/'publication-binding.json').read_text();saved=json.loads(text)
    assert 'secret-marker' not in text and saved['matches'] is True and saved['differences']==[]


@pytest.mark.parametrize('expected,actual',[(False,True),({'x':1},{}),([1],[1,2]),({'a/b':1},{'a/b':2})])
def test_comparison_rejects_changed_values_and_missing_or_added_fields(tmp_path,expected,actual):
    with pytest.raises(RuntimeError):diagnostics.compare_snapshot(tmp_path,'publication',expected,actual)
    assert json.loads((tmp_path/'publication.json').read_text())['matches'] is False


def test_original_worker_stderr_and_phase_saved_without_stdin_or_secrets(tmp_path,monkeypatch):
    host=diagnostics.DiagnosticHost(tmp_path);host.phase='service-materialization';host.secrets=['secret-marker']
    monkeypatch.setattr(subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout='',stderr='original failure secret-marker'))
    with pytest.raises(RuntimeError,match='original failure'):
        host.run_input('python3 -c pass',json.dumps({'source':'code','request':{'action':'apply','env':'secret-marker'}}))
    text=(tmp_path/'worker-events.json').read_text();rows=json.loads(text)
    assert 'secret-marker' not in text and 'original failure <redacted>' in text
    assert rows[0]['action']=='apply' and rows[0]['phase']=='service-materialization'
    assert rows[0]['exit_code']==1 and rows[0]['status']=='failed'
    assert rows[0]['causes'][0]['type']=='RuntimeError' and rows[0]['elapsed_seconds']>=0
    assert (tmp_path/'worker-events.json').stat().st_mode & 0o777==0o600
    assert 'stdin' not in rows[0] and 'source' not in rows[0]


def test_snapshot_keeps_failure_step_before_cleanup_and_omits_config(tmp_path,monkeypatch):
    (tmp_path/'jump').mkdir()
    record={'phase':'recovery_required','step':'veth_create','action':'ensure','error_type':'JumphostError',
        'nonce':'a'*32,'config':{'generation':'b'*32,'env':{'JUMPHOST_PASSWORD':'secret-marker'}},'management_attachments':{}}
    (tmp_path/'jump/test.json').write_text(json.dumps(record))
    host=diagnostics.DiagnosticHost(tmp_path)
    monkeypatch.setattr(subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout='[]',stderr=''))
    diagnostics.capture_before_cleanup(tmp_path,host,None,None,'fixture')
    record['phase']='cleaned';record['step']='dhcp_assets_cleanup'
    (tmp_path/'jump/test.json').write_text(json.dumps(record))
    text=(tmp_path/'before-cleanup.json').read_text();saved=json.loads(text)['journals'][0]
    assert saved['phase']=='recovery_required' and saved['step']=='veth_create'
    assert 'secret-marker' not in text and 'env' not in text


def test_qualified_fixture_delete_accepts_empty_204_and_checks_absence(fixture):
    worker,env=fixture;worker.operate()
    class API:
        def request(self,method,path):
            assert method=='DELETE' and path=='/networks/'+'a'*64
            env.value=None;env.links=[]
            return None  # Docker HTTP204, already handled by Backend.Docker.
    assert diagnostics.remove_fixture_external(worker,API())=='a'*64
    assert env.value is None and len(env.creates)==1


def test_fixture_delete_refuses_foreign_or_occupied_network(fixture):
    worker,env=fixture;worker.operate();calls=[]
    class API:
        def request(self,*args):calls.append(args)
    env.value['Containers']={'foreign':{}}
    with pytest.raises(RuntimeError,match='consumers'):diagnostics.remove_fixture_external(worker,API())
    assert calls==[]
    env.value['Containers']={};env.value['Labels']['org.dnlab.jumphost.network.creator']='f'*32
    with pytest.raises(RuntimeError):diagnostics.remove_fixture_external(worker,API())
    assert calls==[] and env.value is not None
