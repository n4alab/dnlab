"""Force must remain an explicit choice across GUI transport paths."""
import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.lifecycle import NodeStopOptions
from app.services.lab_resolver import ResolvedLab
from app.services.multinode_service import MultinodeService, MultinodeServiceError


@pytest.fixture
def lab(tmp_path):
    path = tmp_path / 'lab.yml'
    path.write_text('name: lab\n')
    return ResolvedLab(uuid4(), 'Lab', 'lab', 'br-lab', path, None)


@pytest.mark.parametrize('action', ['stop', 'remove'])
@pytest.mark.parametrize('force', [False, True])
@pytest.mark.parametrize('remote', [False, True])
def test_gui_service_propagates_force_without_escalation(lab, monkeypatch, action, force, remote):
    service = MultinodeService()
    service._api_url = 'http://fixture' if remote else ''
    calls = []
    expected = {'lab_name': 'lab'}

    async def post(path, payload):
        calls.append((path, payload['node'], payload['force']))
        return expected

    class Controller:
        def __init__(self, *args, **kwargs):
            pass

        def stop(self, node, *, force=False):
            calls.append(('stop', node, force))
            return SimpleNamespace(to_dict=lambda: expected)

        def remove(self, node, *, force=False):
            calls.append(('remove', node, force))
            return SimpleNamespace(to_dict=lambda: expected)

    monkeypatch.setattr(service, '_api_post', post)
    monkeypatch.setitem(sys.modules, 'dnlab_multinode', SimpleNamespace(NodeLifecycleController=Controller))
    result = asyncio.run(getattr(service, 'node_' + action)(lab, 'a', force=force))
    assert result == expected
    assert calls == [('/labs/nodes/' + action if remote else action, 'a', force)]


@pytest.mark.parametrize('action', ['stop', 'remove'])
def test_gui_service_default_does_not_force(lab, monkeypatch, action):
    service = MultinodeService()
    service._api_url = 'http://fixture'
    service._api_post = AsyncMock(return_value={})
    asyncio.run(getattr(service, 'node_' + action)(lab, 'a'))
    assert service._api_post.call_args.args[1]['force'] is False


@pytest.mark.parametrize('value', ['false', 'true', 0, 1, None, [], {}])
def test_force_requires_a_boolean(value):
    with pytest.raises(ValueError):
        NodeStopOptions(force=value)


@pytest.mark.parametrize('force', [False, True])
def test_stop_route_passes_choice_and_records_it(lab, monkeypatch, force):
    from app.views.api import lab_routes as routes
    resolver = AsyncMock(return_value=lab)
    stop = AsyncMock(return_value={'success': True})
    recorded = AsyncMock()
    monkeypatch.setattr(routes, '_resolve_write', resolver)
    monkeypatch.setattr(routes._ctrl, 'node_stop', stop)
    monkeypatch.setattr(routes.audit, 'record', recorded)
    db = SimpleNamespace(commit=AsyncMock())
    user = SimpleNamespace(username='fixture')
    asyncio.run(routes.stop_node(lab.id, 'a', SimpleNamespace(), db, user, NodeStopOptions(force=force)))
    stop.assert_awaited_once_with(lab, 'a', force=force)
    assert recorded.call_args.kwargs['detail']['force'] is force


@pytest.mark.parametrize('force', [False, True])
def test_remove_route_preserves_topology_after_runtime_failure(lab, monkeypatch, force):
    from app.views.api import topology_routes as routes
    monkeypatch.setattr(routes, 'resolve_for_write', AsyncMock(return_value=lab))
    monkeypatch.setattr(routes.multinode, 'node_list', AsyncMock(return_value={'a': {}}))
    remove = AsyncMock(side_effect=MultinodeServiceError('shutdown not verified'))
    monkeypatch.setattr(routes.multinode, 'node_remove', remove)
    edits = []
    monkeypatch.setattr(routes._ctrl, 'remove_node_by_path', lambda *args: edits.append(args))
    before = lab.yaml_path.read_bytes()
    with pytest.raises(routes.HTTPException) as error:
        asyncio.run(routes.remove_node(lab.id, 'a', object(), object(), NodeStopOptions(force=force)))
    assert error.value.status_code == 409
    remove.assert_awaited_once_with(lab, 'a', force=force)
    assert edits == [] and lab.yaml_path.read_bytes() == before


def test_javascript_client_sends_only_the_requested_force():
    import shutil
    import subprocess
    node = shutil.which('node')
    if node is None:
        pytest.skip('node is needed to execute the browser API client')
    source = Path(__file__).parents[1] / 'app/views/static/js/api.js'
    script = r'''
const fs=require('fs'), vm=require('vm'), assert=require('assert');
const calls=[];
const context={fetch:async (path,init)=>{
 calls.push({path,method:init.method,body:JSON.parse(init.body)});
 return {ok:true,status:200,headers:{get:()=>'application/json'},json:async()=>({})};
}};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1],'utf8')+';globalThis.client=API;',context);
(async()=>{
 await context.client.Labs.stopNode('lab','a');
 await context.client.Labs.stopNode('lab','a',{force:true});
 await context.client.Labs.removeNode('lab','a');
 await context.client.Labs.removeNode('lab','a',{force:true});
 assert.deepStrictEqual(calls.map(x=>x.body),[{},{force:true},{},{force:true}]);
 assert.deepStrictEqual(calls.map(x=>x.method),['POST','POST','DELETE','DELETE']);
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    subprocess.run([node, '-e', script, str(source)], check=True, capture_output=True, text=True, timeout=10)
