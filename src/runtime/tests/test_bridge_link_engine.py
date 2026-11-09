import copy
import json
import threading
from types import SimpleNamespace

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.bridge import BridgeManager
from dnlab_runtime.journal import Journal
from dnlab_runtime.link_engine import LinkEngine,validate
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from dnlab_runtime.vxlan import VxlanManager
from test_bridge import Linux,Crash


@pytest.fixture
def fixture(tmp_path):
    journal=Journal(tmp_path);linux=Linux();verified=[]
    for index,source in enumerate(linux.records,1):
        node='vd'+str(index)
        spec={'kind':'linux','container_name':node,'image':'sha256:'+'a'*64,
              'endpoints':[{'host_interface':source['ifname'],'node_interface':'eth1','mtu':1450}]}
        source['ifalias']=Backend.alias({'lab_id':'lab','node_id':node},spec)
        journal.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?)',('lab',node,1,json.dumps(spec),'running'))
    backend=SimpleNamespace(linux=linux,verify=lambda owner,spec:verified.append(owner['node_id']))
    engine=SimpleNamespace(journal=journal,backend=backend,execution_lock=threading.Lock())
    links=LinkEngine(engine,VxlanManager(journal,linux),BridgeManager(journal,linux));engine.links=links
    yield links,linux,engine,verified
    journal.close()


def request(**changes):
    value={'schema_version':1,'kind':'bridge','request_id':'create1','lab_id':'lab','link_id':'l0','action':'create',
           'endpoints':[{'node_id':'vd1','host_interface':'rt-left','expected_node_revision':1},
                        {'node_id':'vd2','host_interface':'rt-right','expected_node_revision':1}], 'spec':{'mtu':1450}}
    value.update(changes)
    if value['action']!='create':value.pop('spec',None)
    return value


def execute(links,raw):return links.execute(links.submit(raw)['id'])


def assert_states(links,expected):
    for name in ('rt-left','rt-right'):
        assert links.state('lab','l0',name)['state']==expected


def test_two_owner_plan_dedup_retry_delete_and_stop_guard(fixture):
    links,linux,engine,verified=fixture
    assert links.plan(request())['affected_nodes']==['vd1','vd2'] and not linux.calls
    operation=execute(links,request());assert operation['phase']=='completed'
    assert verified==['vd1','vd2'];assert_states(links,'active')
    reverse=request();reverse['endpoints'].reverse()
    assert links.submit(reverse)['id']==operation['id']
    count=len(linux.calls)
    assert execute(links,request(request_id='retry'))['phase']=='completed' and len(linux.calls)==count
    for node in ('vd1','vd2'):
        with pytest.raises(Conflict,match='before stopping'):links.node_free('lab',node)
        assert engine.journal.node('lab',node)['revision']==1
    assert execute(links,request(request_id='delete',action='delete'))['phase']=='completed'
    assert_states(links,'deleted')
    for node in ('vd1','vd2'):links.node_free('lab',node)


@pytest.mark.parametrize('change',['revision','owner','interface','stopped','kind'])
def test_each_endpoint_owner_is_checked_before_queue(fixture,change):
    links,linux,engine,_=fixture;raw=request()
    if change=='revision':raw['endpoints'][1]['expected_node_revision']=2
    if change=='owner':raw['endpoints'][1]['node_id']='foreign'
    if change=='interface':raw['endpoints'][1]['host_interface']='foreign0'
    if change=='stopped':engine.journal.db.execute("UPDATE nodes SET state='stopped' WHERE node='vd2'")
    if change=='kind':
        spec=engine.journal.node('lab','vd2')['spec'];spec['kind']='nos'
        engine.journal.db.execute('UPDATE nodes SET spec=? WHERE node=?',(json.dumps(spec),'vd2'))
    with pytest.raises(Conflict):links.submit(raw)
    assert not linux.calls and not links.pending()


def test_kernel_ownership_of_second_endpoint_is_checked_before_mutation(fixture):
    links,linux,_,_=fixture;linux.records[1]['ifalias']='dnlab-runtime:foreign'
    assert execute(links,request())['phase']=='failed'
    assert not linux.calls;assert_states(links,'deleted')


def test_queued_bridge_reserves_both_nodes_and_both_endpoints(fixture):
    from test_link_engine import request as vxlan_request
    links,linux,_,_=fixture;links.submit(request())
    for node in ('vd1','vd2'):
        with pytest.raises(Conflict,match='before stopping'):links.node_free('lab',node)
    with pytest.raises(Conflict,match='busy'):links.submit(request(request_id='other',link_id='l1'))
    raw=vxlan_request(lab_id='lab',node_id='vd2',host_interface='rt-right',request_id='vxlan')
    with pytest.raises(Conflict,match='busy'):links.submit(raw)
    assert not linux.calls


def test_pending_node_operation_on_second_owner_blocks_bridge(fixture):
    links,linux,engine,_=fixture
    engine.journal.db.execute('INSERT INTO operations(id,lab,node,request_id,payload,hash,phase) VALUES(?,?,?,?,?,?,?)',
        ('pending-node','lab','vd2','start2','{}','hash','queued'))
    with pytest.raises(Conflict,match='pending'):links.submit(request())
    assert not linux.calls


def test_active_bridge_cannot_be_reconfigured_or_used_by_vxlan(fixture):
    from test_link_engine import request as vxlan_request
    links,linux,_,_=fixture;execute(links,request());count=len(linux.calls)
    with pytest.raises(Conflict,match='reconfigured'):links.submit(request(request_id='mtu',spec={'mtu':1500}))
    with pytest.raises(Conflict,match='another transport'):
        links.submit(vxlan_request(lab_id='lab',node_id='vd2',host_interface='rt-right',link_id='l0',request_id='vxlan'))
    assert len(linux.calls)==count


def test_queued_cancellation_keeps_kernel_untouched(fixture):
    links,linux,_,_=fixture;operation=links.submit(request());links.cancel(operation['id'])
    assert links.execute(operation['id'])['phase']=='cancelled' and not linux.calls
    for node in ('vd1','vd2'):links.node_free('lab',node)


@pytest.mark.parametrize('mutation',range(1,14))
def test_cancelled_crash_create_recovers_both_endpoint_states(fixture,mutation):
    links,linux,engine,_=fixture;operation=links.submit(request());linux.fail_after=mutation;linux.crash=True
    with pytest.raises(Crash):links.execute(operation['id'])
    links.cancel(operation['id'])
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux),BridgeManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']=='cancelled';assert_states(restarted,'deleted')
    assert not linux.forward and not linux.qd and not any(linux.rules.values())
    assert len(linux.records)==2


@pytest.mark.parametrize('mutation',range(1,12))
@pytest.mark.parametrize('cancelled',[False,True])
def test_interrupted_delete_completes_both_endpoints(fixture,mutation,cancelled):
    links,linux,engine,_=fixture;execute(links,request())
    operation=links.submit(request(request_id='delete',action='delete'));linux.fail_after=len(linux.calls)+mutation;linux.crash=True
    with pytest.raises(Crash):links.execute(operation['id'])
    if cancelled:links.cancel(operation['id'])
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux),BridgeManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']=='completed';assert_states(restarted,'deleted')
    assert not linux.forward and not linux.qd and not any(linux.rules.values())


def test_interrupted_active_retry_preserves_existing_bridge(fixture):
    links,linux,engine,_=fixture;execute(links,request())
    operation=links.submit(request(request_id='retry'));original=links.bridge_manager.verify
    def crash(*args):raise Crash()
    links.bridge_manager.verify=crash
    with pytest.raises(Crash):links.execute(operation['id'])
    links.bridge_manager.verify=original;links.cancel(operation['id']);count=len(linux.calls)
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux),BridgeManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']=='cancelled';assert_states(restarted,'active')
    assert len(linux.calls)==count


def test_replay_failure_holds_both_nodes_until_explicit_recovery(fixture):
    links,linux,_,_=fixture;operation=links.submit(request());linux.fail_after=3;linux.crash=True
    with pytest.raises(Crash):links.execute(operation['id'])
    original=links.bridge_manager.delete
    def reject(*args):raise Conflict('ownership cannot be verified')
    links.bridge_manager.delete=reject;links.cancel(operation['id'])
    assert links.execute(operation['id'])['phase']=='recovery_required'
    for node in ('vd1','vd2'):
        with pytest.raises(Conflict,match='before stopping'):links.node_free('lab',node)
    links.bridge_manager.delete=original
    assert execute(links,request(request_id='recover',action='recover'))['phase']=='completed'
    assert links.get(operation['id'])['phase']=='failed';assert_states(links,'deleted')


@pytest.mark.parametrize('change',['extra','one','duplicate','boolean_revision','mtu','delete_spec','unknown_kind'])
def test_bridge_request_rejects_ambiguous_or_invalid_schema(change):
    raw=request()
    if change=='extra':raw['node_id']='vd1'
    if change=='one':raw['endpoints'].pop()
    if change=='duplicate':raw['endpoints'][1]=copy.deepcopy(raw['endpoints'][0])
    if change=='boolean_revision':raw['endpoints'][1]['expected_node_revision']=True
    if change=='mtu':raw['spec']['mtu']=True
    if change=='delete_spec':raw['action']='delete'
    if change=='unknown_kind':raw['kind']='unknown'
    with pytest.raises(RuntimeErrorBase):validate(raw)


def test_bridge_protocol_through_real_cli_adapter_and_unix_socket(fixture,tmp_path,monkeypatch):
    import os,shlex,subprocess,sys
    from pathlib import Path
    from dnlab_runtime.transport import Client,Server
    runtime_root=Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(runtime_root.parent/'multinode'))
    from dnlab_multinode.services.custom_runtime import RuntimeClient
    launcher=tmp_path/'dnlab-runtime'
    launcher.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable,'-m','dnlab_runtime.cli'])+' "$@"\n');launcher.chmod(0o700)
    env={**os.environ,'PATH':str(tmp_path)+os.pathsep+os.environ['PATH'],'PYTHONPATH':str(runtime_root)}
    class LocalCommand:
        def run(self,command):
            return subprocess.run(['/bin/sh','-c',command],env=env,check=True,capture_output=True,text=True,timeout=5).stdout
    links,_,engine,_=fixture;socket=str(tmp_path/'socket');server=Server(socket,engine)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    adapter=RuntimeClient(LocalCommand(),socket_path=socket);client=Client(socket)
    try:
        assert adapter.plan(request())['affected_nodes']==['vd1','vd2']
        operation=adapter.submit(request());result=adapter.wait(operation['id'],timeout=5)
        assert result['kind']=='bridge' and result['affected_nodes']==['vd1','vd2']
        assert adapter.submit(request())['id']==operation['id']
        for node,name in [('vd1','rt-left'),('vd2','rt-right')]:
            state=adapter.invoke('link-inspect','lab','l0',name)
            assert state['kind']=='bridge' and state['committed_state']=='active'
            assert state['node_id']==node and state['guest_readiness']=='unknown'
            with pytest.raises(RuntimeErrorBase,match='before stopping'):
                client.request('POST','/v1/operations',{'action':'stop','lab_id':'lab','node_id':node})
        deleted=adapter.submit(request(action='delete',request_id='delete-cli'))
        assert adapter.wait(deleted['id'],timeout=5)['phase']=='completed';assert_states(links,'deleted')
    finally:server.shutdown();server.server_close();thread.join()
