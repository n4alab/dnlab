import json
import threading
from types import SimpleNamespace

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.journal import Journal
from dnlab_runtime.link_engine import LinkEngine
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase
from dnlab_runtime.vxlan import VxlanManager
from test_vxlan import Linux, Crash


@pytest.fixture
def fixture(tmp_path):
    journal = Journal(tmp_path)
    linux = Linux()
    spec = {'kind':'linux','container_name':'vd1','image':'sha256:'+'a'*64,
            'endpoints':[{'host_interface':linux.source['ifname'],'guest_interface':'eth1'}]}
    request = {'lab_id':'lab1','node_id':'vd1'}
    linux.source['ifalias'] = Backend.alias(request,spec)
    journal.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?)', ('lab1','vd1',1,json.dumps(spec),'running'))
    backend = SimpleNamespace(verify=lambda request, spec: None, linux=linux)
    engine = SimpleNamespace(journal=journal,backend=backend,execution_lock=threading.Lock())
    manager = VxlanManager(journal,linux)
    links = LinkEngine(engine,manager)
    yield links,linux,engine
    journal.close()


def request(**changes):
    value={'schema_version':1,'request_id':'create1','lab_id':'lab1','node_id':'vd1','link_id':'link1',
           'host_interface':'rt-0123456789ab','expected_node_revision':1,'action':'create',
           'spec':{'vni':3001,'underlay':'underlay0','local':'198.18.201.1','remote':'198.18.201.2','mtu':1450}}
    value.update(changes)
    if value['action']!='create':value.pop('spec')
    return value


def execute(links,raw):
    operation=links.submit(raw)
    return links.execute(operation['id'])


def test_plan_dedup_retry_delete_and_stop_guard(fixture):
    links,linux,_=fixture
    assert not links.plan(request())['mutations_performed'] and not linux.calls
    first=execute(links,request())
    assert first['phase']=='completed'
    count=len(linux.calls)
    assert links.submit(request())['id']==first['id']
    assert execute(links,request(request_id='repeat'))['phase']=='completed'
    assert len(linux.calls)==count
    assert links.inspect('lab1','link1',linux.source['ifname'])['committed_state']=='active'
    with pytest.raises(Conflict,match='before stopping'):
        links.node_free('lab1','vd1')
    assert execute(links,request(request_id='delete',action='delete'))['phase']=='completed'
    links.node_free('lab1','vd1')


@pytest.mark.parametrize('change', [{'lab_id':'foreign'}, {'node_id':'other'}, {'expected_node_revision':2}, {'host_interface':'foreign0'}])
def test_foreign_or_stale_owner_rejected_before_queue(fixture,change):
    links,linux,_=fixture
    with pytest.raises(Conflict):links.submit(request(**change))
    assert not linux.calls and not links.pending()


def test_kernel_alias_must_match_exact_node_not_just_runtime_prefix(fixture):
    links,linux,_=fixture
    linux.source['ifalias']='dnlab-runtime:foreign-node'
    assert execute(links,request())['phase']=='failed'
    assert not linux.calls


def test_duplicate_id_with_changed_payload_is_rejected(fixture):
    links,linux,_=fixture
    links.submit(request())
    with pytest.raises(Conflict,match='different content'):
        links.submit(request(expected_node_revision=2))
    assert not linux.calls


def test_queued_cancellation_has_no_mutations(fixture):
    links,linux,_=fixture
    operation=links.submit(request())
    links.cancel(operation['id'])
    assert links.execute(operation['id'])['phase']=='cancelled'
    assert not linux.calls


def test_cancellation_between_mutations_rolls_back_only_new_link(fixture):
    links,linux,_=fixture
    operation=links.submit(request())
    original=linux.run
    def run(args):
        result=original(args)
        if len(linux.calls)==3:links.cancel(operation['id'])
        return result
    linux.run=run
    assert links.execute(operation['id'])['phase']=='cancelled'
    assert links.inspect('lab1','link1',linux.source['ifname'])['committed_state']=='deleted'
    assert not linux.rules and not linux.qd


def test_restart_compensates_interrupted_create_without_recreation(fixture):
    links,linux,engine=fixture
    operation=links.submit(request())
    linux.fail_after,linux.crash=3,True
    with pytest.raises(Crash):links.execute(operation['id'])
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']=='failed'
    assert restarted.inspect('lab1','link1',linux.source['ifname'])['committed_state']=='deleted'
    assert not linux.rules and not linux.qd


@pytest.mark.parametrize('mutation',range(1,10))
def test_restart_of_cancelled_interrupted_create_cleans_partial_resources(fixture,mutation):
    links,linux,engine=fixture
    operation=links.submit(request())
    linux.fail_after,linux.crash=mutation,True
    with pytest.raises(Crash):links.execute(operation['id'])
    # Cancellation is durable, but must not bypass compensation of the
    # applying operation when its worker returns after interruption.
    links.cancel(operation['id'])
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']=='cancelled'
    state=restarted.inspect('lab1','link1',linux.source['ifname'])
    assert state['committed_state']=='deleted'
    assert state['runtime_phase']=='cleaned'
    assert state['kernel_state']=='absent'
    assert not linux.rules and not linux.qd


@pytest.mark.parametrize('cancelled',[False,True])
def test_interrupted_retry_preserves_preexisting_active_link(fixture,cancelled):
    links,linux,engine=fixture
    execute(links,request())
    operation=links.submit(request(request_id='repeat'))
    original=links.manager.verify
    def crash(*args):raise Crash()
    links.manager.verify=crash
    with pytest.raises(Crash):links.execute(operation['id'])
    links.manager.verify=original
    if cancelled:links.cancel(operation['id'])
    count=len(linux.calls)
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']==('cancelled' if cancelled else 'failed')
    assert len(linux.calls)==count
    assert restarted.inspect('lab1','link1',linux.source['ifname'])['committed_state']=='active'


@pytest.mark.parametrize('cancelled',[False,True])
@pytest.mark.parametrize('mutation',range(1,4))
def test_restart_finishes_interrupted_delete_without_recreation(fixture,cancelled,mutation):
    links,linux,engine=fixture
    execute(links,request())
    operation=links.submit(request(request_id='delete',action='delete'))
    linux.fail_after,linux.crash=len(linux.calls)+mutation,True
    with pytest.raises(Crash):links.execute(operation['id'])
    if cancelled:links.cancel(operation['id'])
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux))
    assert restarted.execute(operation['id'])['phase']=='completed'
    assert restarted.inspect('lab1','link1',linux.source['ifname'])['committed_state']=='deleted'
    assert not linux.rules and not linux.qd


def test_cancelled_replay_cleanup_failure_requires_explicit_recovery(fixture):
    links,linux,engine=fixture
    operation=links.submit(request())
    linux.fail_after,linux.crash=3,True
    with pytest.raises(Crash):links.execute(operation['id'])
    links.cancel(operation['id'])
    restarted=LinkEngine(engine,VxlanManager(engine.journal,linux))
    def reject(*args):raise Conflict('cleanup ownership cannot be verified')
    restarted.manager.delete=reject
    assert restarted.execute(operation['id'])['phase']=='recovery_required'
    assert restarted.state('lab1','link1',linux.source['ifname'])['state']=='applying'
    with pytest.raises(Conflict,match='before stopping'):restarted.node_free('lab1','vd1')
    healthy=LinkEngine(engine,VxlanManager(engine.journal,linux))
    assert execute(healthy,request(request_id='recover',action='recover'))['phase']=='completed'
    assert healthy.get(operation['id'])['phase']=='failed'
    assert healthy.inspect('lab1','link1',linux.source['ifname'])['kernel_state']=='absent'


def test_replay_after_prior_cleanup_does_not_recreate_link(fixture):
    links,linux,_=fixture
    operation=links.submit(request())
    links.phase(operation['id'],'applying')
    assert links.execute(operation['id'])['phase']=='failed'
    assert not linux.calls


def test_unix_link_protocol_queues_status_and_inspection(fixture,tmp_path):
    import time
    from dnlab_runtime.transport import Client,Server
    links,linux,engine=fixture
    engine.links=links
    server=Server(str(tmp_path/'socket'),engine)
    thread=threading.Thread(target=server.serve_forever)
    thread.start()
    client=Client(str(tmp_path/'socket'))
    try:
        assert client.request('POST','/v1/link-plan',request())['mutations_performed'] is False
        operation=client.request('POST','/v1/link-operations',request())
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            result=client.request('GET','/v1/link-operations/'+operation['id'])
            if result['phase']=='completed':break
            time.sleep(.01)
        assert result['phase']=='completed'
        state=client.request('GET','/v1/links/lab1/link1/'+linux.source['ifname'])
        assert state['committed_state']=='active' and state['guest_readiness']=='unknown'
        with pytest.raises(RuntimeErrorBase,match='before stopping'):
            client.request('POST','/v1/operations',{'action':'stop','lab_id':'lab1','node_id':'vd1'})
        assert client.request('POST','/v1/link-operations',request())['id']==operation['id']
    finally:
        server.shutdown();server.server_close();thread.join()


def test_multinode_adapter_uses_real_cli_and_unix_operation_envelopes(fixture,tmp_path,monkeypatch):
    import os
    from pathlib import Path
    import shlex
    import subprocess
    import sys
    from dnlab_runtime.transport import Server

    runtime_root=Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(runtime_root.parent/'multinode'))
    from dnlab_multinode.services.custom_runtime import RuntimeClient,CustomRuntimeError

    # Exercise the actual shell pipeline, CLI JSON and Unix HTTP boundaries.
    # Kernel and workload checks remain the isolated fake fixture above.
    launcher=tmp_path/'dnlab-runtime'
    launcher.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable,'-m','dnlab_runtime.cli'])+' "$@"\n')
    launcher.chmod(0o700)
    env={**os.environ,'PATH':str(tmp_path)+os.pathsep+os.environ['PATH'],
         'PYTHONPATH':str(runtime_root)}
    class LocalCommand:
        def run(self,command):
            return subprocess.run(['/bin/sh','-c',command],env=env,check=True,
                                  capture_output=True,text=True,timeout=5).stdout

    links,linux,engine=fixture
    engine.links=links
    socket=str(tmp_path/'socket')
    server=Server(socket,engine)
    thread=threading.Thread(target=server.serve_forever)
    thread.start()
    client=RuntimeClient(LocalCommand(),socket_path=socket)
    try:
        assert client.plan(request())['mutations_performed'] is False
        created=client.submit(request())
        assert client.wait(created['id'],timeout=5)['error']==''
        assert client.submit(request())['id']==created['id']
        state=client.invoke('link-inspect','lab1','link1',linux.source['ifname'])
        assert state['committed_state']=='active' and state['guest_readiness']=='unknown'
        deleted=client.submit(request(request_id='delete-cli',action='delete'))
        assert client.wait(deleted['id'],timeout=5)['phase']=='completed'
        linux.source['ifalias']='dnlab-runtime:foreign-node'
        failed=client.submit(request(request_id='foreign-cli'))
        with pytest.raises(CustomRuntimeError,match='local link operation failed:'):
            client.wait(failed['id'],timeout=5)
    finally:
        server.shutdown();server.server_close();thread.join()
