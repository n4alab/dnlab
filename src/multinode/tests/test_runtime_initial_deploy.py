from copy import deepcopy
import json
import threading

import pytest

from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.services.runtime_operations import OperationStore,RuntimeOperationError
from tests.test_native_public import Client,Docker
from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from fakes import FakeLinux,FakeClock


@pytest.fixture
def world(tmp_path):
    store=OperationStore(tmp_path/'coordinator');clients={};engines={};members=[]
    for index,host in enumerate(('master','worker')):
        journal=Journal(tmp_path/host);clock=FakeClock();engine=Engine(journal,Backend(Docker(),FakeLinux(),clock=clock.clock,sleep=clock.sleep))
        clients[host]=Client(engine);engines[host]=engine
        request={'schema_version':1,'lab_id':'demo','node_id':'vd'+str(index),'request_id':'start-'+str(index),
                 'action':'start','expected_revision':0,'spec':{'kind':'linux','container_name':'drsp-vd'+str(index),
                 'image':'sha256:'+'a'*64,'stop_timeout':1,'env':{'SECRET':'private-test-value'}}}
        target={'host':host,'socket_path':'/run/runtime.sock','container_name':'runtime-fixture'}
        members.append({'request':request,'target':target})
    batch=RuntimeInitialDeployment(store,lambda target:clients[target['host']])
    yield batch,store,clients,engines,members
    store.close()
    for engine in engines.values():engine.journal.close()


def count(clients):return sum(sum(call[0]=='submit' for call in client.calls) for client in clients.values())


def test_prepares_all_before_any_mutation_and_commits_qualified_bindings(world):
    batch,store,clients,engines,members=world
    prepared=batch.prepare('demo','deploy',members)
    assert prepared['phase']=='prepared' and count(clients)==0
    assert 'private-test-value' not in json.dumps(prepared)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==2
    for e in engines.values():assert e.backend.docker.calls==[]
    assert batch.advance('demo','deploy')['phase']=='applying'
    assert count(clients)==1
    assert batch.advance('demo','deploy')['phase']=='completed'
    bindings=batch.bindings('demo','deploy')
    assert set(bindings)=={'vd0','vd1'} and all(b['revision']==1 for b in bindings.values())
    assert batch.advance('demo','deploy')['phase']=='completed' and count(clients)==2


def test_invalid_last_plan_prevents_all_intents_and_allocations(world):
    batch,store,clients,engines,members=world
    members[1]['request']['spec']['management']={'network':'missing','ipv4':'192.0.2.2'}
    with pytest.raises(Exception):batch.prepare('demo','deploy',members)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0]==0
    assert count(clients)==0 and all(not e.backend.docker.calls for e in engines.values())


@pytest.mark.parametrize('resource',['container','interface','management','wildcard_port'])
def test_intra_batch_conflicts_are_rejected_before_mutation(world,resource):
    batch,store,clients,engines,members=world
    for i,m in enumerate(members):
        if resource!='management':m['target']=deepcopy(members[0]['target'])
        if resource=='container':m['request']['spec']['container_name']='same-name'
        if resource=='interface':m['request']['spec']['endpoints']=[{'host_interface':'drsp-same','node_interface':'eth1'}]
        if resource in ('management','wildcard_port'):
            m['request']['spec']['management']={'network':'mgmt','ipv4':'192.0.2.'+str(2 if resource=='management' else 2+i)}
        if resource=='wildcard_port':m['request']['spec']['ports']=[{'host_ip':'0.0.0.0' if i==0 else '127.0.0.1','host_port':18080,'container_port':80,'protocol':'tcp'}]
    with pytest.raises(RuntimeOperationError,match='conflicting resources'):batch.prepare('demo','deploy',members)
    assert count(clients)==0 and store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0


def test_members_on_different_hosts_can_use_same_container_and_interface_names(world):
    batch,store,clients,engines,members=world
    for m in members:m['request']['spec'].update(container_name='same-name',endpoints=[{'host_interface':'drsp-same','node_interface':'eth1'}])
    batch.prepare('demo','deploy',members)
    batch.advance('demo','deploy');assert batch.advance('demo','deploy')['phase']=='completed'


def test_batch_admission_rolls_back_all_children_on_last_write_failure(world,monkeypatch):
    batch,store,clients,engines,members=world;original=store._prepare_locked
    def fail(request,*args):
        original(request,*args)
        if request['node_id']=='vd1':raise OSError('injected write failure')
    monkeypatch.setattr(store,'_prepare_locked',fail)
    with pytest.raises(OSError):batch.prepare('demo','deploy',members)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0]==0 and count(clients)==0


def test_same_batch_replay_never_replans_or_refreshes_management_proofs(world,monkeypatch):
    batch,store,clients,engines,members=world
    members[0]['request']['spec']['management']={'network':'mgmt','ipv4':'192.0.2.2'}
    batch.prepare('demo','deploy',members)
    before=deepcopy(batch.get('demo','deploy',private=True)['payload'])
    monkeypatch.setattr(clients['master'],'plan_node',lambda _:(_ for _ in ()).throw(AssertionError('must not replan')))
    assert batch.prepare('demo','deploy',deepcopy(members))['phase']=='prepared'
    assert batch.get('demo','deploy',private=True)['payload']==before
    changed=deepcopy(members);changed[0]['request']['spec']['env']['SECRET']='changed'
    with pytest.raises(RuntimeOperationError,match='manifest changed'):batch.prepare('demo','deploy',changed)


def test_drift_on_last_host_blocks_first_spawn_and_preserves_original_proof(world):
    batch,store,clients,engines,members=world
    members[1]['request']['spec']['management']={'network':'mgmt','ipv4':'192.0.2.2'}
    batch.prepare('demo','deploy',members)
    proof=deepcopy(store.get('demo','start-1',private=True)['request'])
    engines['worker'].backend.docker.networks['mgmt']['Id']='recreated'
    with pytest.raises(Exception):batch.advance('demo','deploy')
    assert count(clients)==0 and batch.get('demo','deploy')['phase']=='recovery_required'
    assert store.get('demo','start-1',private=True)['request']==proof
    with pytest.raises(RuntimeOperationError,match='explicit recovery'):batch.advance('demo','deploy')
    engines['worker'].backend.docker.networks['mgmt']['Id']='mgmt-id'
    batch.recover('demo','deploy');batch.advance('demo','deploy')
    assert batch.advance('demo','deploy')['phase']=='completed'


def test_lost_submit_ack_recovers_original_generation_without_duplicate_spawn(world):
    batch,store,clients,engines,members=world;client=clients['master'];submit=client.submit_node
    def lost(request):
        client.submit_node=submit;submit(request);raise TimeoutError('lost ACK')
    client.submit_node=lost;batch.prepare('demo','deploy',members)
    with pytest.raises(TimeoutError):batch.advance('demo','deploy')
    original_id=engines['master'].backend.docker.inspect('drsp-vd0')['Id']
    fresh=RuntimeInitialDeployment(store,batch.factory)
    fresh.recover('demo','deploy')
    assert count(clients)==1
    assert fresh.advance('demo','deploy')['phase']=='completed' and count(clients)==2
    assert engines['master'].backend.docker.inspect('drsp-vd0')['Id']==original_id


def test_cancellation_before_apply_seals_both_requests_without_spawning(world):
    batch,store,clients,engines,members=world
    batch.prepare('demo','deploy',members);batch.cancel('demo','deploy')
    assert batch.advance('demo','deploy')['phase']=='cancelled'
    assert count(clients)==0 and all(not e.backend.docker.calls for e in engines.values())


def test_cancellation_after_partial_commit_stops_only_owned_child_without_force(world):
    batch,store,clients,engines,members=world
    batch.prepare('demo','deploy',members);batch.advance('demo','deploy')
    batch.cancel('demo','deploy');assert batch.advance('demo','deploy')['phase']=='cancelled'
    assert engines['master'].backend.docker.containers=={} and engines['worker'].backend.docker.containers=={}
    assert ('signal','SIGTERM') in engines['master'].backend.docker.calls
    assert not any(('signal','SIGKILL') in e.backend.docker.calls for e in engines.values())


def test_partial_commit_replacement_blocks_next_spawn_and_cancellation(world):
    batch,store,clients,engines,members=world
    batch.prepare('demo','deploy',members);batch.advance('demo','deploy')
    docker=engines['master'].backend.docker;docker.containers['drsp-vd0']['Id']='foreign'
    before=list(docker.calls)
    with pytest.raises(Exception):batch.advance('demo','deploy')
    assert count(clients)==1 and docker.calls==before
    batch.cancel('demo','deploy')
    with pytest.raises(Exception):batch.advance('demo','deploy')
    assert docker.calls==before and count(clients)==1


def test_private_directory_sync_failure_prevents_any_remote_action(world,monkeypatch):
    batch,store,clients,engines,members=world;batch.prepare('demo','deploy',members)
    def fail():raise OSError('directory sync failed')
    monkeypatch.setattr(store,'sync_directory',fail)
    with pytest.raises(OSError):batch.advance('demo','deploy')
    assert count(clients)==0


@pytest.mark.parametrize('which',['node','request','generation','revision','kind'])
def test_invalid_batch_context_never_creates_intents(world,which):
    batch,store,clients,engines,members=world
    if which=='node':members[1]['request']['node_id']=members[0]['request']['node_id']
    if which=='request':members[1]['request']['request_id']=members[0]['request']['request_id']
    if which=='generation':members[1]['request']['lab_generation']=2
    if which=='revision':members[1]['request']['expected_revision']=False
    if which=='kind':members[1]['request']['spec']['kind']='cisco_n9kv'
    with pytest.raises(RuntimeOperationError):batch.prepare('demo','deploy',members)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0 and count(clients)==0


def test_remote_committed_node_cannot_be_adopted_by_new_batch(world):
    batch,store,clients,engines,members=world
    req=members[0]['request'];clients['master'].submit_node(req)
    members[0]['request']={**req,'request_id':'different','expected_revision':1}
    with pytest.raises(RuntimeOperationError,match='verified absent or stopped'):batch.prepare('demo','deploy',members)
    assert count(clients)==1 and store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0


def test_foreign_pending_coordinator_claim_blocks_new_batch_before_allocation(world):
    batch,store,clients,engines,members=world
    pending=deepcopy(members[0]);pending['request'].update(lab_id='other',node_id='other',request_id='other-start')
    pending['request']['spec']['container_name']=members[0]['request']['spec']['container_name']
    batch.driver.prepare(pending['request'],pending['target'])
    with pytest.raises(RuntimeOperationError,match='unfinished coordinator owner'):batch.prepare('demo','deploy',members)
    assert count(clients)==0 and store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==1


def test_closure_arriving_after_remote_preflight_rolls_back_entire_admission(world,monkeypatch):
    batch,store,clients,engines,members=world;old=clients['worker'].plan_node
    def closing(request):
        plan=old(request)
        with store.transaction():
            store.db.execute('INSERT INTO lab_closures VALUES(?,?)',('demo',json.dumps({'generation':1,'phase':'closed','allowed':{}})))
        return plan
    monkeypatch.setattr(clients['worker'],'plan_node',closing)
    with pytest.raises(RuntimeOperationError,match='closing or closed'):batch.prepare('demo','deploy',members)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0 and count(clients)==0


def test_shutdown_timeout_retains_owned_generation_without_force(world):
    batch,store,clients,engines,members=world
    batch.prepare('demo','deploy',members);batch.advance('demo','deploy')
    engines['master'].backend.docker.resist_term=True
    batch.cancel('demo','deploy')
    with pytest.raises(RuntimeOperationError,match='no force sent'):batch.advance('demo','deploy')
    assert batch.get('demo','deploy')['phase']=='recovery_required'
    docker=engines['master'].backend.docker
    assert docker.inspect('drsp-vd0')['State']['Running'] and ('signal','SIGKILL') not in docker.calls


def test_batch_and_member_integrity_are_checked_before_remote_actions(world):
    batch,store,clients,engines,members=world;batch.prepare('demo','deploy',members)
    original=store.get('demo','start-1',private=True)['request'];original['spec']['env']['SECRET']='tampered'
    store.db.execute('UPDATE operations SET request=? WHERE lab=? AND request_id=?',(json.dumps(original),'demo','start-1'))
    with pytest.raises(RuntimeOperationError,match='intent integrity'):batch.advance('demo','deploy')
    assert count(clients)==0


def test_cancelled_batch_replay_stays_terminal(world):
    batch,store,clients,engines,members=world
    batch.prepare('demo','deploy',members);batch.cancel('demo','deploy')
    assert batch.advance('demo','deploy')['phase']=='cancelled'
    before=count(clients)
    assert batch.cancel('demo','deploy')['phase']=='cancelled'
    assert batch.advance('demo','deploy')['phase']=='cancelled' and count(clients)==before


def test_duplicate_management_mac_across_hosts_rejected_before_any_spawn(world):
    batch,store,clients,engines,members=world
    for i,m in enumerate(members):
        m['request']['spec']['management']={'network':'mgmt','ipv4':'192.0.2.'+str(2+i),'mac':'02:11:22:33:44:55'}
    with pytest.raises(RuntimeOperationError,match='conflicting resources'):batch.prepare('demo','deploy',members)
    assert count(clients)==0 and store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
