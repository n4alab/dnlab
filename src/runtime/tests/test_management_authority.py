import copy
import json
import multiprocessing
import os
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from dnlab_runtime.backend import Backend,labels
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.management_authority import assignment
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.stable_management import Handoff
from test_stable_management import NetworkDocker,Port
from test_vxlan import Linux


def seed_management_network(journal,request,network):
    from dnlab_runtime.management_network import snapshot
    journal.db.execute('INSERT INTO management_network_proofs VALUES(?,?,?,?,?)',
        (request['lab_id'],request['node_id'],1,network['Name'],json.dumps({'network':snapshot(network),'operation_id':'qualified-fixture','request_fingerprint':'fixture'})))


class Docker(NetworkDocker):
    def __init__(self,request,spec):
        super().__init__();self.index=0;self.live={'Id':'vd','State':{'Running':True,'Pid':100},'Config':{'Labels':labels(request,spec)}}
        for network in self.networks.values():
            network['Driver']='dnlab-vrf';network['IPAM']['Driver']='dnlab-vrf'
            network['Labels']={'io.dnlab.lab':'lab','io.dnlab.managed':'mgmt-vrf'}
    def inspect(self,name):
        if self.live is None:return None
        value=copy.deepcopy(self.live);value['NetworkSettings']={'Networks':copy.deepcopy(self.endpoints)};return value
    def create(self,name,config):
        self.index+=1;self.calls.append(('create',config['HostConfig']['NetworkMode']))
        network=config['HostConfig']['NetworkMode'];ip=config['NetworkingConfig']['EndpointsConfig'][network]['IPAMConfig']['IPv4Address']
        self.endpoints={network:self.endpoint(network,ip)}
        self.live={'Id':'restart-'+str(self.index),'State':{'Running':False,'Pid':100+self.index},'Config':{'Labels':config['Labels']}}
        return {'Id':self.live['Id']}
    def start(self,identity):self.live['State']['Running']=True
    def signal(self,identity,signal):self.calls.append(('signal',identity));self.live['State']['Running']=False
    def remove(self,identity):self.live=None;self.endpoints={}


@pytest.fixture
def managed(tmp_path):
    request={'lab_id':'lab','node_id':'R1'}
    spec={'kind':'linux','container_name':'vd','image':'sha256:'+'a'*64,'management':{'network':'blue','ipv4':'192.0.2.2'}}
    journal=Journal(tmp_path/'state');docker=Docker(request,spec);port=Port(docker)
    port.container=lambda:docker.inspect('vd')
    backend=Backend(docker=docker,linux=Linux());engine=Engine(journal,backend)
    from fakes import seed_birth
    seed_birth(journal,request,spec,docker.live)
    seed_management_network(journal,request,docker.networks['blue'])
    journal.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?)',('lab','R1',1,json.dumps(spec),'running'))
    probe=SimpleNamespace(check=lambda network,name:{'network_id':network['Id'],'name':name,'cleanup_verified':True,'canary_container_id':'canary'})
    handoff=Handoff(journal,backend,request,spec,port,name_probe=probe)
    yield handoff,engine,docker,port,spec
    journal.close()


def move(handoff,identity='move',revision=1):
    handoff.submit(identity,'red','198.51.100.2',expected_node_revision=revision)
    return handoff.execute(handoff.by_request(identity)['id'])


def lifecycle(engine,action,revision,spec=None,identity=None):
    raw={'schema_version':1,'lab_id':'lab','node_id':'R1','request_id':identity or action,'action':action,'expected_revision':revision}
    if spec is not None:raw['spec']=spec
    from fakes import planned_request
    operation=engine.journal.submit(planned_request(engine,raw));return engine.execute(operation['id'])


def test_move_commits_assignment_revision_and_preserves_birth_spec(managed):
    handoff,engine,docker,port,spec=managed;original=copy.deepcopy(spec)
    assert move(handoff)['phase']=='completed'
    state=assignment(engine.journal,'lab','R1');assert state['phase']=='stable' and state['connection']['network_name']=='red'
    assert engine.journal.node('lab','R1')['spec']==original and engine.journal.node('lab','R1')['revision']==2
    assert engine.backend.verify(handoff.request,spec)['Id']=='vd'
    assert engine.inspect('lab','R1')['management']['connection']['network_name']=='red'
    assert handoff.submit('move','red','198.51.100.2',expected_node_revision=1)['phase']=='completed'


def test_management_request_id_is_scoped_to_lab_and_operation_ids_are_independent(managed):
    first,engine,_,_,_=managed
    assert move(first)['phase']=='completed'
    first_node=engine.journal.node('lab','R1')
    first_assignment=assignment(engine.journal,'lab','R1')
    request={'lab_id':'lab-two','node_id':'R1'}
    spec={'kind':'linux','container_name':'vd-two','image':'sha256:'+'a'*64,
          'management':{'network':'blue-two','ipv4':'192.0.2.2'}}
    docker=Docker(request,spec)
    docker.networks={name+'-two':{**network,'Name':name+'-two','Id':name+'-two',
                     'Labels':{'io.dnlab.lab':'lab-two','io.dnlab.managed':'mgmt-vrf'}}
                     for name,network in docker.networks.items()}
    docker.endpoints={'blue-two':docker.endpoint('blue-two','192.0.2.2')}
    docker.live['Id']='vd-two'
    port=Port(docker);port.owner='lab-two-port';port.identity['container_id']='vd-two'
    port.container=lambda:docker.inspect('vd-two')
    backend=Backend(docker=docker,linux=Linux())
    from fakes import seed_birth
    seed_birth(engine.journal,request,spec,docker.live)
    seed_management_network(engine.journal,request,docker.networks['blue-two'])
    engine.journal.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?)',('lab-two','R1',1,json.dumps(spec),'running'))
    second=Handoff(engine.journal,backend,request,spec,port,name_probe=first.name_probe)
    operation=second.submit('move','red-two','198.51.100.2',expected_node_revision=1)
    original=first.by_request('move')
    assert operation['id']!=original['id'] and operation['id']!='move'
    assert operation['request_id']==original['request_id']=='move'
    assert second.submit('move','red-two','198.51.100.2',expected_node_revision=1)==operation
    assert docker.calls==[] and assignment(engine.journal,'lab-two','R1')['phase']=='pending'
    assert engine.journal.node('lab-two','R1')['revision']==1
    assert engine.journal.node('lab','R1')==first_node
    assert assignment(engine.journal,'lab','R1')==first_assignment
    assert second.execute(operation['id'])['phase']=='completed'
    assert assignment(engine.journal,'lab-two','R1')['connection']['network_name']=='red-two'
    assert engine.journal.node('lab','R1')==first_node
    assert assignment(engine.journal,'lab','R1')==first_assignment


def test_pending_move_reserves_node_against_lifecycle_and_links(managed):
    handoff,engine,_,_,_=managed;handoff.submit('move','red','198.51.100.2')
    with pytest.raises(Conflict,match='management'):lifecycle(engine,'stop',1)
    with pytest.raises(Conflict,match='management'):engine.links.owner({'lab_id':'lab','node_id':'R1','expected_node_revision':1},creating=True)
    assert assignment(engine.journal,'lab','R1')['phase']=='pending'


def test_pending_lifecycle_prevents_move_before_probe_or_disconnect(managed):
    handoff,engine,docker,_,_=managed
    engine.journal.submit({'schema_version':1,'lab_id':'lab','node_id':'R1','request_id':'stop','action':'stop','expected_revision':1})
    with pytest.raises(Conflict,match='lifecycle'):handoff.submit('move','red','198.51.100.2')
    assert not docker.calls and assignment(engine.journal,'lab','R1') is None


@pytest.mark.parametrize('revision',[0,True,2])
def test_stale_or_invalid_move_revision_has_no_side_effects(managed,revision):
    handoff,engine,docker,_,_=managed
    with pytest.raises(Conflict):handoff.submit('move','red','198.51.100.2',expected_node_revision=revision)
    assert not docker.calls and assignment(engine.journal,'lab','R1') is None


@pytest.mark.parametrize('checkpoint',['detached','connected'])
def test_crash_before_commit_preserves_pending_until_verified_replay(managed,checkpoint):
    handoff,engine,_,port,spec=managed;handoff.submit('move','red','198.51.100.2')
    class Crash(BaseException):pass
    def crash(stage):
        if stage==checkpoint:raise Crash()
    with pytest.raises(Crash):handoff.execute(handoff.by_request('move')['id'],checkpoint=crash)
    assert assignment(engine.journal,'lab','R1')['phase']=='pending' and engine.journal.node('lab','R1')['revision']==1
    restored=Handoff(engine.journal,engine.backend,handoff.request,spec,port,name_probe=handoff.name_probe)
    assert restored.execute(restored.by_request('move')['id'])['phase']=='completed'
    assert engine.journal.node('lab','R1')['revision']==2
    engine.backend.verify(handoff.request,spec)


def test_rollback_commits_source_assignment_and_failed_rollback_stays_reserved(managed):
    handoff,engine,docker,port,spec=managed;port.fail_bind=True;docker.failure='blue'
    assert move(handoff)['phase']=='recovery_required'
    assert assignment(engine.journal,'lab','R1')['phase']=='pending'
    with pytest.raises(Conflict):lifecycle(engine,'stop',1)
    docker.failure=None;port.fail_bind=False
    assert handoff.execute(handoff.by_request('move')['id'])['phase']=='rolled_back'
    assert assignment(engine.journal,'lab','R1')['connection']['network_name']=='blue'
    assert engine.journal.node('lab','R1')['revision']==2
    engine.backend.verify(handoff.request,spec)


def test_container_generation_change_refuses_replay_without_mutations(managed):
    handoff,engine,docker,_,_=managed;handoff.submit('move','red','198.51.100.2')
    docker.live['Id']='foreign';count=len(docker.calls)
    assert handoff.execute(handoff.by_request('move')['id'])['phase']=='recovery_required'
    assert len(docker.calls)==count and assignment(engine.journal,'lab','R1')['phase']=='pending'


def test_stop_start_keeps_current_assignment_and_rebinds_new_container(managed):
    handoff,engine,docker,_,spec=managed;move(handoff)
    assert lifecycle(engine,'stop',2)['phase']=='completed'
    assert assignment(engine.journal,'lab','R1')['phase']=='stopped'
    assert lifecycle(engine,'start',3,spec)['phase']=='completed'
    assert docker.calls[-1]==('create','red')
    assert assignment(engine.journal,'lab','R1')['container_id']=='restart-1'
    assert engine.journal.node('lab','R1')['revision']==4
    engine.backend.verify(handoff.request,spec)


def test_failed_restart_restores_previous_desired_management(managed):
    handoff,engine,docker,_,spec=managed;move(handoff);lifecycle(engine,'stop',2)
    original=engine.backend.verify
    engine.backend.verify=lambda *args:(_ for _ in ()).throw(Conflict('fixture verification failed'))
    assert lifecycle(engine,'start',3,spec)['phase']=='failed'
    value=assignment(engine.journal,'lab','R1');assert value['phase']=='stopped' and 'restart' not in value
    engine.backend.verify=original
    assert lifecycle(engine,'start',3,spec,identity='retry')['phase']=='completed'
    assert docker.calls[-1]==('create','red')


def test_new_birth_image_keeps_independent_management_assignment(managed):
    handoff,engine,docker,_,spec=managed;move(handoff);lifecycle(engine,'stop',2)
    new=copy.deepcopy(spec);new['image']='sha256:'+'b'*64
    assert lifecycle(engine,'start',3,new)['phase']=='completed'
    assert docker.calls[-1]==('create','red')
    engine.backend.verify(handoff.request,new)


def test_explicit_new_management_at_restart_commits_new_birth_configuration(managed):
    handoff,engine,docker,_,spec=managed;move(handoff);lifecycle(engine,'stop',2)
    new=copy.deepcopy(spec);new['management']={'network':'blue','ipv4':'192.0.2.3'}
    assert lifecycle(engine,'start',3,new)['phase']=='completed'
    assert docker.calls[-1]==('create','blue') and assignment(engine.journal,'lab','R1') is None
    engine.backend.verify(handoff.request,new)


def test_journal_gate_is_reentrant_and_excludes_forked_runtime(managed):
    handoff,engine,_,_,_=managed;context=multiprocessing.get_context('fork');read,write=context.Pipe(duplex=False)
    directory=Path(engine.journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    def child():
        fresh=Journal(directory)
        try:
            with fresh.execution_lock:write.send('unexpected')
        except Conflict:write.send('blocked')
        finally:fresh.close()
    with engine.journal.execution_lock:
        with engine.journal.execution_lock:pass
        process=context.Process(target=child);process.start();process.join(5)
        if process.is_alive():process.kill();process.join();pytest.fail('forked execution lock hung')
        assert process.exitcode==0 and read.poll(1) and read.recv()=='blocked'


def test_server_keeps_queued_operation_alive_while_external_handoff_gate_busy(managed,tmp_path):
    import threading
    import time
    from dnlab_runtime.transport import Client,Server
    handoff,engine,_,_,spec=managed;context=multiprocessing.get_context('fork')
    parent,child_pipe=context.Pipe();directory=Path(engine.journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    def child():
        fresh=Journal(directory)
        try:
            with fresh.execution_lock:child_pipe.send('held');child_pipe.recv()
        finally:fresh.close()
    process=context.Process(target=child);process.start();assert parent.poll(3) and parent.recv()=='held'
    server=Server(str(tmp_path/'socket'),engine);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        client=Client(str(tmp_path/'socket'))
        raw={'schema_version':1,'lab_id':'lab','node_id':'R1','request_id':'repeat',
                        'action':'start','expected_revision':1,'spec':spec}
        proof=client.request('POST','/v1/plan',raw)['management_preflight']
        operation=client.request('POST','/v1/operations',{**raw,'management_preflight':proof})
        time.sleep(.6)
        assert server.worker.is_alive() and engine.journal.get(operation['id'])['phase']=='queued'
        parent.send('release');process.join(3);assert process.exitcode==0
        server.wake.set();deadline=time.monotonic()+3
        while time.monotonic()<deadline and engine.journal.get(operation['id'])['phase']=='queued':time.sleep(.02)
        assert engine.journal.get(operation['id'])['phase']=='completed' and server.worker.is_alive()
    finally:
        if process.is_alive():process.kill();process.join()
        server.shutdown();server.server_close();thread.join(3);parent.close();child_pipe.close()


def test_lifecycle_stop_refuses_replaced_container_before_signal(managed):
    handoff,engine,docker,_,_=managed;move(handoff);docker.live['Id']='replacement'
    count=len(docker.calls)
    result=lifecycle(engine,'stop',2)
    assert result['phase']=='recovery_required' and len(docker.calls)==count
    assert assignment(engine.journal,'lab','R1')['phase']=='stable'


def test_backend_cannot_switch_authority_to_another_journal(managed,tmp_path):
    from dnlab_runtime.management_authority import bind_backend
    handoff,engine,_,_,_=managed;other=Journal(tmp_path/'other')
    try:
        with pytest.raises(Conflict,match='another management authority'):bind_backend(engine.backend,other)
        assert engine.backend.management_journal is engine.journal
    finally:other.close()


def test_assignment_and_revision_roll_back_together_on_commit_storage_failure(managed):
    import sqlite3
    handoff,engine,_,_,_=managed;handoff.submit('move','red','198.51.100.2')
    def deny_revision(action,table,column,*args):
        return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_UPDATE and table=='nodes' and column=='revision' else sqlite3.SQLITE_OK
    engine.journal.db.set_authorizer(deny_revision)
    assert handoff.execute(handoff.by_request('move')['id'])['phase']=='recovery_required'
    assert assignment(engine.journal,'lab','R1')['phase']=='pending' and engine.journal.node('lab','R1')['revision']==1
    engine.journal.db.set_authorizer(None)
    assert handoff.execute(handoff.by_request('move')['id'])['phase']=='rolled_back'
    assert assignment(engine.journal,'lab','R1')['phase']=='stable' and engine.journal.node('lab','R1')['revision']==2


def test_pending_data_link_intent_blocks_management_before_disconnect(managed):
    handoff,engine,docker,_,_=managed
    payload={'node_id':'R1','host_interface':'source0','expected_node_revision':1}
    engine.journal.db.execute('INSERT INTO link_operations(id,lab,node,request_id,payload,hash,phase) VALUES(?,?,?,?,?,?,?)',
                              ('pending','lab','R1','pending',json.dumps(payload),'fixture','queued'))
    with pytest.raises(Conflict,match='link operation'):handoff.submit('move','red','198.51.100.2')
    assert not docker.calls and assignment(engine.journal,'lab','R1') is None


@pytest.mark.parametrize('phase',['queued','completed'])
@pytest.mark.parametrize('difference',['lab','node','birth','port'])
def test_handoff_operation_access_and_recovery_require_context(managed,phase,difference):
    handoff,engine,docker,port,spec=managed
    operation=handoff.submit('move','red','198.51.100.2')
    if phase=='completed':handoff.execute(operation['id'])
    request=copy.deepcopy(handoff.request);other_spec=copy.deepcopy(spec)
    other_port=copy.copy(port)
    if difference in ('lab','node'):request[difference+'_id']='other'
    elif difference=='birth':other_spec['image']='sha256:'+'b'*64
    else:other_port.owner='other-port'
    other=Handoff(engine.journal,engine.backend,request,other_spec,other_port,name_probe=handoff.name_probe)
    before=handoff.get(operation['id']);count=len(docker.calls)
    for call in (lambda:other.get(operation['id']),lambda:other.execute(operation['id']),
                 lambda:other.rollback(operation['id']),lambda:other.phase(operation['id'],'detaching')):
        with pytest.raises(Conflict,match='ownership'):call()
    assert handoff.get(operation['id'])==before and len(docker.calls)==count


def test_handoff_same_lab_request_key_cannot_be_reused_for_other_node(managed):
    handoff,engine,docker,port,spec=managed
    operation=handoff.submit('move','red','198.51.100.2')
    other=Handoff(engine.journal,engine.backend,{'lab_id':'lab','node_id':'other'},spec,port,name_probe=handoff.name_probe)
    with pytest.raises(Conflict,match='ownership'):other.submit('move','red','198.51.100.2')
    with pytest.raises(Conflict,match='ownership'):other.by_request('move')
    assert handoff.get(operation['id'])==operation and not docker.calls


def test_request_key_and_operation_id_have_explicit_distinct_lookup(managed):
    handoff,_,_,_,_=managed
    operation=handoff.submit('move','red','198.51.100.2')
    from dnlab_runtime.manifest import NotFound
    with pytest.raises(NotFound):handoff.get('move')
    assert handoff.by_request('move')['id']==operation['id']
    with pytest.raises(NotFound):handoff.by_request(operation['id'])


def test_terminal_rollback_is_read_only(managed):
    handoff,engine,docker,_,_=managed;operation=move(handoff)
    before=assignment(engine.journal,'lab','R1');count=len(docker.calls)
    assert handoff.rollback(operation['id'])==operation
    assert assignment(engine.journal,'lab','R1')==before and len(docker.calls)==count


def test_unscoped_legacy_move_is_preserved_and_not_adopted(managed):
    handoff,engine,docker,_,_=managed
    payload={'intent':{'owner':handoff.port.owner}}
    engine.journal.db.execute('INSERT INTO management_moves VALUES(?,?,?,?,?)',('legacy','vd',json.dumps(payload),'connecting',''))
    before=tuple(engine.journal.db.execute('SELECT * FROM management_moves').fetchone())
    with pytest.raises(Conflict,match='legacy'):handoff.get('legacy')
    with pytest.raises(Conflict,match='outstanding'):handoff.submit('legacy','red','198.51.100.2')
    assert tuple(engine.journal.db.execute('SELECT * FROM management_moves').fetchone())==before
    assert not docker.calls and assignment(engine.journal,'lab','R1') is None


def test_request_mapping_and_reservation_roll_back_together_on_storage_failure(managed):
    import sqlite3
    handoff,engine,docker,_,_=managed
    def deny(action,table,*args):
        return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT and table=='management_move_requests' else sqlite3.SQLITE_OK
    engine.journal.db.set_authorizer(deny)
    try:
        with pytest.raises(sqlite3.DatabaseError):handoff.submit('move','red','198.51.100.2')
    finally:engine.journal.db.set_authorizer(None)
    assert engine.journal.db.execute('SELECT count(*) FROM management_moves').fetchone()[0]==0
    assert engine.journal.db.execute('SELECT count(*) FROM management_move_requests').fetchone()[0]==0
    assert assignment(engine.journal,'lab','R1') is None and not docker.calls
    assert move(handoff)['phase']=='completed'
