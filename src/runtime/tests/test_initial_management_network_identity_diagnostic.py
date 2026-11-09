"""Regression for durable initial management identity across stop/restart.
"""
from copy import deepcopy

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from fakes import FakeDocker, FakeLinux,planned_request


class Docker(FakeDocker):
    def __init__(self):
        super().__init__()
        self.networks['mgmt']['Id']='a'*64
        self.networks['mgmt']['Name']='mgmt'
        self.networks['mgmt']['IPAM']['Config']=[{'Subnet':'192.0.2.0/24','Gateway':'192.0.2.1'}]

    def create(self,name,config):
        result=super().create(name,config)
        for network,endpoint in self.containers[name]['NetworkSettings']['Networks'].items():
            endpoint['NetworkID']=self.networks[network]['Id']
        return result


def request(action,revision,identity,spec=None):
    value={'schema_version':1,'lab_id':'demo','node_id':'R1','action':action,
           'expected_revision':revision,'request_id':identity}
    if spec is not None:value['spec']=spec
    return value


def test_restart_refuses_recreated_initial_management_network(tmp_path):
    journal=Journal(tmp_path/'native')
    try:
        docker=Docker();engine=Engine(journal,Backend(docker,FakeLinux()))
        spec={'kind':'linux','container_name':'native-r1','image':'sha256:'+'d'*64,
              'management':{'network':'mgmt','ipv4':'192.0.2.2'}}
        def execute(raw):return engine.execute(journal.submit(planned_request(engine,raw))['id'])
        assert execute(request('start',0,'initial',spec))['phase']=='completed'
        original=deepcopy(docker.networks['mgmt'])
        assert docker.containers['native-r1']['NetworkSettings']['Networks']['mgmt']['NetworkID']==original['Id']
        assert execute(request('stop',1,'stop'))['phase']=='completed'
        # Same name, driver, IPAM, addresses and labels; different Docker object.
        docker.networks['mgmt']={**original,'Id':'b'*64}
        calls=len(docker.calls)
        with pytest.raises(NetworkIdentityConflict):execute(request('start',2,'restart',spec))
        assert docker.calls[calls:]==[] and docker.containers=={}
        assert binding(journal,request('start',2,'restart',spec),'mgmt')['network']['Id']=='a'*64
        with pytest.raises(NetworkIdentityConflict):engine.inspect('demo','R1')
    finally:journal.close()


import pytest
from contextlib import contextmanager
from dnlab_runtime.management_network import binding,NetworkIdentityConflict


@pytest.fixture
def managed(tmp_path):
    journal=Journal(tmp_path/'native');docker=Docker();linux=FakeLinux()
    linux.network_identity=lambda:{'boot':'fixture','namespace':'fixture'}
    engine=Engine(journal,Backend(docker,linux))
    spec={'kind':'linux','container_name':'native-r1','image':'sha256:'+'d'*64,
          'management':{'network':'mgmt','ipv4':'192.0.2.2'}}
    yield engine,journal,docker,spec
    journal.close()


def execute(engine,journal,raw):return engine.execute(journal.submit(planned_request(engine,raw))['id'])


def test_initial_proof_is_durable_before_create_and_same_network_restart_succeeds(managed):
    engine,journal,docker,spec=managed;original=docker.create
    def create(name,config):
        proof=binding(journal,request('start',0,'initial',spec),'mgmt')
        assert proof['network']['Id']=='a'*64
        assert config['HostConfig']['NetworkMode']=='a'*64
        assert set(config['NetworkingConfig']['EndpointsConfig'])=={'a'*64}
        return original(name,config)
    docker.create=create
    assert execute(engine,journal,request('start',0,'initial',spec))['phase']=='completed'
    proof=binding(journal,{'lab_id':'demo','node_id':'R1'},'mgmt')
    assert execute(engine,journal,request('stop',1,'stop'))['phase']=='completed'
    assert binding(journal,{'lab_id':'demo','node_id':'R1'},'mgmt')==proof
    assert execute(engine,journal,request('start',2,'restart',spec))['phase']=='completed'
    assert binding(journal,{'lab_id':'demo','node_id':'R1'},'mgmt')==proof


@pytest.mark.parametrize('field,value',[
    ('Id','b'*64),('Driver','bridge'),('Options',{'bridge':'foreign'}),
    ('Labels',{'io.dnlab.lab':'another'}),('EnableIPv6',False),
    ('IPAM',{'Driver':'dnlab-vrf','Config':[{'Subnet':'192.0.2.0/25','Gateway':'192.0.2.1'}]}),
    ('IPAM',{'Driver':'dnlab-vrf','Options':{'foreign':'yes'},'Config':[{'Subnet':'192.0.2.0/24','Gateway':'192.0.2.1'}]}),
])
def test_inspect_and_stop_refuse_network_configuration_drift_before_mutation(managed,field,value):
    engine,journal,docker,spec=managed
    assert execute(engine,journal,request('start',0,'initial',spec))['phase']=='completed'
    before=deepcopy(docker.calls);docker.networks['mgmt'][field]=value
    with pytest.raises(NetworkIdentityConflict):engine.inspect('demo','R1')
    result=execute(engine,journal,request('stop',1,'stop'))
    assert result['phase']=='recovery_required' and docker.calls==before
    assert docker.containers['native-r1']['State']['Running'] is True


def test_retry_and_reopened_journal_preserve_original_network_identity(managed):
    engine,journal,docker,spec=managed
    assert execute(engine,journal,request('start',0,'initial',spec))['phase']=='completed'
    assert execute(engine,journal,request('stop',1,'stop'))['phase']=='completed'
    path=journal.db.execute('PRAGMA database_list').fetchone()[2]
    original=deepcopy(docker.networks['mgmt'])
    raw=planned_request(engine,request('start',2,'restart',spec));op=journal.submit(raw)
    docker.networks['mgmt']['Id']='b'*64
    assert engine.execute(op['id'])['phase']=='recovery_required'
    before=deepcopy(docker.calls);journal.close()
    from pathlib import Path
    reopened=Journal(Path(path).parent)
    try:
        engine=Engine(reopened,Backend(docker,FakeLinux()))
        assert engine.reconcile(op['id'])['phase']=='recovery_required'
        assert docker.calls==before
        docker.networks['mgmt']=original
        assert engine.reconcile(op['id'])['phase']=='completed'
        assert docker.containers['native-r1']['NetworkSettings']['Networks']['mgmt']['NetworkID']=='a'*64
    finally:reopened.close()


def test_network_changed_immediately_after_pin_is_not_allocated(managed):
    engine,journal,docker,spec=managed;transaction=journal.transaction;changed=[False]
    @contextmanager
    def replace_after_commit():
        with transaction():yield
        if not changed[0] and binding(journal,{'lab_id':'demo','node_id':'R1'},'mgmt'):
            changed[0]=True;docker.networks['mgmt']['Id']='b'*64
    journal.transaction=replace_after_commit
    result=execute(engine,journal,request('start',0,'initial',spec))
    assert changed[0] and result['phase']=='recovery_required'
    assert docker.calls==[] and docker.containers=={}


def test_pin_storage_failure_prevents_docker_allocation(managed):
    import sqlite3
    engine,journal,docker,spec=managed
    def deny_insert(action,table,*args):
        return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT and table=='management_network_proofs' else sqlite3.SQLITE_OK
    journal.db.set_authorizer(deny_insert)
    result=execute(engine,journal,request('start',0,'initial',spec))
    assert result['phase'] in ('failed','recovery_required') and docker.calls==[]
    assert binding(journal,{'lab_id':'demo','node_id':'R1'},'mgmt') is None
    journal.db.set_authorizer(None)


def placeholder(docker):
    value=docker.containers['native-r1'];name=next(iter(value['NetworkSettings']['Networks']))
    value['HostConfig']=deepcopy(value['Config']['HostConfig'])
    value['State']={'Status':'created','Running':False,'Pid':0}
    value['NetworkSettings']['SandboxID']=''
    value['NetworkSettings']['Networks'][name]={'NetworkID':'','EndpointID':'',
        'IPAMConfig':{'IPv4Address':'192.0.2.2'}}
    return value


def test_created_and_exited_docker_placeholders_are_qualified_by_birth_and_pin(managed):
    engine,journal,docker,spec=managed
    create,start,signal=docker.create,docker.start,docker.signal
    def created(name,config):
        result=create(name,config);placeholder(docker);return result
    def started(identity):
        start(identity)
        value=docker.find(identity);value['State']['Status']='running'
        value['NetworkSettings']['SandboxID']='sandbox'
        value['NetworkSettings']['Networks']['mgmt'].update(NetworkID='a'*64,EndpointID='endpoint',IPAddress='192.0.2.2')
    def stopped(identity,sig):
        signal(identity,sig);placeholder(docker)['State']['Status']='exited'
    docker.create=created;docker.start=started;docker.signal=stopped
    assert execute(engine,journal,request('start',0,'initial',spec))['phase']=='completed'
    assert execute(engine,journal,request('stop',1,'stop'))['phase']=='completed'
    assert docker.containers=={}


@pytest.mark.parametrize('change',['mode','ipam','sandbox','running','network_id','endpoint_id','extra_network'])
def test_unqualified_placeholder_refuses_start_and_compensation(managed,change):
    engine,journal,docker,spec=managed;create=docker.create
    def created(name,config):
        result=create(name,config);value=placeholder(docker);endpoint=value['NetworkSettings']['Networks']['mgmt']
        if change=='mode':value['HostConfig']['NetworkMode']='foreign'
        if change=='ipam':endpoint['IPAMConfig']['IPv4Address']='192.0.2.99'
        if change=='sandbox':value['NetworkSettings']['SandboxID']='foreign'
        if change=='running':value['State']['Running']=True
        if change=='network_id':endpoint['NetworkID']='b'*64
        if change=='endpoint_id':endpoint['EndpointID']='foreign'
        if change=='extra_network':value['NetworkSettings']['Networks']['extra']={}
        return result
    docker.create=created
    result=execute(engine,journal,request('start',0,'initial',spec))
    assert result['phase']=='recovery_required'
    assert [call[0] for call in docker.calls]==['create']


def test_new_lab_epoch_keeps_history_but_missing_proof_within_epoch_is_rejected(managed):
    from dnlab_runtime.lab_closure import control
    engine,journal,docker,spec=managed
    assert execute(engine,journal,request('start',0,'initial',spec))['phase']=='completed'
    stop={**request('stop',1,'stop'),'stop_mode':'coordinated'}
    op=journal.submit(stop);assert engine.execute(op['id'])['phase']=='awaiting_link_cleanup'
    for stage in ('cleanup','finalize'):
        engine.stops.request_stage(op['id'],'demo','R1',stage);engine.execute(op['id'])
    close={'closure_id':'1'*32,'generation':1,'stops':[stop]}
    control(engine,'demo','close',close);control(engine,'demo','finish',{'closure_id':'1'*32,'generation':1})
    control(engine,'demo','reopen',{'closure_id':'1'*32,'generation':1,'request_id':'explicit-reopen'})
    docker.networks['mgmt']['Id']='b'*64
    assert execute(engine,journal,{**request('start',2,'new-epoch',spec),'lab_generation':2})['phase']=='completed'
    assert journal.db.execute('SELECT count(*) FROM management_network_proofs').fetchone()[0]==2
    assert execute(engine,journal,{**request('stop',3,'new-stop'),'lab_generation':2})['phase']=='completed'
    journal.db.execute('DELETE FROM management_network_proofs WHERE generation=2')
    calls=deepcopy(docker.calls)
    assert execute(engine,journal,{**request('start',4,'lost-proof',spec),'lab_generation':2})['phase']=='recovery_required'
    assert docker.calls==calls and docker.containers=={}


def test_new_node_cannot_reset_a_shared_lab_network_pin(managed):
    engine,journal,docker,spec=managed
    assert execute(engine,journal,request('start',0,'initial',spec))['phase']=='completed'
    assert execute(engine,journal,request('stop',1,'stop'))['phase']=='completed'
    docker.networks['mgmt']['Id']='b'*64
    raw={**request('start',0,'spawn-new-node',{**spec,'container_name':'native-r2'}),'node_id':'R2'}
    calls=deepcopy(docker.calls)
    with pytest.raises(NetworkIdentityConflict):execute(engine,journal,raw)
    assert docker.calls==calls and docker.containers=={}
    assert binding(journal,raw,'mgmt')['network']['Id']=='a'*64
