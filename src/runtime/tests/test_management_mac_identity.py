from copy import deepcopy
import hashlib

import pytest

from test_runtime import runtime,request,stop,run
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase,validate_request
from dnlab_runtime.endpoint_uplink import vrf_host_peer

MAC='02:11:22:33:44:55'


@pytest.fixture
def mac_runtime(runtime):
    engine,journal,docker,linux=runtime
    docker.networks['mgmt']['Options']={'dnlab.bridge':'br-test'}
    original_inspect=docker.inspect
    def inspect(identity):
        return original_inspect(identity) or next((deepcopy(c) for c in docker.containers.values() if c['Id']==identity),None)
    docker.inspect=inspect
    def hook(event):
        if event!='start':return
        for c in docker.containers.values():
            for name,e in c['NetworkSettings']['Networks'].items():
                e['EndpointID']=hashlib.sha256(c['Id'].encode()).hexdigest()
                peer=vrf_host_peer(docker.networks[name]['Id'],e['EndpointID'])
                linux.links[(None,peer)]={'ifname':peer,'ifindex':11,'link_index':12,'master':'br-test','linkinfo':{'info_kind':'veth'}}
                linux.links[(100,'arbitrary0')]={'ifname':'arbitrary0','ifindex':12,'link_index':11,'address':MAC,'linkinfo':{'info_kind':'veth'}}
    docker.hook=hook
    raw=request(spec={'kind':'linux','image':'sha256:'+'a'*64,'container_name':'native-mac',
                      'management':{'network':'mgmt','ipv4':'192.0.2.2','mac':MAC},'stop_timeout':1})
    return engine,journal,docker,linux,raw


@pytest.mark.parametrize('mac',[None,True,123,'','02:11:22:33:44','02:11:22:33:44:GG','02:11:22:33:44:AA','01:11:22:33:44:55','ff:ff:ff:ff:ff:ff','00:00:00:00:00:00'])
def test_invalid_native_mac_refused_before_allocation(mac_runtime,mac):
    engine,journal,docker,linux,raw=mac_runtime;raw['spec']['management']['mac']=mac
    with pytest.raises(RuntimeErrorBase,match='management.mac'):validate_request(raw)
    assert docker.calls==[]


def test_endpoint_creation_restart_and_plan_keep_original_mac(mac_runtime):
    engine,journal,docker,linux,raw=mac_runtime
    assert engine.plan(raw)['management_preflight']['management']['mac']==MAC
    assert run(engine,journal,raw)['phase']=='completed'
    first=docker.inspect('native-mac');endpoint=first['Config']['NetworkingConfig']['EndpointsConfig']['mgmt-id']
    assert endpoint['MacAddress']==MAC and engine.inspect('demo','R1')['container_state']=='running'
    assert run(engine,journal,stop())['phase']=='completed'
    again={**raw,'request_id':'restart','expected_revision':2}
    assert run(engine,journal,again)['phase']=='completed'
    assert docker.inspect('native-mac')['Id']!=first['Id']
    assert docker.inspect('native-mac')['NetworkSettings']['Networks']['mgmt']['MacAddress']==MAC


@pytest.mark.parametrize('changed',[None,'02:11:22:33:44:66'])
def test_restart_cannot_drop_or_change_device_identity(mac_runtime,changed):
    engine,journal,docker,linux,raw=mac_runtime
    run(engine,journal,raw);run(engine,journal,stop());before=list(docker.calls)
    raw.update(request_id='restart',expected_revision=2)
    if changed is None:del raw['spec']['management']['mac']
    else:raw['spec']['management']['mac']=changed
    with pytest.raises(Conflict,match='cannot change'):engine.plan(raw)
    assert docker.calls==before


@pytest.mark.parametrize('tamper',['docker','kernel','peer'])
def test_inspect_stop_and_recovery_preserve_changed_endpoint(mac_runtime,tamper):
    engine,journal,docker,linux,raw=mac_runtime;run(engine,journal,raw)
    if tamper=='docker':docker.containers['native-mac']['NetworkSettings']['Networks']['mgmt']['MacAddress']='02:11:22:33:44:66'
    elif tamper=='kernel':linux.links[(100,'arbitrary0')]['address']='02:11:22:33:44:66'
    else:linux.links[(100,'arbitrary0')]['link_index']=999
    before=list(docker.calls)
    with pytest.raises(Conflict):engine.inspect('demo','R1')
    op=journal.submit(stop());assert engine.execute(op['id'])['phase']=='recovery_required'
    assert engine.reconcile(op['id'])['phase']=='recovery_required'
    assert docker.calls==before and docker.inspect('native-mac')['State']['Running']


def test_duplicate_mac_reservation_and_foreign_docker_endpoint_refused(mac_runtime):
    engine,journal,docker,linux,raw=mac_runtime
    from fakes import planned_request
    journal.submit(planned_request(engine,raw))
    other=deepcopy(raw);other.update(node_id='R2',request_id='other');other['spec']['container_name']='other'
    with pytest.raises(Conflict,match='reserved'):engine.plan(other)
    assert docker.calls==[]


def test_occupied_mac_in_network_refuses_read_only_plan(mac_runtime):
    engine,journal,docker,linux,raw=mac_runtime
    docker.networks['mgmt']['Containers']={'foreign':{'MacAddress':MAC}}
    with pytest.raises(Conflict,match='occupied'):engine.plan(raw)
    assert docker.calls==[]


def test_reopened_recovery_retains_original_mac_and_workload_generation(mac_runtime):
    from pathlib import Path
    from dnlab_runtime.engine import Engine
    from dnlab_runtime.journal import Journal
    from fakes import planned_request
    engine,journal,docker,linux,raw=mac_runtime
    op=journal.submit(planned_request(engine,raw));hook=docker.hook
    def crash(event):
        hook(event)
        if event=='start':raise SystemExit('injected daemon crash after start')
    docker.hook=crash
    with pytest.raises(SystemExit):engine.execute(op['id'])
    identity=docker.inspect('native-mac')['Id'];before=list(docker.calls);docker.hook=hook
    path=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent;journal.close()
    reopened=Journal(path)
    try:
        fresh=Engine(reopened,engine.backend)
        assert fresh.execute(op['id'])['phase']=='completed'
        assert docker.inspect('native-mac')['Id']==identity
        assert docker.inspect('native-mac')['NetworkSettings']['Networks']['mgmt']['MacAddress']==MAC
        assert sum(c[0]=='create' for c in docker.calls)==sum(c[0]=='create' for c in before)==1
    finally:reopened.close()


@pytest.mark.parametrize('retained',[True,False])
def test_exited_original_generation_allows_cleared_mac_only_in_detached_placeholder(mac_runtime,retained):
    engine,journal,docker,linux,raw=mac_runtime;run(engine,journal,raw)
    c=docker.containers['native-mac'];c['HostConfig']=deepcopy(c['Config']['HostConfig'])
    c['State'].update(Running=False,Pid=0,Status='exited');c['NetworkSettings']['SandboxID']=''
    endpoint=c['NetworkSettings']['Networks']['mgmt']
    endpoint.update(NetworkID='mgmt-id' if retained else '',EndpointID='',MacAddress='',IPAMConfig={'IPv4Address':'192.0.2.2'})
    assert engine.inspect('demo','R1')['container_state']=='stopped'
    assert run(engine,journal,stop())['phase']=='completed'


@pytest.mark.parametrize('field,value',[('NetworkID','foreign'),('EndpointID','foreign'),('MacAddress','02:00:00:00:00:99')])
def test_inactive_mac_placeholder_rejects_nonoriginal_identity(mac_runtime,field,value):
    engine,journal,docker,linux,raw=mac_runtime;run(engine,journal,raw)
    c=docker.containers['native-mac'];c['HostConfig']=deepcopy(c['Config']['HostConfig'])
    c['State'].update(Running=False,Pid=0,Status='exited');c['NetworkSettings']['SandboxID']=''
    e=c['NetworkSettings']['Networks']['mgmt'];e.update(NetworkID='mgmt-id',EndpointID='',MacAddress='',IPAMConfig={'IPv4Address':'192.0.2.2'});e[field]=value
    with pytest.raises(Conflict):engine.inspect('demo','R1')
