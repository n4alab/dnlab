from copy import deepcopy
import hashlib

import pytest

from tests.test_runtime_initial_deploy import world
from tests.conftest import make_topology
from dnlab_multinode.models.topology import VDNode
from dnlab_multinode.models.schedule import SchedulePlan,HostAssignment
from dnlab_multinode.services.runtime_manifest import compile_initial,NativeManifestError
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from dnlab_runtime.endpoint_uplink import vrf_host_peer


def topology(world):
    batch,store,clients,engines,members=world
    topo=make_topology(name='demo',num_workers=1,links=[],nodes={m['request']['node_id']:VDNode(
        name=m['request']['node_id'],kind='linux',image=m['request']['spec']['image'],mgmt_ipv4='192.0.2.'+str(2+i),
        mgmt_mac='02:11:22:33:44:'+str(10+i)) for i,m in enumerate(members)})
    worker=topo.workers.pop('worker1');worker.name='worker';topo.workers['worker']=worker
    topo.mgmt.network='mgmt';topo.mgmt.ipv4_subnet='192.0.2.0/24';topo.mgmt.ipv4_gw='192.0.2.1'
    topo.webui_wishlist={'vd0':[{'container_port':443,'scheme':'https','path':'/'}]}
    plan=SchedulePlan(lab_name='demo',assignments={m['target']['host']:HostAssignment(m['target']['host'],'unused',[m['request']['node_id']]) for m in members})
    options={'targets':{m['target']['host']:m['target'] for m in members}}
    return topo,plan,options


def test_topology_metadata_durably_admitted_with_all_original_children(world,monkeypatch):
    batch,store,clients,engines,members=world;topo,plan,options=topology(world)
    assert batch.prepare_topology(topo,plan,'deploy',**options)['phase']=='prepared'
    payload=batch.get('demo','deploy',private=True)['payload']
    assert payload['compilation']['webui_wishlist']==topo.webui_wishlist
    assert all('ports' not in m['request']['spec'] for m in payload['original'])
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==2
    assert all(not e.backend.docker.calls for e in engines.values())
    for client in clients.values():monkeypatch.setattr(client,'plan_node',lambda _:(_ for _ in ()).throw(AssertionError('no remote replan')))
    assert batch.prepare_topology(topo,plan,'deploy',**options)['phase']=='prepared'
    topo.webui_wishlist['vd0'][0]['path']='/changed'
    with pytest.raises(RuntimeOperationError,match='compilation changed'):batch.prepare_topology(topo,plan,'deploy',**options)
    assert batch.get('demo','deploy',private=True)['payload']==payload


def test_unsupported_last_node_is_rejected_before_any_remote_preflight(world,monkeypatch):
    batch,store,clients,engines,members=world;topo,plan,options=topology(world)
    topo.nodes['vd1'].extra={'ports':['8456:443/tcp']}
    batch.factory=lambda _:(_ for _ in ()).throw(AssertionError('no remote call'))
    batch.driver.client_factory=batch.factory
    with pytest.raises(NativeManifestError,match='publication'):batch.prepare_topology(topo,plan,'deploy',**options)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0]==0


def test_compilation_integrity_checked_before_remote_admission(world):
    batch,store,clients,engines,members=world;topo,plan,options=topology(world)
    compiled=compile_initial(topo,plan,batch_id='deploy',**options);compiled['fingerprint']='0'*64
    with pytest.raises(RuntimeOperationError,match='provenance'):batch.prepare('demo','deploy',compiled['members'],compilation=compiled)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert all(not e.backend.docker.calls for e in engines.values())


@pytest.mark.parametrize('runtime_container',[None,'runtime-fixture'])
def test_compiled_linux_batch_executes_through_real_runtime_engine_and_generation_guards(world,runtime_container):
    batch,store,clients,engines,members=world;topo,plan,options=topology(world)
    for target in options['targets'].values():target['container_name']=runtime_container
    observed=[];factory=batch.factory
    def traced(target):
        observed.append(deepcopy(target))
        assert target==options['targets'][target['host']]
        return factory(target)
    batch.factory=traced;batch.driver.client_factory=traced
    for engine in engines.values():
        docker=engine.backend.docker;linux=engine.backend.linux
        docker.networks['mgmt']['Options']={'dnlab.bridge':'br-fixture'}
        original=docker.inspect
        def inspect(identity,original=original,docker=docker):
            return original(identity) or next((deepcopy(c) for c in docker.containers.values() if c['Id']==identity),None)
        docker.inspect=inspect
        def hook(event,docker=docker,linux=linux):
            if event!='start':return
            for container in docker.containers.values():
                for network,endpoint in container['NetworkSettings']['Networks'].items():
                    endpoint['EndpointID']=hashlib.sha256(container['Id'].encode()).hexdigest()
                    peer=vrf_host_peer(docker.networks[network]['Id'],endpoint['EndpointID'])
                    linux.links[(None,peer)]={'ifname':peer,'ifindex':11,'link_index':12,'master':'br-fixture','linkinfo':{'info_kind':'veth'}}
                    linux.links[(100,'mgmt-native')]={'ifname':'mgmt-native','ifindex':12,'link_index':11,'address':endpoint['MacAddress'],'linkinfo':{'info_kind':'veth'}}
        docker.hook=hook
    batch.prepare_topology(topo,plan,'deploy',**options)
    payload=batch.get('demo','deploy',private=True)['payload']
    for member in payload['original']:
        original=store.get('demo',member['request']['request_id'],private=True)
        assert original['target']==options['targets'][original['target']['host']]
    assert batch.advance('demo','deploy')['phase']=='applying'
    assert batch.advance('demo','deploy')['phase']=='completed'
    bindings=batch.bindings('demo','deploy');assert set(bindings)=={'vd0','vd1'}
    assert {target['host'] for target in observed}==set(options['targets'])
    for node,vd in topo.nodes.items():
        host=plan.host_for_vd(node);container=engines[host].backend.docker.inspect(bindings[node]['container_id'])
        assert container['Config']['HostConfig']['PortBindings']=={}
        assert container['NetworkSettings']['Networks']['mgmt']['MacAddress']==vd.mgmt_mac
