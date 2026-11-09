"""Compiled segment plans are checked before durable native batch admission."""
from copy import deepcopy
import hashlib

import pytest

from tests.test_runtime_initial_deploy import world
from tests.test_runtime_topology_batch import topology
from dnlab_multinode.services.runtime_manifest import compile_initial
from dnlab_multinode.services.runtime_operations import RuntimeOperationError, digest
from dnlab_multinode.utils.naming import vrf_name
from dnlab_runtime.endpoint_uplink import vrf_host_peer


def inputs(world):
    batch,store,clients,engines,members=world;topo,plan,options=topology(world)
    for node in topo.nodes.values():node.mgmt_ipv4='';node.mgmt_mac=''
    topo.nodes['vd1'].management_network='blue'
    topo.raw={'management_networks':{
        'default':{'ipv4-subnet':'198.18.1.0/24','ipv6-subnet':'2001:db8:1::/64'},
        'blue':{'ipv4-subnet':'198.18.2.0/24','ipv6-subnet':'2001:db8:2::/64'}}}
    compiled=compile_initial(topo,plan,batch_id='deploy',**options)
    for host,engine in engines.items():
        docker=engine.backend.docker;linux=engine.backend.linux
        for cfg in compiled['management_plan']['networks'].values():
            docker.networks[cfg['network']]={'Id':hashlib.sha256((host+cfg['network']).encode()).hexdigest(),'Name':cfg['network'],
                'Driver':'dnlab-vrf','EnableIPv6':True,'Labels':{'io.dnlab.lab':topo.name,'io.dnlab.managed':'mgmt-vrf'},
                'Options':{'dnlab.bridge':cfg['bridge'],'dnlab.vrf':vrf_name(topo.name),'dnlab.lab':topo.name},
                'IPAM':{'Driver':'dnlab-vrf','Options':{'dnlab.tenant':cfg['network']},'Config':[
                    {'Subnet':cfg['ipv4_subnet'],'Gateway':cfg['docker_ipv4_gw']},{'Subnet':cfg['ipv6_subnet'],'Gateway':cfg['ipv6_gw']}]}}
        original=docker.inspect
        docker.inspect=lambda identity,original=original,docker=docker:original(identity) or next((deepcopy(c) for c in docker.containers.values() if c['Id']==identity),None)
        def hook(event,docker=docker,linux=linux):
            if event!='start':return
            for c in docker.containers.values():
                for network,endpoint in c['NetworkSettings']['Networks'].items():
                    endpoint['EndpointID']=hashlib.sha256(c['Id'].encode()).hexdigest();cfg=docker.networks[network]
                    peer=vrf_host_peer(cfg['Id'],endpoint['EndpointID'])
                    linux.links[(None,peer)]={'ifname':peer,'ifindex':11,'link_index':12,'master':cfg['Options']['dnlab.bridge'],'linkinfo':{'info_kind':'veth'}}
                    linux.links[(100,'mgmt-native')]={'ifname':'mgmt-native','ifindex':12,'link_index':11,'address':endpoint['MacAddress'],'linkinfo':{'info_kind':'veth'}}
        docker.hook=hook
    return topo,plan,options,compiled


def test_two_segment_members_execute_with_original_network_and_mac_proofs(world):
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    batch.prepare_topology(topo,plan,'deploy',**options)
    assert batch.get('demo','deploy',private=True)['payload']['compilation']['management_plan']==compiled['management_plan']
    assert all(not e.backend.docker.calls for e in engines.values())
    batch.advance('demo','deploy');assert batch.advance('demo','deploy')['phase']=='completed'
    bindings=batch.bindings('demo','deploy')
    for name,binding in bindings.items():
        model=compiled['management_plan'];segment=model['assignments'][name]['network'];network=model['networks'][segment]['network']
        container=engines[plan.host_for_vd(name)].backend.docker.inspect(binding['container_id'])
        assert set(container['NetworkSettings']['Networks'])=={network}
        assert container['NetworkSettings']['Networks'][network]['MacAddress']==model['ledgers']['mac'][name]


@pytest.mark.parametrize('difference',['subnet','bridge','vrf','tenant','gateway6'])
def test_wrong_actual_segment_is_rejected_before_any_child_or_allocation(world,difference):
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    name=compiled['management_plan']['networks']['blue']['network'];actual=engines['worker'].backend.docker.networks[name]
    if difference=='subnet':actual['IPAM']['Config'][0]['Subnet']='198.18.0.0/16'
    if difference=='bridge':actual['Options']['dnlab.bridge']='foreign-br'
    if difference=='vrf':actual['Options']['dnlab.vrf']='foreign-vrf'
    if difference=='tenant':actual['IPAM']['Options']['dnlab.tenant']='foreign'
    if difference=='gateway6':actual['IPAM']['Config'][1]['Gateway']='2001:db8:2::1'
    with pytest.raises(RuntimeOperationError,match='segment differs'):batch.prepare_topology(topo,plan,'deploy',**options)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0]==0
    assert all(not e.backend.docker.calls for e in engines.values())


def test_inconsistent_metadata_with_recomputed_hash_is_refused_before_remote_call(world):
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    compiled['management_plan']['ledgers']['ipv4']['default']['vd0']='198.18.1.99'
    compiled['fingerprint']=digest({k:v for k,v in compiled.items() if k!='fingerprint'})
    batch.factory=lambda _:(_ for _ in ()).throw(AssertionError('no remote preflight'))
    batch.driver.client_factory=batch.factory
    with pytest.raises(RuntimeOperationError,match='management compilation differs'):
        batch.prepare('demo','deploy',compiled['members'],compilation=compiled)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0


def test_segment_metadata_is_immutable_across_batch_replay(world):
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    batch.prepare_topology(topo,plan,'deploy',**options);before=batch.get('demo','deploy',private=True)['payload']
    topo.raw['management_networks']['blue']['dhcp']=True
    with pytest.raises(RuntimeOperationError,match='compilation changed'):batch.prepare_topology(topo,plan,'deploy',**options)
    assert batch.get('demo','deploy',private=True)['payload']==before


@pytest.mark.parametrize('difference',['peer','host','address','dhcp','dns','routing'])
def test_service_metadata_rejected_before_remote_preflight_even_with_valid_hash(world,difference):
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    services=compiled['management_services']
    if difference=='peer':services['jumphost']['attachments']['blue']['config']['interface']='foreign'
    if difference=='host':services['jumphost']['attachments']['blue']['host_interface']='foreign'
    if difference=='address':services['jumphost']['attachments']['blue']['config']['ipv4']='192.0.2.1/24'
    if difference=='dhcp':services['dhcp_segments']=['blue']
    if difference=='dns':services['dns']['external_network']['gateway']='10.100.0.2'
    if difference=='routing':services['routing']['via']='host'
    compiled['fingerprint']=digest({k:v for k,v in compiled.items() if k!='fingerprint'})
    batch.factory=lambda _:(_ for _ in ()).throw(AssertionError('no remote preflight'))
    batch.driver.client_factory=batch.factory
    with pytest.raises(RuntimeOperationError,match='management compilation differs'):
        batch.prepare('demo','deploy',compiled['members'],compilation=compiled)
    assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert store.db.execute('SELECT count(*) FROM initial_batches').fetchone()[0]==0
    assert all(not engine.backend.docker.calls for engine in engines.values())


def test_service_plan_is_durable_and_unchanged_on_retry(world,tmp_path):
    from dnlab_multinode.services.runtime_operations import OperationStore
    from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    batch.prepare_topology(topo,plan,'deploy',**options)
    second=OperationStore(tmp_path/'coordinator')
    try:
        restarted=RuntimeInitialDeployment(second,lambda _:(_ for _ in ()).throw(AssertionError('no replan')))
        assert restarted.get('demo','deploy',private=True)['payload']['compilation']['management_services']==compiled['management_services']
        assert restarted.prepare_topology(topo,plan,'deploy',**options)['phase']=='prepared'
    finally:second.close()


def test_old_compilation_retry_retains_its_original_metadata_without_implicit_services(world):
    batch,store,clients,engines,members=world;topo,plan,options,compiled=inputs(world)
    del compiled['management_services'];compiled['fingerprint']=digest({k:v for k,v in compiled.items() if k!='fingerprint'})
    batch.prepare('demo','deploy',compiled['members'],compilation=compiled)
    before=batch.get('demo','deploy',private=True)['payload']
    batch.factory=lambda _:(_ for _ in ()).throw(AssertionError('no remote replan'))
    batch.driver.client_factory=batch.factory
    assert batch.prepare_topology(topo,plan,'deploy',**options)['phase']=='prepared'
    assert batch.get('demo','deploy',private=True)['payload']==before
