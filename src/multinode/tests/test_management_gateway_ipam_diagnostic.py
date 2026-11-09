"""The explicit VD gateway must be protected in Docker's management pool too."""
import ipaddress
import pytest
from tests.test_management_network_host import fixture

from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.mgmt_network import _expected_network
from dnlab_multinode.vrf_plugin import PluginStore,TENANT_OPTION,RESERVED_OPTION,HOST_INDEX_OPTION,HOST_COUNT_OPTION
from tests.test_management_segments import input_topology


def test_custom_jumphost_gateway_cannot_be_dynamically_assigned_by_ipam(topo_factory,tmp_path):
    topo=input_topology(topo_factory)
    topo.raw['management_networks']['default']['ipv4-gw']='198.18.1.2'
    topo,model=resolve(topo);expected=_expected_network(topo,'master');gateway=topo.mgmt.ipv4_gw
    assert all(node.mgmt_ipv4!=gateway for node in topo.nodes.values()),'the topology ledger already protects its gateway'
    store=PluginStore(tmp_path/'isolated-ipam.json')
    pool=store.request_pool({'AddressSpace':'dnlab-vrf-local','Pool':expected['ipv4_subnet'],'V6':False,
        'Options':{TENANT_OPTION:expected['network'],RESERVED_OPTION:','.join(expected['reserved']),
            HOST_INDEX_OPTION:str(expected['host_index']),HOST_COUNT_OPTION:str(expected['host_count'])}})
    # Account for Docker's own gateway request, as in a real network birth.
    store.request_address({'PoolID':pool['PoolID'],'Address':expected['ipv4_gateway'],
        'Options':{'RequestAddressType':'com.docker.network.gateway'}})
    allocated=store.request_address({'PoolID':pool['PoolID']})
    assert str(ipaddress.ip_interface(allocated['Address']).ip)!=gateway, 'IPAM allocated the live jumphost gateway'



def test_default_gateway_keeps_the_existing_reservation_contract(topo_factory):
    from copy import deepcopy
    from dnlab_multinode.services.mgmt_ips import ipv4_reservations
    topo,_=resolve(input_topology(topo_factory));before=deepcopy(topo)
    r=ipv4_reservations(topo.mgmt.ipv4_subnet)
    assert _expected_network(topo)['reserved']==sorted({r.docker_gw,r.anchor,r.dns,r.jumphost})
    assert topo==before


def test_all_hosts_protect_custom_gateway_with_stable_pool_retry(topo_factory,tmp_path):
    topo=input_topology(topo_factory);topo.raw['management_networks']['default']['ipv4-gw']='198.18.1.2'
    topo,_=resolve(topo)
    expected=[_expected_network(topo,host) for host in sorted(topo.all_hosts)]
    assert all('198.18.1.2' in e['reserved'] for e in expected)
    assert expected[0]['reserved']==expected[1]['reserved']
    store=PluginStore(tmp_path/'retry-ipam.json');e=expected[0]
    req={'AddressSpace':'dnlab-vrf-local','Pool':e['ipv4_subnet'],'V6':False,
        'Options':{TENANT_OPTION:e['network'],RESERVED_OPTION:','.join(e['reserved']),
            HOST_INDEX_OPTION:str(e['host_index']),HOST_COUNT_OPTION:str(e['host_count'])}}
    pool=store.request_pool(req)
    assert store.request_pool(req)['PoolID']==pool['PoolID']
    for _ in range(4):
        value=str(ipaddress.ip_interface(store.request_address({'PoolID':pool['PoolID']})['Address']).ip)
        assert value not in e['reserved']


@pytest.mark.parametrize('action',['preflight','ensure','recover'])
def test_existing_incompatible_reservations_are_refused_without_adoption_or_mutation(fixture,action):
    from copy import deepcopy
    from dnlab_multinode.services.management_network_host import NetworkGuard,NetworkError
    host,worker,docker,guard=fixture;guard.operate('ensure')
    wanted=deepcopy(guard.networks);wanted['default']['reserved'].append('10.1.0.2')
    wanted['default']['reserved'].sort()
    changed=NetworkGuard(worker,wanted,docker=docker,plugin=lambda:deepcopy(docker.plugin))
    before=worker.path.read_bytes();calls=deepcopy(docker.calls);networks=deepcopy(docker.networks)
    with pytest.raises(NetworkError):changed.operate(action)
    assert worker.path.read_bytes()==before and docker.calls==calls and docker.networks==networks
