"""Routing reservations cover DHCP-disabled segments without enabling DHCP."""
from dnlab_multinode.controllers.management_prepare import compile_inputs
from dnlab_multinode.controllers.management_routing_prepare import requests
from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.services.management_segments import resolve
from tests.test_management_segments import input_topology
from tests.test_management_service_intent import inputs


def prepared(topo_factory):
    topo,model=resolve(input_topology(topo_factory),prepare_probes=True)
    assert model['networks']['default']['dhcp'] is True
    assert model['networks']['blue']['dhcp'] is False
    return topo,model


def test_management_without_dhcp_has_an_infrastructure_routing_identity(topo_factory):
    topo,model=prepared(topo_factory)
    assert set(model['probes'])==set(model['networks'])


def test_prepared_static_management_can_enter_the_routing_gate(topo_factory):
    topo,model=prepared(topo_factory);topo,model,configs=inputs(topo,model)
    ips={'master':'192.0.2.1','worker1':'192.0.2.2'}
    schedule=SchedulePlan(lab_name=topo.name,assignments={},vrf_table_id=42000)
    _,plan=compile_inputs(topo,schedule,ips,management_generation='1'*32,
        service_configs=configs,service_model=model)
    original={'barrier_id':'2'*32,'plan':plan,'targets':{host:{} for host in ips}}
    proofs={host:{'networks':{'proof':{'networks':{key:{'id':'a'*64,'nonce':'b'*32}
        for key in model['networks']}}}} for host in ips}
    servers={key:{'mac':'02:00:00:00:00:f'+str(index),'link_local':'fe80::f'+str(index)}
        for index,key in enumerate(sorted(model['networks']))}
    assert len(requests(original,proofs,servers))==4
