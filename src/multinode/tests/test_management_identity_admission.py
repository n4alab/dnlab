"""Coordinator admission rejects identity conflicts before remote work."""
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from dnlab_multinode.controllers import node as node_module, plan as plan_module
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.services import state as state_svc
from dnlab_multinode.services.config import ConfigError, assign_sticky_management
from tests.test_management_identity_ledger_diagnostic import management, make_nodes


class Admitted(Exception):
    pass


def topology(topo_factory):
    topo=topo_factory(name='lab',nodes=make_nodes('r1','r2'),links=[],num_workers=0)
    topo.mgmt=management()
    return topo


def test_plan_retry_reuses_original_identity_before_resources_or_ssh(tmp_path,monkeypatch,topo_factory):
    topo=topology(topo_factory)
    topo.nodes['r1'].mgmt_mac='02:00:00:00:00:11'
    allocated=assign_sticky_management(deepcopy(topo.nodes),topo.mgmt,lab_name=topo.name)
    st=DeploymentState(lab_name='lab',topology_file=str(tmp_path/'lab.yml'))
    (st.mgmt_ip_reservations,st.mgmt_ipv6_reservations,st.mgmt_mac_reservations,
     st.mgmt_duid_reservations,st.mgmt_iaid_reservations)=allocated
    state_svc.save_state(st,tmp_path)
    disk_before=state_svc.load_state('lab',tmp_path)
    monkeypatch.setattr(plan_module,'parse_topology',lambda *a,**kw:topo)
    clients=MagicMock();monkeypatch.setattr(plan_module,'create_clients',clients)
    def admitted(*args,**kwargs):
        for name,values in zip(('ip','ipv6','mac','duid','iaid'),allocated):
            assert topo.raw['dnlab_mgmt_'+name+'_reservations']==values
        assert topo.nodes['r1'].mgmt_mac=='02:00:00:00:00:11'
        raise Admitted()
    monkeypatch.setattr(plan_module,'extract_resources',admitted)
    with pytest.raises(Admitted):plan_module.PlanController(str(tmp_path/'lab.yml')).run()
    assert state_svc.load_state('lab',tmp_path)==disk_before
    clients.assert_not_called()


@pytest.mark.parametrize('conflict',['ipv6','mac','ipv4-owner'])
def test_plan_conflict_keeps_topology_ledgers_and_remote_state_unchanged(tmp_path,monkeypatch,topo_factory,conflict):
    topo=topology(topo_factory);st=DeploymentState(lab_name='lab',topology_file=str(tmp_path/'lab.yml'))
    if conflict=='ipv6':
        for node in topo.nodes.values():node.mgmt_ipv6='2001:db8:1::20';node.mgmt_ipv6_explicit=True
    if conflict=='mac':topo.nodes['r2'].mgmt_mac='invalid'
    if conflict=='ipv4-owner':
        st.mgmt_ip_reservations={'removed':'198.18.0.20'}
        topo.nodes['r2'].mgmt_ipv4='198.18.0.20';topo.nodes['r2'].mgmt_ipv4_explicit=True
    state_svc.save_state(st,tmp_path);before=deepcopy(topo);disk_before=state_svc.load_state('lab',tmp_path)
    monkeypatch.setattr(plan_module,'parse_topology',lambda *a,**kw:topo)
    clients=MagicMock();resources=MagicMock()
    monkeypatch.setattr(plan_module,'create_clients',clients);monkeypatch.setattr(plan_module,'extract_resources',resources)
    with pytest.raises(ConfigError):plan_module.PlanController(str(tmp_path/'lab.yml')).run()
    assert topo==before and state_svc.load_state('lab',tmp_path)==disk_before
    clients.assert_not_called();resources.assert_not_called()


@pytest.mark.parametrize('conflict',['ipv6','mac','ipv4-owner'])
def test_hot_add_conflict_is_rejected_before_clients_or_state_save(tmp_path,monkeypatch,topo_factory,conflict):
    topo=topology(topo_factory);st=DeploymentState(lab_name='lab',topology_file=str(tmp_path/'lab.yml'),runtime_mode='per-vd')
    if conflict=='ipv6':
        for node in topo.nodes.values():node.mgmt_ipv6='2001:db8:1::20';node.mgmt_ipv6_explicit=True
    if conflict=='mac':topo.nodes['r2'].mgmt_mac='invalid'
    if conflict=='ipv4-owner':
        st.mgmt_ip_reservations={'removed':'198.18.0.20'}
        topo.nodes['r2'].mgmt_ipv4='198.18.0.20';topo.nodes['r2'].mgmt_ipv4_explicit=True
    state_svc.save_state(st,tmp_path);before=deepcopy(topo);state_before=deepcopy(st)
    ctrl=object.__new__(node_module.NodeLifecycleController);ctrl.topo=topo;ctrl.state=st;ctrl.state_dir=tmp_path
    clients=MagicMock();save=MagicMock()
    monkeypatch.setattr(node_module,'create_clients',clients);monkeypatch.setattr(node_module,'save_state',save)
    with pytest.raises(ConfigError):ctrl.add('r2')
    assert topo==before and st==state_before and state_svc.load_state('lab',tmp_path)==state_before
    clients.assert_not_called();save.assert_not_called()
