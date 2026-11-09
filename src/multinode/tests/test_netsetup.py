"""Management coordinator admission and native worker boundary."""
import copy
import json
from types import SimpleNamespace

import pytest

from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.services import netsetup
from dnlab_multinode.services.management_host import ManagementError, digest
from dnlab_multinode.services.realnet_vni import Registry


class Client:
    def __init__(self, name, events): self.name=name;self.events=events;self.reject=None
    def run_input(self, command, payload, **kwargs):
        p=json.loads(payload);self.events.append((self.name,p['action']))
        if self.reject==p['action']:raise RuntimeError('host preflight refused')
        action=p['action'];network=action.startswith('network-');operation=action.removeprefix('network-')
        status=('verified' if operation.startswith('preflight') else ('cleaned' if operation in ('cleanup','verify-cleaned') else 'active')) if network else {'provision':'active','preflight-provision':'verified','read':'read','preflight':'verified','preflight-cleanup':'verified','ensure':'active','verify-cleaned':'cleaned','cleanup':'cleaned'}[action]
        out=dict(status=status,plan=digest(p['plan']))
        if network:out['networks']=p['networks']
        if p['action']=='read':out['record']=None
        return json.dumps(out)


def inventory(clients, hosts):
    return {host:dict(context=dict(boot_id='boot',device=1,inode=1),links=[]) for host in hosts}


def setup(topo_factory, tmp_path, monkeypatch):
    topo=topo_factory(name='demo',num_workers=1)
    state=DeploymentState(lab_name=topo.name,topology_file='demo.yml');events=[]
    clients={h:Client(h,events) for h in ('master','worker1')}
    ips={'master':'192.0.2.1','worker1':'192.0.2.2'}
    plan=SchedulePlan(lab_name=topo.name,assignments={},vrf_table_id=42000,mgmt_vxlan_id=3000)
    monkeypatch.setattr(netsetup,'snapshots',inventory)
    registry=Registry(tmp_path/'vni');saves=[]
    return topo,state,clients,ips,plan,registry,events,lambda:saves.append(copy.deepcopy(state.to_dict())),saves


def test_all_hosts_preflight_before_setup_and_intent_precedes_reservation(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    intent=netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry)
    assert events==[('master','preflight-provision'),('worker1','preflight-provision'),('master','network-preflight'),('worker1','network-preflight')]
    assert saves[0]['mgmt']['infrastructure']['phase']=='planning'
    assert saves[-1]['mgmt']['infrastructure']['phase']=='applying'
    for h,c in clients.items():netsetup.setup_mgmt_infra(topo,plan,c,h,ips,intent=intent)
    assert state.mgmt.vxlan_id==plan.mgmt_vxlan_id and state.mgmt.vxlan_id>=65536
    assert len({p['segments']['default']['vni'] for p in intent['plans'].values()})==1


def test_second_host_conflict_prevents_all_setup(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    clients['worker1'].reject='preflight-provision'
    with pytest.raises(RuntimeError):netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry)
    assert not any(action=='ensure' for _,action in events)
    assert state.mgmt.infrastructure['phase']=='preflight'


def test_failed_coordinator_save_prevents_reservation_and_remote_operations(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    def fail():raise OSError('save failed')
    with pytest.raises(OSError):netsetup.prepare(topo,plan,clients,ips,state,fail,registry=registry)
    assert not registry.directory.exists() and not events


def test_cleanup_preflights_all_hosts_before_first_mutation_and_releases_last(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry);events.clear()
    netsetup.destroy_management(state,clients,checkpoint=save,registry=registry)
    assert events[:2]==[('master','preflight-cleanup'),('worker1','preflight-cleanup')]
    assert events.index(('worker1','network-preflight-cleanup')) < events.index(('master','network-cleanup'))
    assert events.index(('worker1','network-cleanup')) < events.index(('master','cleanup'))
    assert events.index(('worker1','cleanup')) < events.index(('master','network-verify-cleaned'))
    assert state.mgmt.infrastructure['phase']=='cleaned'
    assert all(v['phase']=='released' for v in registry.read()['reservations'].values())


def test_cleanup_error_keeps_reservations_and_recovery_state(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry);clients['worker1'].reject='cleanup'
    with pytest.raises(RuntimeError):netsetup.destroy_management(state,clients,checkpoint=save,registry=registry)
    assert state.mgmt.infrastructure['phase']=='cleanup_pending'
    assert all(v['phase']=='reserved' for v in registry.read()['reservations'].values())
    clients['worker1'].reject=None
    netsetup.destroy_management(state,clients,checkpoint=save,registry=registry)
    assert state.mgmt.infrastructure['phase']=='cleaned'


def test_no_legacy_name_only_setup_or_teardown():
    with pytest.raises(ManagementError,match='preflight'):netsetup.setup_mgmt_infra(None,None,None,'master',{})
    with pytest.raises(ManagementError,match='proof'):netsetup.teardown_mgmt_infra('demo','br-demo',None,'master')


def test_missing_host_refuses_before_worker_calls(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry);events.clear()
    with pytest.raises(ManagementError,match='unavailable'):netsetup.destroy_management(state,{'master':clients['master']},registry=registry)
    assert not events


def test_network_restore_crash_between_hosts_reuses_operation_identity(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry);events.clear();calls=[]
    original=netsetup.invoke;fail=[True]
    def invoke(client,action,plan,**kwargs):
        calls.append((client.name,action,kwargs.get('operation_id')))
        if client.name=='worker1' and action=='network-restore' and fail[0]:fail[0]=False;raise RuntimeError('coordinator crashed after master')
        return original(client,action,plan,**kwargs)
    monkeypatch.setattr(netsetup,'invoke',invoke)
    with pytest.raises(RuntimeError):netsetup.network_action(state,clients,'restore',checkpoint=save)
    intent=copy.deepcopy(state.mgmt.infrastructure['network_operation']);assert intent['phase']=='pending'
    netsetup.network_action(state,clients,'recover',checkpoint=save)
    assert state.mgmt.infrastructure['network_operation']['phase']=='completed'
    assert all(token==intent['id'] for _,action,token in calls if action.endswith('restore'))


def test_second_host_network_conflict_prevents_first_network_create(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry);events.clear();clients['worker1'].reject='network-preflight'
    with pytest.raises(RuntimeError):netsetup.network_action(state,clients,'ensure',checkpoint=save)
    assert not any(action=='network-ensure' for _,action in events)


def test_pending_restore_target_scope_cannot_change_with_same_operation_id(topo_factory,tmp_path,monkeypatch):
    topo,state,clients,ips,plan,registry,events,save,saves=setup(topo_factory,tmp_path,monkeypatch)
    netsetup.prepare(topo,plan,clients,ips,state,save,registry=registry);clients['worker1'].reject='network-restore'
    with pytest.raises(RuntimeError):netsetup.network_action(state,clients,'restore',checkpoint=save)
    operation=state.mgmt.infrastructure['network_operation']['id'];events.clear()
    with pytest.raises(ManagementError,match='immutable'):
        netsetup.network_action(state,clients,'restore',targets={'worker1':['default']},operation_id=operation,checkpoint=save)
    assert not events
