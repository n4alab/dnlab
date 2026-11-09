"""Read-only initial data endpoint preflight acceptance and recovery tests."""
from copy import deepcopy

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.endpoint_preflight import EndpointConflict,stored
from fakes import FakeClock,FakeDocker,FakeLinux


@pytest.mark.parametrize('occupied',['host','staging'])
def test_plan_and_apply_reject_foreign_endpoint_before_allocation(tmp_path,occupied):
    journal=Journal(tmp_path/'runtime')
    docker,linux,clock=FakeDocker(),FakeLinux(),FakeClock()
    engine=Engine(journal,Backend(docker,linux,clock=clock.clock,sleep=clock.sleep))
    endpoint={'host_interface':'drsp-diag-data','node_interface':'eth1','mtu':1450}
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'initial',
             'expected_revision':0,'action':'start',
             'spec':{'kind':'linux','container_name':'drsp-diag-vd','image':'sha256:'+'a'*64,
                     'stop_timeout':1,'endpoints':[endpoint]}}
    name=endpoint['host_interface'] if occupied=='host' else Backend.staging_name(endpoint)
    foreign={'ifname':name,'ifindex':900,'link_index':901,'ifalias':'foreign-owner','address':'02:00:00:00:09:00'}
    linux.links[(None,name)]=deepcopy(foreign)
    reads=[];original=linux.link
    def link(name,pid=None):
        reads.append((pid,name));return original(name,pid)
    linux.link=link
    try:
        changes=journal.db.total_changes
        with pytest.raises(EndpointConflict):engine.plan(request)
        assert reads and not docker.calls and not linux.commands
        assert journal.db.total_changes==changes
        operation=journal.submit(request)
        result=engine.execute(operation['id'])
        assert result['phase']=='recovery_required'
        assert docker.calls==[] and docker.containers=={} and linux.commands==[]
        assert linux.links=={(None,name):foreign}
        assert journal.node('demo','R1') is None
        assert stored(journal,request) is None
    finally:
        journal.close()


@pytest.fixture
def runtime(tmp_path):
    journal=Journal(tmp_path/'runtime');docker=FakeDocker();linux=FakeLinux()
    clock=FakeClock();engine=Engine(journal,Backend(docker,linux,clock=clock.clock,sleep=clock.sleep))
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'initial',
             'expected_revision':0,'action':'start','spec':{'kind':'linux','container_name':'drsp-test-vd',
             'image':'sha256:'+'a'*64,'endpoints':[{'host_interface':'drsp-test-data','node_interface':'eth1'}]}}
    yield engine,journal,docker,linux,request
    journal.close()


def test_valid_plan_observes_absence_without_pinning(runtime):
    engine,journal,docker,linux,request=runtime;changes=journal.db.total_changes
    plan=engine.plan(request)
    assert plan['endpoint_preflight']['endpoints']=={'drsp-test-data':None}
    assert plan['endpoint_preflight']['scope']==linux.network_identity()
    assert stored(journal,request) is None and journal.db.total_changes==changes
    assert docker.calls==linux.commands==[]


def test_conflict_after_plan_still_refuses_before_allocating(runtime):
    engine,journal,docker,linux,request=runtime
    engine.plan(request)
    foreign={'ifname':'drsp-test-data','ifindex':90,'ifalias':'foreign'}
    linux.links[(None,'drsp-test-data')]=foreign
    operation=journal.submit(request)
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert not docker.calls and not linux.commands and stored(journal,request) is None
    assert linux.links[(None,'drsp-test-data')]==foreign


def test_last_recheck_rejects_conflict_during_durable_birth_reservation(runtime,monkeypatch):
    engine,journal,docker,linux,request=runtime
    from dnlab_runtime import workload_generation
    original=workload_generation.reserve
    def reserve(*args):
        result=original(*args)
        linux.links[(None,'drsp-test-data')]={'ifname':'drsp-test-data','ifindex':90,'ifalias':'foreign'}
        return result
    monkeypatch.setattr(workload_generation,'reserve',reserve)
    operation=journal.submit(request)
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert not docker.calls and not linux.commands
    assert stored(journal,request)['original']['endpoints']=={'drsp-test-data':None}


def test_storage_failure_prevents_workload_allocation(runtime,monkeypatch):
    engine,journal,docker,linux,request=runtime
    from dnlab_runtime import endpoint_preflight
    def fail(*args):raise OSError('injected storage failure')
    monkeypatch.setattr(endpoint_preflight,'checkpoint',fail)
    operation=journal.submit(request)
    assert engine.execute(operation['id'])['phase']=='failed'
    assert not docker.calls and not linux.commands


def test_crash_before_create_preserves_original_scope_across_recovery(runtime,monkeypatch):
    engine,journal,docker,linux,request=runtime;create=docker.create
    def crash(*args):raise SystemExit('crash before create')
    monkeypatch.setattr(docker,'create',crash)
    operation=journal.submit(request)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    proof=deepcopy(stored(journal,request));assert proof['original']['endpoints']=={'drsp-test-data':None}
    scope=linux.network_identity()
    monkeypatch.setattr(linux,'network_identity',lambda:{**scope,'inode':999})
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert not docker.calls and stored(journal,request)==proof
    monkeypatch.setattr(linux,'network_identity',lambda:scope);monkeypatch.setattr(docker,'create',create)
    assert engine.reconcile(operation['id'])['phase']=='completed'
    assert stored(journal,request)['original']==proof['original']


@pytest.mark.parametrize('replacement',['indices','guest_namespace','mac','alias','kind'])
def test_retry_refuses_replaced_kernel_pair_without_mutation(runtime,monkeypatch,replacement):
    engine,journal,docker,linux,request=runtime;finish=journal.finish
    def crash(*args,**kwargs):raise SystemExit('before commit')
    monkeypatch.setattr(journal,'finish',crash)
    operation=journal.submit(request)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    proof=deepcopy(stored(journal,request));host=linux.links[(None,'drsp-test-data')];peer=linux.links[(100,'eth1')]
    if replacement=='indices':
        host.update(ifindex=91,link_index=92);peer.update(ifindex=92,link_index=91)
    if replacement=='guest_namespace':monkeypatch.setattr(linux,'namespace_identity',lambda ns:{'device':1,'inode':999})
    if replacement=='mac':host['address']='02:00:00:00:00:ff'
    if replacement=='alias':host['ifalias']='foreign'
    if replacement=='kind':host['linkinfo']={'info_kind':'bridge'}
    before=(list(docker.calls),deepcopy(linux.commands),deepcopy(linux.links))
    monkeypatch.setattr(journal,'finish',finish)
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert (docker.calls,linux.commands,linux.links)==before
    assert stored(journal,request)==proof


def test_staging_name_reservation_prevents_other_node_claim(runtime):
    engine,journal,docker,linux,request=runtime
    journal.submit(request)
    other=deepcopy(request);other.update(node_id='R2',request_id='other')
    other['spec']['container_name']='drsp-other'
    other['spec']['endpoints'][0]['host_interface']=Backend.staging_name(request['spec']['endpoints'][0])
    from dnlab_runtime.manifest import Conflict
    with pytest.raises(Conflict,match='reserved'):engine.plan(other)
    with pytest.raises(Conflict,match='resource reserved'):journal.submit(other)
    assert not docker.calls and not linux.commands


def test_new_request_cannot_adopt_replaced_pair_from_committed_birth(runtime):
    engine,journal,docker,linux,request=runtime
    operation=journal.submit(request);assert engine.execute(operation['id'])['phase']=='completed'
    host=linux.links[(None,'drsp-test-data')];peer=linux.links[(100,'eth1')]
    host.update(ifindex=91,link_index=92);peer.update(ifindex=92,link_index=91)
    before=(list(docker.calls),deepcopy(linux.commands),deepcopy(linux.links))
    with pytest.raises(EndpointConflict,match='birth identity'):
        engine.plan({**request,'request_id':'new-request','expected_revision':1})
    assert (docker.calls,linux.commands,linux.links)==before


@pytest.mark.parametrize('where',['host','guest'])
def test_manifest_rejects_names_overlapping_another_staging_slot(runtime,where):
    engine,journal,docker,linux,request=runtime
    stage=Backend.staging_name(request['spec']['endpoints'][0])
    request['spec']['endpoints'].append({'host_interface':stage if where=='host' else 'drsp-second',
                                       'node_interface':stage if where=='guest' else 'eth2'})
    from dnlab_runtime.manifest import RuntimeErrorBase
    with pytest.raises(RuntimeErrorBase,match='staging names overlap'):engine.plan(request)
    assert not docker.calls and not linux.commands


def test_reopened_journal_keeps_original_preflight_and_pair_proofs(runtime,monkeypatch):
    engine,journal,docker,linux,request=runtime
    from pathlib import Path
    directory=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    def crash(*args,**kwargs):raise SystemExit('before commit')
    monkeypatch.setattr(journal,'finish',crash)
    operation=journal.submit(request)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    proof=deepcopy(stored(journal,request));before=list(docker.calls)
    journal.close();reopened=Journal(directory)
    try:
        resumed=Engine(reopened,engine.backend)
        assert resumed.execute(operation['id'])['phase']=='completed'
        assert stored(reopened,request)==proof and docker.calls==before
    finally:reopened.close()


@pytest.mark.parametrize('occupied',['host','staging'])
def test_original_failed_attempt_recovers_only_after_foreign_resource_is_gone(runtime,occupied):
    engine,journal,docker,linux,request=runtime
    endpoint=request['spec']['endpoints'][0]
    name=endpoint['host_interface'] if occupied=='host' else Backend.staging_name(endpoint)
    linux.links[(None,name)]={'ifname':name,'ifindex':90,'ifalias':'foreign'}
    operation=journal.submit(request)
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert not docker.calls and not linux.commands
    assert engine.reconcile(operation['id'])['phase']=='recovery_required'
    assert not docker.calls and not linux.commands
    del linux.links[(None,name)]  # External owner removes its own test object.
    assert engine.reconcile(operation['id'])['phase']=='completed'
    assert stored(journal,request)['original']['endpoints']=={'drsp-test-data':None}
    assert sum(call[0]=='create' for call in docker.calls)==1
