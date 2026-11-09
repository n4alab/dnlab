"""Coordinated stop against real journals/link guards and stateful fake hosts."""
from copy import deepcopy

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.manifest import Conflict
from fakes import FakeClock, FakeDocker
from test_bridge_link_engine import fixture, execute, request as link_request


class Crash(BaseException):
    pass


@pytest.fixture
def stopped_runtime(fixture):
    links, linux, setup, verified = fixture
    assert execute(links, link_request())['phase']=='completed'
    docker,clock=FakeDocker(),FakeClock()

    class NodeBackend(Backend):
        # The bridge fixture models host endpoints, not guest namespaces.
        def verify(self, request, spec):
            container=self.inspect(request,spec)
            if not container or not container['State']['Running']:raise Conflict('fixture workload is not running')
            for edge in spec['endpoints']:
                found=next((r for r in linux.records if r['ifname']==edge['host_interface']),None)
                if not found or found['ifalias']!=self.alias(request,spec):raise Conflict('fixture endpoint owner differs')
            return container

        def delete_endpoints(self, request, spec):
            for edge in spec['endpoints']:
                found=next((r for r in linux.records if r['ifname']==edge['host_interface']),None)
                if found:
                    if found['ifalias']!=self.alias(request,spec):raise Conflict('fixture endpoint owner differs')
                    linux.records.remove(found)

    backend=NodeBackend(docker,linux,clock=clock.clock,sleep=clock.sleep)
    for node in ('vd1','vd2'):
        owner={'lab_id':'lab','node_id':node};spec=setup.journal.node('lab',node)['spec']
        backend.create(owner,spec,'fixture-'+node);backend.start(owner,spec)
        from fakes import seed_birth
        seed_birth(setup.journal,owner,spec,docker.containers[node])
    engine=Engine(setup.journal,backend);engine.links=links;links.engine=engine
    return engine,docker,linux


def request(**changes):
    return {'schema_version':1,'request_id':'stop1','lab_id':'lab','node_id':'vd1',
            'expected_revision':1,'action':'stop','stop_mode':'coordinated',**changes}


def begin(engine, **changes):
    operation=engine.journal.submit(request(**changes))
    return engine.execute(operation['id'])


def stage(engine, operation, value):
    engine.stops.request_stage(operation['id'],'lab','vd1',value)
    return engine.execute(operation['id'])


def test_timeout_keeps_all_links_and_owners_then_explicit_force_finishes(stopped_runtime):
    engine,docker,linux=stopped_runtime;docker.resist_term=True
    before=deepcopy(linux.records);calls=list(linux.calls);other=deepcopy(docker.inspect('vd2'))
    plan=engine.plan(request())
    assert plan['affected_nodes']==['vd1'] and plan['link_affected_nodes']==['vd1','vd2']
    operation=begin(engine)
    assert operation['phase']=='recovery_required' and operation['stop_stage']=='shutdown_requested'
    assert not operation['shutdown_verified'] and docker.inspect('vd1')['State']['Running']
    assert linux.records==before and linux.calls==calls and ('signal','SIGKILL') not in docker.calls
    assert engine.links.inspect('lab','l0','rt-left')['committed_state']=='active'
    operation=engine.reconcile(operation['id'],force=True)
    assert operation['phase']=='awaiting_link_cleanup' and operation['shutdown_verified']
    assert operation['id'] not in engine.journal.pending()
    assert linux.records==before and linux.calls==calls
    assert engine.journal.node('lab','vd1')['revision']==1
    with pytest.raises(Conflict):engine.links.submit(link_request(request_id='outside-delete',action='delete'))
    with pytest.raises(Conflict):engine.journal.submit(request(request_id='other'))
    operation=stage(engine,operation,'cleanup')
    assert operation['phase']=='awaiting_finalization'
    assert engine.links.inspect('lab','l0','rt-left')['committed_state']=='deleted'
    operation=stage(engine,operation,'finalize')
    assert operation['phase']=='completed' and operation['stop_stage']=='finished'
    assert docker.inspect('vd1') is None and docker.inspect('vd2')==other
    assert engine.journal.node('lab','vd1')['revision']==2
    assert engine.journal.db.execute('SELECT count(*) FROM stop_reservations').fetchone()[0]==0
    assert engine.stops.request_stage(operation['id'],'lab','vd1','cleanup')['phase']=='completed'


def test_preflight_checks_foreign_tc_before_process_signal(stopped_runtime):
    engine,docker,linux=stopped_runtime
    linux.rules['rt-right'][49140]['options']['actions'][0]['to_dev']='foreign'
    calls=deepcopy(docker.calls);kernel=deepcopy(linux.records)
    operation=begin(engine)
    assert operation['phase']=='recovery_required' and docker.calls==calls and linux.records==kernel
    assert engine.links.inspect('lab','l0','rt-left')['committed_state']=='active'


@pytest.mark.parametrize('change',['container','namespace','source'])
def test_post_exit_identity_change_refuses_cleanup_without_mutation(stopped_runtime,change):
    engine,docker,linux=stopped_runtime;operation=begin(engine)
    assert operation['phase']=='awaiting_link_cleanup'
    if change=='container':docker.containers['vd1']['Id']='foreign-container'
    if change=='namespace':linux.network_identity=lambda:{'boot':'foreign'}
    if change=='source':linux.records[0]['ifalias']='foreign'
    calls=list(linux.calls)
    result=stage(engine,operation,'cleanup')
    assert result['phase']=='recovery_required' and linux.calls==calls
    assert engine.journal.node('lab','vd1')['revision']==1
    assert engine.journal.db.execute('SELECT count(*) FROM stop_reservations').fetchone()[0]==2


def test_stage_context_order_and_child_payload_are_bound(stopped_runtime):
    engine,docker,linux=stopped_runtime;operation=begin(engine);calls=list(linux.calls)
    for lab,node in [('foreign','vd1'),('lab','foreign')]:
        with pytest.raises(Conflict):engine.stops.request_stage(operation['id'],lab,node,'cleanup')
    with pytest.raises(Conflict):engine.stops.request_stage(operation['id'],'lab','vd1','finalize')
    engine.stops.request_stage(operation['id'],'lab','vd1','cleanup')
    wrong=link_request(request_id='foreign',action='delete')
    with pytest.raises(Conflict):engine.links.submit(wrong,stop_parent=operation['id'])
    assert linux.calls==calls


@pytest.mark.parametrize('point',['signal','exit_verified','cleanup','links_cleaned','remove','finish'])
def test_crash_resumes_without_second_signal_or_guest_recreation(stopped_runtime,monkeypatch,point):
    engine,docker,linux=stopped_runtime;other=deepcopy(docker.inspect('vd2'))
    operation=engine.journal.submit(request());original_save=engine.stops.save
    original_signal=docker.signal;original_remove=docker.remove;original_finish=engine.journal.finish
    original_link_execute=engine.links.execute

    def save(identity,value,**kwargs):
        original_save(identity,value,**kwargs)
        if value['stage']==point:raise Crash()

    def signal(*args):
        original_signal(*args)
        if point=='signal':raise Crash()

    def remove(*args):
        original_remove(*args)
        if point=='remove':raise Crash()

    def finish(*args,**kwargs):
        original_finish(*args,**kwargs)
        if point=='finish':raise Crash()

    def link_execute(*args):
        result=original_link_execute(*args)
        if point=='cleanup':raise Crash()
        return result

    monkeypatch.setattr(engine.stops,'save',save);monkeypatch.setattr(docker,'signal',signal)
    monkeypatch.setattr(docker,'remove',remove);monkeypatch.setattr(engine.journal,'finish',finish)
    monkeypatch.setattr(engine.links,'execute',link_execute)
    with pytest.raises(Crash):
        operation=engine.execute(operation['id'])
        operation=stage(engine,operation,'cleanup')
        operation=stage(engine,operation,'finalize')
    monkeypatch.undo()
    operation=engine.execute(operation['id'])
    if operation['phase']=='awaiting_link_cleanup':operation=stage(engine,operation,'cleanup')
    if operation['phase']=='awaiting_finalization':operation=stage(engine,operation,'finalize')
    assert operation['phase']=='completed'
    assert [call for call in docker.calls if call[0]=='signal']==[('signal','SIGTERM')]
    assert [call for call in docker.calls if call[0]=='create']==[('create','vd1'),('create','vd2')]
    assert docker.inspect('vd2')==other and engine.journal.node('lab','vd1')['revision']==2


def test_cancellation_after_exit_does_not_restart_or_release_reservations(stopped_runtime):
    engine,docker,linux=stopped_runtime;operation=begin(engine)
    engine.journal.cancel(operation['id'])
    assert engine.journal.node('lab','vd1')['state']=='running'
    assert not docker.inspect('vd1')['State']['Running']
    assert engine.journal.db.execute('SELECT count(*) FROM stop_reservations').fetchone()[0]==2
    operation=stage(engine,operation,'cleanup');operation=stage(engine,operation,'finalize')
    assert operation['phase']=='completed' and operation['cancel_requested']


@pytest.mark.parametrize('mutation',range(1,12))
def test_crash_inside_link_cleanup_replays_parent_and_child(stopped_runtime,mutation):
    engine,docker,linux=stopped_runtime;operation=begin(engine)
    engine.stops.request_stage(operation['id'],'lab','vd1','cleanup')
    linux.fail_after=len(linux.calls)+mutation;linux.crash=True
    from test_bridge import Crash as KernelCrash
    with pytest.raises(KernelCrash):engine.execute(operation['id'])
    result=engine.execute(operation['id'])
    assert result['phase']=='awaiting_finalization'
    assert engine.links.inspect('lab','l0','rt-left')['committed_state']=='deleted'
    assert stage(engine,result,'finalize')['phase']=='completed'
    assert [call for call in docker.calls if call[0]=='signal']==[('signal','SIGTERM')]
    assert docker.inspect('vd2')['State']['Running']


@pytest.mark.parametrize('moment',['queued','prepared'])
def test_cancel_before_shutdown_preserves_workloads_and_links(stopped_runtime,monkeypatch,moment):
    engine,docker,linux=stopped_runtime;operation=engine.journal.submit(request())
    before=deepcopy(docker.containers);kernel=deepcopy(linux.records)
    if moment=='queued':engine.journal.cancel(operation['id'])
    else:
        original=engine.stops.prepare
        def prepared(*args):
            value=original(*args);engine.journal.cancel(operation['id']);return value
        monkeypatch.setattr(engine.stops,'prepare',prepared)
    result=engine.execute(operation['id'])
    assert result['phase']=='cancelled'
    assert docker.containers==before and linux.records==kernel
    assert engine.journal.db.execute('SELECT count(*) FROM stop_reservations').fetchone()[0]==0


def test_phased_stop_reserves_neighbor_before_any_other_lifecycle(stopped_runtime):
    engine,docker,linux=stopped_runtime;operation=begin(engine)
    request_b={**request(),'node_id':'vd2','request_id':'stop-neighbor'}
    with pytest.raises(Conflict,match='reserved'):engine.journal.submit(request_b)
    assert docker.inspect('vd2')['State']['Running']


@pytest.mark.parametrize('tamper',[None,'cookie','index','bind','missing-proof'])
def test_kernel_unbound_redirect_requires_complete_proof(stopped_runtime,tamper):
    engine,docker,linux=stopped_runtime;operation=begin(engine)
    # Native evidence: deleting the peer causes mirred to expose to_dev='*'.
    linux.records=[r for r in linux.records if r['ifname']!='rt-left']
    for rule in linux.rules['rt-right'].values():
        rule['options']['actions'][0]['to_dev']='*'
    if tamper in ('cookie','index','bind'):
        linux.rules['rt-right'][49140]['options']['actions'][0][tamper]='foreign'
    if tamper=='missing-proof':
        engine.journal.db.execute("UPDATE local_bridges SET payload=json_remove(payload,'$.tc_proofs')")
    before=list(linux.calls)
    result=stage(engine,operation,'cleanup')
    if tamper is None:
        assert result['phase']=='awaiting_finalization'
    else:
        assert result['phase']=='recovery_required' and linux.calls==before
        assert ('stop link proof generation changed' if tamper=='missing-proof' else 'foreign bridge TC rule') in result['error']
    assert engine.journal.node('lab','vd1')['revision']==1
    assert docker.inspect('vd2')['State']['Running']
