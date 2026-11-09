from copy import deepcopy
import threading

import pytest

from dnlab_multinode.services import management_barrier as barrier
from dnlab_multinode.services.runtime_operations import OperationStore,RuntimeOperationError
from tests.test_runtime_operations import REQUEST,TARGET,JOURNAL

PLAN={'hosts':{'master':{'segments':['default','red']},'worker':{'segments':['default','red']}}}
TARGETS={'master':{'target':TARGET,'journal_id':JOURNAL},
         'worker':{'target':{**TARGET,'host':'worker'},'journal_id':'b'*32}}


class Remote:
    def __init__(self):self.records={};self.calls=[];self.lose=None;self.unavailable=None;self.tamper=None;self.running=False
    def factory(self,target):
        world=self;host=target['host']
        class Client:
            def bound_to(self,journal):
                assert journal==TARGETS[host]['journal_id'];return self
            def management_barrier(self,lab,action,payload):
                world.calls.append((host,action,deepcopy(payload)))
                if world.unavailable==host:raise OSError('host unavailable')
                previous=world.records.get(host)
                if action=='acquire' and previous and previous['barrier_id']==payload['barrier_id'] and previous['phase']=='cancelled':raise RuntimeOperationError('token cancelled')
                value={'lab_id':lab,'journal_id':TARGETS[host]['journal_id'],**payload,
                       'phase':{'plan':'planned','acquire':'held','activate':'applying','cancel':'cancelled','release':'released'}[action],
                       'workload_fingerprint':'e'*64,'mutations_performed':False,'acquisition_observed':action not in ('plan','cancel') or bool(previous and previous.get('acquisition_observed'))}
                if world.running and action in ('plan','acquire'):raise RuntimeOperationError('local workload still running')
                if action!='plan':world.records[host]=deepcopy(value)
                if world.lose==(host,action):world.lose=None;raise OSError('lost acknowledgement')
                if world.tamper:value[world.tamper]='changed'
                return value
        return Client()


@pytest.fixture
def setup(tmp_path):
    store=OperationStore(tmp_path/'private');world=Remote();store.fixture_factory=world.factory
    yield store,world,barrier.Driver(store,world.factory)
    store.close()


def prepare(store,key='add-red',**kw):return barrier.Driver(store,store.fixture_factory).prepare('lab',key,PLAN,TARGETS,**kw)


def ready(plan,targets):return {'plan_fingerprint':barrier.digest(plan),'hosts':{h:{'verified':'fixture-proof'} for h in targets}}


def test_all_hosts_fenced_before_ready_and_release(setup):
    store,world,driver=setup
    intent=prepare(store);assert intent['phase']=='acquiring' and [c[1] for c in world.calls]==['plan','plan']
    world.calls.clear()
    with pytest.raises(RuntimeOperationError,match='fences'):store.prepare(REQUEST,TARGET,JOURNAL)
    acquired=driver.acquire('lab','add-red')
    assert set(acquired['receipts'])=={'master','worker'} and acquired['phase']=='held'
    assert [c[:2] for c in world.calls]==[('master','acquire'),('worker','acquire')]
    def verify(plan,targets):
        assert all(v['phase'] in ('held','released') for v in world.records.values())
        return ready(plan,targets)
    result=driver.release('lab','add-red',verify)
    assert result['phase']=='released' and len(result['released'])==2
    assert store.prepare(REQUEST,TARGET,JOURNAL)['phase']=='prepared'
    assert driver.release('lab','add-red',lambda *a:pytest.fail('repeat readiness'))==result


@pytest.mark.parametrize('phase',['prepared','recovery_required','awaiting_link_cleanup'])
def test_pending_intent_prevents_any_remote_fence(setup,phase):
    store,world,driver=setup
    store.prepare(REQUEST,TARGET,JOURNAL);store.db.execute('UPDATE operations SET phase=?',(phase,))
    with pytest.raises(RuntimeOperationError,match='operations concluded'):prepare(store)
    assert barrier.get(store,'lab') is None and world.calls==[]


@pytest.mark.parametrize('mode',['lost-acquire','unavailable','lost-release'])
def test_restart_recovers_partial_acquisition_or_release_and_keeps_fence(setup,mode):
    store,world,driver=setup;prepare(store)
    if mode=='lost-acquire':world.lose=('worker','acquire')
    if mode=='unavailable':world.unavailable='worker'
    if mode=='lost-release':driver.acquire('lab','add-red');world.lose=('worker','release')
    with pytest.raises(OSError):
        (driver.release('lab','add-red',ready) if mode=='lost-release' else driver.acquire('lab','add-red'))
    other=OperationStore(store.directory);other.fixture_factory=world.factory
    try:
        with pytest.raises(RuntimeOperationError,match='fences'):other.prepare(REQUEST,TARGET,JOURNAL)
        assert prepare(other)['barrier_id']==barrier.get(store,'lab')['barrier_id']
        world.unavailable=None;fresh=barrier.Driver(other,world.factory)
        if mode!='lost-release':assert fresh.acquire('lab','add-red')['phase']=='held'
        def verification(*args):
            return ready(*args)
        assert fresh.release('lab','add-red',verification)['phase']=='released'
        assert len({call[2]['barrier_id'] for call in world.calls})==1
    finally:other.close()


def test_conflicting_intents_generation_and_roster_are_refused(setup):
    store,world,driver=setup
    with pytest.raises(RuntimeOperationError,match='generation'):prepare(store,generation=2)
    with pytest.raises(RuntimeOperationError,match='host roster'):driver.prepare('lab','add',PLAN,{'master':TARGETS['master']})
    prepare(store)
    with pytest.raises(RuntimeOperationError,match='intent changed'):
        driver.prepare('lab','add-red',{'hosts':{**PLAN['hosts'],'master':{}}},TARGETS)
    with pytest.raises(RuntimeOperationError,match='fences'):prepare(store,'another')
    assert all(c[1]=='plan' for c in world.calls)


def test_original_runtime_cannot_be_omitted_even_after_stop(setup):
    store,world,driver=setup
    store.prepare(REQUEST,TARGET,JOURNAL);store.db.execute("UPDATE operations SET phase='completed'")
    with pytest.raises(RuntimeOperationError,match='omits an original'):
        driver.prepare('lab','add',{'hosts':{'worker':{}}},{'worker':TARGETS['worker']})
    assert all(c[1]=='plan' for c in world.calls)


@pytest.mark.parametrize('evidence',[None,True,{}, {'plan_fingerprint':'0'*64,'hosts':{'master':{},'worker':{}}},
    {'plan_fingerprint':barrier.digest(PLAN),'hosts':{'master':{'proof':1}}},
    {'plan_fingerprint':barrier.digest(PLAN),'hosts':{'master':{},'worker':{}}}])
def test_incomplete_readiness_cannot_release_any_runtime(setup,evidence):
    store,world,driver=setup;prepare(store);driver.acquire('lab','add-red');world.calls.clear()
    with pytest.raises(RuntimeOperationError,match='readiness evidence'):driver.release('lab','add-red',lambda *args:evidence)
    assert world.calls==[] and barrier.get(store,'lab')['phase']=='held'


def test_new_operation_rejects_old_key_and_release(setup):
    store,world,driver=setup;prepare(store);driver.acquire('lab','add-red');driver.release('lab','add-red',ready)
    prepare(store,'next')
    with pytest.raises(RuntimeOperationError,match='missing or replaced'):driver.release('lab','add-red',ready)
    with pytest.raises(RuntimeOperationError):prepare(store)
    with pytest.raises(RuntimeOperationError):store.prepare(REQUEST,TARGET,JOURNAL)


def test_bad_runtime_receipt_keeps_coordinator_fenced(setup):
    store,world,driver=setup;prepare(store);world.tamper='journal_id'
    with pytest.raises(RuntimeOperationError,match='receipt differs'):driver.acquire('lab','add-red')
    assert barrier.get(store,'lab')['phase']=='acquiring'
    with pytest.raises(RuntimeOperationError):store.prepare(REQUEST,TARGET,JOURNAL)


def test_two_connections_cannot_admit_start_and_offline_operation_together(setup):
    store,world,driver=setup;other=OperationStore(store.directory)
    gate=threading.Barrier(2);result=[];errors=[]
    def start():
        try:
            gate.wait()
            try:other.prepare(REQUEST,TARGET,JOURNAL);result.append('start')
            except RuntimeOperationError:result.append('start-rejected')
        except BaseException as error:errors.append(error)
    thread=threading.Thread(target=start);thread.start();gate.wait()
    try:
        try:prepare(store);result.append('management')
        except RuntimeOperationError:result.append('management-rejected')
        thread.join(5);assert not thread.is_alive() and not errors
        assert set(result) in ({'start','management-rejected'},{'management','start-rejected'})
    finally:other.close()


def test_failed_running_admission_must_not_trap_original_ordinary_stop(setup):
    store,world,driver=setup;world.running=True
    original={**REQUEST,'action':'stop','request_id':'ordinary-stop','expected_revision':1}
    original.pop('spec')
    with pytest.raises(RuntimeOperationError,match='still running'):
        driver.prepare('lab','add-red',PLAN,TARGETS)
    assert barrier.get(store,'lab') is None and world.records=={}
    assert store.prepare(original,TARGET,JOURNAL)['phase']=='prepared'


def test_failed_acquisition_after_preflight_requires_verified_cancellation_before_stop(setup):
    store,world,driver=setup
    prepare(store);world.running=True
    with pytest.raises(RuntimeOperationError,match='still running'):driver.acquire('lab','add-red')
    original={**REQUEST,'action':'stop','request_id':'ordinary-stop','expected_revision':1};original.pop('spec')
    with pytest.raises(RuntimeOperationError,match='fences'):store.prepare(original,TARGET,JOURNAL)
    world.calls.clear();world.unavailable='worker'
    with pytest.raises(OSError):driver.cancel('lab','add-red')
    assert barrier.get(store,'lab')['phase']=='cancelling'
    assert [c[:2] for c in world.calls]==[('master','cancel'),('worker','cancel')]
    with pytest.raises(RuntimeOperationError,match='fences'):store.prepare(original,TARGET,JOURNAL)
    world.unavailable=None
    assert driver.cancel('lab','add-red')['phase']=='cancelled'
    assert store.prepare(original,TARGET,JOURNAL)['phase']=='prepared'


@pytest.mark.parametrize('after_acquire',[False,True])
def test_cancel_lost_reply_recovers_all_host_tombstones_after_restart(setup,after_acquire):
    store,world,driver=setup;prepare(store)
    if after_acquire:
        world.lose=('worker','acquire')
        with pytest.raises(OSError):driver.acquire('lab','add-red')
    world.lose=('worker','cancel')
    with pytest.raises(OSError):driver.cancel('lab','add-red')
    assert barrier.get(store,'lab')['phase']=='cancelling'
    other=OperationStore(store.directory)
    try:
        fresh=barrier.Driver(other,world.factory)
        result=fresh.cancel('lab','add-red')
        assert result['phase']=='cancelled' and set(result['cancelled'])==set(TARGETS)
        assert all(r['phase']=='cancelled' for r in world.records.values())
        with pytest.raises(RuntimeOperationError,match='no longer admissible'):fresh.acquire('lab','add-red')
        assert other.prepare(REQUEST,TARGET,JOURNAL)['phase']=='prepared'
    finally:other.close()


def test_partial_provisioning_seal_is_not_cancellable_and_recovers_exact_activation(setup):
    store,world,driver=setup;prepare(store);driver.acquire('lab','add-red')
    world.lose=('worker','activate')
    with pytest.raises(OSError):driver.begin_provisioning('lab','add-red')
    assert barrier.get(store,'lab')['phase']=='activating'
    before=deepcopy(world.calls)
    with pytest.raises(RuntimeOperationError,match='before provisioning'):driver.cancel('lab','add-red')
    assert world.calls==before
    assert driver.begin_provisioning('lab','add-red')['phase']=='provisioning'
    with pytest.raises(RuntimeOperationError,match='before provisioning'):driver.cancel('lab','add-red')
    assert driver.release('lab','add-red',ready)['phase']=='released'


def test_cancelled_request_cannot_be_reused_and_stale_cancel_cannot_unlock_successor(setup):
    store,world,driver=setup;prepare(store);driver.cancel('lab','add-red')
    prepare(store,'next');driver.acquire('lab','next')
    before=deepcopy(world.calls)
    with pytest.raises(RuntimeOperationError,match='missing or replaced'):driver.cancel('lab','add-red')
    assert world.calls==before
    with pytest.raises(RuntimeOperationError,match='fences'):store.prepare(REQUEST,TARGET,JOURNAL)


def test_missing_preflight_proof_cannot_install_coordinator_fence(setup):
    store,world,driver=setup
    with pytest.raises(RuntimeOperationError,match='preflights required'):
        barrier.prepare(store,'lab','add-red',PLAN,TARGETS)
    assert barrier.get(store,'lab') is None and world.calls==[]


def test_invalid_last_host_preflight_does_not_persist_admission(setup):
    store,world,driver=setup;world.tamper='journal_id'
    with pytest.raises(RuntimeOperationError,match='preflight identity'):
        driver.prepare('lab','add-red',PLAN,TARGETS)
    assert barrier.get(store,'lab') is None and world.records=={}


def test_partial_release_recovery_revalidates_original_readiness_before_more_releases(setup):
    store,world,driver=setup
    prepare(store);driver.acquire('lab','add-red')
    world.lose=('master','release')
    with pytest.raises(OSError,match='lost acknowledgement'):
        driver.release('lab','add-red',ready)
    assert barrier.get(store,'lab')['phase']=='releasing'
    assert world.records['master']['phase']=='released'
    assert world.records['worker']['phase']=='held'
    calls=list(world.calls)
    def no_longer_ready(plan,targets):
        raise RuntimeOperationError('original management service no longer present')
    with pytest.raises(RuntimeOperationError,match='no longer present'):
        driver.release('lab','add-red',no_longer_ready)
    assert world.calls==calls
    assert barrier.get(store,'lab')['phase']=='releasing'
    assert world.records['worker']['phase']=='held'


@pytest.mark.parametrize('fault',['missing','replacement','unavailable','incomplete'])
def test_release_rechecks_all_hosts_between_remote_releases_and_keeps_attestation(setup,fault):
    store,world,driver=setup;prepare(store);driver.acquire('lab','add-red')
    checks=[]
    def verify(plan,targets):
        checks.append(True)
        if world.records['master']['phase']=='released':
            if fault=='missing':raise RuntimeOperationError('service missing')
            if fault=='unavailable':raise OSError('host unavailable')
            evidence=ready(plan,targets)
            if fault=='replacement':evidence['hosts']['worker']={'generation':'replacement'}
            if fault=='incomplete':evidence['hosts'].pop('worker')
            return evidence
        return ready(plan,targets)
    with pytest.raises((RuntimeOperationError,OSError)):driver.release('lab','add-red',verify)
    value=barrier.get(store,'lab')
    assert value['phase']=='releasing' and value['readiness']==ready(PLAN,TARGETS)
    assert value['readiness_fingerprint']==barrier.digest(value['readiness'])
    assert len(checks)==3 and value['release_checks']=={'master':1}
    assert world.records['master']['phase']=='released' and world.records['worker']['phase']=='held'
    assert [h for h,a,p in world.calls if a=='release']==['master']


def test_crash_recovery_reobserves_before_idempotent_release_and_preserves_proof(setup):
    store,world,driver=setup;prepare(store);driver.acquire('lab','add-red')
    world.lose=('master','release')
    with pytest.raises(OSError):driver.release('lab','add-red',ready)
    sealed=deepcopy(barrier.get(store,'lab')['readiness']);calls=deepcopy(world.calls)
    other=OperationStore(store.directory)
    try:
        fresh=barrier.Driver(other,world.factory)
        with pytest.raises(RuntimeOperationError,match='attestation differs'):
            fresh.release('lab','add-red',lambda p,t:{**ready(p,t),'hosts':{h:{'replacement':True} for h in t}})
        assert world.calls==calls and barrier.get(other,'lab')['readiness']==sealed
        recovered=fresh.release('lab','add-red',ready)
        assert recovered['phase']=='released' and recovered['readiness']==sealed
        assert recovered['release_checks']=={'master':2,'worker':1}
    finally:other.close()


def test_failed_revalidation_checkpoint_prevents_remote_release(setup,monkeypatch):
    store,world,driver=setup;prepare(store);driver.acquire('lab','add-red')
    original=barrier.put;world.calls.clear()
    def fail(store,lab,value):
        if value.get('release_checks'):raise OSError('checkpoint failed')
        return original(store,lab,value)
    monkeypatch.setattr(barrier,'put',fail)
    with pytest.raises(OSError,match='checkpoint failed'):driver.release('lab','add-red',ready)
    assert world.calls==[]
    value=barrier.get(store,'lab');assert value['phase']=='releasing' and not value.get('release_checks')
    monkeypatch.setattr(barrier,'put',original)
    assert driver.release('lab','add-red',ready)['phase']=='released'
