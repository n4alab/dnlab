from copy import deepcopy
from pathlib import Path
import threading

import pytest

from dnlab_runtime import management_barrier as barrier
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from test_runtime import runtime,request,stop,run

INTENT={'barrier_id':'b'*32,'generation':1,'plan_fingerprint':'f'*64}
READY={**INTENT,'readiness_fingerprint':'e'*64}


def control(engine,lab,action,raw):
    raw=deepcopy(raw)
    if action!='plan' and 'workload_fingerprint' not in raw:
        previous=barrier.get(engine.journal,lab)
        if previous and previous['barrier_id']==raw.get('barrier_id'):
            raw['workload_fingerprint']=previous['workload_fingerprint']
        else:
            import json
            historical=engine.journal.db.execute('SELECT payload FROM management_barrier_history WHERE lab=? AND barrier_id=?',(lab,raw.get('barrier_id'))).fetchone()
            proof=json.loads(historical[0]) if historical else barrier.control(engine,lab,'plan',{k:v for k,v in raw.items() if k!='readiness_fingerprint'})
            raw['workload_fingerprint']=proof['workload_fingerprint']
    return barrier.control(engine,lab,action,raw)


def acquire(engine,intent=INTENT):return control(engine,'demo','acquire',intent)


def test_offline_operation_preserves_stopped_node_and_permits_start_only_after_release(runtime):
    engine,journal,docker,linux=runtime
    assert run(engine,journal,request())['phase']=='completed'
    assert run(engine,journal,stop())['phase']=='completed'
    node=deepcopy(journal.node('demo','R1'));calls=list(docker.calls)
    value=acquire(engine)
    assert value['phase']=='held' and value['journal_id']==journal.identity
    for method in (journal.submit,journal.cancel_request,engine.plan):
        with pytest.raises(Conflict,match='offline management'):
            method(request(request_id='restart',expected_revision=2))
    assert journal.node('demo','R1')==node and docker.calls==calls
    assert engine.inspect('demo','R1')['container_state']=='absent'
    assert acquire(engine)==value
    released=control(engine,'demo','release',READY)
    assert released['phase']=='released'
    assert control(engine,'demo','release',READY)==released
    assert acquire(engine)==released  # late acquire retry must not relock
    assert journal.node('demo','R1')==node
    assert run(engine,journal,request(request_id='restart',expected_revision=2))['phase']=='completed'


@pytest.mark.parametrize('state',['queued','running','recovery_required','failed_unclean'])
def test_offline_refuses_pending_running_or_unclean_workload_before_fence(runtime,state):
    engine,journal,docker,linux=runtime
    if state=='queued':journal.submit(request())
    else:
        result=run(engine,journal,request())
        if state=='recovery_required':journal.phase(result['id'],'recovery_required','fixture')
        if state=='failed_unclean':journal.phase(result['id'],'failed','fixture')
    before=deepcopy(docker.containers);calls=list(docker.calls)
    with pytest.raises(Conflict):acquire(engine)
    assert barrier.get(journal,'demo') is None
    assert docker.containers==before and docker.calls==calls


@pytest.mark.parametrize('change',[{'generation':True},{'generation':2},{'plan_fingerprint':'x'}, {'barrier_id':'invalid'},{'extra':True}])
def test_invalid_or_wrong_generation_intent_has_no_effect(runtime,change):
    engine,journal,docker,linux=runtime
    with pytest.raises(Conflict):acquire(engine,{**INTENT,**change})
    assert barrier.get(journal,'demo') is None and docker.calls==[]


def test_conflicts_and_old_release_never_unlock_a_new_operation(runtime):
    engine,journal,docker,linux=runtime
    acquire(engine)
    with pytest.raises(Conflict,match='intent changed'):acquire(engine,{**INTENT,'plan_fingerprint':'a'*64})
    with pytest.raises(Conflict,match='another offline'):acquire(engine,{**INTENT,'barrier_id':'c'*32})
    control(engine,'demo','release',READY)
    with pytest.raises(Conflict,match='attestation changed'):
        control(engine,'demo','release',{**READY,'readiness_fingerprint':'a'*64})
    next_intent={**INTENT,'barrier_id':'c'*32}
    acquire(engine,next_intent)
    with pytest.raises(Conflict,match='missing or replaced'):control(engine,'demo','release',READY)
    control(engine,'demo','release',{**READY,**next_intent})
    with pytest.raises(Conflict,match='retired'):acquire(engine)
    assert journal.db.execute('SELECT count(*) FROM management_barrier_history').fetchone()[0]==1


def test_fence_survives_new_connection_and_remains_lab_scoped(runtime):
    engine,journal,docker,linux=runtime
    acquire(engine)
    other=Journal(Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent)
    try:
        with pytest.raises(Conflict,match='offline management'):other.submit(request())
        assert other.submit(request(lab_id='other'))['phase']=='queued'
        assert barrier.get(other,'demo')['barrier_id']==INTENT['barrier_id']
    finally:other.close()


def test_concurrent_acquire_and_submit_cannot_both_succeed(runtime):
    engine,journal,docker,linux=runtime
    other=Journal(Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent)
    gate=threading.Barrier(2);results=[];errors=[]
    def submit():
        try:
            gate.wait()
            try:other.submit(request());results.append('submitted')
            except Conflict:results.append('submit-rejected')
        except BaseException as error:errors.append(error)
    worker=threading.Thread(target=submit);worker.start();gate.wait()
    try:
        try:acquire(engine);results.append('acquired')
        except Conflict:results.append('acquire-rejected')
        worker.join(5);assert not worker.is_alive() and not errors
        assert set(results) in ({'submitted','acquire-rejected'},{'acquired','submit-rejected'})
    finally:other.close()


def test_readiness_release_rechecks_stopped_inventory_and_keeps_fence_on_error(runtime):
    engine,journal,docker,linux=runtime
    acquire(engine)
    journal.db.execute("INSERT INTO nodes VALUES('demo','foreign',1,'{}','running')")
    with pytest.raises(Conflict):control(engine,'demo','release',READY)
    assert barrier.get(journal,'demo')['phase']=='held'


def test_teardown_closure_cannot_bypass_management_operation(runtime):
    engine,journal,docker,linux=runtime
    acquire(engine)
    from dnlab_runtime.lab_closure import control
    with pytest.raises(Conflict,match='offline management'):
        control(engine,'demo','close',{'closure_id':'c'*32,'generation':1,'stops':[stop(stop_mode='coordinated')]})


def test_sync_failure_prevents_success_and_retry_uses_same_fence(runtime,monkeypatch):
    engine,journal,docker,linux=runtime
    original=barrier.sync;calls=[]
    def fail_second(journal):
        calls.append(1)
        if len(calls)==2:raise OSError('injected uncertain ack')
        original(journal)
    monkeypatch.setattr(barrier,'sync',fail_second)
    with pytest.raises(OSError):acquire(engine)
    assert barrier.get(journal,'demo')['phase']=='held'
    with pytest.raises(Conflict):journal.submit(request())
    monkeypatch.setattr(barrier,'sync',original)
    assert acquire(engine)['phase']=='held'


def test_direct_bridge_and_vxlan_creation_are_fenced_before_mutation(runtime):
    from dnlab_runtime.bridge import BridgeManager
    from dnlab_runtime.bridge_identity import BridgeIdentity
    from dnlab_runtime.vxlan import VxlanManager
    from dnlab_runtime.link_identity import VxlanIdentity
    from test_bridge import Linux as BridgeLinux
    from test_vxlan import Linux as VxlanLinux
    engine,journal,docker,linux=runtime
    bridge_linux=BridgeLinux();vxlan_linux=VxlanLinux()
    bridge=BridgeManager(journal,bridge_linux);vxlan=VxlanManager(journal,vxlan_linux)
    acquire(engine)
    with pytest.raises(Conflict,match='offline management'):
        bridge.create(BridgeIdentity('demo','l0'),sources=deepcopy(bridge_linux.records),mtu=1450)
    with pytest.raises(Conflict,match='offline management'):
        vxlan.create(VxlanIdentity('demo','l1',vxlan_linux.source['ifname'],5011),source=vxlan_linux.source,
                     underlay='underlay0',local='192.0.2.1',remote='192.0.2.2',mtu=1450)
    assert bridge_linux.calls==vxlan_linux.calls==[]


def test_barrier_uses_actual_cli_adapter_and_requires_bound_journal(runtime,tmp_path,monkeypatch):
    import os,shlex,subprocess,sys
    from dnlab_runtime.transport import Client,Server
    root=Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root.parent/'multinode'))
    from dnlab_multinode.services.custom_runtime import RuntimeClient,CustomRuntimeError
    launcher=tmp_path/'dnlab-runtime'
    launcher.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable,'-m','dnlab_runtime.cli'])+' "$@"\n');launcher.chmod(0o700)
    env={**os.environ,'PATH':str(tmp_path)+os.pathsep+os.environ['PATH'],'PYTHONPATH':str(root)}
    class SSH:
        def run(self,command):return self.run_input(command,None)
        def run_input(self,command,payload):
            return subprocess.run(shlex.split(command),input=payload,env=env,check=True,capture_output=True,text=True,timeout=5).stdout
    engine,journal,docker,linux=runtime;socket=str(tmp_path/'socket')
    server=Server(socket,engine);thread=threading.Thread(target=server.serve_forever);thread.start()
    adapter=RuntimeClient(SSH(),socket_path=socket).bound_to(journal.identity)
    path='/v1/labs/demo/management-barrier/'
    try:
        with pytest.raises(RuntimeErrorBase,match='journal binding'):Client(socket).request('POST',path+'acquire',INTENT)
        with pytest.raises(CustomRuntimeError,match='bound runtime'):RuntimeClient(SSH(),socket_path=socket).management_barrier('demo','acquire',INTENT)
        planned=adapter.management_barrier('demo','plan',INTENT)
        bound={**INTENT,'workload_fingerprint':planned['workload_fingerprint']}
        assert adapter.management_barrier('demo','acquire',bound)['phase']=='held'
        with pytest.raises(RuntimeErrorBase,match='offline management'):Client(socket).request('POST','/v1/operations',request())
        assert adapter.management_barrier('demo','release',{**READY,'workload_fingerprint':planned['workload_fingerprint']})['phase']=='released'
    finally:server.shutdown();server.server_close();thread.join()


def planned(engine):
    return barrier.control(engine,'demo','plan',INTENT)


def test_readonly_preflight_never_reserves_a_barrier_or_changes_workload(runtime):
    engine,journal,docker,linux=runtime
    before=journal.db.total_changes
    proof=planned(engine)
    assert proof['phase']=='planned' and proof['mutations_performed'] is False
    assert barrier.get(journal,'demo') is None and journal.db.total_changes==before
    assert docker.calls==[] and linux.commands==[]


def test_cancel_before_acquire_leaves_live_workload_untouched_and_blocks_late_acquire(runtime):
    engine,journal,docker,linux=runtime
    proof=planned(engine);bound={**INTENT,'workload_fingerprint':proof['workload_fingerprint']}
    assert run(engine,journal,request())['phase']=='completed'
    before=deepcopy(docker.containers);calls=list(docker.calls)
    cancelled=barrier.control(engine,'demo','cancel',bound)
    assert cancelled['phase']=='cancelled' and cancelled['acquisition_observed'] is False
    assert docker.containers==before and docker.calls==calls
    assert barrier.control(engine,'demo','cancel',bound)==cancelled
    with pytest.raises(Conflict,match='cancelled'):barrier.control(engine,'demo','acquire',bound)
    assert run(engine,journal,stop())['phase']=='completed'
    with pytest.raises(Conflict,match='cancelled'):barrier.control(engine,'demo','acquire',bound)


def test_partial_acquisition_cancel_releases_fence_and_survives_restart(runtime):
    engine,journal,docker,linux=runtime
    proof=planned(engine);bound={**INTENT,'workload_fingerprint':proof['workload_fingerprint']}
    held=barrier.control(engine,'demo','acquire',bound)
    cancelled=barrier.control(engine,'demo','cancel',bound)
    assert held['phase']=='held' and cancelled['acquisition_observed'] is True
    other=Journal(Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent)
    try:
        assert barrier.get(other,'demo')['phase']=='cancelled'
        assert other.submit(request())['phase']=='queued'
    finally:other.close()


def test_sealed_provisioning_cannot_be_cancelled_or_reacquired(runtime):
    engine,journal,docker,linux=runtime
    proof=planned(engine);bound={**INTENT,'workload_fingerprint':proof['workload_fingerprint']}
    barrier.control(engine,'demo','acquire',bound)
    assert barrier.control(engine,'demo','activate',bound)['phase']=='applying'
    assert barrier.control(engine,'demo','activate',bound)['phase']=='applying'
    for action in ('acquire','cancel'):
        with pytest.raises(Conflict,match='provisioning'):barrier.control(engine,'demo',action,bound)
    with pytest.raises(Conflict,match='offline management'):journal.submit(request())
    assert barrier.control(engine,'demo','release',{**READY,'workload_fingerprint':proof['workload_fingerprint']})['phase']=='released'


def test_changed_preflight_and_stale_cancel_cannot_unlock_active_fence(runtime):
    engine,journal,docker,linux=runtime
    proof=planned(engine);bound={**INTENT,'workload_fingerprint':proof['workload_fingerprint']}
    with pytest.raises(Conflict,match='changed after preflight'):
        barrier.control(engine,'demo','acquire',{**bound,'workload_fingerprint':'0'*64})
    assert barrier.get(journal,'demo') is None
    barrier.control(engine,'demo','acquire',bound)
    with pytest.raises(Conflict,match='preflight differs'):
        barrier.control(engine,'demo','cancel',{**bound,'workload_fingerprint':'0'*64})
    with pytest.raises(Conflict,match='intent changed'):
        barrier.control(engine,'demo','cancel',{**bound,'plan_fingerprint':'0'*64})
    assert barrier.get(journal,'demo')['phase']=='held'


def test_lost_cancel_ack_recovers_durable_tombstone(runtime,monkeypatch):
    engine,journal,docker,linux=runtime
    proof=planned(engine);bound={**INTENT,'workload_fingerprint':proof['workload_fingerprint']}
    barrier.control(engine,'demo','acquire',bound)
    original=barrier.sync;calls=[]
    def fail_second(journal):
        calls.append(True)
        if len(calls)==2:raise OSError('lost cancel ack')
        original(journal)
    monkeypatch.setattr(barrier,'sync',fail_second)
    with pytest.raises(OSError):barrier.control(engine,'demo','cancel',bound)
    assert barrier.get(journal,'demo')['phase']=='cancelled'
    monkeypatch.setattr(barrier,'sync',original)
    assert barrier.control(engine,'demo','cancel',bound)['phase']=='cancelled'
    with pytest.raises(Conflict,match='cancelled'):barrier.control(engine,'demo','acquire',bound)
