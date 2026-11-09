"""Crash/retry boundaries of pre-birth usage with real in-memory host guards."""
from copy import deepcopy
import json

import pytest

from tests.test_runtime_initial_deploy import world, count
from tests.test_native_lifecycle_parser import segmented
from tests.test_runtime_management_parent import managed, prepare
from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.services import management_barrier as barrier
from dnlab_multinode.services.runtime_operations import RuntimeOperationError, OperationStore


def transports(managed):
    return {h:c.ssh for h,c in managed[0][2].items()}


def marks(managed):
    return {h:sum(action=='network-mark-used' for _,action in c.events) for h,c in transports(managed).items()}


def test_all_host_usage_finishes_before_first_workload_birth(managed, monkeypatch):
    batch,store,clients,engines,_=managed[0];prepare(managed)
    events=[]
    for host,transport in transports(managed).items():
        execute=transport.run_input
        def call(command,payload,execute=execute,host=host,**kwargs):
            action=json.loads(payload)['action'];events.append((host,action))
            if action=='network-mark-used':assert count(clients)==0
            return execute(command,payload,**kwargs)
        monkeypatch.setattr(transport,'run_input',call)
    create=engines['master'].backend.docker.create
    def born(*args):
        phase=batch.management_usage.get('demo','deploy')
        assert phase['phase']=='completed' and set(phase['progress']['completed'])=={'master','worker'}
        assert ('worker','network-verify-ready') in events[:events.index(('master','network-mark-used'))]
        return create(*args)
    monkeypatch.setattr(engines['master'].backend.docker,'create',born)
    assert batch.advance('demo','deploy')['phase']=='applying'
    assert batch.advance('demo','deploy')['phase']=='completed'
    assert marks(managed)=={'master':1,'worker':1}


def test_last_host_conflict_prevents_every_mark_and_workload(managed):
    batch,store,clients,_,_=managed[0];prepare(managed)
    transports(managed)['worker'].reject='network-verify-ready'
    with pytest.raises(RuntimeError,match='refused'):batch.advance('demo','deploy')
    assert count(clients)==0 and marks(managed)=={'master':0,'worker':0}
    assert batch.management_usage.get('demo','deploy') is None


def test_lost_mark_ack_reopens_original_intent_without_second_mark(managed, monkeypatch):
    batch,store,clients,_,_=managed[0];prepare(managed)
    host=transports(managed)['master'];execute=host.run_input
    def lost(command,payload,**kwargs):
        result=execute(command,payload,**kwargs)
        if json.loads(payload)['action']=='network-mark-used':
            monkeypatch.setattr(host,'run_input',execute)
            raise OSError('lost original mark acknowledgement')
        return result
    monkeypatch.setattr(host,'run_input',lost)
    with pytest.raises(OSError,match='lost original'):batch.advance('demo','deploy')
    original=deepcopy(batch.management_usage.get('demo','deploy')['intent'])
    assert count(clients)==0 and marks(managed)=={'master':1,'worker':0}
    fresh=OperationStore(store.directory)
    try:
        recovered=RuntimeInitialDeployment(fresh,batch.factory)
        recovered.recover('demo','deploy')
        recovered.advance('demo','deploy');assert recovered.advance('demo','deploy')['phase']=='completed'
        assert recovered.management_usage.get('demo','deploy')['intent']==original
        assert marks(managed)=={'master':1,'worker':1} and count(clients)==2
    finally:fresh.close()


@pytest.mark.parametrize('boundary',['intent','attempt','completed'])
def test_uncertain_checkpoint_blocks_birth_until_original_recovery(managed,monkeypatch,boundary):
    batch,store,clients,_,_=managed[0];prepare(managed);sync=store.sync_directory;failed=[]
    def uncertain():
        sync();row=batch.management_usage.get('demo','deploy')
        selected=(row and ((boundary=='intent' and not row['progress']['attempted'])
                  or (boundary=='attempt' and row['progress']['attempted'] and not row['progress']['completed'])
                  or (boundary=='completed' and row['phase']=='completed')))
        if selected and not failed:
            failed.append(True);raise OSError('uncertain usage checkpoint')
    monkeypatch.setattr(store,'sync_directory',uncertain)
    with pytest.raises(OSError,match='uncertain usage'):batch.advance('demo','deploy')
    assert count(clients)==0
    if boundary in ('intent','attempt'):assert marks(managed)=={'master':0,'worker':0}
    original=deepcopy(batch.management_usage.get('demo','deploy')['intent'])
    batch.recover('demo','deploy');batch.advance('demo','deploy');batch.advance('demo','deploy')
    assert batch.get('demo','deploy')['phase']=='completed'
    assert marks(managed)=={'master':1,'worker':1}
    assert batch.management_usage.get('demo','deploy')['intent']==original


def test_missing_intent_after_first_birth_is_not_backfilled(managed):
    batch,store,clients,_,_=managed[0];prepare(managed);batch.advance('demo','deploy')
    with store.transaction():store.db.execute('DELETE FROM initial_management_usage')
    before=marks(managed);assert count(clients)==1
    with pytest.raises(RuntimeOperationError,match='missing pre-birth'):batch.advance('demo','deploy')
    assert count(clients)==1 and marks(managed)==before


def test_replaced_network_after_lost_ack_preserves_pending_hosts(managed,monkeypatch):
    batch,store,clients,_,_=managed[0];prepare(managed)
    host=transports(managed)['master'];execute=host.run_input
    def lost(command,payload,**kwargs):
        result=execute(command,payload,**kwargs)
        if json.loads(payload)['action']=='network-mark-used':
            monkeypatch.setattr(host,'run_input',execute);raise OSError('lost ack')
        return result
    monkeypatch.setattr(host,'run_input',lost)
    with pytest.raises(OSError):batch.advance('demo','deploy')
    other=transports(managed)['worker'];old=next(iter(other.docker.networks));network=other.docker.networks.pop(old)
    other.docker.networks['f'*64]={**network,'Id':'f'*64}
    before=deepcopy(batch.management_usage.get('demo','deploy'))
    batch.recover('demo','deploy')
    with pytest.raises(RuntimeError,match='replaced'):batch.advance('demo','deploy')
    assert count(clients)==0 and marks(managed)=={'master':1,'worker':0}
    assert batch.management_usage.get('demo','deploy')==before


def test_cancel_before_usage_never_marks_or_spawns(managed):
    batch,store,clients,_,_=managed[0];prepare(managed);batch.cancel('demo','deploy')
    assert batch.advance('demo','deploy')['phase']=='cancelled'
    assert count(clients)==0 and marks(managed)=={'master':0,'worker':0}


def test_host_without_workload_is_preflighted_before_marking(managed):
    batch,store,clients,_,_=managed[0]
    _,topo,schedule,options=managed
    topo.nodes.pop('R2');schedule.assignments.pop('worker')
    options['targets'].pop('worker')
    prepare(managed)
    transports(managed)['worker'].reject='network-verify-ready'
    with pytest.raises(RuntimeError,match='refused'):batch.advance('demo','deploy')
    assert count(clients)==0 and marks(managed)=={'master':0,'worker':0}


def test_completed_usage_is_reobserved_before_next_workload(managed):
    batch,store,clients,_,_=managed[0];prepare(managed);batch.advance('demo','deploy')
    intent=batch.management_usage.get('demo','deploy')['intent']
    host=transports(managed)['worker'];worker=host.worker(intent['plans']['worker']);record=worker.read()
    segment=intent['selected']['worker'][0];record['networks'][segment]['used']=False;worker.save(record)
    with pytest.raises(RuntimeOperationError,match='completed management usage was lost'):
        batch.advance('demo','deploy')
    assert count(clients)==1 and marks(managed)=={'master':1,'worker':1}
