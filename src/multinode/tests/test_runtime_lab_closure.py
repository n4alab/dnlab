import pytest

from dnlab_multinode.services import runtime_lab_closure as closure
from dnlab_multinode.services.runtime_operations import OperationStore,RuntimeOperationError
from tests.test_runtime_cleanup import fixture,START,REQUEST,TARGET,JOURNAL,STOP


def completed(fixture):
    state,runtime,client,store,directory=fixture
    runtime.node_stop_stage(STOP,'demo','R1','finalize');store.observe('demo','stop',runtime.remote)
    value=closure.begin(store,'demo',['stop']);target=closure.digest({'target':TARGET,'journal_id':JOURNAL})
    closure.receipt(store,'demo',value['closure_id'],TARGET,JOURNAL,{
        'lab_id':'demo','journal_id':JOURNAL,'closure_id':value['closure_id'],'generation':1,'phase':'closed'})
    closure.finish(store,'demo',value['closure_id'],[target])
    return store,value


def test_durable_closure_excludes_another_coordinator_connection(fixture):
    state,runtime,client,store,directory=fixture
    value=closure.begin(store,'demo',['stop']);other=OperationStore(store.directory)
    try:
        assert closure.get(other,'demo')['closure_id']==value['closure_id']
        with pytest.raises(RuntimeOperationError,match='closing or closed'):
            other.prepare({**START,'request_id':'late','node_id':'other'},TARGET,JOURNAL)
        # Existing immutable teardown intent remains replayable.
        assert other.prepare(REQUEST,TARGET,JOURNAL)['request_id']=='stop'
    finally:other.close()


def test_pending_unqualified_intent_prevents_fence_before_remote_work(fixture):
    state,runtime,client,store,directory=fixture
    store.prepare({**START,'request_id':'other','node_id':'other'},TARGET,JOURNAL)
    with pytest.raises(RuntimeOperationError,match='outside qualified'):
        closure.begin(store,'demo',['stop'])
    assert closure.get(store,'demo') is None and runtime.calls==[]


def test_reopening_unknown_ack_keeps_fence_and_recovers_exact_request(fixture):
    store,value=completed(fixture)
    class Client:
        def __init__(self):self.lose_ack=True;self.calls=[]
        def bound_to(self,journal):assert journal==JOURNAL;return self
        def lab_closure(self,lab,action,payload):
            self.calls.append(payload)
            if self.lose_ack:self.lose_ack=False;raise RuntimeError('lost ack')
            return {'lab_id':lab,'journal_id':JOURNAL,'closure_id':payload['closure_id'],
                'generation':2,'phase':'open','reopen_request_id':payload['request_id']}
    client=Client();factory=lambda target:client
    with pytest.raises(RuntimeError,match='lost ack'):
        closure.reopen(store,'demo',value['closure_id'],'reopen',factory,deployment_state_absent=True)
    assert closure.get(store,'demo')['phase']=='reopening'
    with pytest.raises(RuntimeOperationError):store.prepare({**START,'request_id':'late','lab_generation':2},TARGET,JOURNAL)
    with pytest.raises(RuntimeOperationError,match='identity'):
        closure.reopen(store,'demo',value['closure_id'],'other',factory,deployment_state_absent=True)
    result=closure.reopen(store,'demo',value['closure_id'],'reopen',factory,deployment_state_absent=True)
    assert result['generation']==2 and client.calls[0]==client.calls[1]
    with pytest.raises(RuntimeOperationError,match='generation'):store.prepare({**START,'request_id':'stale','expected_revision':2},TARGET,JOURNAL)
    assert store.prepare({**START,'request_id':'new','expected_revision':2,'lab_generation':2},TARGET,JOURNAL)['phase']=='prepared'
    assert store.db.execute('SELECT count(*) FROM lab_closure_history').fetchone()[0]==1


def test_reopen_requires_old_deployment_state_absent(fixture):
    store,value=completed(fixture);calls=[]
    with pytest.raises(RuntimeOperationError,match='state must be absent'):
        closure.reopen(store,'demo',value['closure_id'],'reopen',lambda target:calls.append(target),deployment_state_absent=False)
    assert calls==[] and closure.get(store,'demo')['phase']=='closed'


def test_failed_fence_durability_prevents_remote_mutation(fixture,monkeypatch):
    state,runtime,client,store,directory=fixture
    from dnlab_multinode.services.runtime_cleanup import Delegate
    from tests.test_runtime_cleanup import artifacts
    delegate=Delegate(state,{'master':client},directory)
    try:
        delegate.preflight(artifacts(client))
        def failed_sync():raise OSError('fixture directory sync failed')
        monkeypatch.setattr(delegate.store,'sync_directory',failed_sync)
        with pytest.raises(OSError,match='directory sync'):delegate.fence()
        assert runtime.calls==[]
        assert closure.get(store,'demo')['phase']=='closing'
        with pytest.raises(RuntimeOperationError):store.prepare({**START,'node_id':'other','request_id':'late'},TARGET,JOURNAL)
    finally:delegate.close()
