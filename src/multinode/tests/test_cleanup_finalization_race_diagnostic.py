"""Regression: a durable fence excludes late native start during finalization."""
import pytest
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from dnlab_multinode.services import lab_cleanup as cleanup,state as state_svc
from tests.test_runtime_cleanup import fixture,START,STOP,TARGET
from tests.test_lab_cleanup import _hosts


def test_late_native_start_intent_is_rejected_before_deleting_deployment_state(fixture,monkeypatch):
    state,runtime,client,store,directory=fixture
    runtime.node_stop_stage(STOP,'demo','R1','finalize')
    store.observe('demo','stop',runtime.remote)
    original=cleanup._teardown_remaining_artifacts
    def verify_absence_then_prepare_next_generation(*args):
        result=original(*args)
        assert result==(False,'')
        # A second coordinator cannot cross the durable closing fence.
        with pytest.raises(RuntimeOperationError,match='closing or closed'):
            store.prepare({**START,'request_id':'late-start','expected_revision':2},TARGET,
                          state.node_runtime['R1'].runtime_binding['journal_id'])
        return result
    monkeypatch.setattr(cleanup,'_teardown_remaining_artifacts',verify_absence_then_prepare_next_generation)
    status=cleanup._finalize_requested_teardowns({'demo':state},directory,_hosts(),clients={'master':client})
    assert status['demo']=='pending teardown state finalized'
    assert state_svc.load_state('demo',directory) is None
    assert store.pending()==[]
