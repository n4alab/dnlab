"""Regressions: native ownership selects public lifecycle, regardless of name."""
import pytest

from dnlab_multinode.services import native_public as public,state as state_svc
from dnlab_multinode.services.runtime_operations import OperationDriver
from tests.test_native_public import native


def parked(native):
    ctrl,client,docker,store=native
    source=public.source(store,ctrl.state,'R1')
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'original-stop',
             'action':'stop','stop_mode':'coordinated','expected_revision':1}
    driver=OperationDriver(store,lambda target:client)
    driver.prepare(request,source['target']);assert driver.advance('demo','original-stop')['phase']=='awaiting_link_cleanup'
    ctrl.state.node_runtime['R1'].runtime_binding['stop_request_id']='original-stop'
    state_svc.save_state(ctrl.state,ctrl.state_dir)
    return ctrl,client,docker,store


@pytest.mark.parametrize('force',[False,True])
def test_public_stop_completes_original_native_stop_without_legacy_fallback(native,force):
    ctrl,client,docker,store=parked(native)
    state=ctrl.stop('R1',force=force)
    assert state.node_runtime['R1'].state=='stopped'
    assert store.get('demo','original-stop')['phase']=='completed'
    assert ('stage','cleanup') in client.calls and ('stage','finalize') in client.calls
    assert not any(c[0]=='reconcile' for c in client.calls)


def test_public_start_refuses_an_unfinished_native_stop_before_mutation(native):
    ctrl,client,docker,store=parked(native);calls=list(client.calls)
    with pytest.raises(public.NativeOwnershipError,match='another native operation'):
        ctrl.start('R1')
    assert client.calls==calls
    assert store.get('demo','original-stop')['phase']=='awaiting_link_cleanup'


def test_public_native_owner_with_arbitrary_name_is_supported(native):
    ctrl,client,docker,store=native
    assert ctrl.state.node_runtime['R1'].container=='native-owned-R1'
    assert ctrl.stop('R1').node_runtime['R1'].state=='stopped'
