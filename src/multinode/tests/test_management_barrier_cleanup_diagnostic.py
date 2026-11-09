"""Daemon must preserve a sealed management operation even before the first VD."""
import pytest
from copy import deepcopy
from dnlab_multinode.services import lab_cleanup as cleanup,management_barrier as barrier
from dnlab_multinode.services.runtime_cleanup import CleanupBlocked
from dnlab_multinode.services import runtime_cleanup
from dataclasses import replace
from dnlab_multinode.services.paths import PATHS
from tests.test_management_prepare import setup
from tests.test_lab_cleanup import _hosts


def pending(f,phase,monkeypatch):
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=f
    controller.prepare('pre-vd-management',topo,schedule,ips,targets,state)
    if phase!='acquiring':controller.driver.acquire('demo','pre-vd-management')
    if phase=='provisioning':controller.driver.begin_provisioning('demo','pre-vd-management')
    monkeypatch.setattr(runtime_cleanup,'PATHS',replace(PATHS,runtime_operations_dir=str(store.directory)))
    assert not state.node_runtime and not state.retired_native_nodes
    assert not store.pending()
    state.teardown_requested=True
    return state,store


@pytest.mark.parametrize('phase',['acquiring','held','provisioning'])
def test_daemon_preflight_refuses_pending_management_without_vds(setup,monkeypatch,tmp_path,phase):
    state,store=pending(setup,phase,monkeypatch)
    with pytest.raises(CleanupBlocked,match='management'):
        cleanup._vd_preflight(cleanup.LabCleanupPlan(lab='demo'),state,{},tmp_path,advance=False)
    assert barrier.get(store,'demo')['phase']==phase


def test_daemon_cannot_finalize_state_while_service_parent_barrier_is_sealed(setup,monkeypatch,tmp_path):
    state,store=pending(setup,'provisioning',monkeypatch)
    deleted=[]
    monkeypatch.setattr(cleanup.state_svc,'delete_state',lambda *args:deleted.append(args))
    result=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients={'master':object(),'worker1':object()})
    assert deleted==[], 'daemon deleted state while original management provisioning barrier remains active'
    assert 'retained' in result['demo']
    assert barrier.get(store,'demo')['phase']=='provisioning'


def test_cancellation_must_be_acknowledged_by_all_original_hosts_before_cleanup(setup,monkeypatch,tmp_path):
    state,store=pending(setup,'held',monkeypatch)
    topo,_,ips,clients,runtimes,targets,_,controller,schedule,registry,events,save=setup
    runtimes['worker1'].reject=True
    with pytest.raises(RuntimeError):controller.driver.cancel('demo','pre-vd-management')
    with pytest.raises(CleanupBlocked,match='management'):
        cleanup._vd_preflight(cleanup.LabCleanupPlan(lab='demo'),state,{},tmp_path,advance=False)
    runtimes['worker1'].reject=False
    assert controller.driver.cancel('demo','pre-vd-management')['phase']=='cancelled'
    cleanup._vd_preflight(cleanup.LabCleanupPlan(lab='demo'),state,{},tmp_path,advance=False)


def test_terminal_receipt_drift_and_pending_service_recovery_keep_state(setup,monkeypatch,tmp_path):
    state,store=pending(setup,'held',monkeypatch)
    controller=setup[7];controller.driver.cancel('demo','pre-vd-management')
    current=barrier.get(store,'demo');original=deepcopy(current)
    current['cancelled']['master']['journal_id']='f'*32
    with store.transaction():barrier.put(store,'demo',current)
    with pytest.raises(CleanupBlocked,match='receipt identity'):
        cleanup._vd_preflight(cleanup.LabCleanupPlan(lab='demo'),state,{},tmp_path,advance=False)
    original['services']={'phase':'applying'}
    with store.transaction():barrier.put(store,'demo',original)
    with pytest.raises(CleanupBlocked,match='service recovery'):
        cleanup._vd_preflight(cleanup.LabCleanupPlan(lab='demo'),state,{},tmp_path,advance=False)


def test_cleanup_and_provisioning_share_lock_even_without_vds(setup,monkeypatch,tmp_path):
    from dnlab_multinode.services.runtime_operations import OperationStore,RuntimeOperationError
    from dnlab_multinode.services.runtime_cleanup import management_cleanup_guard
    state,store=pending(setup,'provisioning',monkeypatch);controller=setup[7]
    with controller.driver.provisioning('demo','pre-vd-management'):
        with pytest.raises(CleanupBlocked,match='already executing'):
            with management_cleanup_guard('demo',state,tmp_path):pytest.fail('cleanup crossed provisioning lock')


def test_new_coordinator_cannot_enter_while_cleanup_holds_terminal_barrier_lock(setup,monkeypatch,tmp_path):
    from dnlab_multinode.services.runtime_operations import OperationStore,RuntimeOperationError
    from dnlab_multinode.services.runtime_cleanup import management_cleanup_guard
    state,store=pending(setup,'held',monkeypatch);controller=setup[7]
    controller.driver.cancel('demo','pre-vd-management')
    other=OperationStore(store.directory)
    try:
        with management_cleanup_guard('demo',state,tmp_path):
            with pytest.raises(RuntimeOperationError,match='already executing'):
                with other.executing('demo','management-barrier'):pytest.fail('provisioning crossed cleanup lock')
    finally:other.close()
