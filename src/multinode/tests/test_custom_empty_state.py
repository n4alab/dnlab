"""Loading placement never invents native workload ownership."""
import pytest

from dnlab_multinode.models.state import DeploymentState, HostScheduleState, NodeRuntimeState
from dnlab_multinode.services.state import save_state, load_state


@pytest.mark.parametrize('deployed', [False, True])
@pytest.mark.parametrize('retired', [False, True])
def test_custom_empty_workloads_roundtrip_exactly_with_placement(tmp_path, deployed, retired):
    state = DeploymentState(lab_name='demo', topology_file='fixture.yml',
                            runtime_mode='custom', dnlab_deployed=deployed)
    state.scheduling['master'] = HostScheduleState(host='fixture', topology_file='', vd=['R1'])
    state.management_plan = {'original': 'ledger'}
    state.mgmt_ip_reservations = {'R1': '192.0.2.2'}
    if retired:
        state.retired_native_nodes['old'] = NodeRuntimeState(node='old', state='stopped')
    before = state.to_dict()
    save_state(state, tmp_path)
    loaded = load_state('demo', tmp_path)
    assert loaded.to_dict() == before
    assert loaded.node_runtime == {}
    assert DeploymentState.from_dict(loaded.to_dict()).to_dict() == before


@pytest.mark.parametrize('mode', ['', 'legacy', 'per-vd'])
def test_compatible_containerlab_states_keep_placement_reconstruction(mode):
    state = DeploymentState(lab_name='demo', topology_file='fixture.yml', runtime_mode=mode)
    state.scheduling['master'] = HostScheduleState(host='fixture', topology_file='old.yml', vd=['R1'])
    saved = state.to_dict()
    if not mode:
        saved.pop('runtime_mode')  # Actual older files omitted the field.
    loaded = DeploymentState.from_dict(saved)
    assert loaded.node_runtime['R1'].container == 'clab-demo-R1'
    assert loaded.node_runtime['R1'].host == 'master'
    assert loaded.node_runtime['R1'].topology_file == 'old.yml'
    assert loaded.node_runtime['R1'].runtime_binding == {}
    assert loaded.runtime_mode == (mode or 'legacy')


def test_unknown_backend_remains_unqualified_without_legacy_conversion():
    state = DeploymentState(lab_name='demo', topology_file='fixture.yml', runtime_mode='unknown-backend')
    state.scheduling['master'] = HostScheduleState(host='fixture', topology_file='', vd=['R1'])
    loaded = DeploymentState.from_dict(state.to_dict())
    assert loaded.node_runtime == {} and loaded.runtime_mode == 'unknown-backend'


def test_custom_partial_inventory_does_not_fill_unpublished_nodes():
    state = DeploymentState(lab_name='demo', topology_file='fixture.yml', runtime_mode='custom')
    state.scheduling['master'] = HostScheduleState(host='fixture', topology_file='', vd=['R1', 'R2'])
    state.node_runtime['R1'] = NodeRuntimeState(node='R1', container='original', state='starting',
                                               runtime_binding={'backend': 'custom', 'container_id': 'original-id'})
    assert DeploymentState.from_dict(state.to_dict()).to_dict() == state.to_dict()
