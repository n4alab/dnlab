"""Loading native ownership does not invent an IPv4 reservation ledger."""
from copy import deepcopy

import pytest

from dnlab_multinode.models.state import DeploymentState, NodeRuntimeState
from dnlab_multinode.services.state import save_state, load_state


def populated(mode):
    value = DeploymentState(lab_name='demo', topology_file='fixture.yml', runtime_mode=mode)
    value.node_runtime['R1'] = NodeRuntimeState(node='R1', host='master', container='original-R1',
                                               mgmt_ipv4='192.0.2.2', state='running')
    return value


@pytest.mark.parametrize('mode', ['custom', 'unknown-backend'])
@pytest.mark.parametrize('with_ledger', [False, True])
@pytest.mark.parametrize('with_reservations', [False, True])
def test_native_and_unknown_states_preserve_saved_reservations_and_ledger(tmp_path, mode, with_ledger, with_reservations):
    value = populated(mode)
    if with_ledger:
        value.management_plan = {'original': {'ledgers': {'ipv4': {'blue': {'R1': '192.0.2.2'}}}}}
    if with_reservations:
        value.mgmt_ip_reservations = {'removed-node': '198.51.100.2'}
        value.mgmt_ipv6_reservations = {'R1': '2001:db8::2'}
        value.mgmt_mac_reservations = {'R1': '02:11:22:33:44:55'}
        value.mgmt_duid_reservations = {'R1': '00:03:00:01:02:11:22:33:44:55'}
        value.mgmt_iaid_reservations = {'R1': 1}
    original = deepcopy(value.to_dict())
    save_state(value, tmp_path)
    for _ in range(3):
        loaded = load_state('demo', tmp_path)
        assert loaded.to_dict() == original
        save_state(loaded, tmp_path)
    assert value.to_dict() == original


@pytest.mark.parametrize('with_ledger', [False, True])
def test_custom_missing_old_ipv4_field_does_not_infer_a_reservation(with_ledger):
    value = populated('custom')
    if with_ledger: value.management_plan = {'original': 'ledger'}
    saved = value.to_dict(); del saved['mgmt_ip_reservations']
    loaded = DeploymentState.from_dict(saved)
    assert loaded.mgmt_ip_reservations == {}
    assert loaded.management_plan == value.management_plan
    assert loaded.node_runtime == value.node_runtime


@pytest.mark.parametrize('mode', ['', 'legacy', 'per-vd'])
@pytest.mark.parametrize('missing', [False, True])
def test_compatible_legacy_states_keep_ipv4_backfill(mode, missing):
    saved = populated(mode).to_dict()
    if not mode: del saved['runtime_mode']
    if missing: del saved['mgmt_ip_reservations']
    loaded = DeploymentState.from_dict(saved)
    assert loaded.mgmt_ip_reservations == {'R1': '192.0.2.2'}


@pytest.mark.parametrize('mode', ['', 'legacy', 'per-vd'])
def test_legacy_backfill_never_replaces_existing_reservations(mode):
    value = populated(mode)
    value.mgmt_ip_reservations = {'removed-node': '198.51.100.2'}
    assert DeploymentState.from_dict(value.to_dict()).mgmt_ip_reservations == value.mgmt_ip_reservations
