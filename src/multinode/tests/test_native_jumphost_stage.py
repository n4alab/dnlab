"""Integrated stage orchestration with real public lifecycle and fake Docker."""
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
import native_jumphost_stage as stage_module
import management_services_smoke as service_fixture
from tests.test_native_public import native
from tests.test_native_jumphost_inventory_diagnostic import inventory, configure


@pytest.fixture
def stage(inventory, tmp_path, monkeypatch):
    ctrl, client, docker, store, control = inventory
    ctrl.state.runtime_relays={}
    stage_module.states.save_state(ctrl.state,ctrl.state_dir)
    relay = {'record': None, 'calls': [], 'allocations':0}

    def guard(host, lab, name, action, config=None, generation=None):
        relay['calls'].append(action)
        if action=='preflight' and relay['record'] is not None and config is not None:
            assert config==relay['record']['config']
        if action == 'ensure':
            if relay['record'] is None:
                relay['allocations']+=1
                relay['record'] = {'phase': 'active', 'config': deepcopy(config),
                               'container_id': '9' * 64, 'nonce': '8' * 32,
                               'image': {'Config': {'Labels': {
                                   'io.dnlab.runtime-relay.capabilities': 'qualified-container-id-v1'}}}}
            else:assert config==relay['record']['config']
        elif action == 'delete':
            assert generation == relay['record']['config']['generation']
            relay['record']['phase'] = 'cleaned'
        return deepcopy(relay['record'] or {'phase': 'absent'})

    api = SimpleNamespace(inspect=lambda cid: next(
        (value for value in docker.containers.values() if value['Id'] == cid), None))
    monkeypatch.setattr(stage_module.relays, '_guard', guard)
    monkeypatch.setattr(stage_module, 'Docker', lambda: api)
    value = stage_module.NativeJumphostStage(tmp_path, ctrl.topo, ctrl.state, store, client,
                                             SimpleNamespace(), 'sha256:' + '7' * 64,
                                             '127.0.0.1', node='R1')
    return value, docker, control, relay


def test_stage_publishes_initial_and_restart_ids_without_replacing_helpers(stage):
    value, docker, control, relay = stage
    original = value.state.node_runtime['R1'].runtime_binding['container_id']
    value.prepare()
    assert value.state.node_runtime['R1'].runtime_binding['container_id'] == original
    first_relay = deepcopy(value.proof)
    value.restart()
    current = value.state.node_runtime['R1'].runtime_binding['container_id']
    assert current != original and current in control['record']['inventory_current']['relays']
    assert original not in control['record']['inventory_current']['relays']
    assert relay['record'] == first_relay and relay['calls'].count('ensure') == 1
    result = value.cleanup()
    assert result['verified'] and len(result['lifecycle']['births']) == 2 and not docker.containers
    assert relay['record']['phase'] == 'cleaned'


def test_stage_pending_publication_preserves_relay_and_running_vd(stage):
    value, docker, control, relay = stage
    value.prepare()
    control['failure'] = 'ack'
    with pytest.raises(OSError):
        value.restart()
    calls = deepcopy(docker.calls)
    with pytest.raises(RuntimeError, match='recovery pending'):
        value.cleanup()
    assert docker.calls == calls and relay['record']['phase'] == 'active'
    assert 'delete' not in relay['calls']
    value.restart()
    value.cleanup()


def test_replaced_relay_is_preserved_after_qualified_vd_stop(stage):
    value, docker, control, relay = stage
    value.prepare()
    value.restart()
    # Substitution after the stop (whose publication qualifies the relay).
    cleanup = value.lifecycle.cleanup

    def substitute(key):
        cleanup(key)
        relay['record']['container_id'] = '6' * 64

    value.lifecycle.cleanup = substitute
    with pytest.raises(RuntimeError, match='relay changed'):
        value.cleanup()
    assert not docker.containers and 'delete' not in relay['calls']


def test_runner_refuses_stage_without_original_managed_batch(tmp_path):
    with pytest.raises(ValueError, match='managed initial batch'):
        service_fixture.run(str(tmp_path / 'not-created'), 'unused', 'unused', 'unused',
                            native_lifecycle_relay_image='sha256:' + '7' * 64)
    assert not (tmp_path / 'not-created').exists()


@pytest.mark.parametrize('native_scope', [False, True])
def test_coordinator_selection_preserves_old_default_and_uses_canonical_for_lifecycle(tmp_path, monkeypatch, native_scope):
    from dnlab_multinode.services import runtime_cleanup
    root = tmp_path / 'not-created'
    monkeypatch.setattr(runtime_cleanup, 'operation_directory', lambda path: Path(path) / '.runtime-operations')
    assert service_fixture.fixture_coordinator(root, native_scope) == root / (
        '.runtime-operations' if native_scope else 'coordinator')
    assert not root.exists()


def test_lifecycle_fixture_refuses_external_coordinator_before_creating_state(tmp_path, monkeypatch):
    from dnlab_multinode.services import runtime_cleanup
    monkeypatch.setattr(runtime_cleanup, 'operation_directory', lambda path: tmp_path / 'shared')
    with pytest.raises(RuntimeError, match='externally configured'):
        service_fixture.fixture_coordinator(tmp_path / 'not-created', True)
    assert not (tmp_path / 'not-created').exists() and not (tmp_path / 'shared').exists()


def test_unresolved_cli_initialization_blocks_workload_and_relay_cleanup(stage):
    value,docker,control,relay=stage
    value.prepare();value.cli.append(None);calls=deepcopy(docker.calls)
    with pytest.raises(RuntimeError,match='CLI initialization unresolved'):
        value.cleanup()
    assert docker.calls==calls and relay['record']['phase']=='active' and 'delete' not in relay['calls']


def test_relay_process_snapshot_is_stable_and_original_proof_not_rewritten(stage,monkeypatch):
    import os
    value,docker,control,relay=stage;value.prepare()
    record={'Id':value.proof['container_id'],'Image':value.image,'RestartCount':0,
            'State':{'Running':True,'Pid':os.getpid(),'StartedAt':'original'}}
    monkeypatch.setattr(stage_module,'Docker',lambda:SimpleNamespace(inspect=lambda cid:deepcopy(record)))
    before=value.relay_snapshot('before');assert value.relay_snapshot('after')==before
    raw=(value.root/'native-relay-process-before.json').read_bytes()
    record['State']['StartedAt']='replacement'
    with pytest.raises(RuntimeError,match='observation differs'):value.relay_snapshot('before')
    assert (value.root/'native-relay-process-before.json').read_bytes()==raw
