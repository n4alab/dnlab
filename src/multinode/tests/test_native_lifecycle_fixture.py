"""Restart-aware gate cleanup against the real public coordinator and fake host."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from native_lifecycle_fixture import LifecycleWorkload
from tests.test_native_public import native
from tests.test_native_jumphost_inventory_diagnostic import inventory, configure


def tracked(inventory, tmp_path):
    ctrl, client, docker, store, control = inventory
    api = SimpleNamespace(inspect=lambda cid: next(
        (value for value in docker.containers.values() if value['Id'] == cid), None))
    fixture = LifecycleWorkload(tmp_path / 'lifecycle.json', ctrl, 'R1', client, store, api)
    return fixture, docker, control


def test_preserves_all_births_and_stops_only_through_public_lifecycle(inventory, tmp_path):
    fixture, docker, control = tracked(inventory, tmp_path)
    first = deepcopy(fixture.record['births'][0])
    fixture.step('restart', 'restart-1')
    second = deepcopy(fixture.record['births'][1])
    fixture.step('restart', 'restart-2')
    assert fixture.record['births'][:2] == [first, second]
    assert [r['generation'] for r in fixture.record['births']] == [1, 2, 3]
    fixture.cleanup('cleanup-stop')
    assert fixture.record['cleanup_verified'] and not docker.containers
    assert all(json.loads(r['receipt']['payload'])['inventory_phase'] == 'published'
               for r in fixture.record['steps'])
    calls = deepcopy(docker.calls)
    fixture.cleanup('cleanup-stop')
    assert docker.calls == calls and fixture.record['cleanup_verified']


@pytest.mark.parametrize('failure', ['ack', 'pending'])
def test_lost_publication_reopens_original_step_without_second_restart(inventory, tmp_path, failure):
    fixture, docker, control = tracked(inventory, tmp_path)
    control['failure'] = failure
    with pytest.raises(OSError):
        fixture.step('restart', 'restart-1')
    calls = deepcopy(docker.calls)
    with pytest.raises(RuntimeError, match='recovery pending'):
        fixture.cleanup('cleanup-stop')
    assert docker.calls == calls and not fixture.record['cleanup_verified']
    reopened = LifecycleWorkload(fixture.path, fixture.controller, 'R1', fixture.runtime,
                                 fixture.store, fixture.docker)
    reopened.step('restart', 'restart-1')
    assert docker.calls == calls and len(reopened.record['births']) == 2
    reopened.cleanup('cleanup-stop')
    assert reopened.record['cleanup_verified']


def test_fixture_checkpoint_loss_replays_completed_parent_without_restart(inventory, tmp_path, monkeypatch):
    fixture, docker, control = tracked(inventory, tmp_path)
    save = fixture.save

    def fail_receipt():
        if fixture.record['steps'] and fixture.record['steps'][-1]['phase'] == 'completed':
            raise OSError('lost fixture receipt')
        save()

    monkeypatch.setattr(fixture, 'save', fail_receipt)
    with pytest.raises(OSError, match='fixture receipt'):
        fixture.step('restart', 'restart-1')
    calls = deepcopy(docker.calls)
    reopened = LifecycleWorkload(fixture.path, fixture.controller, 'R1', fixture.runtime,
                                 fixture.store, fixture.docker)
    reopened.step('restart', 'restart-1')
    assert docker.calls == calls and len(reopened.record['births']) == 2


def test_foreign_generation_refuses_before_new_public_request(inventory, tmp_path):
    fixture, docker, control = tracked(inventory, tmp_path)
    original = deepcopy(fixture.record)
    name = fixture.controller.state.node_runtime['R1'].container
    docker.containers[name]['Id'] = 'f' * 64
    calls = deepcopy(docker.calls)
    with pytest.raises(Exception):
        fixture.step('restart', 'restart-1')
    assert docker.calls == calls and fixture.record == original


def test_requires_canonical_ledger_before_creating_fixture_journal(inventory, tmp_path):
    ctrl, client, docker, store, control = inventory
    path = tmp_path / 'wrong-ledger.json'
    wrong = SimpleNamespace(directory=tmp_path / 'coordinator')
    with pytest.raises(RuntimeError, match='canonical'):
        LifecycleWorkload(path, ctrl, 'R1', client, wrong, docker)
    assert not path.exists()


def test_cleanup_keeps_pending_when_any_original_id_still_exists(inventory, tmp_path):
    fixture, docker, control = tracked(inventory, tmp_path)
    first = fixture.record['births'][0]['container_id']
    fixture.step('restart', 'restart-1')
    fixture.docker = SimpleNamespace(inspect=lambda cid: {'Id': cid} if cid == first else None)
    with pytest.raises(RuntimeError, match='remains present'):
        fixture.cleanup('cleanup-stop')
    assert not fixture.record['cleanup_verified']


def test_request_key_cannot_change_action(inventory, tmp_path):
    fixture, docker, control = tracked(inventory, tmp_path)
    fixture.step('restart', 'restart-1')
    calls = deepcopy(docker.calls)
    with pytest.raises(RuntimeError, match='action differs'):
        fixture.step('stop', 'restart-1')
    assert docker.calls == calls


def test_completed_receipt_is_immutable_on_replay(inventory, tmp_path):
    fixture, docker, control = tracked(inventory, tmp_path)
    fixture.step('restart', 'restart-1')
    row = fixture.store.db.execute(
        'SELECT payload FROM public_requests WHERE request_id=?', ('restart-1',)).fetchone()
    payload = json.loads(row['payload'])
    payload['fixture-unexpected-field'] = True
    fixture.store.db.execute('UPDATE public_requests SET payload=? WHERE request_id=?',
                             (json.dumps(payload), 'restart-1'))
    calls = deepcopy(docker.calls)
    with pytest.raises(RuntimeError, match='receipt changed'):
        fixture.step('restart', 'restart-1')
    assert docker.calls == calls
