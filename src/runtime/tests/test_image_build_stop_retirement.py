"""Never-dispatched stop retirement: synthetic service and original history."""
from copy import deepcopy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_stop_retirement import (
    UnreleasedStopRecovery, stop_state, stop_receipt, retire_stop,
)
from image_build_admin_service import AdministrativeService
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def pending_stop(executor, monkeypatch):
    hold, op, state, native, commands, adapter = executor
    hold._action(hold.read(op), 'disable_restart', recover=False)
    original = commands.verify
    def refuse(reference, command):
        if (command['action'] == 'stop'
                and hold.read(op)['actions']['stop']['phase'] == 'armed'):
            raise TemplateError('synthetic healthcheck transition')
        return original(reference, command)
    monkeypatch.setattr(commands, 'verify', refuse)
    with pytest.raises(TemplateError, match='synthetic healthcheck'):
        hold.acquire(op)
    args = dict(hold_id=op, command_id=hold.read(op)['actions']['stop']['reference']['token'],
                epoch=commands.runtime.check())
    proof = stop_state(hold.journal.db, **args)
    request = dict(id='7'*32, nonce='8'*32, original_sha256=fingerprint(proof),
                   owner_sha256=fingerprint(args['epoch']['snapshot']), service_sha256='9'*64,
                   restart_policy=deepcopy(proof['hold']['policy']))
    exited = dict(owner_sha256=request['owner_sha256'], pidfd_exit_verified=True,
                  term_count=1, force_used=False)
    return hold, commands, state, args, proof, request, exited


def test_retirement_preserves_arm_and_invalidates_dispatch(pending_stop):
    hold, commands, state, args, proof, request, exited = pending_stop
    actions = deepcopy(state['actions'])
    receipt = retire_stop(hold.journal.db, request, exited, **args, check=lambda: None)
    assert receipt == stop_receipt(request)
    assert stop_state(hold.journal.db, **args, claim_present=False) == proof
    ref = proof['hold']['actions']['stop']['reference']
    with pytest.raises(TemplateError, match='administratively retired'):
        commands.outcome(ref)
    assert commands._read(ref, historical=True)['phase'] == 'armed'
    assert state['actions'] == actions == ['policy']
    before = hold.journal.db.total_changes
    assert retire_stop(hold.journal.db, request, exited, **args, check=lambda: None) == receipt
    assert hold.journal.db.total_changes == before


@pytest.mark.parametrize('fault', ['release', 'dispatch', 'foreign-vm', 'claim'])
def test_conflict_prevents_retirement(pending_stop, fault):
    hold, _, _, args, _, _, _ = pending_stop
    db = hold.journal.db
    if fault in ('release', 'dispatch'):
        row = db.execute("SELECT id,payload FROM image_build_control_commands WHERE action='stop'").fetchone()
        value = json.loads(row['payload'])
        if fault == 'release': value['phase'] = 'release_requested'
        else: value['native_dispatch_started'] = True
        db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=? WHERE id=?',
                   (canonical(value), fingerprint(value), row['id']))
    elif fault == 'claim': db.execute('DELETE FROM resources')
    else:
        db.execute('CREATE TABLE vm_definition_intents (id TEXT)')
        db.execute("INSERT INTO vm_definition_intents VALUES('foreign')")
    before = db.total_changes
    with pytest.raises(TemplateError): stop_state(db, **args)
    assert db.total_changes == before


def test_changed_observation_rolls_back_retirement(pending_stop):
    hold, _, _, args, proof, request, exited = pending_stop
    def changed(): raise TemplateError('service changed')
    with pytest.raises(TemplateError, match='service changed'):
        retire_stop(hold.journal.db, request, exited, **args, check=changed)
    assert stop_state(hold.journal.db, **args) == proof


@pytest.mark.parametrize("lost_response", [False, True])
def test_one_policy_restore_without_service_stop_start(tmp_path, lost_response):
    journal = Journal(tmp_path/'admin')
    request = dict(id='1'*32, nonce='2'*32, original_sha256='3'*64,
                   owner_sha256='4'*64, service_sha256='5'*64,
                   restart_policy=dict(Name='unless-stopped', MaximumRetryCount=0))
    state = dict(alive=True, policy=dict(Name='no', MaximumRetryCount=0), actions=[])
    def preflight(current, **_):
        return dict(original_sha256=current['original_sha256'], owner_sha256=current['owner_sha256'],
                    service_sha256=current['service_sha256'], owner_alive=state['alive'],
                    restart_policy=state['policy'], execution_lock_held=True,
                    no_native_dispatch=True, vm_resources_absent=True, window_active=True)
    def terminate(current, *, check):
        check(); state['alive'] = False; state['actions'].append('owner-term')
        return dict(owner_sha256=current['owner_sha256'], pidfd_exit_verified=True, term_count=1, force_used=False)
    def update(policy):
        state['policy'] = deepcopy(policy); state['actions'].append('policy')
        if lost_response: raise OSError('lost policy response')
    driver = UnreleasedStopRecovery(journal, preflight=preflight, terminate_owner=terminate,
                                   update_policy=update, retire_claim=lambda current, _: stop_receipt(current))
    driver.prepare(request)
    if lost_response:
        with pytest.raises(OSError, match='lost policy response'): driver.apply(request['id'])
        assert driver.read(request['id'])['phase'] == 'policy_requested'
    assert driver.apply(request['id'])['phase'] == 'completed'
    assert driver.apply(request['id'])['phase'] == 'completed'
    assert state['actions'] == ['owner-term', 'policy']
    journal.close()


def test_original_generation_requires_exact_saved_profile(observation):
    original, hold, state, profile = observation
    state['inspect']['HostConfig']['RestartPolicy'] = dict(Name='no', MaximumRetryCount=0)
    def build(capture):
        return AdministrativeService(profile, hold, capture=capture, generation=profile['generation'],
            networks=state['inspect']['NetworkSettings']['Networks'], api=original.api,
            read_context=original.context, query_factory=lambda _: original.query,
            binding=original.binding, ledger=original.ledger, process=original.process,
            generation_origin='original-profile')
    assert build(profile['capture']).observe(state['inspect']['HostConfig']['RestartPolicy'])['generation_verified']
    changed = deepcopy(profile['capture']); changed['process']['start_ticks'] = '999'
    with pytest.raises(TemplateError): build(changed)
