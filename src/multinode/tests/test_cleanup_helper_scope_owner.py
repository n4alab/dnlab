"""Existing helper guards on private files and stateful simulated Docker."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from tests.test_dns_host import world as dns_world, config as dns_config
from tests.test_jumphost_host import world as jump_world
from tests.test_relay_host import relay
from cleanup_helper_scope_owner import HelperScopeOwner, birth_projection


@pytest.fixture(params=['dns', 'jumphost', 'relay'])
def helper(request):
    role = request.param
    if role == 'relay':
        worker, backend, config = request.getfixturevalue('relay')
        worker.host_context = lambda: {'boot_id': 'boot', 'device': 1, 'inode': 2}
        record = worker.control('ensure', config)
        def cleanup(): return worker.control('delete', generation=config['generation'])
    else:
        backend, worker = request.getfixturevalue('dns_world' if role == 'dns' else 'jump_world')
        config = dns_config() if role == 'dns' else backend.cfg
        record = worker.operate('ensure', config, '192.0.2.3 R1\n') if role == 'dns' else worker.operate('ensure', config)
        def cleanup(): return worker.operate('delete')
    context = dict(gate_id='gate', lab_id=worker.lab, host_id='master', coordinator_id='only',
                   boot_id='boot', window_id='window', image_build_hold_sha256='f' * 64)
    owner = HelperScopeOwner(worker, role=role, context=context, expected=birth_projection(role, record))
    return owner, worker, backend, record, cleanup


def files(worker):
    return {str(path): path.read_bytes() for path in worker.directory.rglob('*') if path.is_file()}


def test_active_and_cleaned_observations_reuse_guards_without_writes(helper, monkeypatch):
    owner, worker, backend, record, cleanup = helper
    def forbidden(*args, **kwargs): raise AssertionError('observer attempted a journal write')
    before = files(worker); resources = deepcopy(backend.values)
    with monkeypatch.context() as patch:
        patch.setattr(worker, 'save', forbidden)
        first = owner.observe('created')
        second = owner.observe('created')
    assert first == second and first['container']['Id'] == record['container_id']
    assert files(worker) == before and backend.values == resources
    cleanup()
    before = files(worker); resources = deepcopy(backend.values)
    with monkeypatch.context() as patch:
        patch.setattr(worker, 'save', forbidden)
        assert owner.observe('removed') == {'birth': owner.expected, 'container': None}
    assert files(worker) == before and backend.values == resources


@pytest.mark.parametrize('fault', ['container', 'nonce', 'configuration', 'pending'])
def test_changed_or_pending_helper_is_not_adopted_or_recovered(helper, fault):
    owner, worker, backend, record, _ = helper
    value = json.loads(worker.path.read_text())
    if fault == 'container': value['container_id'] = '9' * 64
    elif fault == 'nonce': value['nonce'] = '9' * 32
    elif fault == 'configuration': value['config']['generation'] = '9' * 32
    else: value['phase'] = 'creating'
    worker.path.write_text(json.dumps(value))
    before = files(worker); resources = deepcopy(backend.values)
    with pytest.raises((ValueError, RuntimeError)): owner.observe('created')
    assert files(worker) == before and backend.values == resources


def test_active_record_cannot_qualify_removed_scope(helper):
    owner, *_ = helper
    with pytest.raises(ValueError, match='cleanup pending'): owner.observe('removed')
