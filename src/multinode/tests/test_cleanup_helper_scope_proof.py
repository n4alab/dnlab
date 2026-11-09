"""Helper proof composition with existing simulated workers and private data."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_execution import canonical_digest
from cleanup_helper_scope_proof import HelperScopeProof, ManagementHelperOrigin, RelayHelperOrigin, capture_helper_birth
from cleanup_scope_definitions import ScopeDefinitions, CONFIG_FIELDS, TOKEN, ROOT
from tests.test_cleanup_helper_scope_owner import helper, dns_world, jump_world, relay


@pytest.fixture
def proof_case(helper):
    owner, worker, backend, record, cleanup = helper
    cid = record['container_id']
    container = next(value for value in backend.values.values() if value['Id'] == cid)
    for key in CONFIG_FIELDS:
        if key not in container['HostConfig']:
            container['HostConfig'][key] = '' if key == 'CgroupParent' else 'private' if key == 'CgroupnsMode' else None
    container.setdefault('Mounts', []); container.setdefault('Path', '/synthetic/entrypoint')
    container.setdefault('Args', []); container.setdefault('RestartCount', 0)
    container['State'].setdefault('Status', 'running'); container['State'].setdefault('Pid', 42)
    container['State'].setdefault('StartedAt', 'synthetic-original-start')
    templates = {'': '[Unit]\nDescription=container ' + TOKEN + '\n[Scope]\nDelegate=yes\n',
                 '.d/50-DeviceAllow.conf': '[Scope]\nDeviceAllow=\n',
                 '.d/50-DevicePolicy.conf': '[Scope]\nDevicePolicy=strict\n'}
    profile = {'configuration': {key: deepcopy(container['HostConfig'][key]) for key in CONFIG_FIELDS},
        'directory': {'mode': 0o755, 'uid': 0, 'gid': 0},
        'files': {key: {'template': value, 'mode': 0o644, 'uid': 0, 'gid': 0} for key, value in templates.items()}}
    definitions = ScopeDefinitions([profile])
    scope = ROOT + '/docker-' + cid + '.scope'; rows = []; bodies = {}
    for suffix, template in templates.items():
        body = template.replace(TOKEN, cid).encode(); bodies[scope + suffix] = body
        rows.append({'source_id': scope + suffix, 'kind': 'file', 'sha256': hashlib.sha256(body).hexdigest(),
                     'metadata': [1, 2, stat.S_IFREG | 0o644, 0, 0, len(body), 3, 4]})
    rows.append({'source_id': scope + '.d', 'kind': 'directory', 'metadata': [1, 5, stat.S_IFDIR | 0o755, 0, 0, 10, 20, 30],
                 'names': ['50-DeviceAllow.conf', '50-DevicePolicy.conf']})
    state = {'scope': {'rows': rows, 'bodies': bodies}, 'process': {'pid': container['State']['Pid'], 'start_ticks': 'original'},
             'origin': {'original-service-receipt': owner.expected}}
    calls = []
    class Docker:
        def inspect(self, identity):
            assert identity == cid; calls.append(('GET', identity))
            return next((deepcopy(v) for v in backend.values.values() if v['Id'] == identity), None)
    class Process:
        @contextmanager
        def capture(self, pid, identity, copies):
            assert pid == container['State']['Pid'] and identity == cid and copies == {}
            calls.append(('pidfd', pid)); yield {'process': deepcopy(state['process'])}
    def scopes(identity):
        assert identity == cid; calls.append(('scope-read',)); return deepcopy(state['scope'])
    options = dict(definitions=definitions, docker=Docker(), process=Process(), scopes=scopes)
    origin = lambda: deepcopy(state['origin'])
    payload = capture_helper_birth(owner, origin, **options)
    proof = HelperScopeProof(owner, origin, read_record=lambda: deepcopy(payload), **options)
    intent = dict(action='created', container_id=cid, nonce=record['nonce'], rows=deepcopy(rows),
                  birth_sha256=canonical_digest(payload['birth']), journal_sha256=canonical_digest(origin()))
    return owner, worker, backend, cleanup, state, payload, proof, intent, calls


def test_original_helpers_have_created_and_removed_scope_proofs_without_mutation(proof_case, monkeypatch):
    owner, worker, backend, cleanup, state, payload, proof, intent, calls = proof_case
    before = deepcopy(backend.values); journal = worker.path.read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(worker, 'save', lambda *args: pytest.fail('proof attempted a journal write'))
        receipt = proof(intent, {row['source_id']: row for row in intent['rows']})
    assert receipt['definition_profile_sha256'] == proof.definitions.sha256
    assert backend.values == before and worker.path.read_bytes() == journal
    cleanup(); state['scope'] = {'rows': [], 'bodies': {}}; intent['action'] = 'removed'
    journal = worker.path.read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(worker, 'save', lambda *args: pytest.fail('proof attempted a journal write'))
        assert proof(intent, {})['action'] == 'removed'
    assert worker.path.read_bytes() == journal and backend.values == {}


@pytest.mark.parametrize('fault', ['origin', 'docker-start', 'process', 'definition', 'saved-birth'])
def test_changed_proof_inputs_are_never_adopted(proof_case, fault):
    owner, _, backend, _, state, payload, proof, intent, _ = proof_case
    if fault == 'origin': state['origin']['foreign'] = True
    elif fault == 'docker-start': next(iter(backend.values.values()))['State']['StartedAt'] = 'foreign'
    elif fault == 'process': state['process']['start_ticks'] = 'foreign'
    elif fault == 'definition': state['scope']['rows'][0]['sha256'] = '9' * 64
    else: payload['birth']['nonce'] = '9' * 32
    before = deepcopy(backend.values)
    with pytest.raises((ValueError, RuntimeError)):
        proof(intent, {row['source_id']: row for row in intent['rows']})
    assert backend.values == before


@pytest.mark.parametrize('helper', ['dns', 'jumphost'], indirect=True)
def test_management_origin_reuses_original_coordinator_receipt(helper, tmp_path):
    from dnlab_multinode.services.runtime_operations import OperationStore
    from dnlab_multinode.services import management_barrier as barrier
    owner, worker, _, record, _ = helper
    bundle = {'host': 'master', owner.role: {'config': record['config']} if owner.role == 'dns' else record['config']}
    bundle['fingerprint'] = canonical_digest(bundle)
    plan = {'services': bundle}
    row = {'request_id': 'management', 'barrier_id': '1' * 32, 'generation': 1,
        'plan': plan, 'plan_fingerprint': canonical_digest(plan),
        'services': {'intent_fingerprint': bundle['fingerprint'],
                     'receipt': {'phase': 'materialized', 'intent_fingerprint': bundle['fingerprint'],
                                 owner.role: {k: record[k] for k in ('container_id', 'nonce')}}}}
    store = OperationStore(tmp_path / 'coordinator')
    try:
        with store.transaction(): barrier.put(store, worker.lab, row)
        origin = ManagementHelperOrigin(store, 'management', owner)
        before = store.db.total_changes
        assert origin()['birth']['container_id'] == record['container_id']
        assert store.db.total_changes == before
        row['services']['receipt'][owner.role]['nonce'] = '9' * 32
        with store.transaction(): barrier.put(store, worker.lab, row)
        with pytest.raises(ValueError, match='receipt differs'): origin()
    finally: store.close()


@pytest.mark.parametrize('helper', ['relay'], indirect=True)
def test_relay_origin_requires_pinned_precreate_gate_intent_and_birth(helper, tmp_path):
    owner, _, _, record, _ = helper
    def saved(name, value):
        path = tmp_path / name; raw = json.dumps(value).encode(); path.write_bytes(raw)
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
    intent = {'gate_context': owner.context, 'relay_attempted': True, 'config': record['config']}
    plan = saved('intent.json', intent); birth = saved('birth.json', record)
    origin = RelayHelperOrigin(plan, birth, owner)
    assert origin()['birth']['nonce'] == record['nonce']
    Path(plan['path']).write_bytes(b'{}')
    with pytest.raises(ValueError, match='receipt changed'): origin()
