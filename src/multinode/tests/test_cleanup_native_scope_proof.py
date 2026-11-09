"""Native scope proof wiring with synthetic runtime/Docker/process IO."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_container_observer import config_digest
from cleanup_execution import canonical_digest
from cleanup_native_scope_proof import NativeScopeProof
from tests.test_cleanup_scope_definitions import definitions


@pytest.fixture
def native_scope(definitions):
    verifier, cid, container, rows, bodies = definitions
    context = dict(gate_id='gate', lab_id='demo', host_id='master', coordinator_id='only',
                   boot_id='boot', window_id='window', image_build_hold_sha256='f' * 64)
    spec = {'kind': 'linux', 'image': 'sha256:' + 'e' * 64, 'container_name': 'fixture-vd'}
    request = dict(schema_version=1, lab_id='demo', node_id='vd', request_id='start',
                   action='start', expected_revision=0, spec=spec)
    target = dict(host='master', socket_path='/synthetic/runtime.sock', container_name=None)
    start = dict(phase='completed', operation_id='c' * 32, journal_id='d' * 32,
                 request=request, target=target, node='vd')
    stop = dict(phase='completed', operation_id='b' * 32, journal_id='d' * 32,
                native_force_requested=0, target=target,
                request={**{k: v for k, v in request.items() if k != 'spec'},
                         'request_id': 'stop', 'action': 'stop', 'expected_revision': 1})
    nonce = '1' * 32
    container.update(Config={'Image': spec['image'], 'Labels': {
        'org.dnlab.runtime.birth': nonce, 'org.dnlab.runtime.creator': start['operation_id']}},
        Image=spec['image'], Mounts=[], Path='python3', Args=['program.py'], RestartCount=0,
        State={'Running': True, 'Status': 'running', 'Pid': 42, 'StartedAt': 'original-start'})
    process_view = {'pid': 42, 'start_ticks': '123', 'namespace': 'original'}
    record = dict(context=context, node_id='vd', start_request_id='start', stop_request_id='stop',
        journal_id=start['journal_id'], container_id=cid, nonce=nonce, generation=1, revision=1,
        creator_operation_id=start['operation_id'], spec_fingerprint=canonical_digest(spec),
        docker=dict(config_sha256=config_digest(container), image_id=spec['image'], pid=42,
                    started_at='original-start', restart_count=0), process_sha256=canonical_digest(process_view),
        definition=dict(rows_sha256=canonical_digest(rows), profile_sha256=verifier.sha256))
    raw = [json.dumps(record).encode()]
    pin = {'path': '/synthetic/scope-birth.json', 'sha256': hashlib.sha256(raw[0]).hexdigest()}
    journal = {key: start[key] for key in ('request', 'target', 'journal_id', 'operation_id')}
    intent = dict(action='created', container_id=cid, nonce=nonce, rows=deepcopy(rows),
                  birth_sha256=canonical_digest(record), journal_sha256=canonical_digest(journal))
    view = dict(lab_id='demo', node_id='vd', journal_id=start['journal_id'], revision=1,
        committed_state='running', container_state='running', container_id=cid, operation=None,
        workload=dict(generation=1, phase='running', container_id=cid, creator_operation_id=start['operation_id'],
                      spec_fingerprint=record['spec_fingerprint'], committed_revision=1))
    receipt = dict(id=stop['operation_id'], lab='demo', node='vd', request_id='stop', phase='completed',
                   shutdown_verified=True, stop_stage='finished', recovery_force=False)
    state = {'container': container, 'view': view, 'scope': {'rows': rows, 'bodies': bodies},
             'process': process_view, 'post_error': None, 'start': start, 'stop': stop, 'receipt': receipt}
    calls = []
    class Store:
        def get(self, lab, key, private=False):
            assert lab == 'demo' and private
            calls.append(('get', key)); return deepcopy(state[key])
    class Bound:
        def inspect_node(self, lab, node):
            calls.append(('runtime-inspect', lab, node)); return deepcopy(state['view'])
        def find_node_request(self, request, verify_content=False):
            assert verify_content and request == state['stop']['request']
            calls.append(('runtime-stop-receipt',)); return deepcopy(state['receipt'])
    class Runtime:
        def bound_to(self, journal_id):
            assert journal_id == record['journal_id']; return Bound()
        def inspect_node(self, *args): raise AssertionError('unbound runtime used')
    class Docker:
        def inspect(self, identity):
            assert identity == cid; calls.append(('GET-inspect', identity)); return deepcopy(state['container'])
    class Process:
        @contextmanager
        def capture(self, pid, identity, copies):
            assert (pid, identity, copies) == (42, cid, {})
            calls.append(('pidfd', pid))
            yield {'process': deepcopy(state['process'])}
            if state['post_error']: raise state['post_error']
    def scopes(identity):
        assert identity == cid; calls.append(('scope-read',)); return deepcopy(state['scope'])
    proof = NativeScopeProof(pin, context=context, store=Store(), runtime=Runtime(), docker=Docker(),
        definitions=verifier, process=Process(), scopes=scopes, read=lambda path, limit: (raw[0], []))
    return proof, intent, state, calls, raw, record


def observed(intent):
    return {row['source_id']: deepcopy(row) for row in intent['rows']}


def test_created_proof_binds_coordinator_runtime_docker_pidfd_and_definition(native_scope):
    proof, intent, state, calls, *_ = native_scope
    result = proof(intent, observed(intent))
    assert result['birth_sha256'] == intent['birth_sha256']
    assert result['definition_profile_sha256'] == proof.definitions.sha256
    assert calls.count(('get', 'start')) == 2 and calls.count(('GET-inspect', intent['container_id'])) == 2
    assert ('pidfd', 42) in calls and ('scope-read',) in calls


@pytest.mark.parametrize('change', ['creator', 'journal', 'target', 'pending-start', 'spec', 'generation',
    'pending-runtime', 'container-id', 'image', 'nonce', 'config', 'pid', 'started', 'restart', 'process', 'scope'])
def test_creation_conflicts_refuse_without_mutations(native_scope, change):
    proof, intent, state, calls, *_ = native_scope
    if change == 'creator': state['start']['operation_id'] = '9' * 32
    elif change == 'journal': state['start']['journal_id'] = '9' * 32
    elif change == 'target': state['start']['target']['host'] = 'foreign'
    elif change == 'pending-start': state['start']['phase'] = 'applying'
    elif change == 'spec': state['start']['request']['spec']['image'] = 'sha256:' + '9' * 64
    elif change == 'generation': state['view']['workload']['generation'] = 2
    elif change == 'pending-runtime': state['view']['operation'] = {'id': 'foreign'}
    elif change == 'container-id': state['container']['Id'] = '9' * 64
    elif change == 'image': state['container']['Image'] = 'sha256:' + '9' * 64
    elif change == 'nonce': state['container']['Config']['Labels']['org.dnlab.runtime.birth'] = '9' * 32
    elif change == 'config': state['container']['Args'].append('foreign')
    elif change == 'pid': state['container']['State']['Pid'] = 43
    elif change == 'started': state['container']['State']['StartedAt'] = 'new'
    elif change == 'restart': state['container']['RestartCount'] = 1
    elif change == 'process': state['process']['start_ticks'] = 'new'
    else: state['scope']['rows'][0]['sha256'] = '9' * 64
    with pytest.raises(ValueError): proof(intent, observed(intent))
    assert all(call[0] in {'get', 'runtime-inspect', 'GET-inspect', 'pidfd', 'scope-read'} for call in calls)


def test_immutable_birth_record_and_pidfd_postcheck_are_required(native_scope):
    proof, intent, state, _, raw, *_ = native_scope
    original = raw[0]; raw[0] += b' '
    with pytest.raises(ValueError, match='record changed'): proof(intent, observed(intent))
    raw[0] = original; state['post_error'] = OSError('synthetic process exited')
    with pytest.raises(OSError): proof(intent, observed(intent))


def test_removed_original_uses_historical_ordinary_stop_and_double_absence(native_scope):
    proof, intent, state, calls, *_ = native_scope
    intent['action'] = 'removed'; state['container'] = None; state['scope'] = {'rows': [], 'bodies': {}}
    # A later generation does not rewrite the old completed shutdown receipt.
    state['view']['workload']['generation'] = 2
    assert proof(intent, {})['action'] == 'removed'
    assert calls.count(('GET-inspect', intent['container_id'])) == 2
    assert calls.count(('runtime-stop-receipt',)) == 2
    assert not any(call[0] in ('pidfd', 'runtime-inspect') for call in calls)


@pytest.mark.parametrize('change', ['pending-stop', 'force', 'wrong-node', 'unverified', 'wrong-receipt',
                                  'scope-present', 'container-present'])
def test_removal_never_accepts_unverified_or_incomplete_cleanup(native_scope, change):
    proof, intent, state, *_ = native_scope
    intent['action'] = 'removed'; original_container = state['container']
    state['container'] = None; state['scope'] = {'rows': [], 'bodies': {}}
    if change == 'pending-stop': state['stop']['phase'] = 'applying'
    elif change == 'force': state['stop']['native_force_requested'] = 1
    elif change == 'wrong-node': state['stop']['request']['node_id'] = 'foreign'
    elif change == 'unverified': state['receipt']['shutdown_verified'] = False
    elif change == 'wrong-receipt': state['receipt']['id'] = '9' * 32
    elif change == 'scope-present': state['scope']['rows'] = deepcopy(intent['rows'])
    else: state['container'] = original_container
    with pytest.raises(ValueError): proof(intent, {})


def test_real_coordinator_read_path_has_no_writes(native_scope, tmp_path):
    from dnlab_multinode.services.runtime_operations import OperationStore
    proof, intent, state, *_ = native_scope
    store = OperationStore(tmp_path / 'coordinator')
    try:
        for key in ('start', 'stop'):
            entry = state[key]
            store.prepare(entry['request'], entry['target'], entry['journal_id'])
            store.observe('demo', key, {'id': entry['operation_id'], 'lab': 'demo', 'node': 'vd',
                                      'request_id': key, 'phase': 'completed'})
        proof.store = store
        count = store.db.total_changes
        assert proof(intent, observed(intent))['action'] == 'created'
        assert store.db.total_changes == count
    finally: store.close()


def test_native_provider_drives_exact_scope_creation_and_removal_projection(native_scope):
    from cleanup_scope_sources import QualifiedScopeSources, ROOT
    proof, intent, state, *_ = native_scope
    parent = {'source_id': ROOT, 'kind': 'directory', 'metadata': [1, 2, 0o40755, 0, 0, 10, 20, 30], 'names': []}
    baseline = {'complete': True, 'candidates': [deepcopy(parent)]}
    current_parent = deepcopy(parent)
    name = 'docker-' + intent['container_id'] + '.scope'
    current_parent['names'] = [name, name + '.d']; current_parent['metadata'][5:] = [100, 200, 300]
    current = {'complete': True, 'candidates': sorted([current_parent, *deepcopy(intent['rows'])], key=lambda row: row['source_id'])}
    qualifier = QualifiedScopeSources(baseline, context=proof.context,
        definition_profile_sha256=proof.definitions.sha256, transitions=lambda: [intent], verify=proof)
    assert qualifier(current) == baseline
    intent['action'] = 'removed'; state['container'] = None; state['scope'] = {'rows': [], 'bodies': {}}
    removal = QualifiedScopeSources(current, context=proof.context,
        definition_profile_sha256=proof.definitions.sha256, transitions=lambda: [intent], verify=proof)
    assert removal(baseline) == current


def test_scope_reader_observes_only_synthetic_tree_and_verified_absence(tmp_path, monkeypatch):
    import cleanup_native_scope_proof as module
    monkeypatch.setattr(module, 'ROOT', str(tmp_path))
    cid = 'a' * 64
    scope = tmp_path / ('docker-' + cid + '.scope')
    scope.write_bytes(b'opaque unit data')
    directory = tmp_path / (scope.name + '.d'); directory.mkdir()
    for name in ('50-DeviceAllow.conf', '50-DevicePolicy.conf'):
        (directory / name).write_bytes(b'opaque drop-in data')
    observed = module.read_scope(cid)
    assert len(observed['rows']) == 4 and len(observed['bodies']) == 3
    for path in directory.iterdir(): path.unlink()
    directory.rmdir(); scope.unlink()
    assert module.read_scope(cid) == {'rows': [], 'bodies': {}}
