"""Read-only scope proofs for coordinator-owned native Linux workloads.

The caller supplies an already-open coordinator, bound runtime client and a
pinned durable birth record captured by the gate's original creation path.
This provider never creates a ledger, adopts a name, writes a record or drives
an operation. Helper-service births need their own existing ownership adapters.
"""
from copy import deepcopy
import hashlib
import json

from cleanup_container_observer import LinuxProcess, config_digest
from cleanup_census_readers import read_regular, scheduled_sources
from cleanup_execution import absolute, canonical_digest, require, sha, _pairs
from cleanup_scope_sources import CONTEXT, ROOT


def read_scope(container_id):
    require(sha(container_id), 'full original scope container ID required')
    scope = ROOT + '/docker-' + container_id + '.scope'
    before = scheduled_sources([scope, scope + '.d'])
    rows = [row for row in before['candidates'] if row['kind'] != 'absent']
    bodies = {}
    for row in rows:
        if row['kind'] == 'file':
            raw, meta = read_regular(row['source_id'], 65536)
            require(meta == row['metadata'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                    'scope file changed during body read')
            bodies[row['source_id']] = raw
    require(before == scheduled_sources([scope, scope + '.d']), 'scope changed during observation')
    return {'rows': rows, 'bodies': bodies}


def capture_birth(*, context, node_id, start_request_id, stop_request_id,
                  store, runtime, docker, definitions, process=None, scopes=read_scope):
    """Acquire a candidate from an existing completed start, without writing.

    The gate must durably save the returned record in its original fixture
    journal before using it for admission. This is initial acquisition only;
    a retry with a saved record must use NativeScopeProof, never recapture it.
    """
    start = store.get(context['lab_id'], start_request_id, private=True)
    request = start['request']
    require(start['phase'] == 'completed' and start['target']['host'] == context['host_id']
            and request['lab_id'] == context['lab_id'] and request['node_id'] == node_id
            and request['request_id'] == start_request_id and request['action'] == 'start'
            and request['spec']['kind'] == 'linux', 'original completed native start required before capture')
    view = runtime.bound_to(start['journal_id']).inspect_node(context['lab_id'], node_id)
    cid = view.get('container_id')
    birth = view.get('workload') or {}
    require(sha(cid) and view.get('operation') is None and view.get('journal_id') == start['journal_id']
            and view.get('lab_id') == context['lab_id'] and view.get('node_id') == node_id
            and view.get('committed_state') == 'running' and view.get('container_state') == 'running'
            and view.get('revision') == request['expected_revision'] + 1
            and birth.get('phase') == 'running' and birth.get('container_id') == cid
            and birth.get('creator_operation_id') == start['operation_id']
            and birth.get('spec_fingerprint') == canonical_digest(request['spec']),
            'existing qualified native Docker birth required')
    container = docker.inspect(cid)
    require(type(container) is dict and container.get('Id') == cid, 'original native Docker birth missing')
    state = container['State']
    require(state.get('Running') is True and state.get('Status') == 'running', 'running native birth required')
    process = LinuxProcess() if process is None else process
    with process.capture(state['Pid'], cid, {}) as captured:
        evidence = scopes(cid)
        definition = definitions.verify(cid, container, evidence['rows'], evidence['bodies'])
        record = dict(context=deepcopy(context), node_id=node_id, start_request_id=start_request_id,
            stop_request_id=stop_request_id, journal_id=start['journal_id'], container_id=cid,
            nonce=container['Config']['Labels'].get('org.dnlab.runtime.birth'),
            generation=view['workload']['generation'], revision=start['request']['expected_revision'] + 1,
            creator_operation_id=start['operation_id'], spec_fingerprint=canonical_digest(start['request']['spec']),
            docker=dict(config_sha256=config_digest(container), image_id=container['Image'],
                        pid=state['Pid'], started_at=state['StartedAt'], restart_count=container['RestartCount']),
            process_sha256=canonical_digest(captured['process']),
            definition=dict(rows_sha256=definition['rows_sha256'], profile_sha256=definition['definition_profile_sha256']))
    # Reuse the complete proof checks on this not-yet-persisted candidate.
    # No receipt escapes this acquisition path; the caller still must save it.
    raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
    reference = {'path': '/candidate/native-scope-birth', 'sha256': hashlib.sha256(raw).hexdigest()}
    proof = NativeScopeProof(reference, context=context, store=store, runtime=runtime, docker=docker,
        definitions=definitions, process=process, scopes=scopes, read=lambda *_: (raw, []))
    journal = {key: start[key] for key in ('request', 'target', 'journal_id', 'operation_id')}
    intent = dict(action='created', container_id=cid, nonce=record['nonce'], rows=deepcopy(evidence['rows']),
                  journal_sha256=canonical_digest(journal), birth_sha256=canonical_digest(record))
    proof(intent, {row['source_id']: row for row in evidence['rows']})
    return {'birth': record, 'rows': deepcopy(evidence['rows'])}


class NativeScopeProof:
    def __init__(self, reference, *, context, store, runtime, docker, definitions,
                 process=None, scopes=read_scope, read=read_regular):
        require(type(reference) is dict and set(reference) == {'path', 'sha256'}
                and absolute(reference['path'])
                and sha(reference['sha256']), 'pinned original native scope record required')
        require(type(context) is dict and set(context) == CONTEXT
                and all(type(value) is str and value for value in context.values())
                and sha(context['image_build_hold_sha256']),
                'complete original scope gate context required')
        self.reference, self.context = deepcopy(reference), deepcopy(context)
        self.store, self.runtime, self.docker, self.definitions = store, runtime, docker, definitions
        self.process = LinuxProcess() if process is None else process
        self.scopes, self.read = scopes, read

    def _record(self):
        raw, _ = self.read(self.reference['path'], 2 * 1024 * 1024)
        require(hashlib.sha256(raw).hexdigest() == self.reference['sha256'], 'native scope birth record changed')
        record = json.loads(raw, object_pairs_hook=_pairs)
        require(type(record) is dict and set(record) == {
            'context', 'node_id', 'start_request_id', 'stop_request_id', 'journal_id',
            'container_id', 'nonce', 'generation', 'revision', 'spec_fingerprint',
            'creator_operation_id', 'docker', 'process_sha256', 'definition'},
            'complete original native scope birth required')
        require(record['context'] == self.context and sha(record['container_id'])
                and sha(record['spec_fingerprint']) and sha(record['process_sha256'])
                and all(type(record[key]) is int and record[key] > 0 for key in ('generation', 'revision')),
                'native scope gate, generation or spec differs')
        require(type(record['docker']) is dict and set(record['docker']) == {
            'config_sha256', 'image_id', 'pid', 'started_at', 'restart_count'}, 'original Docker process snapshot required')
        require(sha(record['docker']['config_sha256']) and type(record['docker']['pid']) is int
                and record['docker']['pid'] > 0 and type(record['docker']['started_at']) is str
                and record['docker']['started_at'] and type(record['docker']['restart_count']) is int
                and record['docker']['restart_count'] >= 0 and type(record['definition']) is dict
                and set(record['definition']) == {'rows_sha256', 'profile_sha256'}
                and all(sha(value) for value in record['definition'].values()),
                'original scope process and definition fingerprints required')
        return record

    def _start(self, record):
        lab = self.context['lab_id']
        entry = self.store.get(lab, record['start_request_id'], private=True)
        request = entry['request']
        require(entry['phase'] == 'completed' and entry['operation_id'] == record['creator_operation_id']
                and entry['journal_id'] == record['journal_id'] and entry['target']['host'] == self.context['host_id']
                and request['lab_id'] == lab and request['node_id'] == record['node_id']
                and request['request_id'] == record['start_request_id'] and request['action'] == 'start'
                and request['spec']['kind'] == 'linux' and canonical_digest(request['spec']) == record['spec_fingerprint']
                and request['expected_revision'] + 1 == record['revision'],
                'original completed native start differs')
        return entry

    def _running(self, record):
        view = self.runtime.bound_to(record['journal_id']).inspect_node(self.context['lab_id'], record['node_id'])
        birth = view.get('workload') or {}
        require(view.get('journal_id') == record['journal_id'] and view.get('operation') is None
                and view.get('lab_id') == self.context['lab_id'] and view.get('node_id') == record['node_id']
                and view.get('revision') == record['revision'] and view.get('committed_state') == 'running'
                and view.get('container_state') == 'running' and view.get('container_id') == record['container_id']
                and birth.get('phase') == 'running' and birth.get('generation') == record['generation']
                and birth.get('container_id') == record['container_id']
                and birth.get('creator_operation_id') == record['creator_operation_id']
                and birth.get('spec_fingerprint') == record['spec_fingerprint']
                and birth.get('committed_revision') == record['revision'],
                'native workload birth or current state differs')
        return view

    def _container(self, record):
        value = self.docker.inspect(record['container_id'])
        require(type(value) is dict and value.get('Id') == record['container_id']
                and value.get('Image') == record['docker']['image_id']
                and config_digest(value) == record['docker']['config_sha256'],
                'original native Docker identity or configuration differs')
        state = value['State']
        require(state.get('Running') is True and state.get('Status') == 'running'
                and state.get('Pid') == record['docker']['pid']
                and state.get('StartedAt') == record['docker']['started_at']
                and value.get('RestartCount') == record['docker']['restart_count'],
                'original native Docker process changed')
        labels = value['Config'].get('Labels') or {}
        require(labels.get('org.dnlab.runtime.birth') == record['nonce']
                and labels.get('org.dnlab.runtime.creator') == record['creator_operation_id'],
                'native Docker birth nonce or creator differs')
        return value

    def _stopped(self, record, start):
        entry = self.store.get(self.context['lab_id'], record['stop_request_id'], private=True)
        request = entry['request']
        require(entry['phase'] == 'completed' and entry['target'] == start['target']
                and entry['journal_id'] == record['journal_id'] and not entry['native_force_requested']
                and request['action'] == 'stop' and request['node_id'] == record['node_id']
                and request['request_id'] == record['stop_request_id']
                and request['lab_id'] == self.context['lab_id'] and request['expected_revision'] == record['revision'],
                'original ordinary native stop not completed')
        receipt = self.runtime.bound_to(record['journal_id']).find_node_request(request, verify_content=True)
        require(type(receipt) is dict and receipt.get('id') == entry['operation_id']
                and receipt.get('lab') == self.context['lab_id'] and receipt.get('node') == record['node_id']
                and receipt.get('request_id') == record['stop_request_id']
                and receipt.get('phase') == 'completed' and receipt.get('shutdown_verified') is True
                and receipt.get('stop_stage') == 'finished' and receipt.get('recovery_force') is False,
                'original verified native shutdown receipt required')
        return entry, receipt

    def __call__(self, intent, observed_rows):
        record = self._record()
        start = self._start(record)
        journal = {key: start[key] for key in ('request', 'target', 'journal_id', 'operation_id')}
        require(intent['container_id'] == record['container_id'] and intent['nonce'] == record['nonce']
                and intent['birth_sha256'] == canonical_digest(record)
                and intent['journal_sha256'] == canonical_digest(journal)
                and canonical_digest(intent['rows']) == record['definition']['rows_sha256']
                and record['definition']['profile_sha256'] == self.definitions.sha256,
                'scope intent differs from original native birth and journal')
        if intent['action'] == 'created':
            view = self._running(record)
            container = self._container(record)
            with self.process.capture(record['docker']['pid'], record['container_id'], {}) as process:
                require(canonical_digest(process['process']) == record['process_sha256'],
                        'native scope process or namespace differs')
                evidence = self.scopes(record['container_id'])
                require(evidence['rows'] == intent['rows']
                        and {row['source_id']: row for row in evidence['rows']} == observed_rows,
                        'current native scope rows differ')
                self.definitions.verify(record['container_id'], container, evidence['rows'], evidence['bodies'])
                self._container(record)
                require(self._running(record) == view,
                        'native scope generation changed during observation')
        elif intent['action'] == 'removed':
            stop = self._stopped(record, start)
            require(not observed_rows and self.docker.inspect(record['container_id']) is None,
                    'original native Docker generation remains present')
            evidence = self.scopes(record['container_id'])
            require(evidence == {'rows': [], 'bodies': {}}, 'original native scope remains present')
            require(self.docker.inspect(record['container_id']) is None and self._stopped(record, start) == stop,
                    'native removal proof changed during observation')
        else:
            raise ValueError('explicit native scope transition required')
        require(self._start(record) == start and self._record() == record,
                'native original operation or birth changed during observation')
        return {'context': deepcopy(self.context), **{key: intent[key] for key in (
            'action', 'container_id', 'nonce', 'journal_sha256', 'birth_sha256')},
            'definition_profile_sha256': self.definitions.sha256,
            'rows_sha256': canonical_digest(intent['rows'])}
