"""Opt-in gate scope registration in the existing coordinator operation ledger."""
from copy import deepcopy
import json

from cleanup_execution import canonical_digest, require, sha
from cleanup_native_scope_proof import NativeScopeProof, capture_birth, read_scope
from cleanup_scope_sources import CONTEXT


def bind_gate_context(record, requested, *, existing):
    """Persist the gate binding in a new fixture intent before any VD creation."""
    if requested is None:
        return
    require(type(requested) is dict and set(requested) == CONTEXT
            and all(type(value) is str and value for value in requested.values())
            and sha(requested['image_build_hold_sha256'])
            and requested['lab_id'] == record['lab'] and requested['host_id'] == record['target']['host'],
            'complete original fixture gate context required')
    if existing:
        require(record.get('gate_context') == requested, 'existing fixture lacks the same original gate context')
    else:
        require(record['phase'] == 'planned', 'gate context must precede workload creation')
        record['gate_context'] = deepcopy(requested)


class NativeScopeRegistration:
    def __init__(self, workload, *, context, definitions, stop_request_id,
                 process=None, scopes=read_scope, capture=capture_birth):
        require(workload.record.get('gate_context') == context
                and context['lab_id'] == workload.record['lab']
                and context['host_id'] == workload.record['target']['host'],
                'fixture original pre-create gate context required')
        require(sha(workload.record.get('container_id')), 'fixture original qualified Docker birth required')
        self.workload, self.context, self.definitions = workload, deepcopy(context), definitions
        self.cid, self.node = workload.record['container_id'], workload.record['node']
        self.stop_key, self.process, self.scopes, self.capture = stop_request_id, process, scopes, capture

    def _saved(self):
        value = self.workload.store.gate_scope_birth(self.context['lab_id'], self.context['gate_id'], self.cid)
        require(value is not None, 'original durable gate scope birth missing')
        birth = value['birth']
        require(birth['context'] == self.context and birth['node_id'] == self.node
                and birth['start_request_id'] == self.workload.start['request_id']
                and birth['stop_request_id'] == self.stop_key and birth['container_id'] == self.cid,
                'original gate scope owner or request changed')
        return value

    def intent(self, action):
        require(action in ('created', 'removed'), 'explicit scope transition required')
        saved = self._saved(); birth = saved['birth']
        start = self.workload.store.get(self.context['lab_id'], birth['start_request_id'], private=True)
        journal = {key: start[key] for key in ('request', 'target', 'journal_id', 'operation_id')}
        return dict(action=action, container_id=self.cid, nonce=birth['nonce'], rows=deepcopy(saved['rows']),
                    journal_sha256=canonical_digest(journal), birth_sha256=canonical_digest(birth))

    def proof(self):
        birth = self._saved()['birth']
        def read(path, limit):
            raw = json.dumps(self._saved()['birth'], sort_keys=True, separators=(',', ':')).encode()
            require(len(raw) <= limit, 'gate scope birth exceeds read bound')
            return raw, []
        reference = {'path': str(self.workload.store.directory / 'operations.sqlite3'),
                     'sha256': canonical_digest(birth)}
        return NativeScopeProof(reference, context=self.context, store=self.workload.store,
            runtime=self.workload.runtime, docker=self.workload.api, definitions=self.definitions,
            process=self.process, scopes=self.scopes, read=read)

    def register(self):
        store = self.workload.store
        with store.executing(self.context['lab_id'], 'gate-scope:' + self.context['gate_id'] + ':' + self.cid):
            saved = store.gate_scope_birth(self.context['lab_id'], self.context['gate_id'], self.cid)
            if saved is None:
                require(self.workload.record['phase'] == 'running', 'running original workload required for first capture')
                candidate = self.capture(context=self.context, node_id=self.node,
                    start_request_id=self.workload.start['request_id'], stop_request_id=self.stop_key,
                    store=store, runtime=self.workload.runtime, docker=self.workload.api,
                    definitions=self.definitions, process=self.process, scopes=self.scopes)
                require(candidate['birth']['container_id'] == self.cid, 'fixture Docker birth changed before registration')
                store.save_gate_scope_birth(self.context['lab_id'], self.context['gate_id'], self.cid, candidate)
            # Includes response-loss recovery: reread and verify, never recapture
            # or overwrite a row that the coordinator has already committed.
            intent = self.intent('created')
            self.proof()(intent, {row['source_id']: row for row in intent['rows']})
            return self._saved()
