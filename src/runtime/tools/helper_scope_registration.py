"""Immutable helper scope births in the existing coordinator operation ledger."""
from copy import deepcopy

from cleanup_execution import canonical_digest, require
from cleanup_helper_scope_proof import HelperScopeProof, capture_helper_birth
from cleanup_native_scope_proof import read_scope


class HelperScopeRegistration:
    def __init__(self, store, owner, origin, *, definitions, docker,
                 process=None, scopes=read_scope, capture=capture_helper_birth):
        self.store, self.owner, self.origin = store, owner, origin
        self.context, self.cid = deepcopy(owner.context), owner.expected['container_id']
        self.definitions, self.docker = definitions, docker
        self.process, self.scopes, self.capture = process, scopes, capture

    def _saved(self):
        value = self.store.gate_scope_birth(self.context['lab_id'], self.context['gate_id'], self.cid)
        require(value is not None, 'original durable helper scope birth missing')
        birth = value['birth']
        require(birth['context'] == self.context and birth['role'] == self.owner.role
                and birth['container_id'] == self.cid and birth['owner'] == self.owner.expected,
                'original helper scope owner changed')
        return value

    def intent(self, action):
        require(action in ('created', 'removed'), 'explicit helper scope transition required')
        value = self._saved(); birth = value['birth']
        return dict(action=action, container_id=self.cid, nonce=birth['nonce'], rows=deepcopy(value['rows']),
                    journal_sha256=birth['origin_sha256'], birth_sha256=canonical_digest(birth))

    def proof(self):
        return HelperScopeProof(self.owner, self.origin, definitions=self.definitions,
            docker=self.docker, read_record=self._saved, process=self.process, scopes=self.scopes)

    def register(self):
        with self.store.executing(self.context['lab_id'], 'gate-scope:' + self.context['gate_id'] + ':' + self.cid):
            saved = self.store.gate_scope_birth(self.context['lab_id'], self.context['gate_id'], self.cid)
            if saved is None:
                candidate = self.capture(self.owner, self.origin, definitions=self.definitions,
                    docker=self.docker, process=self.process, scopes=self.scopes)
                require(candidate['birth']['container_id'] == self.cid
                        and candidate['birth']['context'] == self.context
                        and candidate['birth']['owner'] == self.owner.expected,
                        'helper birth changed before registration')
                self.store.save_gate_scope_birth(self.context['lab_id'], self.context['gate_id'], self.cid, candidate)
            # A committed row is always reused, including after a lost response.
            # Conflict must never trigger a new capture of the current resource.
            intent = self.intent('created')
            self.proof()(intent, {row['source_id']: row for row in intent['rows']})
            return self._saved()
