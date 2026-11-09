"""Scope proofs for original gate helpers, reusing their ownership adapters.

No helper lifecycle operation is invoked here. Origins must authenticate the
original coordinator/fixture intent and birth receipt, not current labels alone.
"""
from copy import deepcopy
import hashlib
import json

from cleanup_container_observer import LinuxProcess, config_digest
from cleanup_execution import canonical_digest, require, sha, _pairs
from cleanup_census_readers import read_regular
from cleanup_native_scope_proof import read_scope


def pinned_json(reference):
    raw, _ = read_regular(reference['path'], 2 * 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == reference['sha256'], 'helper origin receipt changed')
    return json.loads(raw, object_pairs_hook=_pairs)


class ManagementHelperOrigin:
    """Read original DNS/jumphost config and nonce/ID from the existing barrier."""
    def __init__(self, store, management_key, owner):
        require(owner.role in ('dns', 'jumphost'), 'management helper origin required')
        self.store, self.key, self.owner = store, management_key, owner

    def __call__(self):
        from dnlab_multinode.services.management_barrier import get
        value = get(self.store, self.owner.context['lab_id'])
        require(value is not None and value['request_id'] == self.key, 'original management service operation missing')
        bundle = value['plan']['services']; progress = value.get('services') or {}
        receipt = progress.get('receipt') or {}; role = self.owner.role
        config = bundle['dns']['config'] if role == 'dns' else bundle['jumphost']
        require(bundle['fingerprint'] == canonical_digest({k: v for k, v in bundle.items() if k != 'fingerprint'})
                and progress.get('intent_fingerprint') == bundle['fingerprint']
                and receipt.get('phase') == 'materialized' and receipt.get('intent_fingerprint') == bundle['fingerprint']
                and bundle.get('host') == self.owner.context['host_id']
                and canonical_digest(config) == self.owner.expected['config_sha256']
                and receipt.get(role) == {key: self.owner.expected[key] for key in ('container_id', 'nonce')},
                'original management helper config or birth receipt differs')
        return {'parent': {k: value[k] for k in ('request_id', 'barrier_id', 'generation', 'plan_fingerprint')},
                'service_intent_sha256': bundle['fingerprint'], 'role': role,
                'birth': deepcopy(receipt[role])}


class RelayHelperOrigin:
    """Pinned pre-create fixture intent plus original relay birth acknowledgement."""
    def __init__(self, intent_reference, birth_reference, owner, *, read=pinned_json):
        require(owner.role == 'relay', 'relay origin required')
        self.intent, self.birth, self.owner, self.read = deepcopy(intent_reference), deepcopy(birth_reference), owner, read

    def __call__(self):
        intent, birth = self.read(self.intent), self.read(self.birth)
        require(intent.get('gate_context') == self.owner.context and intent.get('relay_attempted') is True
                and canonical_digest(intent['config']) == self.owner.expected['config_sha256']
                and birth['config'] == intent['config'] and birth.get('phase') == 'active'
                and birth.get('container_id') == self.owner.expected['container_id']
                and birth.get('nonce') == self.owner.expected['nonce']
                and birth.get('image', {}).get('Id') == self.owner.expected['image_id'],
                'original relay gate intent or birth receipt differs')
        return {'intent_sha256': self.intent['sha256'], 'birth_receipt_sha256': self.birth['sha256'],
                'role': 'relay', 'birth': {key: birth[key] for key in ('container_id', 'nonce')}}


def docker_birth(container):
    state = container['State']
    require(state.get('Running') is True and state.get('Status') == 'running'
            and type(state.get('Pid')) is int and state['Pid'] > 0,
            'original helper running Docker process required')
    return dict(config_sha256=config_digest(container), image_id=container['Image'],
                pid=state['Pid'], started_at=state['StartedAt'], restart_count=container['RestartCount'])


def capture_helper_birth(owner, origin, *, definitions, docker, process=None, scopes=read_scope):
    original = origin()
    value = owner.observe('created'); cid = owner.expected['container_id']
    container = value['container']; generation = docker_birth(container)
    process = LinuxProcess() if process is None else process
    with process.capture(generation['pid'], cid, {}) as observed:
        current = scopes(cid)
        definition = definitions.verify(cid, container, current['rows'], current['bodies'])
        birth = dict(context=deepcopy(owner.context), role=owner.role, owner=deepcopy(owner.expected),
            container_id=cid, nonce=owner.expected['nonce'], origin_sha256=canonical_digest(original),
            docker=generation, process_sha256=canonical_digest(observed['process']),
            definition=dict(profile_sha256=definition['definition_profile_sha256'], rows_sha256=definition['rows_sha256']))
    payload = {'birth': birth, 'rows': deepcopy(current['rows'])}
    intent = dict(action='created', container_id=cid, nonce=birth['nonce'], rows=deepcopy(current['rows']),
                  birth_sha256=canonical_digest(birth), journal_sha256=canonical_digest(original))
    HelperScopeProof(owner, origin, definitions=definitions, docker=docker, read_record=lambda: deepcopy(payload),
        process=process, scopes=scopes)(intent, {row['source_id']: row for row in current['rows']})
    return payload


class HelperScopeProof:
    def __init__(self, owner, origin, *, definitions, docker, read_record, process=None, scopes=read_scope):
        self.owner, self.origin, self.definitions, self.docker = owner, origin, definitions, docker
        self.record, self.scopes = read_record, scopes
        self.process = LinuxProcess() if process is None else process

    def _container(self, birth):
        value = self.owner.observe('created')['container']
        actual = self.docker.inspect(birth['container_id'])
        require(type(actual) is dict and actual.get('Id') == birth['container_id']
                and docker_birth(actual) == birth['docker'] and docker_birth(value) == birth['docker'],
                'original helper Docker configuration or process changed')
        return value

    def __call__(self, intent, observed_rows):
        record = deepcopy(self.record()); birth = record['birth']; original = self.origin()
        require(set(record) == {'birth', 'rows'} and set(birth) == {
            'context', 'role', 'owner', 'container_id', 'nonce', 'origin_sha256', 'docker', 'process_sha256', 'definition'}
                and birth['context'] == self.owner.context and birth['role'] == self.owner.role
                and birth['owner'] == self.owner.expected and birth['container_id'] == self.owner.expected['container_id']
                and birth['nonce'] == self.owner.expected['nonce']
                and canonical_digest(original) == birth['origin_sha256'] == intent['journal_sha256']
                and canonical_digest(birth) == intent['birth_sha256']
                and intent['container_id'] == birth['container_id'] and intent['nonce'] == birth['nonce']
                and intent['rows'] == record['rows'] and canonical_digest(record['rows']) == birth['definition']['rows_sha256']
                and birth['definition']['profile_sha256'] == self.definitions.sha256,
                'helper scope birth or original gate receipt differs')
        cid = birth['container_id']
        if intent['action'] == 'created':
            container = self._container(birth)
            with self.process.capture(birth['docker']['pid'], cid, {}) as observed:
                require(canonical_digest(observed['process']) == birth['process_sha256'], 'helper process or namespace changed')
                current = self.scopes(cid)
                require(current['rows'] == record['rows']
                        and {row['source_id']: row for row in current['rows']} == observed_rows,
                        'helper scope rows changed')
                self.definitions.verify(cid, container, current['rows'], current['bodies'])
                self._container(birth)
        elif intent['action'] == 'removed':
            self.owner.observe('removed')
            require(not observed_rows and self.docker.inspect(cid) is None, 'original helper Docker generation remains')
            require(self.scopes(cid) == {'rows': [], 'bodies': {}}, 'original helper scope remains')
            self.owner.observe('removed')
            require(self.docker.inspect(cid) is None, 'helper Docker absence changed')
        else:
            raise ValueError('explicit helper scope transition required')
        require(self.origin() == original and self.record() == record, 'original helper source changed during observation')
        return {'context': deepcopy(self.owner.context), **{key: intent[key] for key in (
            'action', 'container_id', 'nonce', 'journal_sha256', 'birth_sha256')},
            'definition_profile_sha256': self.definitions.sha256, 'rows_sha256': canonical_digest(record['rows'])}
