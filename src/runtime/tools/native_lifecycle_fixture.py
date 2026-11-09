"""Fixture-only public lifecycle journal preserving every original VD birth.

This helper never creates or deletes containers itself. Public lifecycle owns
restart, publication and shutdown; uncertain steps retain their original key.
"""
from copy import deepcopy
import json
from pathlib import Path

from management_service_diagnostics import private_json
from dnlab_multinode.services import native_public as native, state as states
from dnlab_multinode.services.runtime_cleanup import operation_directory


class LifecycleWorkload:
    def __init__(self, path, controller, node, runtime, store, docker):
        self.path = Path(path)
        self.controller, self.node = controller, node
        self.runtime, self.store, self.docker = runtime, store, docker
        self.lab = controller.state.lab_name
        if store.directory != operation_directory(controller.state_dir):
            raise RuntimeError('fixture requires canonical public lifecycle ledger')
        owner = {'lab': self.lab, 'node': node, 'ledger': str(store.directory)}
        if self.path.exists():
            self.record = json.loads(self.path.read_text())
            if self.record.get('owner') != owner:
                raise RuntimeError('fixture original lifecycle owner differs')
        else:
            proof = self.observe('running')
            self.record = {'owner': owner, 'births': [proof], 'steps': [],
                           'cleanup_verified': False}
            self.save()

    def save(self):
        private_json(self.path, self.record)

    def observe(self, wanted):
        with self.store.executing(self.lab, 'public-lifecycle'):
            state = states.load_state(self.lab, self.controller.state_dir)
            if state is None:
                raise RuntimeError('fixture original deployment state missing')
            view, original = native.inspect_owned(self.store, state, self.node, self.runtime)
            binding = state.node_runtime[self.node].runtime_binding
            if (view['operation'] is not None or view['committed_state'] != wanted
                    or view['container_state'] != ('running' if wanted == 'running' else 'absent')
                    or original['request_id'] != binding['birth_request_id']):
                raise RuntimeError('fixture workload not committed and qualified')
            birth = view['workload']
            if birth['container_id'] != binding['container_id']:
                raise RuntimeError('fixture birth differs from public binding')
            # stop_request_id records a later lifecycle transition, not birth.
            birth_binding = {k: deepcopy(v) for k, v in binding.items() if k != 'stop_request_id'}
            return {'binding': birth_binding, 'request': deepcopy(original['request']),
                    'target': deepcopy(original['target']), 'journal_id': original['journal_id'],
                    'creator_operation_id': birth['creator_operation_id'],
                    'container_id': birth['container_id'], 'generation': birth['generation']}

    def receipt(self, action, key):
        row = self.store.db.execute(
            'SELECT * FROM public_requests WHERE lab=? AND request_id=?', (self.lab, key)).fetchone()
        if (not row or row['node'] != self.node or row['action'] != action or row['force']
                or row['phase'] != 'completed'):
            raise RuntimeError('fixture original public lifecycle not completed')
        payload = json.loads(row['payload'])
        if self.controller.state.jumphost and payload.get('inventory_phase') != 'published':
            raise RuntimeError('fixture original inventory publication not completed')
        return dict(row)

    def step(self, action, key):
        if action not in ('restart', 'stop') or not isinstance(key, str) or not key:
            raise ValueError('explicit fixture restart/stop request required')
        pending = [r for r in self.record['steps'] if r['phase'] != 'completed']
        matches = [r for r in self.record['steps'] if r['request_id'] == key]
        if pending and (len(pending) != 1 or pending[0]['request_id'] != key):
            raise RuntimeError('fixture original lifecycle recovery pending')
        if matches:
            step = matches[0]
            if step['action'] != action:
                raise RuntimeError('fixture request action differs')
        else:
            if self.record['cleanup_verified']:
                raise RuntimeError('fixture already cleaned')
            before = self.observe('running')
            if before != self.record['births'][-1]:
                raise RuntimeError('fixture original generation changed')
            step = {'action': action, 'request_id': key, 'phase': 'pending',
                    'before': deepcopy(before)}
            self.record['steps'].append(step)
            self.save()
        if step['phase'] == 'completed':
            if self.receipt(action, key) != step['receipt']:
                raise RuntimeError('fixture completed lifecycle receipt changed')
            expected = step['after']
            current = self.observe('stopped' if action == 'stop' else 'running')
            if current != expected:
                raise RuntimeError('fixture completed lifecycle generation changed')
            return deepcopy(step)
        getattr(self.controller, action)(self.node, request_id=key)
        receipt = self.receipt(action, key)
        proof = self.observe('stopped' if action == 'stop' else 'running')
        before = step['before']
        if action == 'restart':
            if (proof['generation'] != before['generation'] + 1
                    or proof['container_id'] == before['container_id']
                    or proof['target'] != before['target']
                    or proof['journal_id'] != before['journal_id']
                    or proof['request']['spec'] != before['request']['spec']):
                raise RuntimeError('fixture restart generation or specification differs')
            if self.record['births'][-1] == before:
                self.record['births'].append(deepcopy(proof))
            elif self.record['births'][-1] != proof:
                raise RuntimeError('fixture restart history differs')
        elif proof != before:
            raise RuntimeError('fixture stop replaced original birth')
        step.update(phase='completed', after=deepcopy(proof), receipt=receipt)
        self.save()
        return deepcopy(step)

    def cleanup(self, key):
        self.record['cleanup_verified'] = False
        self.save()
        self.step('stop', key)
        ids = [r['container_id'] for r in self.record['births']]
        if len(ids) != len(set(ids)) or any(self.docker.inspect(cid) is not None for cid in ids):
            raise RuntimeError('fixture original generation remains present')
        self.record['cleanup_verified'] = True
        self.save()
