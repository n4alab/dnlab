"""Read-only adapters to existing DNS, jumphost and relay ownership guards.

Workers and the expected birth projection come from the original gate service
materialization receipts. Neither is discovered from a resource name here.
This module never ensures, recovers, binds, stops or removes a helper service.
"""
from copy import deepcopy

from cleanup_execution import canonical_digest, require, sha
from cleanup_scope_sources import CONTEXT

ROLES = {'dns', 'jumphost', 'relay'}


def birth_projection(role, record):
    require(role in ROLES and type(record) is dict and type(record.get('config')) is dict,
            'original helper journal required')
    require(sha(record.get('container_id')) and type(record.get('nonce')) is str
            and len(record['nonce']) == 32 and all(c in '0123456789abcdef' for c in record['nonce']),
            'bound original helper Docker birth required')
    image = record.get('image') or {}
    require(type(image.get('Id')) is str and image['Id'].startswith('sha256:') and sha(image['Id'][7:]),
            'original helper image identity required')
    return {'role': role, 'config_sha256': canonical_digest(record['config']),
            'host_context': deepcopy(record['context']), 'container_id': record['container_id'],
            'nonce': record['nonce'], 'image_id': image['Id']}


class HelperScopeOwner:
    def __init__(self, worker, *, role, context, expected):
        require(role in ROLES and type(context) is dict and set(context) == CONTEXT
                and all(type(v) is str and v for v in context.values())
                and sha(context['image_build_hold_sha256']), 'complete helper gate context required')
        require(type(expected) is dict and set(expected) == {
            'role', 'config_sha256', 'host_context', 'container_id', 'nonce', 'image_id'}
                and expected['role'] == role, 'original published helper birth projection required')
        self.worker, self.role = worker, role
        self.context, self.expected = deepcopy(context), deepcopy(expected)

    def _record(self):
        record = self.worker.read()
        require(birth_projection(self.role, record) == self.expected,
                'helper original config, nonce, Docker ID or image changed')
        require(record['config']['lab'] == self.context['lab_id']
                and record['context'].get('boot_id') == self.context['boot_id'],
                'helper lab or original gate boot differs')
        if self.role == 'relay':
            require(record['config']['host'] == self.context['host_id'], 'relay gate host differs')
        return record

    def observe(self, action):
        require(action in ('created', 'removed'), 'explicit helper scope transition required')
        record = self._record()
        if action == 'created':
            require(record['phase'] == 'active', 'helper service requires explicit recovery')
            if self.role == 'relay':
                container = self.worker.inspect(record, bind=False)
            else:
                self.worker.infrastructure(record)
                container = self.worker.container(record, bind=False)
                if self.role == 'jumphost':
                    with self.worker.namespace(record, capture=False) as fd:
                        self.worker.verify_attachment(record, fd)
                    self.worker.verify_extensions(record, cleanup=False)
            require(type(container) is dict and container.get('Id') == self.expected['container_id']
                    and container.get('State', {}).get('Running') is True,
                    'original helper running generation unavailable')
        else:
            require(record['phase'] == 'cleaned', 'original helper cleanup pending')
            if self.role == 'relay':
                require(self.worker.inspect(record, bind=False) is None, 'original relay remains present')
            else:
                require(record.get('cleanup_verified') is True, 'original helper cleanup not verified')
                if self.role == 'dns':
                    self.worker.preflight_delete(record)
                else:
                    self.worker.verify_cleaned(record)
            container = None
        after = self._record()
        require(after['phase'] == record['phase'], 'helper lifecycle changed during observation')
        return {'birth': deepcopy(self.expected), 'container': deepcopy(container)}
