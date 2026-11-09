"""Persistent, create-only session provisioning with an injected host adapter.

No concrete host adapter, service start, account lookup or package installation
is supplied here. Adapter creates must be exclusive and expose nonce-bound birth
proofs even after a lost response. Uncertain absence never permits another create.
"""
from copy import deepcopy
import json
import uuid

from .libvirt_service_profile import render_profile, require_installable
from .manifest import Conflict, canonical, fingerprint, identifier


def targets(profile):
    result = []
    account = profile['account']
    result.append({'key': 'group:' + account['group'], 'kind': 'group',
                   'name': account['group'], 'gid': account['gid']})
    result.append({'key': 'account:' + account['name'], 'kind': 'account', **account})
    for directory in profile['directories']:
        result.append({'key': 'directory:' + directory['path'], 'kind': 'directory', **directory})
    for path, value in sorted(profile['files'].items()):
        result.append({'key': 'file:' + path, 'kind': 'file', 'path': path, **value})
    return result


def proof(value, item, operation_id):
    if (not isinstance(value, dict) or set(value) != {'intent_id', 'nonce', 'spec_sha256', 'identity'}
            or value['intent_id'] != operation_id or value['nonce'] != item['nonce']
            or value['spec_sha256'] != fingerprint(item['spec'])
            or not isinstance(value['identity'], dict) or not value['identity']):
        raise Conflict('session installation resource birth differs')
    # The concrete adapter must qualify kind-specific kernel/account/file fields;
    # opaque receipts alone are not operational qualification.
    return deepcopy(value)


class SessionInstaller:
    def __init__(self, journal, adapter):
        self.journal, self.adapter = journal, adapter
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_install_intents '
                '(id TEXT PRIMARY KEY,host TEXT NOT NULL UNIQUE,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation_id):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM libvirt_install_intents WHERE id=?',
                                          (operation_id,)).fetchone()
        if row is None:raise Conflict('original session installation intent missing')
        value = json.loads(row['payload'])
        if fingerprint(value) != row['fingerprint'] or row['host'] != value['profile']['session']['host_id']:
            raise Conflict('session installation journal integrity differs')
        if row['id'] != value['id'] or value['profile'] != render_profile(**value['request']):
            raise Conflict('session installation original profile differs')
        expected = targets(value['profile'])
        if len(expected) != len(value['items']):raise Conflict('session installation inventory differs')
        for spec, item in zip(expected, value['items']):
            if item['spec'] != spec or item['phase'] not in ('prepared', 'create_requested', 'created', 'dependency'):
                raise Conflict('session installation item differs')
            if not isinstance(item['nonce'], str) or len(item['nonce']) != 32:
                raise Conflict('session installation original nonce missing')
            if item['phase'] == 'created':proof(item['proof'], item, value['id'])
            elif item['phase'] == 'dependency':
                if spec['kind'] != 'directory' or item['proof'] != value['dependencies'].get(spec['path']):
                    raise Conflict('session installation directory dependency differs')
            elif item['proof'] is not None:raise Conflict('unexpected session installation proof')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE libvirt_install_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value), fingerprint(value), value['id']))

    def _observe(self, value, *, account_request_sha256=None):
        if account_request_sha256 is None:
            observed = self.adapter.observe(deepcopy(value))
        else:
            observed = self.adapter.account_preflight(deepcopy(value),account_request_sha256)
        if (not isinstance(observed, dict) or set(observed) != {'context', 'prerequisites', 'targets'}
                or observed['context'] != value['context']
                or observed['prerequisites'] != value['prerequisites']
                or set(observed['targets']) != {item['spec']['key'] for item in value['items']}):
            raise Conflict('session installation complete preflight differs')
        for item in value['items']:
            current = observed['targets'][item['spec']['key']]
            if item['phase'] in ('created', 'dependency'):
                if current != item['proof']:raise Conflict('original session installation resource replaced')
            elif item['phase'] == 'prepared':
                if current is not None:raise Conflict('session installation target already occupied')
            elif current is not None:proof(current, item, value['id'])
        return observed

    def prepare(self, operation_id, request, *, context, prerequisites, existing_directories=None):
        identifier(operation_id, 'installation operation_id')
        profile = render_profile(**request)
        require_installable(profile)
        if not isinstance(context, dict) or not context or not isinstance(prerequisites, dict) or not prerequisites:
            raise Conflict('original host context and package/service prerequisites required')
        dependencies = deepcopy(existing_directories or {})
        directories = {item['path'] for item in profile['directories']}
        if set(dependencies) - directories or any(not isinstance(v, dict) or not v for v in dependencies.values()):
            raise Conflict('only explicit original directory dependencies allowed')
        value = dict(id=operation_id, request=deepcopy(request), profile=profile,
            context=deepcopy(context), prerequisites=deepcopy(prerequisites), dependencies=dependencies,
            phase='prepared', items=[])
        for spec in targets(profile):
            dependency = dependencies.get(spec.get('path')) if spec['kind'] == 'directory' else None
            value['items'].append(dict(spec=spec, nonce=uuid.uuid4().hex,
                phase='dependency' if dependency is not None else 'prepared', proof=dependency))
        with self.journal.execution_lock:
            with self.journal.lock:
                prior = self.journal.db.execute('SELECT id FROM libvirt_install_intents WHERE id=? OR host=?',
                    (operation_id, profile['session']['host_id'])).fetchone()
            if prior:
                saved = self.read(prior['id'])
                keys = ('id', 'request', 'context', 'prerequisites', 'dependencies')
                if any(saved[key] != value[key] for key in keys):
                    raise Conflict('session installation original request differs')
                self._observe(saved)
                return saved
            self._observe(value)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_install_intents VALUES(?,?,?,?)',
                    (operation_id, profile['session']['host_id'], canonical(value), fingerprint(value)))
            return self.read(operation_id)

    def apply(self, operation_id):
        """Resume committed creates; reconcile uncertain creates read-only first."""
        with self.journal.execution_lock:
            value = self.read(operation_id)
            require_installable(value['profile'])
            observed = self._observe(value)
            for item in value['items']:
                if item['phase'] != 'create_requested':continue
                current = observed['targets'][item['spec']['key']]
                if current is None:raise Conflict('uncertain create has no qualified birth; recovery required')
                item.update(phase='created', proof=proof(current, item, value['id']))
                with self.journal.transaction():self._save(value)
            for item in value['items']:
                if item['phase'] != 'prepared':continue
                self._observe(value)
                item['phase'] = 'create_requested';value['phase'] = 'applying'
                with self.journal.transaction():self._save(value)
                # Reobserve every target after the durable intent, before mutation.
                observed = self._observe(value)
                if observed['targets'][item['spec']['key']] is not None:
                    raise Conflict('create boundary changed; recover original birth before proceeding')
                receipt = self.adapter.create(deepcopy(item), value['id'])
                receipt = proof(receipt, item, value['id'])
                observed = self._observe(value)
                if observed['targets'][item['spec']['key']] != receipt:
                    raise Conflict('created resource is not independently observed')
                item.update(phase='created', proof=receipt)
                with self.journal.transaction():self._save(value)
            self._observe(value)
            value['phase'] = 'installed_not_started'
            with self.journal.transaction():self._save(value)
            return self.read(operation_id)
