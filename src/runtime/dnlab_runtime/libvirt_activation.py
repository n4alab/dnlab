"""Journaled empty-session activation; all host actions remain injected.

An adapter must verify installed resources, the agreed window and all service
generations on every observation. None means verified inactive/absent, never an
unqualified process ignored by name. Receipts require durable original command
completion plus process/socket qualification in the concrete adapter. This module
does not supply systemctl, libvirt access, enablement, stop or rollback.
"""
from copy import deepcopy
import json
import uuid

from .libvirt_service_profile import render_profile, require_activatable
from .manifest import Conflict, canonical, fingerprint, identifier


def steps(profile):
    config=fingerprint(profile['files'])
    result=[dict(key='manager-reload',kind='reload',config_sha256=config)]
    for unit in profile['service_order']:
        role=unit.removeprefix('dnlab-').removesuffix('.service')
        result.append(dict(key=unit,kind='start',unit=unit,role=role,
            uid=profile['session']['uid'],gid=profile['session']['gid'],
            binary=deepcopy(profile['binaries'][role]),config_sha256=config))
    return result


class SessionActivation:
    def __init__(self,journal,adapter):
        self.journal,self.adapter=journal,adapter
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_intents '
                '(id TEXT PRIMARY KEY,installation_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self,operation_id):
        with self.journal.lock:
            row=self.journal.db.execute('SELECT * FROM libvirt_activation_intents WHERE id=?',(operation_id,)).fetchone()
        if row is None:raise Conflict('original session activation intent missing')
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=row['id']
                or value['installation']['id']!=row['installation_id']
                or value['installation_sha256']!=fingerprint(value['installation'])
                or value['installation']['profile']!=render_profile(**value['installation']['request'])):
            raise Conflict('original session activation journal differs')
        expected=steps(value['installation']['profile'])
        if len(value['items'])!=len(expected):raise Conflict('session activation inventory differs')
        for spec,item in zip(expected,value['items']):
            if (item['spec']!=spec or item['phase'] not in ('prepared','requested','confirmed')
                    or not isinstance(item['nonce'],str) or len(item['nonce'])!=32):
                raise Conflict('original session activation step differs')
            if item['phase']=='confirmed':self._receipt(value,item,item['proof'])
            elif item['proof'] is not None:raise Conflict('unexpected session activation proof')
        return value

    def _save(self,value):
        self.journal.db.execute('UPDATE libvirt_activation_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    @staticmethod
    def _receipt(value,item,receipt):
        if (not isinstance(receipt,dict) or set(receipt)!={'activation_id','nonce','spec_sha256','identity'}
                or receipt['activation_id']!=value['id'] or receipt['nonce']!=item['nonce']
                or receipt['spec_sha256']!=fingerprint(item['spec'])
                or not isinstance(receipt['identity'],dict) or not receipt['identity']):
            raise Conflict('original session activation command/generation proof differs')
        return deepcopy(receipt)

    def _observe(self,value):
        observed=self.adapter.observe(deepcopy(value))
        if (not isinstance(observed,dict) or set(observed)!={'context','installation_sha256','steps'}
                or observed['context']!=value['installation']['context']
                or observed['installation_sha256']!=value['installation_sha256']
                or set(observed['steps'])!={item['spec']['key'] for item in value['items']}):
            raise Conflict('complete session activation preflight differs')
        for item in value['items']:
            current=observed['steps'][item['spec']['key']]
            if item['phase']=='confirmed':
                if current!=item['proof']:raise Conflict('original session service generation replaced or missing')
            elif item['phase']=='prepared':
                if current is not None:raise Conflict('session activation target already occupied')
            elif current is not None:self._receipt(value,item,current)
        return observed

    def prepare(self,operation_id,installation):
        identifier(operation_id,'session activation operation_id')
        if (installation.get('phase')!='installed_not_started'
                or any(item['phase'] not in ('created','dependency') for item in installation['items'])):
            raise Conflict('original completed installation required for activation')
        profile=render_profile(**installation['request']);require_activatable(profile)
        if installation['profile']!=profile:raise Conflict('original installed profile differs')
        value=dict(id=operation_id,installation=deepcopy(installation),installation_sha256=fingerprint(installation),
            phase='prepared',empty_proof=None,items=[dict(spec=spec,nonce=uuid.uuid4().hex,
                phase='prepared',proof=None) for spec in steps(profile)])
        with self.journal.execution_lock:
            prior=self.journal.db.execute('SELECT id FROM libvirt_activation_intents WHERE id=? OR installation_id=?',
                (operation_id,installation['id'])).fetchone()
            if prior:
                saved=self.read(prior['id'])
                if saved['id']!=operation_id or saved['installation']!=installation:
                    raise Conflict('original session activation request differs')
                self._observe(saved);return saved
            self._observe(value)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_activation_intents VALUES(?,?,?,?)',
                    (operation_id,installation['id'],canonical(value),fingerprint(value)))
            return self.read(operation_id)

    def apply(self,operation_id):
        with self.journal.execution_lock:
            value=self.read(operation_id)
            require_activatable(value['installation']['profile'])
            observed=self._observe(value)
            for item in value['items']:
                if item['phase']!='requested':continue
                current=observed['steps'][item['spec']['key']]
                if current is None:raise Conflict('uncertain service action; original completion required, no resend')
                item.update(phase='confirmed',proof=self._receipt(value,item,current))
                with self.journal.transaction():self._save(value)
            for item in value['items']:
                if item['phase']!='prepared':continue
                self._observe(value)
                item['phase']='requested';value['phase']='activating'
                with self.journal.transaction():self._save(value)
                observed=self._observe(value)
                if observed['steps'][item['spec']['key']] is not None:
                    raise Conflict('service action boundary changed; recover original completion first')
                receipt=self._receipt(value,item,self.adapter.apply(deepcopy(item),value['id']))
                if self._observe(value)['steps'][item['spec']['key']]!=receipt:
                    raise Conflict('service action completion not independently observed')
                item.update(phase='confirmed',proof=receipt)
                with self.journal.transaction():self._save(value)
            self._observe(value)
            empty=self.adapter.qualify_empty(deepcopy(value))
            expected=dict(installation_sha256=value['installation_sha256'],domains=[],
                service_proofs_sha256=fingerprint([item['proof'] for item in value['items']]))
            if empty!=expected:raise Conflict('qualified empty session inventory differs')
            self._observe(value)
            if value['empty_proof'] is not None and value['empty_proof']!=empty:
                raise Conflict('original empty session proof differs')
            value.update(phase='ready_empty',empty_proof=deepcopy(empty))
            with self.journal.transaction():self._save(value)
            return self.read(operation_id)
