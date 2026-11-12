"""Persistent VM overlay intents; native filesystem/formatter providers are explicit.

The definition reserves paths first. Each create is requested durably once;
uncertainty requires the original adapter recovery, never another create.
Ready overlays retain their original inode/nonce across guest writes and boots.
Missing files are conflicts: wipe and retirement require separate operations.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath
import uuid
from xml.etree import ElementTree as ET

from .backend_reservations import available, verify_tap_reservations
from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint
from .qemu_process import validate_process_record
from .vm_template import digest, fields, require, template_digest, validate_template


class VMStorage:
    def __init__(self, definitions, *, assets, files, writers):
        require(callable(assets) and callable(writers)
                and all(callable(getattr(files, name, None)) for name in ('observe', 'create', 'recover')),
                'qualified VM asset, overlay and writer providers required')
        self.definitions, self.journal = definitions, definitions.journal
        self.assets, self.files, self.writers = assets, files, writers
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_storage_intents '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _plan(self, definition, template, bundle_root):
        template = validate_template(template)
        require(template_digest(template) == definition['birth']['template_sha256'], 'original VM disk template differs')
        absolute(bundle_root)
        xml = ET.fromstring(definition['xml'])
        require(not xml.findall('os/nvram'), 'writable NVRAM needs a separate qualified storage adapter')
        disks = xml.findall('devices/disk')
        require(len(disks) == len(template['hardware']['disks']), 'complete original VM disk inventory required')
        session = self.definitions.session.profile
        result = []
        for declared, disk in zip(template['hardware']['disks'], disks):
            target = disk.find('target'); source = disk.find('source'); driver = disk.find('driver')
            require(target is not None and target.attrib == dict(dev=declared['target'], bus=declared['bus'])
                    and source is not None and driver is not None and driver.get('type') == 'qcow2',
                    'original VM disk target/format differs')
            base = template['assets'][declared['asset']]
            path = absolute(source.get('file'))
            require(not PurePosixPath(path).is_relative_to(bundle_root), 'overlay must be outside immutable VM bundle')
            result.append(dict(id=declared['id'], path=path, base_path=str(PurePosixPath(bundle_root) / base['path']),
                               base_sha256=base['sha256'], base_format=base['format'],
                               uid=session['uid'], gid=session['gid'], mode=0o600))
        return result

    def read(self, operation):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM vm_storage_intents WHERE id=?', (operation,)).fetchone()
        if row is None:raise Conflict('original VM storage intent missing')
        value = json.loads(row['payload'])
        definition = self.definitions.read(operation)
        if (fingerprint(value) != row['fingerprint'] or value['id'] != row['id']
                or value['birth'] != definition['birth'] or row['domain_uuid'] != value['birth']['uuid']
                or value['definition_sha256'] != definition['request_fingerprint']
                or value['phase'] not in ('prepared', 'creating', 'ready')
                or value['storage_type'] != 'local'):
            raise Conflict('original VM storage lineage differs')
        specs = self._plan(definition, value['template'], value['bundle_root'])
        if len(value['items']) != len(specs):raise Conflict('original VM overlay inventory differs')
        for spec, item in zip(specs, value['items']):
            if (item['spec'] != spec or item['phase'] not in ('prepared', 'create_requested', 'ready')
                    or not isinstance(item['nonce'], str) or len(item['nonce']) != 32
                    or any(c not in '0123456789abcdef' for c in item['nonce'])):
                raise Conflict('original VM overlay intent differs')
            if item['phase'] == 'ready':self._proof(value, item, item['proof'])
            elif item['proof'] is not None:raise Conflict('unexpected VM overlay proof')
        phases = [item['phase'] for item in value['items']]
        pending = [phase for phase in phases if phase != 'ready']
        if (phases != ['ready'] * (len(phases) - len(pending)) + pending
                or pending not in (['prepared'] * len(pending), ['create_requested'] + ['prepared'] * (len(pending) - 1))):
            raise Conflict('VM storage creation order differs')
        if value['phase'] == 'ready' and any(item['phase'] != 'ready' for item in value['items']):
            raise Conflict('incomplete VM storage set marked ready')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_storage_intents SET payload=?,fingerprint=? WHERE id=?',
                                (canonical(value), fingerprint(value), value['id']))

    @staticmethod
    def _proof(value, item, proof):
        fields(proof, ('operation_id', 'nonce', 'spec_sha256', 'identity', 'creation'), 'VM overlay proof')
        spec = item['spec']
        require(proof['operation_id'] == value['id'] and proof['nonce'] == item['nonce']
                and proof['spec_sha256'] == fingerprint(spec), 'original VM overlay owner differs')
        identity = proof['identity']
        fields(identity, ('device', 'inode', 'uid', 'gid', 'mode'), 'VM overlay identity')
        require(all(type(v) is int for v in identity.values()) and identity['device'] >= 0 and identity['inode'] > 0
                and all(identity[k] == spec[k] for k in ('uid', 'gid', 'mode')), 'original VM overlay inode/credentials differ')
        require(all(other['spec']['id'] == spec['id'] or other['phase'] != 'ready'
                    or (other['proof']['identity']['device'], other['proof']['identity']['inode'])
                    != (identity['device'], identity['inode']) for other in value['items']),
                'distinct original VM overlay inodes required')
        creation = proof['creation']
        fields(creation, ('request_sha256', 'worker_reference_sha256', 'exit_code'), 'VM overlay creation')
        require(creation['request_sha256'] == fingerprint(dict(operation_id=value['id'], nonce=item['nonce'], spec=spec))
                and digest(creation['worker_reference_sha256']) and type(creation['exit_code']) is int
                and creation['exit_code'] == 0, 'original successful overlay creation required')
        return deepcopy(proof)

    def _check(self, value, *, mutate):
        definition = self.definitions.read(value['id'])
        require(definition['request_fingerprint'] == value['definition_sha256'], 'VM storage definition changed')
        if mutate:self.definitions._fence(definition)
        available(self.journal, value['birth']['lab_id'], value['birth']['node_id'], 'libvirt', vm_birth=value['birth'])
        self.definitions._session(definition)
        verify_tap_reservations(self.journal, value['birth'], definition['xml'])
        observed = self.assets(deepcopy(value))
        require(observed == dict(template_sha256=template_digest(value['template']), assets_verified=True),
                'original immutable VM bundle verification required')
        writers = self.writers(deepcopy(value))
        require(type(writers) is list and len(writers) <= 1, 'single qualified VM disk writer required')
        original = definition.get('boot', {}).get('process_record')
        if writers:
            writer = validate_process_record(writers[0])
            require(writer == original and writer['birth'] == value['birth']
                    and writer['uid'] == self.definitions.session.profile['uid']
                    and writer['gid'] == self.definitions.session.profile['gid'], 'VM disk writer differs from original QEMU')
        elif original is not None:
            raise Conflict('original VM disk writer absence needs verified shutdown')
        if mutate and writers:raise Conflict('VM overlays cannot be created while a writer exists')
        # Check the whole set before allocating the next disk. The sole
        # create_requested item is handled by the original adapter's create or
        # recovery, which must qualify its own partial birth/formatter first.
        for item in value['items']:
            if item['phase'] == 'create_requested':continue
            current = self.files.observe(deepcopy(item), value['id'])
            if item['phase'] == 'ready' and current != item['proof']:
                raise Conflict('original VM overlay missing or replaced; explicit wipe required')
            if item['phase'] == 'prepared' and current is not None:
                raise Conflict('VM overlay path already occupied; no adoption')
        if mutate:self.definitions._fence(definition)

    def prepare(self, operation, template, bundle_root, *, storage_type='local'):
        require(storage_type == 'local', 'CephFS VM storage needs separate qualification')
        definition = self.definitions.read(operation)
        specs = self._plan(definition, template, bundle_root)
        with self.journal.execution_lock:
            saved = self.journal.db.execute('SELECT id FROM vm_storage_intents WHERE id=?', (operation,)).fetchone()
            if saved:
                value = self.read(operation)
                if value['template'] != template or value['bundle_root'] != bundle_root:
                    raise Conflict('original VM storage request differs')
                return self.observe(operation)
            value = dict(id=operation, birth=deepcopy(definition['birth']), definition_sha256=definition['request_fingerprint'],
                         template=deepcopy(template), bundle_root=bundle_root, storage_type=storage_type, phase='prepared',
                         items=[dict(spec=spec, nonce=uuid.uuid4().hex, phase='prepared', proof=None) for spec in specs])
            self._check(value, mutate=True)
            for item in value['items']:
                if self.files.observe(deepcopy(item), operation) is not None:
                    raise Conflict('VM overlay path already occupied; no adoption')
            with self.journal.transaction():
                self._check(value, mutate=True)
                self.journal.db.execute('INSERT INTO vm_storage_intents VALUES(?,?,?,?)',
                    (operation, value['birth']['uuid'], canonical(value), fingerprint(value)))
            return self.read(operation)

    def observe(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            self._check(value, mutate=False)
            for item in value['items']:
                observed = self.files.observe(deepcopy(item), operation)
                if item['phase'] == 'ready':
                    if observed != item['proof']:raise Conflict('original VM overlay missing or replaced; explicit wipe required')
                elif observed is not None:raise Conflict('VM overlay creation requires original recovery')
            self._check(value, mutate=False)
            return value

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'ready':return self.observe(operation)
            for item in value['items']:
                self._check(value, mutate=True)
                if item['phase'] == 'ready':
                    if self.files.observe(deepcopy(item), operation) != item['proof']:
                        raise Conflict('original VM overlay missing or replaced; explicit wipe required')
                    continue
                if item['phase'] == 'prepared':
                    if self.files.observe(deepcopy(item), operation) is not None:
                        raise Conflict('VM overlay path occupied before create')
                    item['phase'] = 'create_requested'; value['phase'] = 'creating'
                    with self.journal.transaction():self._save(value)
                    self._check(value, mutate=True)
                    proof = self.files.create(deepcopy(item), operation)
                else:
                    proof = self.files.recover(deepcopy(item), operation)
                proof = self._proof(value, item, proof)
                self._check(value, mutate=True)
                if self.files.observe(deepcopy(item), operation) != proof:
                    raise Conflict('original VM overlay completion not independently verified')
                item.update(phase='ready', proof=proof)
                with self.journal.transaction():self._save(value)
            value['phase'] = 'ready'
            with self.journal.transaction():self._save(value)
            return self.observe(operation)
