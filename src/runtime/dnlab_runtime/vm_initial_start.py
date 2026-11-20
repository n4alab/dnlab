"""Initial VM resource/definition/boot composition in the existing journal.

The child controllers remain authoritative for effects and uncertain replies.
This coordinator stores the original input, reports progress and publishes the
running receipt; it neither invents new births nor repeats uncertain VM calls.
Factories must retain the original runtime/collector capabilities on recovery.
"""
from copy import deepcopy
import json

from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint
from .vm_boot import VMBootDriver
from .vm_directory_storage import DirectoryVMStorage
from .vm_resources import VMResourcePreflight, VMResourceRegistry
from .vm_storage import disk_plan
from .vm_template import fields, require, template_digest, validate_template


class VMInitialStart:
    def __init__(self, directories, taps, *, resources, assets, storage_factory, boot_factory):
        require(directories.definitions is taps.definitions and directories.journal is taps.journal
                and isinstance(resources,VMResourceRegistry) and resources.definitions is directories.definitions
                and directories.definitions.preflight is resources
                and callable(getattr(assets,'verify',None))
                and callable(storage_factory) and callable(boot_factory),
                'original VM controllers and capability factories required')
        self.directories, self.taps = directories, taps
        self.definitions, self.journal = directories.definitions, directories.journal
        self.storage_factory, self.boot_factory = storage_factory, boot_factory
        self.resources = resources
        self.assets = assets
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_initial_starts '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _source(self, value):
        definition = self.definitions.read(value['id'])
        require(value['birth'] == definition['birth']
                and value['definition_sha256'] == definition['request_fingerprint']
                and template_digest(value['template']) == value['birth']['template_sha256'],
                'original initial VM request differs from definition')
        self.definitions._fence(definition)
        self.definitions._session(definition)
        disk_plan(definition,value['template'],value['bundle_root'],self.definitions.session.profile)
        require(self.assets.verify(birth=deepcopy(value['birth']),template=deepcopy(value['template']),
                                   bundle_root=value['bundle_root']) ==
                dict(template_sha256=value['birth']['template_sha256'],assets_verified=True),
                'original published VM bundle required before initial allocation')
        return definition

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_initial_starts WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original initial VM start intent missing')
        value = json.loads(row['payload'])
        fields(value,('id','birth','definition_sha256','template','bundle_root','tap_context',
                      'tap_requests','phase','last_step','error_type','receipt'), 'initial VM start')
        require(value['id'] == operation == value['birth']['creator_operation_id']
                and fingerprint(value) == row['fingerprint'] and value['phase'] in ('pending','running'),
                'original initial VM start journal differs')
        validate_template(value['template']);absolute(value['bundle_root'])
        if value['phase'] == 'running':
            fields(value['receipt'],('birth','definition_sha256','reference','process_record_sha256',
                                     'resource_sha256'), 'initial running VM receipt')
            require(value['receipt']['birth'] == value['birth']
                    and value['receipt']['definition_sha256'] == value['definition_sha256'],
                    'original initial VM completion owner differs')
        else:require(value['receipt'] is None, 'unexpected early VM completion')
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_initial_starts SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    def prepare(self, operation, template, bundle_root, tap_context, tap_requests):
        with self.journal.execution_lock:
            template = validate_template(template);absolute(bundle_root)
            definition = self.definitions.read(operation)
            request = dict(id=operation,birth=deepcopy(definition['birth']),
                definition_sha256=definition['request_fingerprint'],template=deepcopy(template),
                bundle_root=bundle_root,tap_context=deepcopy(tap_context),tap_requests=deepcopy(tap_requests))
            self._source(request)
            # Validate the complete NIC plan without reserving or allocating it.
            self.taps._plan(definition,tap_context,tap_requests)
            prior = self.journal.db.execute('SELECT 1 FROM vm_initial_starts WHERE id=?',(operation,)).fetchone()
            if prior:
                value = self.read(operation)
                require(all(value[key] == item for key,item in request.items()),
                        'initial VM retry inputs differ; no replacement')
                return value
            require(definition['phase'] == 'prepared' and definition.get('boot') is None
                    and definition.get('creation_ack') is None,
                    'initial VM request must precede definition and boot')
            value = dict(request,phase='pending',last_step='prepared',error_type='',receipt=None)
            with self.journal.transaction():
                self._source(value)
                self.journal.db.execute('INSERT INTO vm_initial_starts VALUES(?,?,?)',
                    (operation,canonical(value),fingerprint(value)))
            return self.read(operation)

    def _step(self, value, name):
        value = self.read(value['id']);self._source(value)
        if value['phase'] != 'running':
            value.update(last_step=name,error_type='');self._save(value)
        # A saved checkpoint is not authority to ignore a newly closed lab.
        self._source(value)
        return value

    def apply(self, operation, *, recover=False):
        require(type(recover) is bool, 'explicit initial VM recovery mode required')
        with self.journal.execution_lock:
            value = self.read(operation);definition = self._source(value)
            try:
                if definition['phase'] == 'prepared':
                    # Reserve and observe the complete NIC set before any
                    # directory or disk action. These are journal-only intents.
                    value = self._step(value,'preflight')
                    self.taps.prepare(operation,value['tap_context'],value['tap_requests'])
                    value = self._step(value,'directory')
                    directory = self.directories.prepare(operation)
                    if directory['phase'] == 'creating':
                        require(recover, 'original VM directory requires explicit initial recovery')
                        self.directories.recover(operation)
                    else:self.directories.apply(operation)
                else:
                    require(self.directories.observe(operation)['phase'] == 'ready',
                            'original ready VM directory required after definition')
                storage = self.storage_factory(operation)
                require(isinstance(storage,DirectoryVMStorage) and storage.directories is self.directories
                        and storage.operation == operation, 'original VM storage factory capability differs')
                if definition['phase'] == 'prepared':
                    value = self._step(value,'storage')
                    storage.prepare(operation,value['template'],value['bundle_root']);storage.apply(operation)
                    value = self._step(value,'taps')
                    self.taps.prepare(operation,value['tap_context'],value['tap_requests']);self.taps.apply(operation)
                resources = self.resources.register(VMResourcePreflight(storage,self.taps))
                # Definition apply remains one-shot. Its own pending/conflict
                # handling is not weakened even for explicit parent recovery.
                if self.definitions.read(operation).get('boot') is None:
                    value = self._step(value,'definition');self.definitions.apply(operation)
                value = self._step(value,'boot')
                boot = self.boot_factory(operation)
                require(isinstance(boot,VMBootDriver) and boot.definitions is self.definitions,
                        'original VM boot factory capability differs')
                definition = self.definitions.read(operation)
                stage = definition.get('boot',{}).get('phase')
                if recover and stage in ('arming_requested','activation_requested'):
                    boot.recover_events(operation)
                elif recover and stage == 'start_requested':
                    boot.recover_creation(operation)
                running = boot.apply(operation)
                verified = resources(running)
                receipt = dict(birth=deepcopy(value['birth']),definition_sha256=value['definition_sha256'],
                    reference=deepcopy(running['boot']['reference']),
                    process_record_sha256=fingerprint(running['boot']['process_record']),
                    resource_sha256=fingerprint(verified))
                current = self.read(operation);self._source(current)
                if current['phase'] == 'running':
                    require(current['receipt'] == receipt, 'original initial VM completion changed')
                    return current
                current.update(phase='running',last_step='running',error_type='',receipt=receipt)
                with self.journal.transaction():
                    original = self._source(current)
                    require(original == running and boot._boot(original)['phase'] == 'running'
                            and fingerprint(resources(original)) == receipt['resource_sha256'],
                            'original running VM changed before initial publication')
                    self.journal.db.execute('UPDATE vm_initial_starts SET payload=?,fingerprint=? WHERE id=?',
                        (canonical(current),fingerprint(current),operation))
                return self.read(operation)
            except Exception as error:
                current = self.read(operation)
                if current['phase'] != 'running':
                    current['error_type'] = type(error).__name__;self._save(current)
                raise
