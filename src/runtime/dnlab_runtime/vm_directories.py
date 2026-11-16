"""Original per-VM disk/console parent before domain definition.

The administrative root is already qualified. Filesystem operations use the
existing tracked directory adapter; no account, domain, overlay or socket is
created here. Ready directories remain held until separate qualified cleanup.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath
import uuid
from xml.etree import ElementTree as ET

from .backend_reservations import available, verify_tap_reservations
from .libvirt_provisioning import ProvisioningWindow
from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint
from .vm_template import fields, require


class VMDirectories:
    def __init__(self, definitions, *, root, parent_identity, files, window, read_context, preflight):
        absolute(root)
        require(files.journal is definitions.journal and callable(read_context) and callable(preflight)
                and all(callable(getattr(files,name,None)) for name in ('observe','create','recover','directory_requested')),
                'original directory journal, filesystem and preflight providers required')
        fields(parent_identity,('device','inode','uid','gid','mode'),'VM directory root identity')
        require(all(type(v) is int and v>=0 for v in parent_identity.values()) and parent_identity['inode']>0
                and parent_identity['uid']==0 and parent_identity['gid']==0 and parent_identity['mode']==0o755,
                'qualified root:root0755 VM directory root required')
        context = window.receipt['context']
        fields(context,('host_id','boot_id','namespaces'),'VM directory context')
        fields(context['namespaces'],('pid','mnt','net','user'),'VM directory namespaces')
        for namespace in context['namespaces'].values():
            fields(namespace,('device','inode'),'VM directory namespace')
            require(all(type(v) is int and v>0 for v in namespace.values()),'complete original VM directory namespaces required')
        self.definitions,self.journal = definitions,definitions.journal
        self.root,self.parent = root,deepcopy(parent_identity)
        self.files,self.window,self.read_context,self.preflight = files,window,read_context,preflight
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_directory_intents '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,path TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _plan(self, definition):
        path = str(PurePosixPath(self.root)/definition['birth']['uuid'])
        xml = ET.fromstring(definition['xml']);paths = []
        for disk in xml.findall('devices/disk'):
            source = disk.find('source')
            require(source is not None and set(source.attrib)=={'file'},'original VM disk file required')
            paths.append(absolute(source.get('file')))
        for nvram in xml.findall('os/nvram'):paths.append(absolute(nvram.text))
        serial = xml.findall('devices/serial')
        require(len(serial)==1 and serial[0].get('type')=='unix','one original Unix console required')
        sources = serial[0].findall('source')
        require(len(sources)==1 and sources[0].get('mode')=='bind' and set(sources[0].attrib)=={'mode','path'},
                'original bound Unix console path required')
        paths.append(absolute(sources[0].get('path')))
        require(len(paths)>=2 and len(set(paths))==len(paths)
                and all(str(PurePosixPath(p).parent)==path for p in paths),
                'VM disks and console must be distinct direct children of the original UUID directory')
        session = self.definitions.session.profile
        return dict(kind='directory',key='directory:'+path,path=path,uid=session['uid'],gid=session['gid'],mode=0o700)

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_directory_intents WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original VM directory intent missing')
        value = json.loads(row['payload']);definition = self.definitions.read(operation)
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=row['id']
                or value['birth']!=definition['birth'] or row['domain_uuid']!=value['birth']['uuid']
                or value['id']!=value['birth']['creator_operation_id']
                or value['definition_sha256']!=definition['request_fingerprint']
                or value['root']!=self.root or value['parent']!=self.parent
                or value['window_sha256']!=self.window.sha256 or value['spec']!=self._plan(definition)
                or row['path']!=value['spec']['path'] or value['phase'] not in ('prepared','creating','ready')
                or (value['phase']=='ready')!=(value['proof'] is not None)
                or not isinstance(value['nonce'],str) or len(value['nonce'])!=32
                or any(c not in '0123456789abcdef' for c in value['nonce'])):
            raise Conflict('original VM directory lineage differs')
        if value['proof'] is not None:self._proof(value,value['proof'])
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_directory_intents SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    @staticmethod
    def _item(value):return dict(spec=deepcopy(value['spec']),nonce=value['nonce'])

    @staticmethod
    def _proof(value, proof):
        fields(proof,('intent_id','nonce','spec_sha256','identity'),'original VM directory receipt')
        fields(proof['identity'],('device','inode','uid','gid','mode','kind'),'original VM directory inode')
        identity = proof['identity'];spec = value['spec']
        require(proof['intent_id']==value['id'] and proof['nonce']==value['nonce']
                and proof['spec_sha256']==fingerprint(spec) and identity['kind']=='directory'
                and all(type(identity[k]) is int and identity[k]>=0 for k in ('device','inode','uid','gid','mode'))
                and identity['inode']>0 and all(identity[k]==spec[k] for k in ('uid','gid','mode')),
                'original durable VM directory birth differs')
        return deepcopy(proof)

    def _check(self, value, *, mutate):
        definition = self.definitions.read(value['id'])
        require(definition['birth']==value['birth'] and definition['request_fingerprint']==value['definition_sha256'],
                'original VM directory definition changed')
        self.definitions._session(definition)
        available(self.journal,value['birth']['lab_id'],value['birth']['node_id'],'libvirt',vm_birth=value['birth'])
        verify_tap_reservations(self.journal,value['birth'],definition['xml'])
        context = self.window.receipt['context']
        require(context.get('host_id')==value['birth']['host_id']
                and context.get('boot_id')==self.definitions.session.proof()['daemon']['boot_id']
                and self.read_context()==context,'original VM directory host/boot/thread context differs')
        if mutate:
            self.definitions._fence(definition)
            require(definition['phase']=='prepared' and definition.get('creation_ack') is None
                    and definition.get('boot') is None,'VM directory creation must precede any domain definition/start')
            self.definitions._absent(self.definitions.connection.lookupByUUIDString,value['birth']['uuid'])
            self.definitions._absent(self.definitions.connection.lookupByName,ET.fromstring(definition['xml']).findtext('name'))
            self.window.verify(self._item(value),value['id'],value['window_sha256'])
        expected = dict(definition_sha256=value['definition_sha256'],birth_sha256=fingerprint(value['birth']),
                        parent_sha256=fingerprint(dict(root=self.root,identity=self.parent)),
                        template_sha256=value['birth']['template_sha256'],assets_verified=True)
        if mutate:expected['exclusive_writer'] = True
        require(self.preflight(deepcopy(value),mutating=mutate)==expected,'complete VM directory parent/asset preflight differs')
        if value['phase']!='creating':
            actual = self.files.observe(self._item(value),value['id'])
            if value['phase']=='prepared' and actual is not None:raise Conflict('VM directory already occupied; no adoption')
            if value['phase']=='ready' and actual!=value['proof']:raise Conflict('original VM directory missing or replaced')
        require(self.read_context()==context,'VM directory context changed during preflight')
        self.definitions._session(definition)
        require(self.definitions.read(value['id'])==definition,'VM definition changed during directory preflight')
        if mutate:
            self.definitions._fence(definition)
            available(self.journal,value['birth']['lab_id'],value['birth']['node_id'],'libvirt',vm_birth=value['birth'])
            verify_tap_reservations(self.journal,value['birth'],definition['xml'])
            self.definitions._absent(self.definitions.connection.lookupByUUIDString,value['birth']['uuid'])
            self.definitions._absent(self.definitions.connection.lookupByName,ET.fromstring(definition['xml']).findtext('name'))
            self.window.verify(self._item(value),value['id'],value['window_sha256'])

    def prepare(self, operation):
        with self.journal.execution_lock:
            definition = self.definitions.read(operation);self.definitions._fence(definition)
            if self.journal.db.execute('SELECT 1 FROM vm_directory_intents WHERE id=?',(operation,)).fetchone():
                value = self.read(operation);self._check(value,mutate=False);return value
            value = dict(id=operation,birth=deepcopy(definition['birth']),definition_sha256=definition['request_fingerprint'],
                root=self.root,parent=self.parent,window_sha256=self.window.sha256,spec=self._plan(definition),
                nonce=uuid.uuid4().hex,phase='prepared',proof=None)
            self._check(value,mutate=True)
            with self.journal.transaction():
                self._check(value,mutate=True)
                self.journal.db.execute('INSERT INTO vm_directory_intents VALUES(?,?,?,?,?)',
                    (operation,value['birth']['uuid'],value['spec']['path'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def _file_window(self, operation):
        def observe():
            self._check(self.read(operation),mutate=True)
            return self.window.observe()
        return ProvisioningWindow(self.window.receipt,observe)

    def observe(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);self._check(value,mutate=False)
            if value['phase']=='creating':raise Conflict('original VM directory recovery required')
            return value

    def _run(self, operation, *, recover):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase']=='ready':return self.observe(operation)
            if recover and value['phase']=='prepared':raise Conflict('no original VM directory creation requested')
            if value['phase']=='creating' and not recover:raise Conflict('original VM directory requires explicit recovery')
            self._check(value,mutate=True)
            create = value['phase']=='prepared'
            if create:
                value['phase']='creating';self._save(value);self._check(value,mutate=True)
            window = self._file_window(operation)
            if not create:
                requested = self.files.directory_requested(self._item(value),operation)
                require(type(requested) is bool,'qualified original directory request state required')
                if not requested:
                    if self.files.observe(self._item(value),operation) is not None:
                        raise Conflict('unrequested VM directory target occupied; no adoption')
                    # The lower adapter logs before mkdir. No lower request and
                    # no target prove this creator was never released.
                    create = True
                    self._check(value,mutate=True)
            action = self.files.create if create else self.files.recover
            proof = self._proof(value,action(self._item(value),operation,window=window))
            self._check(value,mutate=True)
            if self.files.observe(self._item(value),operation)!=proof:
                raise Conflict('original VM directory durability not independently observed')
            value.update(phase='ready',proof=proof);self._save(value)
            return self.observe(operation)

    def apply(self, operation):return self._run(operation,recover=False)
    def recover(self, operation):return self._run(operation,recover=True)
