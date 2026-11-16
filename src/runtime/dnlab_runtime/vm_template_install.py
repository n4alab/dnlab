"""Complete content-addressed bundle imports; no QEMU or libvirt operations.

The store parent is already qualified. An explicit administrative window and
complete caller preflight guard mutations. Only the final receipt publishes a
bundle; directory presence or a matching manifest never authorizes adoption.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import PurePosixPath
import uuid

from .libvirt_install_files import InstallationFiles
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_bundle import metadata, pinned_file, read_bundle, unique_pairs
from .vm_template import digest, template_digest, validate_template
from .vm_template_files import TemplateAssetFiles, identity


def bundle_plan(root, source, template, manifest):
    """Pure plan, also used to enumerate the provisioning window targets."""
    template = validate_template(template)
    destination = str(PurePosixPath(root)/template_digest(template))
    paths = [asset['path'] for asset in template['assets'].values()]
    if ('manifest.json' in paths or any(a != b and PurePosixPath(a) in PurePosixPath(b).parents
                                      for a in paths + ['manifest.json'] for b in paths + ['manifest.json'])):
        raise Conflict('template file/directory paths overlap')
    directories = {destination}
    for path in paths:
        parent = PurePosixPath(destination)/PurePosixPath(path).parent
        while str(parent) != destination:
            directories.add(str(parent));parent = parent.parent
    specs = [dict(kind='directory', key='directory:'+path, path=path, uid=0, gid=0, mode=0o755)
             for path in sorted(directories, key=lambda p:(len(PurePosixPath(p).parts), p))]
    files = [dict(path=asset['path'], sha256=asset['sha256'], size=asset['size'])
             for asset in sorted(template['assets'].values(), key=lambda a:a['path'])]
    files.append(dict(path='manifest.json', sha256=manifest['sha256'], size=manifest['size']))
    return specs + [dict(kind='asset', key='file:'+str(PurePosixPath(destination)/asset['path']),
                         path=str(PurePosixPath(destination)/asset['path']),
                         source=str(PurePosixPath(source)/asset['path']),
                         sha256=asset['sha256'], size=asset['size']) for asset in files]


class TemplateBundleInstall:
    def __init__(self, journal, *, root, parent_identity, window, preflight, readonly=False):
        from .libvirt_xml import absolute
        absolute(root)
        if type(readonly) is not bool or not callable(preflight):raise Conflict('explicit template import providers required')
        self.journal, self.root, self.parent = journal, root, deepcopy(parent_identity)
        self.window, self.preflight, self.readonly = window, preflight, readonly
        if (set(self.parent) != {'device','inode','uid','gid','mode'} or self.parent['uid'] != 0
                or self.parent['gid'] != 0 or self.parent['mode'] != 0o755):
            raise Conflict('qualified root:root0755 template store required')
        self.files = InstallationFiles(journal=journal, readonly=readonly)
        # Initialize the shared table once; real requests use per-parent
        # clients after their original directory births are confirmed.
        TemplateAssetFiles(journal,root=root,parent_identity=self.parent,
                           preflight=lambda request:None,readonly=readonly)
        self.asset_clients = {}
        if readonly:
            if journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='vm_template_bundle_imports'").fetchone() is None:
                raise Conflict('original bundle import journal required')
        else:
            with journal.transaction():
                journal.db.execute('CREATE TABLE IF NOT EXISTS vm_template_bundle_imports '
                    '(id TEXT PRIMARY KEY,path TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _root(self):
        return self.files._parent(self.root+'/.store-identity-probe')

    @staticmethod
    def _asset_id(value, item):
        return 'template-asset-'+fingerprint(dict(operation=value['request']['id'], nonce=item['nonce']))[:32]

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_template_bundle_imports WHERE id=?', (operation,)).fetchone()
        if row is None:raise Conflict('original bundle import missing')
        value = json.loads(row['payload']);request = value['request']
        expected = bundle_plan(self.root, request['source'], request['source_proof']['template'], request['manifest'])
        if (fingerprint(value) != row['fingerprint'] or request['id'] != row['id']
                or request['root'] != self.root or request['parent'] != self.parent
                or request['window_sha256'] != self.window.sha256
                or request['template_sha256'] != template_digest(request['source_proof']['template'])
                or row['path'] != expected[0]['path'] or value['phase'] not in ('prepared','installing','ready')
                or [item['spec'] for item in value['items']] != expected):
            raise Conflict('original bundle import binding differs')
        unfinished = False;requested = False
        for item in value['items']:
            if (item['phase'] not in ('prepared','requested','created') or not isinstance(item['nonce'],str)
                    or len(item['nonce']) != 32 or any(c not in '0123456789abcdef' for c in item['nonce'])
                    or (item['phase'] == 'created') != (item['proof'] is not None)):
                raise Conflict('original bundle member state differs')
            if item['phase'] == 'created':
                if unfinished:raise Conflict('bundle member creation order differs')
            else:
                if item['phase'] == 'requested':
                    if unfinished or requested:raise Conflict('multiple pending bundle members')
                    requested = True
                unfinished = True
        if ((value['phase'] == 'ready') != (value['proof'] is not None)
                or value['phase'] == 'ready' and unfinished
                or value['phase'] == 'prepared' and any(i['phase'] != 'prepared' for i in value['items'])):
            raise Conflict('incomplete template bundle publication')
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_template_bundle_imports SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value), fingerprint(value), value['request']['id']))

    def _source(self, value):
        if all(item['phase'] == 'created' for item in value['items']):return
        request = value['request'];proof = request['source_proof']
        with self.files._parent(request['source']+'/manifest.json') as (root, _):
            if list(metadata(os.fstat(root))) != proof['directory_metadata']:
                raise Conflict('original source bundle directory changed')
            expected = [('manifest.json',request['manifest']['metadata'])] + [
                (asset['path'],proof['assets'][key]['metadata']) for key,asset in proof['template']['assets'].items()]
            for path, before in expected:
                with pinned_file(root,path) as (_,info):
                    if list(metadata(info)) != before:raise Conflict('original source bundle member changed')

    def _assets(self, value, item, *, readonly=None):
        if readonly is None:readonly = self.readonly
        parent_path = str(PurePosixPath(item['spec']['path']).parent)
        directory = next(i for i in value['items'] if i['spec']['kind'] == 'directory' and i['spec']['path'] == parent_path)
        if directory['phase'] != 'created':raise Conflict('original created asset directory required')
        parent = {k:directory['proof']['identity'][k] for k in ('device','inode','uid','gid','mode')}
        key = (value['request']['id'],self._asset_id(value,item),readonly)
        if key in self.asset_clients:
            client = self.asset_clients[key]
            if client.parent != parent:raise Conflict('original asset parent binding changed')
            return client
        def preflight(request):
            current = self.read(value['request']['id']);self._guard(current)
            spec = item['spec']
            if (request['id'] != self._asset_id(current,item) or request['source'] != spec['source']
                    or request['destination'] != spec['path'] or request['sha256'] != spec['sha256']
                    or request['size'] != spec['size'] or request['parent'] != parent):
                raise Conflict('original bundle asset child differs')
            return dict(request_sha256=fingerprint(request),exclusive_writer=True,source_verified=True)
        client = TemplateAssetFiles(self.journal,root=parent_path,parent_identity=parent,
                                    preflight=preflight,readonly=readonly,
                                    source_opener=lambda path:self._source_asset(value,path))
        self.asset_clients[key] = client
        return client

    @contextmanager
    def _source_asset(self, value, path):
        source = value['request']['source']
        expected = value['request']['source_proof']['directory_metadata']
        if path not in {i['spec']['source'] for i in value['items'] if i['spec']['kind'] == 'asset'}:
            raise Conflict('undeclared template source path')
        relative = str(PurePosixPath(path).relative_to(source))
        # Walk ancestors without following symlinks, but bind content stability
        # to the original bundle subtree. Unrelated ancestor children are not
        # members of this immutable source bundle.
        with self.files._parent(source+'/manifest.json') as (root,_):
            if list(metadata(os.fstat(root))) != expected:raise Conflict('original source bundle changed')
            with pinned_file(root,relative) as (fd,_):yield fd
            if list(metadata(os.fstat(root))) != expected:raise Conflict('source bundle changed during copy')
        with self.files._parent(source+'/manifest.json') as (visible,_):
            if list(metadata(os.fstat(visible))) != expected:raise Conflict('source bundle path replaced')

    def _exists(self, path):
        try:
            with self.files._parent(path) as (parent,name):
                os.stat(name,dir_fd=parent,follow_symlinks=False)
                return True
        except FileNotFoundError:return False

    def _targets(self, value):
        present = set();directories = []
        for item in value['items']:
            spec = item['spec'];path = spec['path']
            if spec['kind'] == 'directory':
                birth = self.files._birth(item,value['request']['id'])
                if item['phase'] == 'prepared' and birth is not None:raise Conflict('unexpected early directory birth')
                if birth is None or birth['file'] is None:
                    if self._exists(path):raise Conflict('foreign or unrecorded template directory')
                    if item['phase'] == 'created':raise Conflict('original template directory missing')
                    continue
                with self.files._parent(path) as (parent,name):
                    proof = self.files._qualified(item,value['request']['id'],parent,name,birth)
                if birth['window_sha256'] != value['request']['window_sha256']:
                    raise Conflict('original template directory window differs')
                if item['phase'] == 'created' and (birth['phase'] != 'durability_confirmed' or proof != item['proof']):
                    raise Conflict('original durable template directory differs')
                present.add(path);directories.append((path,proof))
            else:
                child = self._asset_id(value,item)
                row = self.journal.db.execute('SELECT 1 FROM vm_template_asset_files WHERE id=?',(child,)).fetchone()
                if item['phase'] == 'prepared' and row is not None:raise Conflict('unexpected early asset birth')
                if row is None:
                    if self._exists(path):raise Conflict('foreign template asset')
                    if item['phase'] == 'created':raise Conflict('original template asset missing')
                    continue
                assets = self._assets(value,item,readonly=True);saved = assets.read(child);request = saved['request']
                if (request['source'] != spec['source'] or request['destination'] != path
                        or request['sha256'] != spec['sha256'] or request['size'] != spec['size']):
                    raise Conflict('original template asset request differs')
                observed = assets.preflight_observe(child)
                if item['phase'] == 'created' and (observed['phase'] != 'ready' or observed['proof'] != item['proof']):
                    raise Conflict('original immutable template asset differs')
                if observed['exists']:present.add(path)
        for path,proof in directories:
            with self.files._parent(path+'/.inventory-probe') as (fd,_):
                expected = {PurePosixPath(p).name for p in present if str(PurePosixPath(p).parent) == path}
                if identity(os.fstat(fd)) != {k:proof['identity'][k] for k in self.parent} or set(os.listdir(fd)) != expected:
                    raise Conflict('template directory identity or complete member inventory differs')

    def _guard(self, value, *, mutating=True):
        request = value['request']
        with self._root() as (fd,_):
            if identity(os.fstat(fd)) != self.parent:raise Conflict('original template store parent changed')
        if self.window.receipt['targets'] != [item['spec']['key'] for item in value['items']]:
            raise Conflict('complete original template window targets required')
        if mutating:
            for item in value['items']:self.window.verify(item,request['id'],request['window_sha256'])
        self._source(value);self._targets(value)
        if mutating:
            if self.preflight(deepcopy(request)) != dict(request_sha256=fingerprint(request),exclusive_writer=True):
                raise Conflict('complete template import preflight differs')
            self._source(value);self._targets(value)
            for item in value['items']:self.window.verify(item,request['id'],request['window_sha256'])

    def prepare(self, operation, *, source, template_sha256):
        from .libvirt_xml import absolute
        if self.readonly:raise Conflict('readonly bundle observer')
        identifier(operation,'template bundle import');absolute(source)
        if not digest(template_sha256):raise Conflict('immutable template digest required')
        with self.journal.execution_lock:
            prior = self.journal.db.execute('SELECT id FROM vm_template_bundle_imports WHERE id=?',(operation,)).fetchone()
            if prior:
                saved = self.read(operation)
                if saved['request']['source'] != source or saved['request']['template_sha256'] != template_sha256:
                    raise Conflict('bundle import request changed')
                return saved
            destination = str(PurePosixPath(self.root)/template_sha256)
            if self.journal.db.execute('SELECT 1 FROM vm_template_bundle_imports WHERE path=?',(destination,)).fetchone():
                raise Conflict('template bundle destination reserved by another import')
            proof = read_bundle(source,template_sha256)
            with self.files._parent(source+'/manifest.json') as (root,_):
                if list(metadata(os.fstat(root))) != proof['directory_metadata']:raise Conflict('source bundle changed')
                with pinned_file(root,'manifest.json') as (fd,_):
                    before = metadata(os.fstat(fd));raw = os.read(fd,1024*1024+1)
                    if (len(raw) > 1024*1024 or metadata(os.fstat(fd)) != before
                            or validate_template(json.loads(raw,object_pairs_hook=unique_pairs)) != proof['template']):
                        raise Conflict('original bundle manifest changed')
            manifest = dict(metadata=list(before),sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
            request = dict(id=operation,source=source,template_sha256=template_sha256,source_proof=proof,
                           manifest=manifest,root=self.root,parent=self.parent,window_sha256=self.window.sha256)
            value = dict(request=request,phase='prepared',proof=None,items=[
                dict(spec=spec,phase='prepared',nonce=uuid.uuid4().hex,proof=None)
                for spec in bundle_plan(self.root,source,proof['template'],manifest)])
            self._guard(value)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO vm_template_bundle_imports VALUES(?,?,?,?)',
                    (operation,value['items'][0]['spec']['path'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def _run(self, operation, *, recover):
        if self.readonly:raise Conflict('readonly bundle observer')
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'ready':return self.observe(operation)
            if not recover and value['phase'] != 'prepared':raise Conflict('bundle import pending; explicit recovery required')
            self._guard(value);value['phase'] = 'installing';self._save(value)
            for item in value['items']:
                if item['phase'] == 'created':continue
                self._guard(value)
                if item['phase'] == 'prepared':
                    item['phase'] = 'requested';self._save(value);self._guard(value)
                if item['spec']['kind'] == 'directory':
                    birth = self.files._birth(item,operation)
                    if birth is None:proof = self.files.create(item,operation,window=self.window)
                    elif birth['phase'] == 'durability_confirmed':proof = self.files.observe(item,operation)
                    else:proof = self.files.recover(item,operation,window=self.window)
                else:
                    assets = self._assets(value,item);child = self._asset_id(value,item);spec = item['spec']
                    row = self.journal.db.execute('SELECT 1 FROM vm_template_asset_files WHERE id=?',(child,)).fetchone()
                    if row is None:assets.prepare(child,source=spec['source'],destination=spec['path'],sha256=spec['sha256'],size=spec['size'])
                    state = assets.read(child)['phase']
                    if state == 'prepared':proof = assets.apply(child)
                    elif state == 'ready':proof = assets.observe(child)
                    elif recover:proof = assets.recover(child)
                    else:raise Conflict('original asset copy requires explicit recovery')
                self._guard(value)
                item.update(phase='created',proof=proof);self._save(value)
            self._guard(value)
            proof = read_bundle(value['items'][0]['spec']['path'],value['request']['template_sha256'])
            if proof['template'] != value['request']['source_proof']['template']:raise Conflict('completed bundle template differs')
            self._guard(value)
            value.update(phase='ready',proof=proof);self._save(value)
            return self.observe(operation)

    def apply(self, operation):return self._run(operation,recover=False)
    def recover(self, operation):return self._run(operation,recover=True)

    def observe(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] != 'ready':raise Conflict('complete original bundle publication missing')
            self._guard(value,mutating=False)
            proof = read_bundle(value['items'][0]['spec']['path'],value['request']['template_sha256'])
            if proof != value['proof']:raise Conflict('original published bundle changed')
            self._guard(value,mutating=False)
            return dict(operation_id=operation,directory=value['items'][0]['spec']['path'],
                        template_sha256=value['request']['template_sha256'],bundle=proof)
