"""Tracked recreation of absent session directories in one qualified boot.

No account/file/service mutation or cleanup is exposed. The filesystem adapter
must create exclusive directory births and recover only original durability.
A completed result qualifies these directories, not daemon/VM readiness or the
legacy revision path, whose original boot guard remains unchanged.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath
import uuid

from .libvirt_install import proof
from .manifest import Conflict,canonical,fingerprint,identifier


class VolatileDirectories:
    def __init__(self,qualification,files,*,window):
        self.qualification,self.files,self.window=qualification,files,window
        self.journal=qualification.journal
        if files.journal is not self.journal:raise Conflict('one original recovery journal required')
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_volatile_recoveries '
                '(id TEXT PRIMARY KEY,qualification_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _specs(self,qualified):
        root=PurePosixPath(qualified['installation']['profile']['session']['runtime_root'])
        items=[item for item in qualified['installation']['items'] if item['spec']['key'] in qualified['plan']['volatile']]
        if not items or any(item['spec']['kind']!='directory' or not PurePosixPath(item['spec']['path']).is_relative_to(root) for item in items):
            raise Conflict('only explicit session runtime directories may recover')
        return items

    def _binding(self,value):
        qualified=self.qualification.read(value['qualification_id'])
        if (qualified['phase']!='persistent_qualified' or fingerprint(qualified)!=value['qualification_sha256']
                or qualified['context']!=value['context'] or self.window.sha256!=value['window_sha256']
                or self.window.receipt['operation_id']!=value['id'] or self.window.receipt['context']!=value['context']
                or set(self.window.receipt['targets'])!=set(qualified['plan']['volatile'])):
            raise Conflict('original volatile recovery context/window differs')
        return qualified

    def read(self,operation):
        row=self.journal.db.execute('SELECT * FROM libvirt_volatile_recoveries WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original volatile recovery missing')
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=operation or value['qualification_id']!=row['qualification_id']
                or value['phase'] not in ('prepared','applying','directories_qualified')):
            raise Conflict('original volatile recovery intent differs')
        qualified=self._binding(value);originals=self._specs(qualified)
        if len(value['items'])!=len(originals):raise Conflict('complete volatile directory inventory required')
        if len({item['nonce'] for item in value['items']})!=len(originals):raise Conflict('distinct current-boot births required')
        for item,original in zip(value['items'],originals):
            nonce=item['nonce']
            if (item['spec']!=original['spec'] or not isinstance(nonce,str) or len(nonce)!=32
                    or any(c not in '0123456789abcdef' for c in nonce) or nonce==original['nonce']
                    or item['phase'] not in ('prepared','create_requested','created')):
                raise Conflict('original current-boot directory request differs')
            if item['phase']=='created':proof(item['proof'],item,operation)
            elif item['proof'] is not None:raise Conflict('unexpected current-boot directory proof')
        if value['phase']=='directories_qualified' and any(item['phase']!='created' for item in value['items']):
            raise Conflict('current-boot directory recovery incomplete')
        if value['phase']=='prepared' and any(item['phase']!='prepared' for item in value['items']):
            raise Conflict('unexpected allocation in prepared recovery')
        return value

    def _save(self,value):
        self.journal.db.execute('UPDATE libvirt_volatile_recoveries SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    def _preflight(self,value,*,window=True,pending=None):
        qualified=self._binding(value)
        if window:
            for item in value['items']:self.window.verify(item,value['id'],value['window_sha256'])
        observed=self.qualification.observe_persistent(value['qualification_id'])
        if observed['qualification_sha256']!=value['qualification_sha256']:
            raise Conflict('original persistent qualification changed')
        result={}
        for item in value['items']:
            state=observed['observation']['volatile'][item['spec']['key']]['state']
            if item['nonce']==pending:
                birth=self.files._birth(item,value['id'])
                if birth is None or birth['file'] is None or state!='present_unqualified':
                    raise Conflict('original pending directory birth required; no adoption')
                result[item['spec']['key']]=None
                continue
            current=self.files.observe(item,value['id'])
            if (current is None and state!='absent') or (current is not None and state!='present_unqualified'):
                raise Conflict('current volatile inventory disagrees with birth observer')
            if item['phase']=='prepared' and current is not None:raise Conflict('volatile directory target already occupied')
            if item['phase']=='created' and current!=item['proof']:raise Conflict('current-boot directory replaced or missing')
            if current is not None:proof(current,item,value['id'])
            result[item['spec']['key']]=current
        # Persistent state may change while the directory identities are read.
        after=self.qualification.observe_persistent(value['qualification_id'])
        if after!=observed:raise Conflict('complete volatile recovery preflight changed')
        if window:
            for item in value['items']:self.window.verify(item,value['id'],value['window_sha256'])
        return result

    def prepare(self,operation,qualification_id):
        identifier(operation,'volatile recovery operation_id')
        with self.journal.execution_lock:
            qualified=self.qualification.read(qualification_id)
            if qualified['phase']!='persistent_qualified':raise Conflict('completed persistent qualification required')
            if operation in (qualification_id,qualified['installation']['id']):raise Conflict('separate recovery operation required')
            prior=self.journal.db.execute('SELECT id FROM libvirt_volatile_recoveries WHERE id=? OR qualification_id=?',
                (operation,qualification_id)).fetchone()
            if prior:
                value=self.read(prior['id'])
                if value['id']!=operation or value['qualification_id']!=qualification_id:raise Conflict('original recovery binding differs')
                self._preflight(value);return value
            items=[dict(spec=deepcopy(item['spec']),nonce=uuid.uuid4().hex,phase='prepared',proof=None) for item in self._specs(qualified)]
            value=dict(id=operation,qualification_id=qualification_id,qualification_sha256=fingerprint(qualified),
                context=deepcopy(qualified['context']),window_sha256=self.window.sha256,items=items,phase='prepared')
            self._preflight(value)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_volatile_recoveries VALUES(?,?,?,?)',
                    (operation,qualification_id,canonical(value),fingerprint(value)))
            return self.read(operation)

    def apply(self,operation):
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase']=='directories_qualified':return self.observe(operation)
            self._preflight(value)
            for item in value['items']:
                if item['phase']=='created':continue
                current=self._preflight(value)[item['spec']['key']]
                if item['phase']=='prepared':
                    item['phase']='create_requested';value['phase']='applying'
                    with self.journal.transaction():self._save(value)
                    self._preflight(value)
                    current=self.files.create(deepcopy(item),value['id'],window=self.window)
                    if self._preflight(value)[item['spec']['key']]!=current:
                        raise Conflict('current directory birth not independently observed')
                elif current is None:
                    raise Conflict('uncertain directory absence; create is not repeated')
                item.update(phase='created',proof=proof(current,item,value['id']))
                with self.journal.transaction():self._save(value)
            self._preflight(value)
            value['phase']='directories_qualified'
            with self.journal.transaction():self._save(value)
            return self.observe(operation)

    def recover(self,operation):
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase']=='directories_qualified':return self.observe(operation)
            if value['phase']!='applying':raise Conflict('original pending recovery required; no implicit apply')
            for item in value['items']:
                if item['phase']!='create_requested':continue
                self._preflight(value,pending=item['nonce'])
                current=self.files.recover(deepcopy(item),value['id'],window=self.window)
                if self._preflight(value)[item['spec']['key']]!=current:
                    raise Conflict('recovered directory birth not independently observed')
                item.update(phase='created',proof=proof(current,item,value['id']))
                with self.journal.transaction():self._save(value)
            return self.apply(operation)

    def observe(self,operation):
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase']!='directories_qualified':raise Conflict('volatile directory recovery pending')
            self._preflight(value,window=False)
            return dict(operation_id=operation,context=deepcopy(value['context']),qualification_sha256=value['qualification_sha256'],
                directories={item['spec']['key']:deepcopy(item['proof']) for item in value['items']},
                scope='session-directories-only',daemon_ready=False)
