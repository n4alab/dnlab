"""One explicit prerequisite-policy revision; native replacement stays injected.

The installation record is never rewritten. An adapter must qualify all original
resources and inactive services before acting, reserve staging/backup paths and
durably retain the original inode plus the replacement birth. No path-only
adoption, second replacement on uncertainty, rollback or service reload is here.
"""
from copy import deepcopy
import json
import uuid

from .libvirt_service_profile import EXPLICIT_ACTIVATION, render_profile, require_activatable
from .manifest import Conflict, canonical, fingerprint, identifier

UNIT='/etc/systemd/system/dnlab-libvirtd.service'


def compile_revision(installation):
    if (installation['phase']!='installed_not_started'
            or any(item['phase'] not in ('created','dependency') for item in installation['items'])
            or installation['profile']!=render_profile(**installation['request'])
            or installation['profile'].get('activation_policy') is not None):
        raise Conflict('original inactive legacy installation required for policy revision')
    request=dict(deepcopy(installation['request']),activation_policy=EXPLICIT_ACTIVATION)
    profile=render_profile(**request);require_activatable(profile)
    source=installation['profile']
    if (profile['directories']!=source['directories'] or set(profile['files'])!=set(source['files'])
            or [p for p in source['files'] if source['files'][p]!=profile['files'][p]]!=[UNIT]):
        raise Conflict('policy revision must change only the original libvirtd unit')
    matches=[item for item in installation['items'] if item['spec'].get('path')==UNIT]
    if len(matches)!=1 or matches[0]['phase']!='created':raise Conflict('original unit birth required')
    spec=dict(matches[0]['spec'],**profile['files'][UNIT])
    return dict(request=request,profile=profile,source_item=deepcopy(matches[0]),target_spec=spec,
        unchanged_sha256=fingerprint([item for item in installation['items'] if item is not matches[0]]))


def project_revision(value):
    """Project validated lineage only; this is not a current readiness proof."""
    if (value['phase']!='completed' or value['plan']!=compile_revision(value['installation'])
            or value['source_sha256']!=fingerprint(value['installation'])):
        raise Conflict('completed original configuration lineage required')
    ConfigurationRevision._receipt(value,value['proof'])
    result=deepcopy(value['installation']);result.update(request=value['plan']['request'],profile=value['plan']['profile'])
    result['prerequisites']['profile_sha256']=result['profile']['profile_sha256']
    for item in result['items']:
        if item['spec'].get('path')==UNIT:
            item.update(spec=deepcopy(value['plan']['target_spec']),nonce=value['nonce'],proof=deepcopy(value['proof']['replacement']))
    result['configuration_revision']=dict(operation_id=value['id'],source_sha256=value['source_sha256'],receipt_sha256=fingerprint(value['proof']))
    return result


class ConfigurationRevision:
    def __init__(self,journal,adapter,*,window,generation_source=None,readonly=False):
        self.journal,self.adapter,self.window=journal,adapter,window
        self.generation_source=generation_source
        self.readonly=readonly
        if readonly:return
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_configuration_revisions '
                '(id TEXT PRIMARY KEY,installation_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_configuration_generations '
                '(id TEXT PRIMARY KEY,installation_id TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_configuration_retirements '
                '(id TEXT PRIMARY KEY,revision_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self,operation):
        with self.journal.lock:
            rows=[row for table in ('libvirt_configuration_revisions','libvirt_configuration_generations')
                for row in self.journal.db.execute('SELECT * FROM '+table+' WHERE id=?',(operation,)).fetchall()]
            if len(rows)>1:raise Conflict('ambiguous configuration revision identity')
            row=rows[0] if rows else None
        if row is None:raise Conflict('original configuration revision missing')
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=row['id']
                or value['installation']['id']!=row['installation_id']
                or value['plan']!=compile_revision(value['installation'])
                or value['source_sha256']!=fingerprint(value['installation'])
                or value['phase'] not in ('prepared','replace_requested','completed')):
            raise Conflict('original configuration revision differs')
        nonce=value['nonce']
        if not isinstance(nonce,str) or len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):
            raise Conflict('original configuration revision nonce differs')
        prefix='/etc/systemd/system/.dnlab-libvirtd.'+nonce
        if value['staging']!=prefix+'.candidate' or value['backup']!=prefix+'.previous':
            raise Conflict('original configuration staging paths differ')
        if value['phase']=='completed':self._receipt(value,value['proof'])
        elif value['proof'] is not None:raise Conflict('unexpected configuration revision proof')
        if 'predecessor' in value:
            from .libvirt_configuration_retirement import retirement
            predecessor=self.read(value['predecessor']['revision_id'])
            receipt=retirement(self.journal,predecessor)
            if (receipt is None or fingerprint(receipt)!=value['predecessor']['retirement_sha256']
                    or receipt['current_source_sha256']!=value['source_sha256']):
                raise Conflict('original configuration predecessor differs')
        return value

    def _active(self,value):
        from .libvirt_configuration_retirement import retirement
        if retirement(self.journal,value) is not None:raise Conflict('configuration revision retired')

    def _save(self,value):
        self._active(value)
        tables=[table for table in ('libvirt_configuration_revisions','libvirt_configuration_generations')
            if self.journal.db.execute('SELECT id FROM '+table+' WHERE id=?',(value['id'],)).fetchone()]
        if len(tables)!=1:raise Conflict('original configuration storage differs')
        self.journal.db.execute('UPDATE '+tables[0]+' SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    @staticmethod
    def _receipt(value,receipt):
        source=value['plan']['source_item']['proof']
        if (not isinstance(receipt,dict) or set(receipt)!={'operation_id','nonce','source_proof','backup','replacement'}
                or receipt['operation_id']!=value['id'] or receipt['nonce']!=value['nonce']
                or receipt['source_proof']!=source
                or receipt['backup']!=dict(path=value['backup'],identity=source['identity'])):
            raise Conflict('original configuration backup/transition proof differs')
        replacement=receipt['replacement']
        if (not isinstance(replacement,dict) or set(replacement)!={'intent_id','nonce','spec_sha256','identity'}
                or replacement['intent_id']!=value['id'] or replacement['nonce']!=value['nonce']
                or replacement['spec_sha256']!=fingerprint(value['plan']['target_spec'])
                or not isinstance(replacement['identity'],dict) or not replacement['identity']
                or replacement['identity']==source['identity']):
            raise Conflict('original replacement file birth differs')
        return deepcopy(receipt)

    def _observe(self,value,*,require_window=True):
        if self.readonly:raise Conflict('readonly configuration revision')
        self._active(value)
        if self.window.receipt['context']!=value['installation']['context']:
            raise Conflict('original configuration revision window context differs')
        item=dict(spec=value['plan']['target_spec'])
        if self.window.sha256!=value['window_sha256']:
            raise Conflict('original configuration revision window binding differs')
        if require_window:self.window.verify(item,value['id'],value['window_sha256'])
        result=self.adapter.observe(deepcopy(value))
        if (not isinstance(result,dict) or set(result)!={'context','source_sha256','unchanged_sha256','receipt'}
                or result['context']!=value['installation']['context'] or result['source_sha256']!=value['source_sha256']
                or result['unchanged_sha256']!=value['plan']['unchanged_sha256']):
            raise Conflict('complete configuration revision preflight differs')
        current=result['receipt']
        if value['phase']=='prepared' and current is not None:raise Conflict('configuration revision target already occupied')
        if current is not None:self._receipt(value,current)
        if value['phase']=='completed' and current!=value['proof']:
            raise Conflict('original committed configuration generation replaced or missing')
        if require_window:self.window.verify(item,value['id'],value['window_sha256'])
        return current

    def prepare(self,operation,installation):
        if self.readonly:raise Conflict('readonly configuration revision')
        identifier(operation,'configuration revision operation_id')
        plan=compile_revision(installation)
        with self.journal.execution_lock:
            from .libvirt_configuration_retirement import retirement
            rows=[row for table in ('libvirt_configuration_revisions','libvirt_configuration_generations')
                for row in self.journal.db.execute('SELECT id FROM '+table+' WHERE id=? OR installation_id=?',
                    (operation,installation['id'])).fetchall()]
            values=[self.read(row['id']) for row in rows]
            for value in values:
                if value['id']==operation:self._active(value)
            active=[value for value in values if retirement(self.journal,value) is None]
            if len(active)>1:raise Conflict('multiple active configuration revisions')
            if active:
                value=active[0]
                if value['id']!=operation or value['installation']!=installation:
                    raise Conflict('original configuration revision request differs')
                self._observe(value);return value
            predecessor=None
            if values:
                if not callable(self.generation_source) or self.generation_source()!=installation:
                    raise Conflict('completed current-boot generation source required')
                matches=[value for value in values if retirement(self.journal,value)['current_source_sha256']==fingerprint(installation)]
                if len(matches)!=1:raise Conflict('original retirement for new configuration generation required')
                previous=matches[0];predecessor=dict(revision_id=previous['id'],
                    retirement_sha256=fingerprint(retirement(self.journal,previous)))
            nonce=uuid.uuid4().hex;prefix='/etc/systemd/system/.dnlab-libvirtd.'+nonce
            value=dict(id=operation,installation=deepcopy(installation),source_sha256=fingerprint(installation),plan=plan,
                nonce=nonce,staging=prefix+'.candidate',backup=prefix+'.previous',phase='prepared',proof=None,
                window_sha256=self.window.sha256)
            if predecessor is not None:value['predecessor']=predecessor
            self._observe(value)
            with self.journal.transaction():
                if predecessor is not None and self.generation_source()!=installation:
                    raise Conflict('current configuration generation source changed')
                table='libvirt_configuration_generations' if predecessor is not None else 'libvirt_configuration_revisions'
                self.journal.db.execute('INSERT INTO '+table+' VALUES(?,?,?,?)',
                    (operation,installation['id'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def apply(self,operation):
        if self.readonly:raise Conflict('readonly configuration revision')
        with self.journal.execution_lock:
            value=self.read(operation);self._active(value)
            if value['phase']=='completed':return self.effective(operation)
            current=self._observe(value)
            if value['phase']=='prepared':
                value['phase']='replace_requested'
                with self.journal.transaction():self._save(value)
                if self._observe(value) is not None:
                    raise Conflict('configuration replacement boundary changed; recovery required')
                current=self._receipt(value,self.adapter.replace(deepcopy(value)))
                if self._observe(value)!=current:raise Conflict('replacement not independently observed')
            elif current is None:
                raise Conflict('uncertain replacement requires original completion; no repeat')
            value.update(phase='completed',proof=self._receipt(value,current))
            with self.journal.transaction():self._save(value)
            return self.effective(operation)

    def recover(self,operation):
        if self.readonly:raise Conflict('readonly configuration revision')
        """Resume only a recorded replacement through its qualified adapter."""
        with self.journal.execution_lock:
            value=self.read(operation);self._active(value)
            if value['phase']=='completed':return self.effective(operation)
            recover=getattr(self.adapter,'recover',None)
            if value['phase']!='replace_requested' or not callable(recover):
                raise Conflict('original requested replacement and recovery adapter required')
            item=dict(spec=value['plan']['target_spec'])
            self.window.verify(item,value['id'],value['window_sha256'])
            current=self._receipt(value,recover(deepcopy(value)))
            if self._observe(value)!=current:raise Conflict('recovered replacement not independently observed')
            value.update(phase='completed',proof=current)
            with self.journal.transaction():self._save(value)
            return self.effective(operation)

    def effective(self,operation):
        value=self.read(operation);self._active(value)
        if value['phase']!='completed':raise Conflict('configuration revision remains pending')
        self._observe(value,require_window=False)
        return project_revision(value)
