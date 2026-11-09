"""Durable ownership for opt-in NOS fixtures, outside the production manifest.

Privileged fixture configuration is recorded here, never admitted as a native
Linux deployment. Unknown create responses cannot authorize adoption or cleanup.
"""
import json
import os
from pathlib import Path
import uuid

from dnlab_runtime.backend import LABEL,labels
from dnlab_runtime.manifest import canonical,fingerprint
from dnlab_runtime.management_authority import bind_backend
from dnlab_runtime.workload_generation import GenerationConflict,reserve,bind,latest,cleaned


class NosFixture:
    def __init__(self,journal,backend,request,spec):
        self.journal,self.backend=journal,backend
        self.request=json.loads(canonical(request));self.spec=json.loads(canonical(spec))
        bind_backend(backend,journal)
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS nos_fixture_intents (lab TEXT NOT NULL,node TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,node))')
        self.sync()

    def sync(self):
        path=Path(self.journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def get(self):
        with self.journal.lock:
            row=self.journal.db.execute('SELECT payload FROM nos_fixture_intents WHERE lab=? AND node=?',
                (self.request['lab_id'],self.request['node_id'])).fetchone()
        if not row:return None
        value=json.loads(row[0]);original=value['original']
        if (fingerprint(original)!=value['fingerprint'] or original['request']!=self.request or original['spec']!=self.spec):
            raise GenerationConflict('NOS fixture original intent changed')
        return value

    def put(self,value):
        if value['phase']!='recovery_required':value.pop('resume_from',None)
        with self.journal.transaction():
            prior=self.get()
            if prior and (prior['id']!=value['id'] or prior['fingerprint']!=value['fingerprint']):
                raise GenerationConflict('NOS fixture intent replacement refused')
            self.journal.db.execute('INSERT INTO nos_fixture_intents VALUES(?,?,?) ON CONFLICT(lab,node) DO UPDATE SET payload=excluded.payload',
                (self.request['lab_id'],self.request['node_id'],canonical(value)))
        self.sync()

    def failure(self):
        value=self.get()
        if value and value['phase']!='cleaned':
            if value['phase']!='recovery_required':value['resume_from']=value['phase']
            value['phase']='recovery_required';self.put(value)

    def prepare(self,config):
        config=json.loads(canonical(config))
        expected=labels(self.request,self.spec)
        if (config.get('Image')!=self.spec['image'] or not config.get('Labels',{}).get('io.dnlab.spike')
                or any(config.get('Labels',{}).get(k)!=v for k,v in expected.items())
                or any(k in config.get('Labels',{}) for k in (LABEL+'.creator',LABEL+'.birth'))):
            raise GenerationConflict('NOS fixture creation configuration is not qualified')
        original={'request':self.request,'spec':self.spec,'config':config}
        value=self.get()
        if value:
            if value['fingerprint']!=fingerprint(original):raise GenerationConflict('NOS fixture creation request changed')
        else:
            value={'id':uuid.uuid4().hex,'original':original,'fingerprint':fingerprint(original),
                   'phase':'prepared','container_id':None}
            self.put(value)
        if value['phase']=='prepared':
            birth=reserve(self.journal,self.request,self.spec,value['id'])
            value.update(phase='reserved',nonce=birth['nonce']);self.put(value)
        return value

    def bind_response(self,value):
        identity=value['container_id']
        current=self.backend.docker.inspect(self.spec['container_name'])
        if not current or current['Id']!=identity:
            raise GenerationConflict('NOS fixture Docker response identity changed')
        birth=latest(self.journal,self.request)
        actual=current.get('Config',{}).get('Labels') or {}
        if (not birth or birth['creator']!=value['id'] or birth['nonce']!=value.get('nonce')
                or birth['spec']!=fingerprint(self.spec) or actual.get(LABEL+'.creator')!=value['id']
                or actual.get(LABEL+'.birth')!=value['nonce']):
            raise GenerationConflict('NOS fixture birth intent or labels changed')
        if birth['phase']=='reserved' and birth['container_id'] is None:
            bind(self.journal,self.request,self.spec,value['id'],identity);self.sync()
        elif birth['container_id']!=identity or birth['phase'] not in ('bound','running'):
            raise GenerationConflict('NOS fixture bound generation changed')
        self.backend.owned(self.request,self.spec,current)
        return current

    def create(self,config):
        with self.journal.execution_lock:
            value=self.prepare(config)
            try:
                if value['phase']=='cleaned':raise GenerationConflict('NOS fixture attempt is already cleaned')
                if value['container_id']:
                    self.bind_response(value);return value['container_id']
                if value['phase'] not in ('prepared','reserved'):
                    raise GenerationConflict('NOS fixture create response unknown; recovery required')
                if self.backend.docker.inspect(self.spec['container_name']) is not None:
                    raise GenerationConflict('NOS fixture container name is occupied')
                effective=json.loads(canonical(value['original']['config']))
                effective['Labels'].update({LABEL+'.creator':value['id'],LABEL+'.birth':value['nonce']})
                value.update(phase='create_pending',effective_config=effective);self.put(value)
                response=self.backend.docker.create(self.spec['container_name'],effective)
                identity=response.get('Id') if isinstance(response,dict) else None
                if not isinstance(identity,str) or not identity:raise GenerationConflict('NOS fixture create response has no ID')
                value.update(phase='response_recorded',container_id=identity);self.put(value)
                self.bind_response(value)
                value['phase']='bound';self.put(value)
                return identity
            except BaseException as error:
                if isinstance(error,Exception):self.failure()
                raise

    def start(self):
        with self.journal.execution_lock:
            value=self.get()
            if not value or not value['container_id']:raise GenerationConflict('NOS fixture birth must be bound before start')
            if value.get('resume_from',value['phase']) not in ('bound','response_recorded','start_pending','running'):
                raise GenerationConflict('NOS fixture cannot start during cleanup or after finalization')
            try:
                self.sync();self.bind_response(value)
                value['phase']='start_pending';self.put(value)
                self.backend.start(self.request,self.spec)
                value['phase']='running';self.put(value)
                return self.backend.inspect(self.request,self.spec)
            except BaseException as error:
                if isinstance(error,Exception):self.failure()
                raise

    def recover(self):
        """Explicitly resume a proven attempt; never resolve unknown create by name."""
        with self.journal.execution_lock:
            value=self.get()
            if not value:raise GenerationConflict('NOS fixture original intent missing')
            if not value['container_id'] and value['phase']=='recovery_required':
                previous=value.get('resume_from')
                if previous not in ('prepared','reserved'):
                    raise GenerationConflict('NOS fixture create response unknown; recovery required')
                if self.backend.docker.inspect(self.spec['container_name']) is not None:
                    raise GenerationConflict('NOS fixture container name is occupied')
                value['phase']=previous;value.pop('resume_from',None);self.put(value)
            return self.create(value['original']['config'])

    def cleanup(self,*,force=False):
        with self.journal.execution_lock:
            value=self.get();self.sync()
            if not value:
                if self.backend.docker.inspect(self.spec['container_name']) is not None:
                    raise GenerationConflict('NOS fixture has no original creation intent')
                return
            try:
                current=self.backend.docker.inspect(self.spec['container_name'])
                identity=value['container_id']
                if identity is None:
                    if value.get('resume_from',value['phase']) not in ('prepared','reserved') or current is not None:
                        raise GenerationConflict('NOS fixture create response unknown; cleanup refused')
                elif current is not None:
                    self.bind_response(value)
                    value['phase']='cleanup_requested';self.put(value)
                    self.backend.stop(self.request,self.spec,force=force)
                    self.backend.remove(self.request,self.spec)
                if (self.backend.docker.inspect(self.spec['container_name']) is not None
                        or identity and self.backend.docker.inspect(identity) is not None):
                    raise GenerationConflict('NOS fixture workload absence is not verified')
                cleaned(self.journal,self.request,self.spec)
                value['phase']='cleaned';self.put(value)
            except BaseException as error:
                if isinstance(error,Exception):self.failure()
                raise
