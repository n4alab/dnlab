"""Separate post-boot persistent qualification; never activates old runtime state.

Only journal metadata is written. Observers are injected, without default host
reads. /run resources remain unqualified even if their names/old inode match.
The historical installation is immutable; this record is not its replacement.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath
import uuid

from .libvirt_install import targets,proof
from .libvirt_service_profile import render_profile,require_installable
from .libvirt_package_policy import INSTALLED_PACKAGES,prerequisites_for_policy
from .libvirt_run_parent import validate_run_parent
from .manifest import Conflict,canonical,fingerprint,identifier


def context(value):
    if (not isinstance(value,dict) or set(value)!={'host_id','boot_id','namespaces'}
            or any(not isinstance(value[k],str) or not value[k] for k in ('host_id','boot_id'))
            or not isinstance(value['namespaces'],dict) or set(value['namespaces'])!={'pid','mnt','net','user'}):
        raise Conflict('complete explicit post-boot context required')
    for identity in value['namespaces'].values():
        if (not isinstance(identity,dict) or set(identity)!={'device','inode'}
                or any(type(n) is not int or n<=0 for n in identity.values())):
            raise Conflict('explicit current namespace identities required')
    return deepcopy(value)


def plan(installation,current):
    current=context(current);old=context(installation['context'])
    if current['host_id']!=old['host_id'] or current['boot_id']==old['boot_id']:
        raise Conflict('same host and explicitly different boot required')
    if (installation['phase']!='installed_not_started'
            or installation['profile']!=render_profile(**installation['request'])
            or [item['spec'] for item in installation['items']]!=targets(installation['profile'])):
        raise Conflict('original complete inactive installation required')
    require_installable(installation['profile'])
    if (old['host_id']!=installation['profile']['session']['host_id']
            or installation['prerequisites'].get('profile_sha256')!=installation['profile']['profile_sha256']):
        raise Conflict('original post-boot profile/context binding differs')
    persistent=[];volatile=[]
    for item in installation['items']:
        spec=item['spec']
        if item['phase']=='dependency':
            if spec['kind']!='directory' or item['proof']!=installation['dependencies'].get(spec['path']):
                raise Conflict('original selected dependency required')
        elif item['phase']=='created':proof(item['proof'],item,installation['id'])
        else:raise Conflict('pending installation cannot qualify post-boot')
        destination=volatile if spec.get('path') and PurePosixPath(spec['path']).is_relative_to('/run') else persistent
        destination.append(spec['key'])
    return dict(persistent=persistent,volatile=volatile)


class PostBootQualification:
    def __init__(self,journal,*,source_reader,observer,account_history):
        if not all(callable(fn) for fn in (source_reader,observer,account_history)):
            raise Conflict('explicit post-boot source/current/history observers required')
        self.journal,self.source_reader,self.observer,self.account_history=journal,source_reader,observer,account_history
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_postboot_qualifications '
                '(id TEXT PRIMARY KEY,context_key TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _source(self,value):
        if self.source_reader(value['installation']['id'])!=value['installation']:
            raise Conflict('original installation changed during post-boot qualification')

    def read(self,operation):
        row=self.journal.db.execute('SELECT * FROM libvirt_postboot_qualifications WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original post-boot qualification missing')
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=operation
                or value['source_sha256']!=fingerprint(value['installation'])
                or value['plan']!=plan(value['installation'],value['context'])
                or value['phase'] not in ('prepared','persistent_qualified')
                or row['context_key']!=fingerprint([value['installation']['id'],value['context']])
                or not isinstance(value['nonce'],str) or len(value['nonce'])!=32
                or any(c not in '0123456789abcdef' for c in value['nonce'])):
            raise Conflict('original post-boot qualification binding differs')
        if value['phase']=='prepared' and value['receipt'] is not None:
            raise Conflict('unexpected post-boot qualification receipt')
        if 'package_policy' in value and value['package_policy']!=INSTALLED_PACKAGES:
            raise Conflict('original installed package policy differs')
        prerequisites_for_policy(value['installation']['prerequisites'],value.get('package_policy'))
        if 'run_parent' in value:validate_run_parent(value['run_parent'],value['installation'],value['context'])
        if value['phase']=='persistent_qualified':self._receipt(value,value['receipt'])
        return value

    @classmethod
    def _receipt(cls,value,receipt):
        fields={'qualification_id','nonce','source_sha256','context','observation','account_history','qualified','pending_volatile'}
        if 'package_policy' in value:fields.add('package_policy')
        if 'run_parent' in value:fields.add('run_parent_sha256')
        if (not isinstance(receipt,dict) or set(receipt)!=fields
                or receipt['qualification_id']!=value['id'] or receipt['nonce']!=value['nonce']
                or receipt['source_sha256']!=value['source_sha256'] or receipt['context']!=value['context']
                or receipt['qualified'] is not False or receipt['pending_volatile']!=value['plan']['volatile']):
            raise Conflict('original post-boot receipt differs')
        if 'package_policy' in value and receipt['package_policy']!=value['package_policy']:
            raise Conflict('original installed package receipt differs')
        if 'run_parent' in value and receipt['run_parent_sha256']!=fingerprint(value['run_parent']):
            raise Conflict('original current-boot /run parent receipt differs')
        cls._validate_observation(value,receipt['observation'])
        cls._histories(value,receipt['account_history'])
        return deepcopy(receipt)

    def prepare(self,operation,installation,current,*,package_policy=None,run_parent=None):
        identifier(operation,'post-boot operation_id');layout=plan(installation,current)
        prerequisites_for_policy(installation['prerequisites'],package_policy)
        if run_parent is not None:run_parent=validate_run_parent(run_parent,installation,current)
        with self.journal.execution_lock:
            if self.source_reader(installation['id'])!=installation:raise Conflict('original installation reference differs')
            key=fingerprint([installation['id'],current])
            prior=self.journal.db.execute('SELECT id FROM libvirt_postboot_qualifications WHERE id=? OR context_key=?',
                (operation,key)).fetchone()
            if prior:
                value=self.read(prior['id'])
                if (value['id']!=operation or value['installation']!=installation or value['context']!=current
                        or value.get('package_policy')!=package_policy or value.get('run_parent')!=run_parent):
                    raise Conflict('original post-boot request differs')
                return value
            value=dict(id=operation,nonce=uuid.uuid4().hex,installation=deepcopy(installation),source_sha256=fingerprint(installation),
                context=deepcopy(current),plan=layout,phase='prepared',receipt=None)
            if package_policy is not None:value['package_policy']=package_policy
            if run_parent is not None:value['run_parent']=deepcopy(run_parent)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_postboot_qualifications VALUES(?,?,?,?)',
                    (operation,key,canonical(value),fingerprint(value)))
            return self.read(operation)

    @staticmethod
    def _validate_observation(value,observed):
        original=value['installation']
        policy=value.get('package_policy')
        baseline=prerequisites_for_policy(original['prerequisites'],policy);baseline.pop('provisioning_window_sha256',None)
        if 'run_parent' in value:
            parent=validate_run_parent(value['run_parent'],original,value['context'])
            baseline['os_parents']['/run']=parent['identity']
        if isinstance(observed,dict) and isinstance(observed.get('prerequisites'),dict):
            observed=deepcopy(observed)
            observed['prerequisites']=prerequisites_for_policy(observed['prerequisites'],policy)
        expected={item['spec']['key']:item['proof'] for item in original['items'] if item['spec']['key'] in value['plan']['persistent']}
        if (not isinstance(observed,dict) or set(observed)!={'context','prerequisites','persistent','volatile'}
                or observed['context']!=value['context'] or observed['prerequisites']!=baseline
                or observed['persistent']!=expected or not isinstance(observed['volatile'],dict)
                or set(observed['volatile'])!=set(value['plan']['volatile'])):
            raise Conflict('complete current post-boot observation differs')
        for state in observed['volatile'].values():
            if not isinstance(state,dict) or set(state)!={'state'} or state['state'] not in ('absent','present_unqualified'):
                raise Conflict('volatile resource needs separate current-boot qualification')
        services=baseline.get('services',{});profile=original['profile']
        if (set(services)!={'units','dedicated_uid','processes'} or type(services['dedicated_uid']) is not int
                or services['dedicated_uid']!=profile['session']['uid'] or services['processes']!=[]
                or set(services['units'])!=set(profile['service_order']+profile['forbidden_vendor_activation'])):
            raise Conflict('complete inactive post-boot service inventory required')
        for state in services['units'].values():
            if (set(state)!={'active_state','job_id'} or state['active_state']!='inactive'
                    or type(state['job_id']) is not int or state['job_id']!=0):
                raise Conflict('post-boot service active or pending')
        return deepcopy(observed)

    def _observation(self,value):
        return self._validate_observation(value,self.observer(deepcopy(value)))

    @staticmethod
    def _histories(value,histories):
        items=[item for item in value['installation']['items'] if item['spec']['kind'] in ('group','account')]
        if not isinstance(histories,dict) or set(histories)!={item['spec']['key'] for item in items}:
            raise Conflict('complete original historical account inventory required')
        for item in items:
            history=histories[item['spec']['key']]
            if (not isinstance(history,dict) or set(history)!={'kind','installation_sha256','original_proof','creation_context_sha256','evidence_sha256'}
                    or history['kind']!='historical-account-creation-v1' or history['installation_sha256']!=value['source_sha256']
                    or history['original_proof']!=item['proof']
                    or history['creation_context_sha256']!=fingerprint(value['installation']['context'])
                    or not isinstance(history['evidence_sha256'],str) or len(history['evidence_sha256'])!=64
                    or any(c not in '0123456789abcdef' for c in history['evidence_sha256'])):
                raise Conflict('original historical account creation not qualified')

    def qualify_persistent(self,operation):
        with self.journal.execution_lock:
            value=self.read(operation);self._source(value)
            histories={item['spec']['key']:self.account_history(deepcopy(item)) for item in value['installation']['items']
                if item['spec']['kind'] in ('group','account')}
            self._histories(value,histories)
            observed=self._observation(value)
            if self._observation(value)!=observed:raise Conflict('post-boot resources changed during observation')
            self._source(value)
            candidate=dict(qualification_id=operation,nonce=value['nonce'],source_sha256=value['source_sha256'],
                context=value['context'],observation=observed,account_history=histories,qualified=False,pending_volatile=value['plan']['volatile'])
            if 'package_policy' in value:candidate['package_policy']=value['package_policy']
            if 'run_parent' in value:candidate['run_parent_sha256']=fingerprint(value['run_parent'])
            receipt=self._receipt(value,candidate)
            if value['phase']=='persistent_qualified':
                if receipt!=value['receipt']:raise Conflict('original post-boot observation changed; no implicit requalification')
                return receipt
            value.update(phase='persistent_qualified',receipt=receipt)
            with self.journal.transaction():
                self.journal.db.execute('UPDATE libvirt_postboot_qualifications SET payload=?,fingerprint=? WHERE id=?',
                    (canonical(value),fingerprint(value),operation))
            return receipt

    def require_revision_ready(self,operation):
        self.read(operation)
        raise Conflict('persistent qualification cannot authorize revision: current-boot volatile resources remain pending')

    def observe_persistent(self,operation):
        """Recheck persistent evidence without adopting changes to volatile paths.

        A separate recovery must explain each volatile delta with its own births.
        This method neither rewrites the original observation nor makes it ready.
        """
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase']!='persistent_qualified':raise Conflict('original persistent qualification required')
            self._source(value)
            histories={item['spec']['key']:self.account_history(deepcopy(item)) for item in value['installation']['items']
                if item['spec']['kind'] in ('group','account')}
            self._histories(value,histories)
            if histories!=value['receipt']['account_history']:raise Conflict('original account history changed')
            observed=self._observation(value)
            if self._observation(value)!=observed:raise Conflict('post-boot resources changed during observation')
            self._source(value)
            return dict(qualification_sha256=fingerprint(value),receipt=deepcopy(value['receipt']),observation=observed)
