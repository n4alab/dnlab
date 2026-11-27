"""Persistent image-build exclusion for one gate; transports are explicit.

The observer qualifies original Docker/process/config/binding/job state. The
command provider arms original workers and owns their dispatch/exit receipts.
This controller never discovers a service, sends a signal, or retries an
uncertain dispatch. Native providers and the operator window remain mandatory.
"""
from copy import deepcopy
import json
import uuid

from .libvirt_account_commands import reference_proof
from .manifest import Conflict, canonical, fingerprint
from .vm_template import digest, fields, require

NO_RESTART = dict(Name='no',MaximumRetryCount=0)
STEPS = {'prepared':'disable_restart','policy_disabled':'stop',
         'cleanup_verified':'start','restarted':'restore_restart'}
NEXT = dict(disable_restart='policy_disabled',stop='held',start='restarted',restore_restart='restored')


def policy(value):
    fields(value,('Name','MaximumRetryCount'),'restart policy')
    require(value['Name'] in ('no','always','unless-stopped','on-failure')
            and type(value['MaximumRetryCount']) is int and value['MaximumRetryCount']>=0
            and (value['Name']=='on-failure' or value['MaximumRetryCount']==0), 'qualified restart policy required')


def actor(value):
    fields(value,('container_id','image_id','config_sha256','artifact_sha256','context_sha256','process_sha256'),
           'original image-build actor')
    require(all(digest(value[key]) for key in value if key!='image_id')
            and isinstance(value['image_id'],str) and value['image_id'].startswith('sha256:')
            and digest(value['image_id'][7:]), 'complete original image-build actor required')


class ImageBuildHold:
    def __init__(self, journal, *, observe, commands, window, cleanup):
        require(all(callable(fn) for fn in (observe,window,cleanup))
                and all(callable(getattr(commands,name,None)) for name in
                        ('arm','original_reference','verify','release','outcome')), 'qualified hold providers required')
        self.journal,self.observe,self.commands,self.window,self.cleanup = journal,observe,commands,window,cleanup
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS image_build_holds '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM image_build_holds WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original image-build hold missing')
        value = json.loads(row['payload'])
        fields(value,('id','scope','actor','policy','binding_sha256','jobs_sha256','nonce','phase','actions','cleanup'),
               'original hold intent')
        require(fingerprint(value)==row['fingerprint'] and value['id']==row['id']
                and value['phase'] in ('prepared','policy_disabled','held','cleanup_verified','restarted','restored'),
                'original image-build hold differs')
        actor(value['actor']);policy(value['policy'])
        completed,optional = {
            'prepared':([], 'disable_restart'), 'policy_disabled':(['disable_restart'],'stop'),
            'held':(['disable_restart','stop'],None), 'cleanup_verified':(['disable_restart','stop'],'start'),
            'restarted':(['disable_restart','stop','start'],'restore_restart'),
            'restored':(['disable_restart','stop','start','restore_restart'],None)}[value['phase']]
        require(type(value['actions']) is dict and set(completed)<=set(value['actions'])
                and set(value['actions'])<=set(completed+([optional] if optional else []))
                and all(value['actions'][key]['phase']=='completed' for key in completed)
                and (value['cleanup'] is not None)==(value['phase'] in ('cleanup_verified','restarted','restored')),
                'original hold lifecycle/action order differs')
        if value['cleanup'] is not None:self._cleanup_proof(value,value['cleanup'])
        for name,item in value['actions'].items():
            require(name in NEXT and item['command']==self._command(value,name)
                    and item['phase'] in ('arming_requested','armed','release_requested','completed'),
                    'original hold command differs')
            if item['reference'] is not None:self._reference(value,item,item['reference'])
            require((item['reference'] is not None or item['phase']=='arming_requested')
                    and (item['outcome'] is not None)==(item['phase']=='completed'), 'hold action receipt/stage differs')
            if item['outcome'] is not None:self._outcome(item,item['outcome'])
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE image_build_holds SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    @staticmethod
    def _key(value):return 'image-build-control:'+value['actor']['container_id']

    @staticmethod
    def _cleanup_proof(value, proof):
        fields(proof,('scope_sha256','resources_absent','pending_operations','receipt_sha256'),'same-gate cleanup')
        require(proof['scope_sha256']==fingerprint(value['scope']) and proof['resources_absent'] is True
                and type(proof['pending_operations']) is int and proof['pending_operations']==0 and digest(proof['receipt_sha256']),
                'same-gate original qualified cleanup required before restore')

    def _claim(self, value):
        row = self.journal.db.execute('SELECT * FROM resources WHERE key=?',(self._key(value),)).fetchone()
        require(row is not None and (row['lab'],row['node'],row['operation_id'])==
                (value['scope']['lab_id'],'image-build',value['id']), 'original exclusive image-build control claim required')

    def _window(self, value):
        self._claim(value)
        current = self.window(deepcopy(value))
        fields(current,('active','scope_sha256'),'original hold window')
        require(current['active'] is True and current['scope_sha256']==fingerprint(value['scope']),
                'original image-build exclusion window unavailable')

    def _snapshot(self, value, *, running, restart, expected_actor=None):
        current = self.observe(deepcopy(value))
        fields(current,('actor','running','restart_policy','idle','binding_aligned','binding_sha256','jobs_sha256'),
               'complete image-build hold observation')
        actor(current['actor']);policy(current['restart_policy'])
        require(all(type(current[key]) is bool for key in ('running','idle','binding_aligned')), 'typed image-build state required')
        require(current==dict(actor=expected_actor or value['actor'],running=running,restart_policy=restart,
                    idle=True,binding_aligned=True,binding_sha256=value['binding_sha256'],jobs_sha256=value['jobs_sha256']),
                'original image-build generation, policy, binding or jobs differ')
        return current

    def prepare(self, operation, *, scope, original_actor, restart_policy, binding_sha256, jobs_sha256):
        fields(scope,('gate_id','lab_id','host_id','coordinator_id','boot_id','window_id'),'original hold scope')
        require(all(type(v) is str and v and len(v)<=256 for v in scope.values())
                and isinstance(operation,str) and len(operation)==32 and all(c in '0123456789abcdef' for c in operation)
                and digest(binding_sha256) and digest(jobs_sha256), 'original scoped hold request required')
        actor(original_actor);policy(restart_policy)
        request = dict(scope=scope,actor=original_actor,policy=restart_policy,binding_sha256=binding_sha256,jobs_sha256=jobs_sha256)
        with self.journal.execution_lock:
            if self.journal.db.execute('SELECT 1 FROM image_build_holds WHERE id=?',(operation,)).fetchone():
                saved = self.read(operation)
                require(all(saved[key]==part for key,part in request.items()), 'original hold request cannot change')
                return saved
            value = deepcopy(dict(id=operation,**request,nonce=uuid.uuid4().hex,phase='prepared',actions={},cleanup=None))
            self._snapshot(value,running=True,restart=restart_policy)
            with self.journal.transaction():
                require(self.journal.db.execute('SELECT 1 FROM resources WHERE key=?',(self._key(value),)).fetchone() is None,
                        'image-build already controlled by another operation')
                self._snapshot(value,running=True,restart=restart_policy)
                self.journal.db.execute('INSERT INTO resources VALUES(?,?,?,?)',
                    (self._key(value),scope['lab_id'],'image-build',operation))
                self.journal.db.execute('INSERT INTO image_build_holds VALUES(?,?,?)',(operation,canonical(value),fingerprint(value)))
            return self.read(operation)

    def _command(self, value, action):
        original = value['actor']
        if action=='restore_restart':original = value['actions']['start']['outcome']['evidence']['actor']
        return dict(kind='image-build-control-v1',action=action,operation_id=value['id'],nonce=value['nonce'],
                    scope=deepcopy(value['scope']),actor=deepcopy(original),
                    restart_policy=deepcopy(value['policy'] if action=='restore_restart' else NO_RESTART),
                    binding_sha256=value['binding_sha256'],jobs_sha256=value['jobs_sha256'])

    @staticmethod
    def _outcome(item, outcome):
        fields(outcome,('reference','command_sha256','dispatch_count','evidence'),'original hold command outcome')
        require(outcome['reference']==item['reference'] and outcome['command_sha256']==fingerprint(item['command'])
                and type(outcome['dispatch_count']) is int and outcome['dispatch_count']==1,
                'original known single hold dispatch required')

    @staticmethod
    def _reference(value, item, reference):
        reference_proof(reference,item['command'])
        require(reference['process_record']['boot_id']==value['scope']['boot_id'],
                'original hold worker boot differs')

    def _pre(self, value, action):
        self._window(value)
        if action in ('start','restore_restart'):
            require(self.cleanup(deepcopy(value))==value['cleanup'], 'original cleanup changed before service restore')
        current_actor = value['actor'] if action!='restore_restart' else value['actions']['start']['outcome']['evidence']['actor']
        self._snapshot(value,running=action!='start',restart=value['policy'] if action=='disable_restart' else NO_RESTART,
                       expected_actor=current_actor)
        self._window(value)

    def _post(self, value, action, outcome):
        self._outcome(value['actions'][action],outcome)
        evidence = outcome['evidence'];expected_actor = value['actor']
        if action=='stop':
            fields(evidence,('process_sha256','pidfd_exit_verified','ordinary_shutdown_verified','drain_verified',
                             'term_count','force_used','exit_code'),'original image-build shutdown')
            require(evidence['process_sha256']==expected_actor['process_sha256']
                    and all(evidence[key] is True for key in ('pidfd_exit_verified','ordinary_shutdown_verified','drain_verified'))
                    and type(evidence['term_count']) is int and evidence['term_count']==1
                    and evidence['force_used'] is False and type(evidence['exit_code']) is int and evidence['exit_code'] in (0,143),
                    'original ordinary shutdown/drain required; exit code alone insufficient')
        elif action=='start':
            fields(evidence,('actor','original_start_verified'),'original image-build start')
            actor(evidence['actor']);expected_actor = evidence['actor']
            require(evidence['original_start_verified'] is True and all(expected_actor[key]==value['actor'][key]
                    for key in value['actor'] if key!='process_sha256')
                    and expected_actor['process_sha256']!=value['actor']['process_sha256'], 'original same-container startup required')
        else:
            require(evidence==dict(policy_verified=True), 'original restart-policy outcome required')
            if action=='restore_restart':expected_actor = value['actions']['start']['outcome']['evidence']['actor']
        self._snapshot(value,running=action!='stop',restart=value['policy'] if action=='restore_restart' else NO_RESTART,
                       expected_actor=expected_actor)
        self._window(value)

    def _action(self, value, action, *, recover):
        item = value['actions'].get(action)
        if item is None:
            require(not recover, 'no original hold command to recover')
            self._pre(value,action)
            item = dict(command=self._command(value,action),phase='arming_requested',reference=None,outcome=None)
            value['actions'][action] = item;self._save(value);self._pre(value,action)
            reference = self.commands.arm(deepcopy(item['command']))
            self._reference(value,item,reference);item.update(reference=reference,phase='armed');self._save(value)
        elif item['phase']=='arming_requested':
            require(recover, 'original hold arm uncertain; recovery required')
            reference = self.commands.original_reference(deepcopy(item['command']))
            if reference is None and callable(getattr(self.commands,'recover_arm',None)):
                reference = self.commands.recover_arm(deepcopy(item['command']))
            require(reference is not None, 'original hold worker unavailable; no second arm')
            self._reference(value,item,reference);item.update(reference=reference,phase='armed');self._save(value)
        if item['phase']=='armed':
            self._pre(value,action)
            require(self.commands.verify(item['reference'],item['command']) is True, 'original armed hold worker required')
            item['phase']='release_requested';self._save(value);self._pre(value,action)
            self.commands.release(deepcopy(item['reference']))
        if item['phase']=='release_requested':
            outcome = self.commands.outcome(deepcopy(item['reference']))
            if outcome is None and recover and callable(getattr(self.commands,'resume_unreleased',None)):
                self.commands.resume_unreleased(deepcopy(item['reference']))
                outcome = self.commands.outcome(deepcopy(item['reference']))
            if outcome is None and recover and callable(getattr(self.commands,'recover_outcome',None)):
                outcome = self.commands.recover_outcome(deepcopy(item['reference']))
            require(outcome is not None, 'hold dispatch/exit uncertain; no resend')
            self._post(value,action,outcome);item.update(phase='completed',outcome=deepcopy(outcome));self._save(value)
        else:self._post(value,action,item['outcome'])
        value['phase'] = NEXT[action];self._save(value)

    def acquire(self, operation, *, recover=False):
        with self.journal.execution_lock:
            value = self.read(operation)
            while value['phase'] in ('prepared','policy_disabled'):
                self._action(value,STEPS[value['phase']],recover=recover)
                recover = False
            require(value['phase']=='held', 'original hold is not held')
            return self.held(operation)

    def held(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);require(value['phase']=='held', 'original image-build hold required')
            self._post(value,'stop',value['actions']['stop']['outcome'])
            return dict(operation_id=operation,scope_sha256=fingerprint(value['scope']),hold_sha256=fingerprint(value),held=True)

    def restore(self, operation, *, recover=False):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase']=='held':
                self.held(operation)
                proof = self.cleanup(deepcopy(value))
                self._cleanup_proof(value,proof)
                value.update(cleanup=deepcopy(proof),phase='cleanup_verified');self._save(value)
                recover = False
            while value['phase'] in ('cleanup_verified','restarted'):
                self._action(value,STEPS[value['phase']],recover=recover);recover=False
            require(value['phase']=='restored', 'hold restore not complete')
            # Release only this operation's claim after the final verified policy.
            with self.journal.transaction():
                self.journal.db.execute('DELETE FROM resources WHERE key=? AND operation_id=?',(self._key(value),operation))
            return self.read(operation)
