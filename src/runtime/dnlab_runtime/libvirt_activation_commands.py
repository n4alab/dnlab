"""Durable activation commands with an explicit blocked-worker runner.

No native runner or subprocess default is supplied. Commands are fixed to one
manager reload and the three original dedicated starts. A successful command
receipt is not service readiness; process/socket qualification stays separate.
"""
from copy import deepcopy
import json
import re

from .libvirt_activation import steps
from .libvirt_account_commands import reference_proof
from .libvirt_service_profile import require_activatable,render_profile
from .manifest import Conflict,canonical,fingerprint

ENVIRONMENT=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',
    SYSTEMD_PAGER='cat',SYSTEMD_COLORS='0',SYSTEMD_LOG_COLOR='0')


def command_plan(installation,item,activation_id,binary):
    from .manifest import identifier
    identifier(activation_id,'original activation command ID');require_activatable(installation['profile'])
    if (installation['profile']!=render_profile(**installation['request'])
            or not isinstance(installation['context'].get('namespaces'),dict) or not installation['context']['namespaces']
            or not isinstance(binary,dict) or set(binary)!={'path','sha256'} or binary['path']!='/usr/bin/systemctl'
            or not isinstance(binary['sha256'],str) or re.fullmatch('[0-9a-f]{64}',binary['sha256']) is None
            or item['spec'] not in steps(installation['profile']) or not isinstance(item['nonce'],str)
            or re.fullmatch('[0-9a-f]{32}',item['nonce']) is None):
        raise Conflict('fixed original activation command required')
    spec=item['spec']
    argv=[binary['path'],'daemon-reload'] if spec['kind']=='reload' else [binary['path'],'start','--',spec['unit']]
    request=dict(activation_id=activation_id,installation_sha256=fingerprint(installation),spec=deepcopy(spec),nonce=item['nonce'])
    return dict(request_sha256=fingerprint(request),binary=deepcopy(binary),argv=argv,environment=deepcopy(ENVIRONMENT))


class ActivationCommands:
    def __init__(self,journal,*,binary,runner,activation_reader,preflight,after_outcome=None):
        if not callable(activation_reader) or not callable(preflight):raise Conflict('explicit original command providers required')
        self.journal,self.binary,self.runner=journal,deepcopy(binary),runner
        self.activation_reader,self.preflight=activation_reader,preflight
        if after_outcome is not None and not callable(after_outcome):raise Conflict('explicit outcome qualifier required')
        self.after_outcome=after_outcome
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_commands '
                '(activation_id TEXT NOT NULL,nonce TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(activation_id,nonce))')

    def _bind(self,item,operation):
        value=self.activation_reader(operation)
        matches=[current for current in value['items'] if current['spec']==item['spec'] and current['nonce']==item['nonce']]
        if (value['id']!=operation or value['installation_sha256']!=fingerprint(value['installation'])
                or len(matches)!=1 or matches[0]['phase'] not in ('requested','confirmed')
                or [current['spec'] for current in value['items']]!=steps(value['installation']['profile'])):
            raise Conflict('original requested activation command binding differs')
        return value,matches[0]

    def _read(self,item,operation):
        activation,current=self._bind(item,operation)
        row=self.journal.db.execute('SELECT * FROM libvirt_activation_commands WHERE activation_id=? AND nonce=?',
            (operation,item['nonce'])).fetchone()
        if row is None:return None
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['activation_id']!=operation or value['nonce']!=item['nonce']
                or value['command']!=command_plan(activation['installation'],current,operation,self.binary)
                or value['installation_sha256']!=activation['installation_sha256']
                or value['context']!=activation['installation']['context']
                or value['phase'] not in ('arming_requested','armed','release_requested','completed')):
            raise Conflict('original activation command journal differs')
        if value['reference'] is not None:self._reference(value,value['reference'])
        if value['phase']=='arming_requested':
            if value['reference'] is not None or value['outcome'] is not None:raise Conflict('unexpected armed command proof')
        elif value['reference'] is None:raise Conflict('original command process reference missing')
        if value['phase']=='completed':self._validate_outcome(value,value['outcome'])
        elif value['outcome'] is not None:raise Conflict('unexpected activation command outcome')
        return value

    def _save(self,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_activation_commands SET payload=?,fingerprint=? WHERE activation_id=? AND nonce=?',
                (canonical(value),fingerprint(value),value['activation_id'],value['nonce']))

    def _check(self,value,item,*,requested=False):
        _,current=self._bind(item,value['activation_id'])
        if requested and current['phase']!='requested':raise Conflict('activation request changed before worker release')
        observed=self.preflight(deepcopy(value['command']))
        if observed!=value['preflight']:raise Conflict('original activation command preflight changed')

    @staticmethod
    def _reference(value,reference):
        reference_proof(reference,value['command'])
        record=reference['process_record'];context=value['context']
        if (record['boot_id']!=context['boot_id'] or record['namespace_sha256']!=fingerprint(context['namespaces'])):
            raise Conflict('original activation worker context differs')

    @staticmethod
    def _validate_outcome(value,result):
        if (not isinstance(result,dict) or set(result)!={'reference','exit_code','stdout','stderr'}
                or result['reference']!=value['reference'] or type(result['exit_code']) is not int
                or result['exit_code']!=0
                or any(not isinstance(result[key],str) or len(result[key].encode())>65536 for key in ('stdout','stderr'))):
            raise Conflict('original successful activation command outcome required')
        return deepcopy(result)

    def _outcome(self,value):
        if value['reference'] is None:return None
        self._reference(value,value['reference'])
        if self.runner.verify(deepcopy(value['reference']),deepcopy(value['command'])) is not True:
            raise Conflict('original activation worker verification failed')
        result=self.runner.outcome(deepcopy(value['reference']))
        if result is None:return None
        return self._validate_outcome(value,result)

    def _proof(self,value):
        return dict(sha256=fingerprint(value['command']),exit_code=0,process_reference_sha256=fingerprint(value['reference']))

    def original_completion(self,item,operation):
        """Readonly worker exit evidence, without recursive resource preflight.

        This does not qualify a service or host state. The owning activation
        preflight must independently qualify resources and process/socket proof.
        """
        with self.journal.execution_lock:
            value=self._read(item,operation)
            if value is None or value['phase'] not in ('release_requested','completed'):return None
            read=getattr(self.runner,'completed_outcome',None)
            if not callable(read):raise Conflict('readonly original activation completion reader required')
            result=read(deepcopy(value['reference']))
            if result is None:return None
            self._validate_outcome(value,result)
            if value['phase']=='completed' and result!=value['outcome']:raise Conflict('original activation outcome changed')
            return self._proof(value)

    def completion(self,item,operation):
        with self.journal.execution_lock:
            value=self._read(item,operation)
            if value is None or value['phase'] not in ('release_requested','completed'):return None
            self._check(value,item);result=self._outcome(value)
            if result is None:return None
            if value['phase']=='completed' and result!=value['outcome']:raise Conflict('original activation outcome changed')
            self._check(value,item)
            return self._proof(value)

    def recover(self,item,operation):
        with self.journal.execution_lock:
            value=self._read(item,operation)
            if value is None or value['phase'] not in ('release_requested','completed'):
                raise Conflict('original released activation command required; no arm or release on recovery')
            # Observe only the already released original worker first. Its exit
            # evidence may be needed by the progressive-service preflight.
            # _outcome still verifies its bound reference/process/context and
            # cannot arm or release a worker. No operation is confirmed here.
            result=self._outcome(value)
            if result is None:raise Conflict('original activation command outcome pending')
            if value['phase']=='completed' and result!=value['outcome']:raise Conflict('original activation outcome changed')
            if self.after_outcome is not None:self.after_outcome(deepcopy(item),operation,self._proof(value))
            self._check(value,item)
            if value['phase']!='completed':value.update(phase='completed',outcome=result);self._save(value)
            return self.completion(item,operation)

    def execute(self,item,operation):
        with self.journal.execution_lock:
            activation,current=self._bind(item,operation)
            if current['phase']!='requested':raise Conflict('original requested activation command required')
            if self._read(item,operation) is not None:raise Conflict('activation command already tracked; no execution retry')
            command=command_plan(activation['installation'],current,operation,self.binary)
            observed=self.preflight(deepcopy(command))
            if (not isinstance(observed,dict) or set(observed)!={'qualified','command_sha256','installation_sha256','context_sha256','inputs_sha256'}
                    or observed['qualified'] is not True or observed['command_sha256']!=fingerprint(command)
                    or observed['installation_sha256']!=activation['installation_sha256']
                    or observed['context_sha256']!=fingerprint(activation['installation']['context'])
                    or any(not isinstance(observed[key],str) or re.fullmatch('[0-9a-f]{64}',observed[key]) is None
                        for key in ('context_sha256','inputs_sha256'))):
                raise Conflict('complete qualified activation command preflight required')
            value=dict(activation_id=operation,nonce=item['nonce'],installation_sha256=activation['installation_sha256'],
                context=deepcopy(activation['installation']['context']),
                command=command,preflight=deepcopy(observed),phase='arming_requested',reference=None,outcome=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_activation_commands VALUES(?,?,?,?)',
                    (operation,item['nonce'],canonical(value),fingerprint(value)))
            self._check(value,item,requested=True)
            reference=self.runner.arm(deepcopy(command));self._reference(value,reference)
            value.update(phase='armed',reference=deepcopy(reference));self._save(value)
            self._check(value,item,requested=True)
            value['phase']='release_requested';self._save(value)
            self._check(value,item,requested=True)
            if self.runner.verify(deepcopy(reference),deepcopy(command)) is not True:
                raise Conflict('original activation worker differs before release')
            self.runner.release(deepcopy(reference))
            result=self._outcome(value)
            if result is None:raise Conflict('activation command outcome pending; no execution retry')
            if self.after_outcome is not None:self.after_outcome(deepcopy(item),operation,self._proof(value))
            self._check(value,item)
            value.update(phase='completed',outcome=result);self._save(value)
            return self.completion(item,operation)
