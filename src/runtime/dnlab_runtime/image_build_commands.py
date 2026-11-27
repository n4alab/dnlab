"""Original image-build commands executed by one qualified runtime process.

Arming creates metadata only. Release records uncertainty before invoking the
mandatory native executor once. Completed receipts are durable; an unknown
execution is never repeated or reconstructed from a matching service name.
No process, signal, Docker request or service action has a default implementation.
"""
from copy import deepcopy
import json
import uuid

from .image_build_hold import actor, policy, NO_RESTART, STEPS
from .libvirt_account_commands import reference_proof
from .manifest import Conflict, canonical, fingerprint
from .vm_runtime_process import RuntimeProcess
from .vm_template import digest, fields, require


def validate_command(command):
    fields(command,('kind','action','operation_id','nonce','scope','actor','restart_policy','binding_sha256','jobs_sha256'),
           'original image-build control command')
    require(command['kind']=='image-build-control-v1' and command['action'] in STEPS.values()
            and all(isinstance(command[key],str) and len(command[key])==32
                    and all(c in '0123456789abcdef' for c in command[key]) for key in ('operation_id','nonce'))
            and all(digest(command[key]) for key in ('binding_sha256','jobs_sha256')), 'original fixed control command required')
    fields(command['scope'],('gate_id','lab_id','host_id','coordinator_id','boot_id','window_id'),'original service scope')
    require(all(type(v) is str and v and len(v)<=256 for v in command['scope'].values()), 'original service scope required')
    actor(command['actor']);policy(command['restart_policy'])
    require(command['action']=='restore_restart' or command['restart_policy']==NO_RESTART,
            'only tracked image-build policy transitions allowed')


class ImageBuildCommands:
    def __init__(self, runtime, *, read_hold, preflight, execute, recover=None):
        require(isinstance(runtime,RuntimeProcess) and all(callable(fn) for fn in (read_hold,preflight,execute)),
                'qualified current runtime and original control providers required')
        self.runtime,self.journal=runtime,runtime.journal
        self.read_hold,self.preflight,self.execute=read_hold,preflight,execute
        require(recover is None or callable(recover), 'qualified readonly recovery callback required')
        self.recover_callback=recover
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS image_build_arm_retirements '
                '(id TEXT PRIMARY KEY,hold_id TEXT UNIQUE NOT NULL,command_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS image_build_control_commands '
                '(id TEXT PRIMARY KEY,operation_id TEXT NOT NULL,action TEXT NOT NULL,container_id TEXT NOT NULL,'
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL,UNIQUE(operation_id,action))')

    @staticmethod
    def _context(epoch):
        return dict(host_id=epoch['profile']['host_id'],boot_id=epoch['snapshot']['record']['boot_id'],
                    namespaces=epoch['snapshot']['namespaces'])

    def _bound(self, command):
        validate_command(command)
        hold=self.read_hold(command['operation_id']);item=hold['actions'].get(command['action'])
        require(hold['id']==command['operation_id'] and hold['nonce']==command['nonce']
                and hold['scope']==command['scope'] and item is not None and item['command']==command,
                'original durable hold command required')
        return hold,item

    def _epoch(self, command, original=None):
        epoch=self.runtime.check();context=self._context(epoch)
        require(command['scope']['host_id']==context['host_id'] and command['scope']['boot_id']==context['boot_id']
                and command['actor']['context_sha256']==fingerprint(context), 'control runtime host/boot/namespaces differ')
        if original is not None:
            require(epoch['id']==original['epoch_id'] and fingerprint(epoch)==original['epoch_sha256']
                    and original['reference']['process_record']==epoch['snapshot']['record'],
                    'original control runtime epoch unavailable; no process adoption')
        return epoch

    def _pre(self, command):
        hold,item=self._bound(command)
        require(STEPS.get(hold['phase'])==command['action'] and item['phase'] in ('arming_requested','armed','release_requested'),
                'original hold command no longer executable')
        self._claim(command)
        wanted=dict(command_sha256=fingerprint(command),scope_sha256=fingerprint(command['scope']),
                    actor_sha256=fingerprint(command['actor']),window_active=True)
        require(self.preflight(deepcopy(command))==wanted, 'qualified current command preflight differs')

    def _claim(self, command):
        row=self.journal.db.execute('SELECT * FROM resources WHERE key=?',('image-build-control:'+command['actor']['container_id'],)).fetchone()
        require(row is not None and (row['lab'],row['node'],row['operation_id'])==
                (command['scope']['lab_id'],'image-build',command['operation_id']), 'original control claim missing')

    @staticmethod
    def _exit_proof(proof):
        fields(proof,('pidfd_exit_verified','term_count','force_used','namespace_pid'),'original pidfd exit proof')
        require(proof['pidfd_exit_verified'] is True and type(proof['term_count']) is int
                and proof['term_count']==1 and proof['force_used'] is False
                and type(proof['namespace_pid']) is int and proof['namespace_pid']>0,
                'original single TERM pidfd exit required')

    def _read(self, reference, *, historical=False):
        if not historical:
            retired=self.journal.db.execute('SELECT 1 FROM image_build_arm_retirements WHERE command_id=?',(reference['token'],)).fetchone()
            require(retired is None, 'original command arm retired; reference cannot be reused')
        row=self.journal.db.execute('SELECT * FROM image_build_control_commands WHERE id=?',(reference['token'],)).fetchone()
        if row is None:raise Conflict('original image-build command reference missing')
        if not historical:
            table=self.journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='image_build_administrative_retirements'").fetchone()
            require(not table or self.journal.db.execute(
                'SELECT 1 FROM image_build_administrative_retirements WHERE hold_id=?',(row['operation_id'],)).fetchone() is None,
                'original gate administratively retired; reference cannot be reused')
        value=json.loads(row['payload']);command=value['command']
        validate_command(command);reference_proof(reference,command)
        require(fingerprint(value)==row['fingerprint'] and value['id']==row['id']==reference['token']
                and value['reference']==reference and row['operation_id']==command['operation_id']
                and row['action']==command['action'] and row['container_id']==command['actor']['container_id']
                and value['phase'] in ('armed','release_requested','completed')
                and (value['outcome'] is not None)==(value['phase']=='completed')
                and (value['details'] is not None)==(value['phase']=='completed'), 'original control command journal differs')
        require('native_dispatch_started' not in value or
                (value['native_dispatch_started'] is True and value['phase'] in ('release_requested','completed')),
                'original native dispatch checkpoint differs')
        if 'exit_progress' in value:
            progress=value['exit_progress'];fields(progress,('actor_sha256','pidfd'),'original exit checkpoint')
            require(command['action']=='stop' and value.get('native_dispatch_started') is True
                    and value['phase'] in ('release_requested','completed')
                    and progress['actor_sha256']==fingerprint(command['actor']), 'original exit checkpoint owner differs')
            self._exit_proof(progress['pidfd'])
        if 'start_ack' in value:
            ack=value['start_ack']
            fields(ack,('container_id','status','empty_body'),'original start acknowledgement')
            require(command['action']=='start' and value.get('native_dispatch_started') is True
                    and value['phase'] in ('release_requested','completed')
                    and type(ack['status']) is int and ack['status']==204 and ack['empty_body'] is True
                    and ack['container_id']==command['actor']['container_id'],
                    'original start acknowledgement differs')
        if 'start_progress' in value:
            require('start_ack' in value, 'original start acknowledgement required before capture')
            self._start_proof(value['start_progress'],command,reference)
        if 'policy_ack' in value:
            ack=value['policy_ack']
            fields(ack,('container_id','status','warnings_empty','restart_policy'),'original policy acknowledgement')
            require(command['action'] in ('disable_restart','restore_restart')
                    and value.get('native_dispatch_started') is True
                    and value['phase'] in ('release_requested','completed')
                    and type(ack['status']) is int and ack['status']==200
                    and ack['warnings_empty'] is True
                    and ack['container_id']==command['actor']['container_id']
                    and ack['restart_policy']==command['restart_policy'],
                    'original policy acknowledgement differs')
        source=self.journal.db.execute('SELECT * FROM vm_runtime_epochs WHERE id=?',(value['epoch_id'],)).fetchone()
        require(source is not None and source['fingerprint']==value['epoch_sha256'], 'original control runtime epoch missing')
        epoch=json.loads(source['payload'])
        require(fingerprint(epoch)==source['fingerprint'] and epoch['snapshot']['record']==reference['process_record']
                and command['actor']['context_sha256']==fingerprint(self._context(epoch)), 'original control producer lineage differs')
        hold,item=self._bound(command)
        require(item['reference'] in (None,reference), 'hold references a different original command')
        if value['outcome'] is not None:
            outcome=value['outcome'];fields(outcome,('reference','command_sha256','dispatch_count','evidence'),'original control outcome')
            require(outcome['reference']==reference and outcome['command_sha256']==fingerprint(command)
                    and type(outcome['dispatch_count']) is int and outcome['dispatch_count']==1
                    and type(outcome['evidence']) is dict and type(value['details']) is dict,
                    'original completed control outcome differs')
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE image_build_control_commands SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    def checkpoint_exit(self, reference, proof):
        """Only the original live producer can record the observed pidfd event."""
        with self.journal.execution_lock:
            self._exit_proof(proof);value=self._read(reference);command=value['command']
            require(command['action']=='stop' and value['phase']=='release_requested'
                    and value.get('native_dispatch_started') is True, 'original stop dispatch required')
            self._epoch(command,value);self._claim(command)
            progress=dict(actor_sha256=fingerprint(command['actor']),pidfd=deepcopy(proof))
            if 'exit_progress' in value:
                require(value['exit_progress']==progress, 'original pidfd exit checkpoint cannot be replaced')
                return deepcopy(progress)
            value['exit_progress']=progress;self._save(value)
            self._epoch(command,value);self._claim(command)
            return deepcopy(progress)

    @staticmethod
    def _start_proof(proof, command, reference):
        fields(proof,('reference','command_sha256','capture','generation','actor','original_start_verified'),
               'original startup checkpoint')
        actor(proof['actor'])
        fields(proof['generation'],('started_at','restart_count'),'original startup generation')
        require(proof['reference']==reference and proof['command_sha256']==fingerprint(command)
                and proof['original_start_verified'] is True
                and type(proof['capture']) is dict
                and type(proof['generation']['started_at']) is str and proof['generation']['started_at']
                and type(proof['generation']['restart_count']) is int and proof['generation']['restart_count']>=0
                and all(proof['actor'][key]==command['actor'][key] for key in command['actor'] if key!='process_sha256')
                and proof['actor']['process_sha256']==fingerprint(dict(capture=proof['capture'],generation=proof['generation']))
                and proof['actor']['process_sha256']!=command['actor']['process_sha256']
                and len(canonical(proof).encode())<=1024*1024, 'original startup checkpoint differs')

    def _checkpoint_start(self, reference, key, proof):
        with self.journal.execution_lock:
            value=self._read(reference);command=value['command']
            require(command['action']=='start' and value['phase']=='release_requested'
                    and value.get('native_dispatch_started') is True, 'original start dispatch required')
            self._epoch(command,value);self._claim(command)
            if key in value:
                require(value[key]==proof, 'original start checkpoint cannot be replaced')
                return deepcopy(proof)
            if key=='start_progress':
                require('start_ack' in value, 'original start acknowledgement required before capture')
                self._start_proof(proof,command,reference)
            value[key]=deepcopy(proof);self._save(value)
            self._epoch(command,value);self._claim(command)
            return deepcopy(proof)

    def checkpoint_start_ack(self, reference):
        """Called only after the original transport accepted HTTP 204/empty body."""
        value=self._read(reference)
        return self._checkpoint_start(reference,'start_ack',
            dict(container_id=value['command']['actor']['container_id'],status=204,empty_body=True))

    def checkpoint_start(self, reference, proof):
        return self._checkpoint_start(reference,'start_progress',proof)

    def checkpoint_policy_ack(self, reference):
        """Persist only after HTTP 200 and the original empty-warnings response."""
        with self.journal.execution_lock:
            value=self._read(reference);command=value['command']
            require(command['action'] in ('disable_restart','restore_restart')
                    and value['phase']=='release_requested'
                    and value.get('native_dispatch_started') is True,
                    'original policy dispatch required')
            self._epoch(command,value);self._claim(command)
            ack=dict(container_id=command['actor']['container_id'],status=200,warnings_empty=True,
                     restart_policy=deepcopy(command['restart_policy']))
            if 'policy_ack' in value:
                require(value['policy_ack']==ack, 'original policy acknowledgement cannot be replaced')
                return deepcopy(ack)
            value['policy_ack']=ack;self._save(value)
            self._epoch(command,value);self._claim(command)
            return deepcopy(ack)

    def arm(self, command):
        with self.journal.execution_lock:
            self._bound(command);epoch=self._epoch(command);self._pre(command)
            row=self.journal.db.execute('SELECT id FROM image_build_control_commands WHERE operation_id=? AND action=?',
                (command['operation_id'],command['action'])).fetchone()
            if row:
                original=json.loads(self.journal.db.execute('SELECT payload FROM image_build_control_commands WHERE id=?',(row['id'],)).fetchone()[0])
                require(original['command']==command, 'original command cannot be replaced')
                self.verify(original['reference'],command);return deepcopy(original['reference'])
            reference=dict(token=uuid.uuid4().hex,command_sha256=fingerprint(command),process_record=deepcopy(epoch['snapshot']['record']))
            value=dict(id=reference['token'],command=deepcopy(command),reference=reference,epoch_id=epoch['id'],
                       epoch_sha256=fingerprint(epoch),phase='armed',outcome=None,details=None)
            with self.journal.transaction():
                self._epoch(command);self._pre(command)
                self.journal.db.execute('INSERT INTO image_build_control_commands VALUES(?,?,?,?,?,?)',
                    (value['id'],command['operation_id'],command['action'],command['actor']['container_id'],canonical(value),fingerprint(value)))
            self.verify(reference,command);return deepcopy(reference)

    def original_reference(self, command):
        with self.journal.execution_lock:
            self._bound(command)
            row=self.journal.db.execute('SELECT payload FROM image_build_control_commands WHERE operation_id=? AND action=?',
                (command['operation_id'],command['action'])).fetchone()
            if row is None:return None
            value=json.loads(row['payload']);self._read(value['reference'])
            require(value['command']==command, 'original control request differs')
            return deepcopy(value['reference'])

    def recover_arm(self, command):
        """No lower row proves no arm occurred: arm creates metadata only."""
        with self.journal.execution_lock:
            reference=self.original_reference(command)
            return reference if reference is not None else self.arm(command)

    def verify(self, reference, command):
        with self.journal.execution_lock:
            value=self._read(reference)
            require(value['command']==command and value['phase']=='armed', 'original unreleased control command required')
            self._epoch(command,value);self._pre(command)
            return True

    def release(self, reference):
        with self.journal.execution_lock:
            value=self._read(reference);command=value['command']
            self.verify(reference,command)
            value['phase']='release_requested';self._save(value)
            self._epoch(command,value);self._pre(command)
            result=self.execute(deepcopy(command),deepcopy(reference))
            fields(result,('evidence','details'),'qualified native control result')
            require(type(result['evidence']) is dict and type(result['details']) is dict
                    and len(canonical(result).encode())<=1024*1024, 'bounded original control result required')
            self._epoch(command,value)
            value=self._read(reference)
            require(value['phase']=='release_requested', 'original control result no longer pending')
            value.update(phase='completed',details=deepcopy(result['details']),outcome=dict(reference=deepcopy(reference),
                command_sha256=fingerprint(command),dispatch_count=1,evidence=deepcopy(result['evidence'])))
            self._save(value)

    def qualified_snapshot(self, reference):
        with self.journal.execution_lock:
            value=self._read(reference);current=self._epoch(value['command'])
            source=self.journal.db.execute('SELECT payload FROM vm_runtime_epochs WHERE id=?',(value['epoch_id'],)).fetchone()
            original=json.loads(source[0])
            require(current['profile']['sources_sha256']==original['profile']['sources_sha256'],
                    'original command producer sources need separate qualification')
            return value

    def resume_unreleased(self, reference):
        """First release of an original arm after the parent checkpoint.

        An already released worker is never dispatched here, even when no
        native acknowledgement exists. Recovery of that worker is observational.
        """
        with self.journal.execution_lock:
            value=self.qualified_snapshot(reference)
            if value['phase']!='armed':return False
            require(set(value)=={'id','command','reference','epoch_id','epoch_sha256',
                                 'phase','outcome','details'},
                    'original arm without dispatch or progress required')
            _,item=self._bound(value['command'])
            require(item['phase']=='release_requested' and item['reference']==reference,
                    'original parent release request required')
            self.verify(reference,value['command'])
            self.release(deepcopy(reference))
            return True

    def outcome(self, reference):
        with self.journal.execution_lock:
            value=self.qualified_snapshot(reference)
            return deepcopy(value['outcome'])

    def recover_outcome(self, reference):
        """Complete only from original durable progress plus fresh readonly proof."""
        with self.journal.execution_lock:
            value=self.qualified_snapshot(reference)
            if value['outcome'] is not None:return deepcopy(value['outcome'])
            key={'stop':'exit_progress','start':'start_progress',
                 'disable_restart':'policy_ack','restore_restart':'policy_ack'}.get(value['command']['action'])
            if self.recover_callback is None or key is None or key not in value:return None
            require(value['phase']=='release_requested', 'original pending command required for observational recovery')
            progress=deepcopy(value[key]);self._claim(value['command'])
            result=self.recover_callback(deepcopy(reference))
            fields(result,('evidence','details'),'qualified observed control result')
            require(type(result['evidence']) is dict and type(result['details']) is dict
                    and len(canonical(result).encode())<=1024*1024, 'bounded original recovery result required')
            value=self.qualified_snapshot(reference);self._claim(value['command'])
            require(value['phase']=='release_requested' and value.get(key)==progress,
                    'original control checkpoint changed during observation')
            value.update(phase='completed',details=deepcopy(result['details']),outcome=dict(reference=deepcopy(reference),
                command_sha256=fingerprint(value['command']),dispatch_count=1,evidence=deepcopy(result['evidence'])))
            self._save(value)
            return deepcopy(value['outcome'])

    def details(self, reference):
        with self.journal.execution_lock:
            require(self.outcome(reference) is not None, 'original control details are not complete')
            value=self._read(reference)
            return dict(reference=deepcopy(reference),command_sha256=fingerprint(value['command']),details=deepcopy(value['details']))
