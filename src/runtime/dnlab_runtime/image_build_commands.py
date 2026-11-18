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
    def __init__(self, runtime, *, read_hold, preflight, execute):
        require(isinstance(runtime,RuntimeProcess) and all(callable(fn) for fn in (read_hold,preflight,execute)),
                'qualified current runtime and original control providers required')
        self.runtime,self.journal=runtime,runtime.journal
        self.read_hold,self.preflight,self.execute=read_hold,preflight,execute
        with self.journal.transaction():
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
        row=self.journal.db.execute('SELECT * FROM resources WHERE key=?',('image-build-control:'+command['actor']['container_id'],)).fetchone()
        require(row is not None and (row['lab'],row['node'],row['operation_id'])==
                (command['scope']['lab_id'],'image-build',command['operation_id']), 'original control claim missing')
        wanted=dict(command_sha256=fingerprint(command),scope_sha256=fingerprint(command['scope']),
                    actor_sha256=fingerprint(command['actor']),window_active=True)
        require(self.preflight(deepcopy(command))==wanted, 'qualified current command preflight differs')

    def _read(self, reference):
        row=self.journal.db.execute('SELECT * FROM image_build_control_commands WHERE id=?',(reference['token'],)).fetchone()
        if row is None:raise Conflict('original image-build command reference missing')
        value=json.loads(row['payload']);command=value['command']
        validate_command(command);reference_proof(reference,command)
        require(fingerprint(value)==row['fingerprint'] and value['id']==row['id']==reference['token']
                and value['reference']==reference and row['operation_id']==command['operation_id']
                and row['action']==command['action'] and row['container_id']==command['actor']['container_id']
                and value['phase'] in ('armed','release_requested','completed')
                and (value['outcome'] is not None)==(value['phase']=='completed')
                and (value['details'] is not None)==(value['phase']=='completed'), 'original control command journal differs')
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
            value.update(phase='completed',details=deepcopy(result['details']),outcome=dict(reference=deepcopy(reference),
                command_sha256=fingerprint(command),dispatch_count=1,evidence=deepcopy(result['evidence'])))
            self._save(value)

    def outcome(self, reference):
        with self.journal.execution_lock:
            value=self._read(reference);current=self._epoch(value['command'])
            source=self.journal.db.execute('SELECT payload FROM vm_runtime_epochs WHERE id=?',(value['epoch_id'],)).fetchone()
            original=json.loads(source[0])
            require(current['profile']['sources_sha256']==original['profile']['sources_sha256'],
                    'original command producer sources need separate qualification')
            return deepcopy(value['outcome'])

    def details(self, reference):
        with self.journal.execution_lock:
            require(self.outcome(reference) is not None, 'original control details are not complete')
            value=self._read(reference)
            return dict(reference=deepcopy(reference),command_sha256=fingerprint(value['command']),details=deepcopy(value['details']))
