"""Versioned StartUnit worker and original job receipts; no native bus default.

The parent must qualify source/interpreter/library, the original armed worker and
its bus connection. This protocol is distinct from historical systemctl commands.
No process launcher, connection constructor or implicit response-loss retry exists.
"""
from copy import deepcopy
import json
import os
import re

from .libvirt_account_commands import reference_proof
from .libvirt_account_worker import frame,require
from .libvirt_activation import steps
from .libvirt_service_profile import require_activatable,render_profile
from .manifest import Conflict,canonical,fingerprint,identifier

UNITS=('dnlab-virtlogd.service','dnlab-virtlockd.service','dnlab-libvirtd.service')


def hex_value(value,length):return isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None


def validate(command):
    require(isinstance(command,dict) and set(command)=={'transport','request_sha256','destination','path','interface','member','signature','body'},
        'fixed original D-Bus start command required')
    transport=command['transport']
    require(isinstance(transport,dict) and set(transport)=={'kind','worker_sha256','library_sha256'}
        and transport['kind']=='dbus-start-v1' and hex_value(transport['worker_sha256'],64)
        and hex_value(transport['library_sha256'],64) and hex_value(command['request_sha256'],64),
        'qualified versioned D-Bus transport required')
    require(command['destination']=='org.freedesktop.systemd1' and command['path']=='/org/freedesktop/systemd1'
        and command['interface']=='org.freedesktop.systemd1.Manager' and command['member']=='StartUnit'
        and command['signature']=='ss' and isinstance(command['body'],list) and len(command['body'])==2
        and command['body'][0] in UNITS and command['body'][1]=='fail','only dedicated StartUnit fail permitted')
    return command


def start_plan(installation,item,activation_id,transport):
    identifier(activation_id,'original D-Bus activation ID');require_activatable(installation['profile'])
    require(installation['profile']==render_profile(**installation['request'])
        and item['spec'] in steps(installation['profile']) and item['spec']['kind']=='start'
        and hex_value(item['nonce'],32),'original dedicated start step required')
    request=dict(activation_id=activation_id,installation_sha256=fingerprint(installation),spec=deepcopy(item['spec']),nonce=item['nonce'])
    return validate(dict(transport=deepcopy(transport),request_sha256=fingerprint(request),destination='org.freedesktop.systemd1',
        path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='StartUnit',signature='ss',
        body=[item['spec']['unit'],'fail']))


class BusStartPlan:
    """Explicit mixed plan: retain systemctl reload, version the three starts."""
    def __init__(self,transport):self.transport=deepcopy(transport)

    def __call__(self,installation,item,activation_id,binary):
        if item['spec']['kind']=='start':return start_plan(installation,item,activation_id,self.transport)
        from .libvirt_activation_commands import command_plan
        return command_plan(installation,item,activation_id,binary)


def connection_proof(connection):
    require(isinstance(connection,dict) and set(connection)=={'token','context_sha256','manager_owner','unique_name'}
        and hex_value(connection['token'],32) and hex_value(connection['context_sha256'],64)
        and all(isinstance(connection[key],str) and re.fullmatch(r':[0-9]+\.[0-9]+',connection[key]) is not None
            for key in ('manager_owner','unique_name'))
        and connection['manager_owner']!=connection['unique_name'],'original pinned bus connection required')


def reply_proof(reply,connection):
    require(isinstance(reply,dict) and set(reply)=={'call_serial','reply_serial','sender','signature','body'}
        and type(reply['call_serial']) is int and 0<reply['call_serial']<2**32
        and type(reply['reply_serial']) is int and reply['reply_serial']==reply['call_serial']
        and reply['sender']==connection['manager_owner'] and reply['signature']=='o'
        and isinstance(reply['body'],list) and len(reply['body'])==1 and isinstance(reply['body'][0],str)
        and re.fullmatch('/org/freedesktop/systemd1/job/[1-9][0-9]*',reply['body'][0]) is not None,
        'original StartUnit method reply required')


def serve(source,sink,*,bus):
    """One StartUnit after release; wait for durable parent acknowledgement.

    bus must use the already pinned connection, match method-call serials and
    authenticate the manager sender. It must not reconnect or retry internally.
    The parent's bounded observer owns timeout/exit qualification of this worker.
    """
    request=frame(source)
    require(isinstance(request,dict) and set(request)=={'token','command','connection'} and hex_value(request['token'],32),
        'original D-Bus worker request required')
    command=validate(request['command']);connection=request['connection'];connection_proof(connection)
    require(os.geteuid()==0,'privileged D-Bus start worker required')
    def verify():
        require(bus.verify(deepcopy(connection),deepcopy(command)) is True,'original D-Bus connection or transport changed')
    verify();digest=fingerprint(command)
    sink.write(canonical(dict(ready=request['token'],command_sha256=digest,connection_sha256=fingerprint(connection)))+'\n');sink.flush()
    require(frame(source)==dict(release=request['token'],command_sha256=digest,connection_sha256=fingerprint(connection)),
        'original D-Bus release differs')
    verify()
    reply=bus.start_unit(deepcopy(connection),deepcopy(command),timeout=5)
    reply_proof(reply,connection);verify()
    result=dict(token=request['token'],command_sha256=digest,connection_sha256=fingerprint(connection),reply=deepcopy(reply))
    sink.write(canonical(dict(job=result))+'\n');sink.flush()
    require(frame(source)==dict(committed=request['token'],job_sha256=fingerprint(result)),
        'durable original job acknowledgement missing or changed')
    return result


class StartJobReceipts:
    """Metadata only: bind original worker before release, collect its own output.

    Worker/connection verification, output collection and full release preflight
    must be supplied by the owning executor. This class never releases a worker.
    """
    def __init__(self,journal,*,verify,read_reply):
        require(callable(verify) and callable(read_reply),'explicit original D-Bus worker observers required')
        self.journal,self.verify,self.read_reply=journal,verify,read_reply
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_start_jobs '
                '(request_sha256 TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _read(self,command):
        validate(command)
        row=self.journal.db.execute('SELECT * FROM libvirt_activation_start_jobs WHERE request_sha256=?',
            (command['request_sha256'],)).fetchone()
        if row is None:return None
        value=json.loads(row['payload'])
        require(fingerprint(value)==row['fingerprint'] and value['command']==command
            and value['phase'] in ('prepared','committed'),'original D-Bus job journal differs')
        reference_proof(value['worker'],command);connection_proof(value['connection'])
        require(value['connection']['context_sha256']==fingerprint(value['context'])
            and value['worker']['process_record']['boot_id']==value['context']['boot_id']
            and value['worker']['process_record']['namespace_sha256']==fingerprint(value['context']['namespaces']),
            'original D-Bus worker context differs')
        if value['phase']=='prepared':require(value['result'] is None,'unexpected uncommitted D-Bus job')
        else:self._result(value,value['result'])
        return value

    @staticmethod
    def _result(value,result):
        require(isinstance(result,dict) and set(result)=={'token','command_sha256','connection_sha256','reply'}
            and result['token']==value['worker']['token'] and result['command_sha256']==fingerprint(value['command'])
            and result['connection_sha256']==fingerprint(value['connection']),'original worker job response differs')
        reply_proof(result['reply'],value['connection'])

    def prepare(self,command,context,connection,worker):
        with self.journal.execution_lock:
            validate(command);connection_proof(connection);reference_proof(worker,command)
            require(connection['context_sha256']==fingerprint(context)
                and worker['process_record']['boot_id']==context['boot_id']
                and worker['process_record']['namespace_sha256']==fingerprint(context['namespaces']),
                'original armed D-Bus worker context required')
            value=dict(command=deepcopy(command),context=deepcopy(context),connection=deepcopy(connection),
                worker=deepcopy(worker),phase='prepared',result=None)
            prior=self._read(command)
            if prior:
                require(all(prior[key]==value[key] for key in ('command','context','connection','worker')),
                    'original D-Bus job intent cannot be replaced')
                return prior
            require(self.verify(deepcopy(worker),deepcopy(command),deepcopy(connection)) is True,'original armed D-Bus worker lost')
            with self.journal.transaction():
                require(self.verify(deepcopy(worker),deepcopy(command),deepcopy(connection)) is True,'original armed D-Bus worker changed')
                self.journal.db.execute('INSERT INTO libvirt_activation_start_jobs VALUES(?,?,?)',
                    (command['request_sha256'],canonical(value),fingerprint(value)))
            return deepcopy(value)

    def collect(self,command):
        with self.journal.execution_lock:
            value=self._read(command);require(value is not None,'original D-Bus job intent required')
            if value['phase']!='committed':
                require(self.verify(deepcopy(value['worker']),deepcopy(command),deepcopy(value['connection'])) is True,
                    'original D-Bus worker or connection lost')
                result=self.read_reply(deepcopy(value['worker']))
                require(result is not None,'original D-Bus job response pending; no resend')
                self._result(value,result)
                require(self.verify(deepcopy(value['worker']),deepcopy(command),deepcopy(value['connection'])) is True,
                    'original D-Bus worker changed during collection')
                value.update(phase='committed',result=deepcopy(result))
                with self.journal.transaction():
                    self.journal.db.execute('UPDATE libvirt_activation_start_jobs SET payload=?,fingerprint=? WHERE request_sha256=?',
                        (canonical(value),fingerprint(value),command['request_sha256']))
            return dict(committed=value['worker']['token'],job_sha256=fingerprint(value['result']))

    def correlate(self,command,subscription,event):
        """Read only the committed original reply; no job lookup or bus call."""
        with self.journal.execution_lock:
            value=self._read(command)
            require(value is not None and value['phase']=='committed','original D-Bus job receipt pending')
            require(subscription['context_sha256']==fingerprint(value['context'])
                and subscription['manager_owner']==value['connection']['manager_owner']
                and event['unit']==command['body'][0] and event['job_path']==value['result']['reply']['body'][0],
                'event differs from original returned StartUnit job')
            return True
