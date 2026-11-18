"""One fixed, journaled QMP query for an acknowledged paused creation.

libvirt marks custom-monitor use and saves domain status even for this query.
This is not an effect-free read. No HMP/command input or automatic resend is
exposed. Returned vCPU TIDs are evidence for a later kernel correlation, never
a QEMU PID or a process birth receipt on their own.
"""
from copy import deepcopy
import hashlib
import json
import re
import uuid
from xml.etree import ElementTree as ET

from .libvirt_observer import xml_fingerprint
from .manifest import canonical, fingerprint
from .vm_events import validate_birth
from .vm_template import digest, fields, require

COMMAND='{"execute":"query-cpus-fast"}'


def cpu_threads(raw, expected):
    require(type(expected) is int and 1<=expected<=256 and isinstance(raw,str)
            and 0<len(raw)<=65536 and len(raw.encode())<=65536, 'bounded CPU query response required')
    def pairs(items):
        value={}
        for key,item in items:
            require(key not in value, 'duplicate QMP response key')
            value[key]=item
        return value
    def invalid(value):raise ValueError('nonfinite QMP number')
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)
    except (ValueError,RecursionError) as error:
        raise ValueError('invalid bounded QMP response') from error
    require(type(value) is dict and set(value) in ({'return'},{'return','id'}), 'successful CPU query response required')
    if 'id' in value:
        require(isinstance(value['id'],str) and re.fullmatch(r'libvirt-[0-9]{1,20}',value['id']),
                'libvirt monitor response identifier differs')
    require(type(value['return']) is list and len(value['return'])==expected, 'qualified CPU count differs')
    result=[];paths=set()
    for cpu in value['return']:
        require(type(cpu) is dict and set(cpu) in
                ({'cpu-index','thread-id','qom-path','target'},{'cpu-index','thread-id','qom-path','target','props'}),
                'qualified x86 CPU response fields required')
        require(type(cpu['cpu-index']) is int and 0<=cpu['cpu-index']<expected
                and type(cpu['thread-id']) is int and 0<cpu['thread-id']<2**31 and cpu['target']=='x86_64'
                and isinstance(cpu['qom-path'],str) and 0<len(cpu['qom-path'])<=1024
                and cpu['qom-path'].startswith('/machine/') and cpu['qom-path'] not in paths,
                'qualified unique x86 CPU/thread identity required')
        if 'props' in cpu:
            props=cpu['props']
            require(type(props) is dict and set(props)<=set(('node-id','drawer-id','book-id','socket-id','die-id',
                    'cluster-id','module-id','core-id','thread-id'))
                    and all(type(v) is int and 0<=v<2**31 for v in props.values()), 'CPU topology properties differ')
        paths.add(cpu['qom-path']);result.append(dict(index=cpu['cpu-index'],thread_id=cpu['thread-id']))
    require({cpu['index'] for cpu in result}==set(range(expected))
            and len({cpu['thread_id'] for cpu in result})==expected, 'CPU indexes or KVM thread identities repeat')
    return sorted(result,key=lambda cpu:cpu['index'])


class PausedCPUQuery:
    def __init__(self,journal,connection,runtime,qemu_sdk,*,preflight):
        require(callable(preflight) and callable(getattr(runtime,'check',None))
                and qemu_sdk.libvirt is connection._sdk and callable(getattr(qemu_sdk,'qemuMonitorCommand',None))
                and type(qemu_sdk.VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT) is int
                and qemu_sdk.VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT==0, 'qualified original QEMU extension and creation preflight required')
        self.journal,self.connection,self.runtime,self.sdk=journal,connection,runtime,qemu_sdk
        self.preflight,self.epoch=preflight,fingerprint(runtime.check())
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_qemu_cpu_queries '
                '(id TEXT PRIMARY KEY,creator TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _snapshot(self,request):
        fields(request,('birth','source_id','creation_sha256','persistent_sha256','live_sha256','domain_id','expected_cpus'), 'original paused query request')
        validate_birth(request['birth'])
        require(isinstance(request['source_id'],str) and re.fullmatch('[0-9a-f]{32}',request['source_id'])
                and all(digest(request[key]) for key in ('creation_sha256','persistent_sha256','live_sha256'))
                and type(request['domain_id']) is int and request['domain_id']>=0
                and type(request['expected_cpus']) is int and 1<=request['expected_cpus']<=256,
                'original paused creation and bounded CPU count required')
        require(not self.connection._readonly and self.connection._event_feed is not None,
                'tracked QMP metadata effect requires original writable monitored connection')
        require(fingerprint(self.runtime.check())==self.epoch and self.preflight(deepcopy(request))==fingerprint(request),
                'original runtime or acknowledged paused-creation proof differs')
        require(self.connection.getURI()=='qemu:///session', 'original dedicated session required')
        domain=self.connection.lookupByUUIDString(request['birth']['uuid'])
        require(domain.ID()==request['domain_id'] and domain.isActive()==1 and domain.isPersistent()==1
                and domain.state(0)[0]==3, 'original acknowledged creation is not paused')
        persistent,live=domain.XMLDesc(2),domain.XMLDesc(0)
        require(xml_fingerprint(persistent,request['birth'])==request['persistent_sha256']
                and xml_fingerprint(live,request['birth'])==request['live_sha256']
                and ET.fromstring(persistent).findtext('vcpu')==str(request['expected_cpus']),
                'original paused domain configuration differs')
        return domain

    def _save(self,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_qemu_cpu_queries SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    def query(self,request):
        with self.journal.execution_lock:
            self._snapshot(request)
            row=self.journal.db.execute('SELECT * FROM vm_qemu_cpu_queries WHERE creator=?',
                                        (request['birth']['creator_operation_id'],)).fetchone()
            if row:
                value=json.loads(row['payload'])
                require(fingerprint(value)==row['fingerprint'] and value['request']==request
                        and value['birth']==request['birth'] and value['epoch_sha256']==self.epoch,
                        'original CPU query intent differs')
                require(value['phase']=='completed', 'uncertain original CPU query is not repeated')
                return value
            value=dict(id=uuid.uuid4().hex,birth=deepcopy(request['birth']),request=deepcopy(request),epoch_sha256=self.epoch,
                       phase='requested',expected_metadata_effect='custom-monitor',effect_may_have_occurred=True,
                       reply_sha256=None,cpus=None,error=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO vm_qemu_cpu_queries VALUES(?,?,?,?)',
                    (value['id'],request['birth']['creator_operation_id'],canonical(value),fingerprint(value)))
            try:
                domain=self._snapshot(request)
                raw=self.connection._call(self.sdk,'qemuMonitorCommand',domain._raw,COMMAND,0,mutate=True)
                require(isinstance(raw,str) and 0<len(raw)<=65536 and len(raw.encode())<=65536, 'bounded QMP response required')
                value['reply_sha256']=hashlib.sha256(raw.encode()).hexdigest();self._save(value)
                value['cpus']=cpu_threads(raw,request['expected_cpus'])
                self._snapshot(request)
                value['phase']='completed';self._save(value)
                return deepcopy(value)
            except BaseException as error:
                value.update(phase='pending',error=dict(type=type(error).__name__,message=str(error)[:512]));self._save(value)
                raise
