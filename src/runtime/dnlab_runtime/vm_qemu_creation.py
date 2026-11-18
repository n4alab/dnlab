"""Persist first QEMU process evidence before paused-boot CPU release.

The creator supplies a qualified query request and process policy from its
original acknowledged start. No defaults infer them from a matching VM. Once
capture is requested, an uncertain attempt cannot reacquire process evidence;
only a completed original receipt can be observed by explicit recovery.
"""
from copy import deepcopy
import json
import uuid

from .libvirt_observer import LibvirtDomainObserver, creation_reference
from .manifest import canonical, fingerprint
from .qemu_creation_process import QEMUCreationProcess
from .qemu_process import PinnedQEMUProcess, validate_process_record
from .vm_template import fields, require


class VMQEMUCreation:
    def __init__(self,definitions,queries,runtime,*,request_for,policy_for,
                 correlator=QEMUCreationProcess,process_factory=PinnedQEMUProcess):
        require(queries.journal is definitions.journal and runtime.journal is definitions.journal
                and queries.connection is definitions.connection
                and all(callable(fn) for fn in (request_for,policy_for,correlator,process_factory)),
                'original shared journal, connection and creation providers required')
        self.definitions,self.journal,self.queries,self.runtime=definitions,definitions.journal,queries,runtime
        self.request_for,self.policy_for=request_for,policy_for
        self.correlator,self.process_factory=correlator,process_factory
        self.epoch=fingerprint(runtime.check())
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_qemu_process_creations '
                '(id TEXT PRIMARY KEY,creator TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @staticmethod
    def _definition(value):
        return fingerprint([value['birth'],value['request_fingerprint'],value['ack'],
                            value['boot']['source_id'],value['boot']['source_ack']])

    def _guard(self,value):
        require(fingerprint(self.runtime.check())==self.epoch, 'original QEMU creator runtime epoch differs')
        require(self.definitions.read(value['birth']['creator_operation_id'])==value
                and value['phase']=='defined' and value['boot']['phase']=='start_requested'
                and value['boot']['reference'] is None and value['boot']['process_record'] is None,
                'original acknowledged-start capture checkpoint required')
        self.definitions._fence(value);self.definitions._session(value)
        domain=self.definitions.connection.lookupByUUIDString(value['birth']['uuid'])
        require(domain.UUIDString()==value['birth']['uuid'] and domain.isActive()==1
                and domain.isPersistent()==1 and domain.state(0)[0]==3, 'original QEMU creation must remain paused')
        return domain

    def _save(self,record):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_qemu_process_creations SET payload=?,fingerprint=? WHERE id=?',
                (canonical(record),fingerprint(record),record['id']))

    def _read(self,value):
        row=self.journal.db.execute('SELECT * FROM vm_qemu_process_creations WHERE creator=?',
                                    (value['birth']['creator_operation_id'],)).fetchone()
        require(row is not None, 'original QEMU creation receipt missing')
        record=json.loads(row['payload'])
        fields(record,('id','birth','definition_sha256','epoch_sha256','request','policy','phase','correlation','receipt','error'),
               'original QEMU creation record')
        require(record['id']==row['id'] and fingerprint(record)==row['fingerprint'] and record['birth']==value['birth']
                and record['definition_sha256']==self._definition(value) and record['epoch_sha256']==self.epoch
                and record['phase'] in ('requested','pending','completed'), 'original QEMU creation lineage differs')
        return record

    def _verify(self,value,record):
        require(record['phase']=='completed', 'uncertain QEMU process capture cannot be repeated or adopted')
        receipt=record['receipt'];fields(receipt,('reference','process_record'),'original QEMU creation receipt')
        process=validate_process_record(receipt['process_record']);reference=receipt['reference']
        require(record['request']['birth']==value['birth'] and record['request']['source_id']==value['boot']['source_id']
                and process['birth']==value['birth'] and reference['birth']==value['birth']
                and process['uid']==record['policy']['uid']==self.definitions.session.profile['uid']
                and process['gid']==record['policy']['gid']==self.definitions.session.profile['gid']
                and process['process']['boot_id']==record['policy']['boot_id']
                and process['process']['executable_sha256']==record['policy']['executable_sha256']
                and process['process']['start_ticks']>=record['policy']['minimum_start_ticks']
                and all(process['namespaces'][key]==expected for key,expected in record['policy']['shared_namespaces'].items())
                and record['correlation']['record']==process
                and record['correlation']['policy_sha256']==fingerprint(record['policy'])
                and reference['uri']==self.definitions.session.profile['uri']
                and reference['persistent_sha256']==record['request']['persistent_sha256']==value['ack']['persistent_sha256']
                and reference['live_sha256']==record['request']['live_sha256'], 'original QEMU process receipt differs')
        query=self.queries.read_completed(deepcopy(record['request']))
        require(fingerprint(query)==record['correlation']['query_sha256'], 'original QEMU query receipt changed')
        process_provider=self.process_factory(deepcopy(process))
        LibvirtDomainObserver(self.definitions.connection,deepcopy(reference),xml_inactive_flag=2,
                              process=process_provider)(deepcopy(value['birth']))
        self._guard(value)
        return deepcopy(receipt)

    def read_original(self,value):
        """Completed immutable receipt only: no new query or kernel correlation."""
        with self.journal.execution_lock:
            self._guard(value)
            return self._verify(value,self._read(value))

    def __call__(self,value,domain):
        with self.journal.execution_lock:
            require(domain.UUIDString()==value['birth']['uuid'], 'original start response domain differs')
            domain=self._guard(value)
            prior=self.journal.db.execute('SELECT 1 FROM vm_qemu_process_creations WHERE creator=?',
                                         (value['birth']['creator_operation_id'],)).fetchone()
            if prior:return self.read_original(value)
            request=self.request_for(deepcopy(value),domain);policy=self.policy_for(deepcopy(value),deepcopy(request))
            require(request['birth']==value['birth'] and request['source_id']==value['boot']['source_id']
                    and policy['uid']==self.definitions.session.profile['uid']
                    and policy['gid']==self.definitions.session.profile['gid'], 'original QEMU creation inputs differ')
            record=dict(id=uuid.uuid4().hex,birth=deepcopy(value['birth']),definition_sha256=self._definition(value),
                        epoch_sha256=self.epoch,request=deepcopy(request),policy=deepcopy(policy),phase='requested',
                        correlation=None,receipt=None,error=None)
            with self.journal.transaction():
                self._guard(value)
                self.journal.db.execute('INSERT INTO vm_qemu_process_creations VALUES(?,?,?,?)',
                    (record['id'],value['birth']['creator_operation_id'],canonical(record),fingerprint(record)))
            try:
                self._guard(value)
                self.queries.query(deepcopy(request))
                self._guard(value)
                correlated=self.correlator(self.queries,deepcopy(request),deepcopy(policy)).correlate()
                process=validate_process_record(correlated['record'])
                self._guard(value)
                reference=creation_reference(value['birth'],uri=self.definitions.session.profile['uri'],
                    persistent_xml=domain.XMLDesc(2),live_xml=domain.XMLDesc(0),process=process['process'])
                record.update(phase='completed',correlation=deepcopy(correlated),
                              receipt=dict(reference=reference,process_record=deepcopy(process)))
                # Validate against the original kernel/domain proof before committing.
                self._verify(value,record)
                self._save(record)
                return self._verify(value,self._read(value))
            except BaseException as error:
                # A lost commit reply must not erase a completed original birth.
                row=self.journal.db.execute('SELECT fingerprint FROM vm_qemu_process_creations WHERE id=?',(record['id'],)).fetchone()
                if not (record['phase']=='completed' and row is not None and row['fingerprint']==fingerprint(record)):
                    record.update(phase='pending',error=dict(type=type(error).__name__,message=str(error)[:512]));self._save(record)
                raise
