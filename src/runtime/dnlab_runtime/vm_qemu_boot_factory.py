"""Wire the original monitored SDK session to initial VM boot.

No SDK import/open, event registration, process launch or VM action occurs here.
The caller supplies the qualified collector, immutable QEMU profile, kernel
policy and binary verifier. The existing child controllers own every effect.
"""
from copy import deepcopy
from xml.etree import ElementTree as ET

from .libvirt_boot_events import LibvirtBootEvents
from .libvirt_cpu_query import PausedCPUQuery
from .libvirt_xml import absolute
from .manifest import fingerprint
from .qemu_creation_process import QEMUCreationProcess
from .qemu_process import PinnedQEMUProcess
from .vm_boot import VMBootDriver
from .vm_qemu_creation import VMQEMUCreation
from .vm_template import digest, fields, require


class _QualifiedBoot(VMBootDriver):
    def __init__(self, definitions, *, prerequisites, handoff=None, **providers):
        self.prerequisites = prerequisites
        self.handoff = handoff
        super().__init__(definitions,**providers)

    def _check(self, value, *, resources=True):
        self.prerequisites()
        return super()._check(value,resources=resources)

    def _source_ack(self, value):
        self.prerequisites()
        return super()._source_ack(value)

    def _before_start(self, value):
        if self.handoff is not None:self.handoff.release(value['birth']['creator_operation_id'])

    def _before_resume(self, value):
        if self.handoff is not None:self.handoff.acquire(value['birth']['creator_operation_id'])

    def _before_exit_publication(self, value):
        if self.handoff is not None:self.handoff.drain_for_exit(value['birth']['creator_operation_id'])


class VMQEMUBootFactory:
    def __init__(self, definitions, source, runtime, qemu_sdk, *, qemu, policy, verify_qemu,
                 correlator=QEMUCreationProcess, process_factory=PinnedQEMUProcess, handoff=None):
        require(isinstance(source,LibvirtBootEvents) and source.definitions is definitions
                and source.runtime is runtime and runtime.journal is definitions.journal
                and all(callable(fn) for fn in (verify_qemu,correlator,process_factory)),
                'original monitored session, runtime and qualified creation providers required')
        fields(qemu,('path','sha256'),'qualified QEMU binary');absolute(qemu['path'])
        fields(policy,('uid','gid','boot_id','executable_sha256','proc_identity','shared_namespaces','minimum_start_ticks'),
               'qualified QEMU kernel policy')
        session = definitions.session.profile
        require(digest(qemu['sha256']) and policy['executable_sha256'] == qemu['sha256']
                and type(policy['uid']) is int and type(policy['gid']) is int
                and (policy['uid'],policy['gid']) == (session['uid'],session['gid'])
                and policy['boot_id'] == definitions.session.proof()['daemon']['boot_id']
                and type(policy['minimum_start_ticks']) is int and policy['minimum_start_ticks'] > 0,
                'original non-root QEMU binary/credentials/boot policy required')
        fields(policy['proc_identity'],('device','inode'),'qualified QEMU procfs')
        fields(policy['shared_namespaces'],('pid','net','user'),'qualified QEMU shared namespaces')
        for identity in (policy['proc_identity'],*policy['shared_namespaces'].values()):
            fields(identity,('device','inode'),'qualified QEMU kernel identity')
            require(all(type(value) is int and value > 0 for value in identity.values()),
                    'qualified QEMU kernel identity required')
        self.definitions,self.source,self.runtime = definitions,source,runtime
        if handoff is not None:
            from .vm_tap_handoff import VMTapHandoff
            require(isinstance(handoff,VMTapHandoff) and handoff.definitions is definitions
                    and handoff.monitor.runtime is runtime, 'original VM TAP handoff capability required')
        self.handoff = handoff
        self.qemu,self.policy,self.verify_qemu = deepcopy(qemu),deepcopy(policy),verify_qemu
        self.qemu_sha256,self.policy_sha256 = fingerprint(qemu),fingerprint(policy)
        self.epoch,self.observer = fingerprint(runtime.check()),source.observer
        self._guard()
        self.queries = PausedCPUQuery(definitions.journal,definitions.connection,runtime,qemu_sdk,
                                      preflight=source.query_preflight)
        self.creation = VMQEMUCreation(definitions,self.queries,runtime,request_for=source.creation_request,
            policy_for=self._policy,correlator=correlator,process_factory=process_factory)
        self.driver = _QualifiedBoot(definitions,prerequisites=self._guard,handoff=handoff,source=source,
                                     capture_started=self._capture,observer=self.observer)

    def _guard(self):
        require(self.source.definitions is self.definitions and self.source.runtime is self.runtime
                and self.source.observer is self.observer and fingerprint(self.runtime.check()) == self.epoch
                and fingerprint(self.qemu) == self.qemu_sha256 and fingerprint(self.policy) == self.policy_sha256
                and self.verify_qemu(deepcopy(self.qemu)) == self.qemu_sha256,
                'original QEMU boot prerequisites changed')

    def _policy(self, value, request):
        self._guard()
        require(value['birth']['host_id'] == self.definitions.session.profile['host_id']
                and ET.fromstring(value['xml']).findtext('devices/emulator') == self.qemu['path'],
                'VM emulator or host differs from qualified QEMU profile')
        return deepcopy(self.policy)

    def _capture(self, value, domain):
        self._policy(value,None)
        return self.creation(value,domain)

    def __call__(self, operation):
        value = self.definitions.read(operation)
        self._policy(value,None)
        if self.handoff is not None:self.handoff.prepare(operation)
        return self.driver
