"""Event anchor -> fixed QMP -> kernel proc files -> durable boot, no host I/O."""
from copy import deepcopy
import json

import pytest

from dnlab_runtime.libvirt_cpu_query import COMMAND, PausedCPUQuery
from dnlab_runtime.libvirt_observer import LibvirtDomainObserver
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.qemu_creation_process import QEMUCreationProcess
from dnlab_runtime.qemu_process import PinnedQEMUProcess
from dnlab_runtime.vm_qemu_creation import VMQEMUCreation
from test_libvirt_boot_events import event_boot, boot, definition, template, instance
from test_qemu_creation_process import creation, process, observer


@pytest.fixture
def pipeline(event_boot,creation):
    e=event_boot;c=creation;driver=e.driver;connection=driver.definitions.connection
    for path in c.leader.parent.rglob('status'):path.write_text(path.read_text().replace('1002','1001'))
    policy=deepcopy(c.policy);policy['gid']=1001
    control=dict(queries=0,correlations=0)
    connection._sdk=object();connection._readonly=False;connection._event_feed=e.feed
    from types import SimpleNamespace
    def monitor(domain,command,flags):
        assert domain is e.state['domains'][e.original['birth']['uuid']] and command==COMMAND and flags==0
        control['queries']+=1
        return json.dumps({'return':[{'cpu-index':0,'thread-id':901,'qom-path':'/machine/cpu[0]','target':'x86_64'}],'id':'libvirt-1'})
    extension=SimpleNamespace(libvirt=connection._sdk,VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT=0,qemuMonitorCommand=monitor)
    connection._call=lambda target,name,*args,mutate=False:getattr(target,name)(*args)
    domain=e.state['domains'][e.original['birth']['uuid']];domain._raw=domain
    runtime=e.source.runtime;runtime.journal=driver.journal
    queries=PausedCPUQuery(driver.journal,connection,runtime,extension,preflight=e.source.query_preflight)
    def correlator(queries,request,policy):
        control['correlations']+=1
        return QEMUCreationProcess(queries,request,policy,proc_root=c.leader.parent,
            pidfd_open=c.value.pidfd_open,poll_factory=c.value.poll_factory,pid_namespace=c.value.pid_namespace,process_id=lambda:77)
    def process_factory(record):
        return PinnedQEMUProcess(record,proc_root=c.leader.parent,pidfd_open=c.value.pidfd_open,
                                 poll_factory=c.value.poll_factory,pid_namespace=c.value.pid_namespace)
    driver.observer=lambda reference,record:LibvirtDomainObserver(connection,reference,xml_inactive_flag=2,process=process_factory(record))
    e.source.observer=driver.observer
    capture=VMQEMUCreation(driver.definitions,queries,runtime,request_for=e.source.creation_request,
        policy_for=lambda value,request:deepcopy(policy),correlator=correlator,process_factory=process_factory)
    driver.capture_started=capture
    return SimpleNamespace(events=e,driver=driver,capture=capture,queries=queries,control=control,kernel=c,extension=extension)


def test_event_qmp_kernel_and_persistent_birth_complete_before_resume(pipeline):
    p=pipeline;e=p.events
    result=p.driver.apply(e.operation)
    assert result['boot']['phase']=='running' and result['boot']['process_record']['process']['pid']==1234
    assert p.control==dict(queries=1,correlations=1) and e.state['starts']==e.state['resumes']==1
    birth=p.capture._read(result)
    anchor=json.loads(p.driver.journal.db.execute('SELECT payload FROM vm_libvirt_creation_events').fetchone()[0])
    from dnlab_runtime.manifest import fingerprint
    assert birth['request']['creation_sha256']==fingerprint(anchor) and birth['request']['domain_id']==22
    assert p.driver.apply(e.operation)==result and p.control==dict(queries=1,correlations=1)


def test_missing_first_event_prevents_qmp_and_kernel_capture(pipeline):
    p=pipeline;e=p.events;e.control['omit_started']=True
    with pytest.raises(RuntimeErrorBase,match='not observed'):p.driver.apply(e.operation)
    assert p.control==dict(queries=0,correlations=0) and e.state['starts']==1 and e.state['resumes']==0


def test_lost_birth_completion_recovery_keeps_original_event_and_issues_no_query(pipeline,monkeypatch):
    p=pipeline;e=p.events;save=p.capture._save;lost=[]
    def checkpoint(value):
        save(value)
        if value['phase']=='completed' and not lost:
            lost.append(True);raise OSError('lost event-bound birth reply')
    monkeypatch.setattr(p.capture,'_save',checkpoint)
    with pytest.raises(OSError):p.driver.apply(e.operation)
    result=p.driver.recover_creation(e.operation)
    assert result['boot']['phase']=='paused' and p.control==dict(queries=1,correlations=1)
    assert e.state['starts']==1 and e.state['resumes']==0
    assert p.driver.apply(e.operation)['boot']['phase']=='running'
    assert p.control==dict(queries=1,correlations=1) and e.state['starts']==e.state['resumes']==1


def test_lost_qmp_reply_cannot_reissue_query_or_acquire_process_on_recovery(pipeline):
    p=pipeline;e=p.events;monitor=p.extension.qemuMonitorCommand
    def lost(*args):
        monitor(*args);raise OSError('original QMP reply lost')
    p.extension.qemuMonitorCommand=lost
    with pytest.raises(OSError):p.driver.apply(e.operation)
    with pytest.raises(RuntimeErrorBase):p.driver.recover_creation(e.operation)
    assert p.control==dict(queries=1,correlations=0) and e.state['starts']==1 and e.state['resumes']==0
