"""Original paused creation -> real synthetic proc correlation -> durable boot."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_observer import LibvirtDomainObserver, xml_fingerprint
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.qemu_creation_process import QEMUCreationProcess
from dnlab_runtime.qemu_process import PinnedQEMUProcess
from dnlab_runtime.vm_qemu_creation import VMQEMUCreation
from test_vm_boot import boot, definition, template, instance
from test_qemu_creation_process import creation, process, observer
from test_vm_definition_fences import install_fence


@pytest.fixture
def creator(boot,creation):
    driver,operation,state,_,_=boot;c=creation
    for path in c.leader.parent.rglob('status'):path.write_text(path.read_text().replace('1002','1001'))
    control=dict(queries=0,correlations=0,epoch=dict(id='e'*32))
    policy=deepcopy(c.policy);policy['gid']=1001
    c.receipt['cpus']=c.receipt['cpus'][:1]
    def request_for(value,domain):
        request=dict(birth=deepcopy(value['birth']),source_id=value['boot']['source_id'],creation_sha256='d'*64,
                     persistent_sha256=xml_fingerprint(domain.XMLDesc(2),value['birth']),
                     live_sha256=xml_fingerprint(domain.XMLDesc(0),value['birth']),domain_id=22,expected_cpus=1)
        c.request.clear();c.request.update(deepcopy(request));c.receipt['request']=deepcopy(request)
        return request
    class Queries:
        journal=driver.journal
        connection=driver.definitions.connection
        def query(self,request):control['queries']+=1;return self.read_completed(request)
        def read_completed(self,request):return c.value.queries.read_completed(request)
    queries=Queries()
    runtime=SimpleNamespace(journal=driver.journal,check=lambda:deepcopy(control['epoch']))
    def correlator(queries,request,policy):
        control['correlations']+=1
        return QEMUCreationProcess(queries,request,policy,proc_root=c.leader.parent,
            pidfd_open=c.value.pidfd_open,poll_factory=c.value.poll_factory,pid_namespace=c.value.pid_namespace,process_id=lambda:77)
    def process_factory(record):
        return PinnedQEMUProcess(record,proc_root=c.leader.parent,pidfd_open=c.value.pidfd_open,
                                 poll_factory=c.value.poll_factory,pid_namespace=c.value.pid_namespace)
    capture=VMQEMUCreation(driver.definitions,queries,runtime,request_for=request_for,policy_for=lambda value,request:deepcopy(policy),
                           correlator=correlator,process_factory=process_factory)
    driver.capture_started=capture
    driver.observer=lambda reference,record:LibvirtDomainObserver(driver.definitions.connection,reference,
                                xml_inactive_flag=2,process=process_factory(record))
    return SimpleNamespace(driver=driver,capture=capture,operation=operation,state=state,kernel=c,control=control)


def test_kernel_process_receipt_is_durable_before_boot_resume_and_not_reacquired(creator):
    e=creator;result=e.driver.apply(e.operation)
    assert result['boot']['phase']=='running'
    saved=e.capture._read(result)
    assert saved['phase']=='completed' and saved['receipt']['process_record']==result['boot']['process_record']
    assert saved['receipt']['process_record']['process']['pid']==1234
    assert e.control['queries']==e.control['correlations']==1 and e.state['starts']==e.state['resumes']==1
    assert e.driver.apply(e.operation)==result
    assert e.control['queries']==e.control['correlations']==1


def lose_completion(e,monkeypatch):
    save=e.capture._save;lost=[]
    def checkpoint(value):
        save(value)
        if value['phase']=='completed' and not lost:
            lost.append(True);raise OSError('original creation completion reply lost')
    monkeypatch.setattr(e.capture,'_save',checkpoint)
    with pytest.raises(OSError,match='completion reply'):e.driver.apply(e.operation)
    return e.driver.definitions.read(e.operation)


def test_lost_completion_preserves_original_birth_and_explicit_recovery_never_recaptures(creator,monkeypatch):
    e=creator;value=lose_completion(e,monkeypatch)
    saved=e.capture._read(value)
    assert saved['phase']=='completed' and value['boot']['phase']=='start_requested'
    with pytest.raises(RuntimeErrorBase,match='not repeated'):e.driver.apply(e.operation)
    result=e.driver.recover_creation(e.operation)
    assert result['boot']['phase']=='paused' and result['boot']['process_record']==saved['receipt']['process_record']
    assert e.capture._read(result)==saved and e.state['starts']==1 and e.state['resumes']==0
    assert e.control['queries']==e.control['correlations']==1
    assert e.driver.apply(e.operation)['boot']['phase']=='running'
    assert e.state['starts']==e.state['resumes']==1 and e.control['queries']==e.control['correlations']==1


def test_failed_first_capture_remains_pending_without_recapture_or_cpu_release(creator):
    e=creator;e.kernel.binary.write_bytes(b'foreign executable')
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    value=e.driver.definitions.read(e.operation)
    assert e.capture._read(value)['phase']=='pending' and value['boot']['phase']=='start_requested'
    with pytest.raises(RuntimeErrorBase,match='cannot be repeated'):e.driver.recover_creation(e.operation)
    assert e.control['queries']==e.control['correlations']==1 and e.state['starts']==1 and e.state['resumes']==0


@pytest.mark.parametrize('fault',['missing','process','runtime','closing','held'])
def test_recovery_refuses_missing_or_changed_original_proofs(creator,monkeypatch,fault):
    e=creator;value=lose_completion(e,monkeypatch);saved=e.capture._read(value)
    if fault=='missing':e.driver.journal.db.execute('DELETE FROM vm_qemu_process_creations')
    elif fault=='process':
        path=e.kernel.leader/'stat';path.write_bytes(path.read_bytes().replace(b'5678',b'5690'))
    elif fault=='runtime':e.control['epoch']['id']='a'*32
    else:install_fence(e.driver.journal,fault)
    with pytest.raises(RuntimeErrorBase):e.driver.recover_creation(e.operation)
    assert e.state['cpu']==3 and e.state['starts']==1 and e.state['resumes']==0
    assert e.control['queries']==e.control['correlations']==1
    if fault!='missing':assert e.capture._read(e.driver.definitions.read(e.operation))==saved


def test_checkpoint_fence_blocks_qmp_and_kernel_capture_after_birth_intent(creator,monkeypatch):
    e=creator;guard=e.capture._guard;changed=[]
    def checkpoint(value):
        if not changed and e.driver.journal.db.execute('SELECT 1 FROM vm_qemu_process_creations').fetchone():
            changed.append(True);install_fence(e.driver.journal,'closing')
        return guard(value)
    monkeypatch.setattr(e.capture,'_guard',checkpoint)
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.state['starts']==1 and e.state['resumes']==0 and e.state['cpu']==3
    assert e.control['queries']==e.control['correlations']==0
    assert e.capture._read(e.driver.definitions.read(e.operation))['phase']=='pending'


def test_creation_record_alone_keeps_its_lab_protected_until_qualified_cleanup(creator,tmp_path):
    e=creator;result=e.driver.apply(e.operation)
    row=e.driver.journal.db.execute('SELECT * FROM vm_qemu_process_creations').fetchone()
    isolated=Journal(tmp_path/'isolated-creation-journal')
    try:
        isolated.db.execute('CREATE TABLE vm_qemu_process_creations '
            '(id TEXT PRIMARY KEY,creator TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
        isolated.db.execute('INSERT INTO vm_qemu_process_creations VALUES(?,?,?,?)',tuple(row))
        assert cleanup_inventory(isolated,result['birth']['lab_id'])==dict(
            nodes=[result['birth']['node_id']],blocked=['vm_qemu_process_creations'])
        assert cleanup_inventory(isolated,'another-lab')==dict(nodes=[],blocked=[])
    finally:isolated.close()
