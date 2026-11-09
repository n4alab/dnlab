"""The original process receipt must survive driver reconstruction unchanged."""
from contextlib import contextmanager
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict
from dnlab_runtime.libvirt_observer import LibvirtDomainObserver, creation_reference
from dnlab_runtime.qemu_process import PinnedQEMUProcess
from dnlab_runtime.vm_boot import VMBootDriver
from dnlab_runtime.vm_template import TemplateError
from test_vm_boot import boot, definition, template, instance
from test_qemu_process import process, observer


def test_reconstructed_driver_uses_saved_complete_record_without_capture(boot):
    driver, operation, state, _, _ = boot
    state['lost_resume'] = True
    with pytest.raises(OSError):driver.apply(operation)
    saved = driver.definitions.read(operation)['boot']
    observed = []
    def observe(reference, record):
        assert reference == saved['reference'] and record == saved['process_record']
        observed.append(deepcopy(record))
        return driver.observer(reference, record)
    def forbidden_capture(*args):pytest.fail('recovery cannot reacquire an original process record')
    recovered = VMBootDriver(driver.definitions, source=driver.source,
                            capture_started=forbidden_capture, observer=observe)
    result = recovered.apply(operation)
    assert result['boot']['phase'] == 'running' and observed == [saved['process_record']]
    assert result['boot']['process_record'] == saved['process_record']
    assert state['starts'] == state['resumes'] == 1


@pytest.mark.parametrize('fault',['birth','process','uid','gid','command','namespace'])
def test_incomplete_or_incompatible_creation_record_never_releases_guest_cpus(boot,fault):
    driver,operation,state,_,_=boot
    capture=driver.capture_started
    def altered(value,domain):
        result=capture(value,domain);record=result['process_record']
        if fault=='birth':record['birth']['nonce']='e'*32
        elif fault=='process':record['process']['pid']+=1
        elif fault in ('uid','gid'):record[fault]+=1
        elif fault=='command':record['cmdline_sha256']='not-a-digest'
        else:record['namespaces']['pid']['inode']=0
        return result
    driver.capture_started=altered
    with pytest.raises(TemplateError):driver.apply(operation)
    saved=driver.definitions.read(operation)['boot']
    assert saved['phase']=='start_requested' and saved['reference'] is None and saved['process_record'] is None
    assert saved['recovery_required'] and state['starts']==1 and state['resumes']==0
    assert state['cpu']==3 and len(state['domains'])==1


def test_original_process_record_cannot_be_overwritten_even_on_same_stage(boot):
    driver,operation,_,_,_=boot
    saved=driver.apply(operation)
    replacement=deepcopy(saved['boot']['process_record']);replacement['cmdline_sha256']='b'*64
    with pytest.raises(Conflict,match='cannot change'):
        driver._advance(operation,'running','running',process_record=replacement)
    assert driver.definitions.read(operation)==saved


def test_old_boot_without_complete_record_requires_explicit_recovery(boot):
    driver,operation,state,_,_=boot
    value=driver.apply(operation)
    del value['boot']['process_record']
    with driver.journal.transaction():driver.definitions._save(operation,value)
    with pytest.raises(TemplateError,match='VM boot journal'):driver.apply(operation)
    assert driver.definitions.read(operation)==value
    assert state['starts']==state['resumes']==1


def test_lost_commit_response_reuses_original_paused_record_without_second_capture(boot,monkeypatch):
    driver,operation,state,_,_=boot
    transaction=driver.journal.transaction;lost=[];captures=[]
    capture=driver.capture_started
    def tracked_capture(value,domain):
        result=capture(value,domain);captures.append(deepcopy(result));return result
    @contextmanager
    def uncertain_commit():
        with transaction():yield
        value=driver.definitions.read(operation)
        if value.get('boot',{}).get('phase')=='paused' and not lost:
            lost.append(True);raise OSError('lost paused receipt commit response')
    monkeypatch.setattr(driver.journal,'transaction',uncertain_commit)
    driver.capture_started=tracked_capture
    with pytest.raises(OSError,match='paused receipt'):driver.apply(operation)
    saved=driver.definitions.read(operation)['boot']
    assert saved['phase']=='paused' and saved['process_record']==captures[0]['process_record']
    result=driver.apply(operation)
    assert result['boot']['phase']=='running' and result['boot']['process_record']==saved['process_record']
    assert len(captures)==1 and state['starts']==state['resumes']==1


def test_boot_and_replay_reconstruct_procfs_provider_from_durable_record(boot,process):
    driver,operation,state,_,_=boot
    provider,record,_,root,_,_,_=process
    record=deepcopy(record);record['gid']=1001
    path=root/'status';path.write_text(path.read_text().replace('1002','1001'))
    reads=[];captures=[]
    def factory(reference,saved_record):
        assert saved_record==record
        reads.append(deepcopy(saved_record))
        pinned=PinnedQEMUProcess(saved_record,proc_root=provider.proc_root,
            pidfd_open=provider.pidfd_open,poll_factory=provider.poll_factory,pid_namespace=provider.pid_namespace)
        return LibvirtDomainObserver(driver.definitions.connection,reference,xml_inactive_flag=2,process=pinned)
    def capture(value,domain):
        assert state['cpu']==3 and value['birth']==record['birth']
        captures.append(True)
        reference=creation_reference(record['birth'],uri=state['uri'],persistent_xml=domain.XMLDesc(2),
                                     live_xml=domain.XMLDesc(0),process=record['process'])
        return {'reference':reference,'process_record':deepcopy(record)}
    driver.capture_started=capture;driver.observer=factory
    saved=driver.apply(operation)
    assert saved['boot']['process_record']==record and len(captures)==1
    assert driver.apply(operation)==saved
    assert reads and state['starts']==state['resumes']==1
