"""Current runtime epoch with synthetic proc snapshots and inert pidfd FDs."""
from copy import deepcopy
import os
import select
from types import SimpleNamespace

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_runtime_process import RuntimeProcess
from test_vm_definition import definition,template,instance
from test_vm_tap_device import kernel


@pytest.fixture
def runtime_process(tmp_path):
    journal=Journal(tmp_path/'journal')
    spaces={name:dict(device=4,inode=index+100) for index,name in enumerate(('pid','mnt','net','user'))}
    profile=dict(host_id='worker',executable_sha256='a'*64,cmdline_sha256='b'*64,namespaces=spaces,sources_sha256='c'*64)
    snapshot=dict(record=dict(boot_id='12345678-1234-4234-8234-123456789abc',pid=123,start_ticks=456,
        uid=0,gid=0,executable_sha256='a'*64,namespace_sha256=fingerprint(spaces)),
        namespaces=deepcopy(spaces),proc_identity=[4,800],cmdline_sha256='b'*64)
    state=dict(snapshot=snapshot,sources='c'*64,pid=123,events=[],fds=[],reads=0,thread=deepcopy(spaces))
    def read(pid):
        assert pid==123;state['reads']+=1
        return deepcopy(state['snapshot'])
    def pidfd(pid,flags):
        assert (pid,flags)==(123,0)
        fd=os.open('/dev/null',os.O_RDONLY);state['fds'].append(fd);return fd
    class Poll:
        def register(self,fd,events):assert events==select.POLLIN;self.fd=fd
        def poll(self,timeout):assert timeout==0;return [(self.fd,event) for event in state['events']]
    instances=[]
    def make():
        instance=RuntimeProcess(journal,profile,verify_sources=lambda:state['sources'],
            reader=SimpleNamespace(read_process=read),pidfd_open=pidfd,poll_factory=Poll,process_id=lambda:state['pid'],
            thread_namespaces=lambda:deepcopy(state['thread']))
        instances.append(instance);return instance
    witness=make();epoch=witness.start()
    birth=dict(uuid='22345678-1234-4234-8234-123456789abc',lab_id='lab',node_id='vd',host_id='worker',
        generation=1,creator_operation_id='d'*32,nonce='e'*32,template_sha256='f'*64)
    command=dict(action='vm-tap-lease',operation_id=birth['creator_operation_id'],birth=birth,definition_sha256='1'*64,
        context=dict(boot_id=snapshot['record']['boot_id'],**spaces['net']),specs=[dict(unexecuted=True)])
    try:yield witness,epoch,command,state,make
    finally:
        for instance in instances:instance.close()
        journal.close()


def test_current_process_epoch_issues_immutable_reference_once(runtime_process):
    witness,epoch,command,state,_=runtime_process
    reference=witness.reference(command)
    assert reference['process_record']==epoch['snapshot']['record']
    assert witness.reference(command)==reference and witness.verify(reference,command) is True
    assert len(state['fds'])==1
    assert witness.journal.db.execute('SELECT count(*) FROM vm_runtime_references').fetchone()[0]==1
    assert cleanup_inventory(witness.journal,'lab')==dict(nodes=['vd'],blocked=['vm_runtime_references'])


@pytest.mark.parametrize('fault',['pid','start','namespace','thread','proc','executable','cmdline','sources','profile'])
def test_changed_runtime_incarnation_is_refused_without_new_reference(runtime_process,fault):
    witness,_,command,state,_=runtime_process;reference=witness.reference(command)
    if fault=='pid':state['pid']=9999
    elif fault=='start':state['snapshot']['record']['start_ticks']+=1
    elif fault=='namespace':state['snapshot']['namespaces']['net']['inode']+=1
    elif fault=='thread':state['thread']['net']['inode']+=1
    elif fault=='proc':state['snapshot']['proc_identity'][1]+=1
    elif fault=='executable':state['snapshot']['record']['executable_sha256']='9'*64
    elif fault=='cmdline':state['snapshot']['cmdline_sha256']='9'*64
    elif fault=='sources':state['sources']='9'*64
    else:witness.profile['sources_sha256']='9'*64
    before=witness.journal.db.total_changes
    with pytest.raises(RuntimeErrorBase):witness.verify(reference,command)
    assert witness.journal.db.total_changes==before and len(state['fds'])==1


@pytest.mark.parametrize('event',[select.POLLIN,select.POLLHUP,select.POLLERR,select.POLLNVAL,select.POLLIN|select.POLLERR])
def test_pidfd_events_cannot_attest_a_live_runtime(runtime_process,event):
    witness,_,command,state,_=runtime_process;reference=witness.reference(command)
    state['events']=[event]
    with pytest.raises(Conflict,match='pidfd'):witness.verify(reference,command)


def test_new_epoch_cannot_adopt_old_command_even_if_snapshot_matches(runtime_process):
    original,epoch,command,_,make=runtime_process
    reference=original.reference(command);other=make();second=other.start()
    assert second['id']!=epoch['id'] and second['snapshot']==epoch['snapshot']
    before=other.journal.db.total_changes
    with pytest.raises(Conflict,match='another epoch'):other.verify(reference,command)
    with pytest.raises(Conflict,match='another epoch'):other.reference(command)
    assert other.journal.db.total_changes==before
    assert original.verify(reference,command) is True


def test_closed_witness_cannot_reopen_and_does_not_claim_process_exit(runtime_process):
    witness,epoch,command,state,_=runtime_process;reference=witness.reference(command)
    row=tuple(witness.journal.db.execute('SELECT * FROM vm_runtime_epochs').fetchone())
    fd=witness.fd;witness.close()
    with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(RuntimeErrorBase):witness.start()
    with pytest.raises(RuntimeErrorBase):witness.verify(reference,command)
    assert tuple(witness.journal.db.execute('SELECT * FROM vm_runtime_epochs').fetchone())==row
    assert len(state['fds'])==1


def test_reference_for_other_host_or_namespace_is_refused(runtime_process):
    witness,_,command,_,_=runtime_process
    for fault in ('host','namespace'):
        changed=deepcopy(command)
        if fault=='host':changed['birth']['host_id']='other'
        else:changed['context']['inode']+=1
        with pytest.raises(RuntimeErrorBase):witness.reference(changed)
    assert witness.journal.db.execute('SELECT count(*) FROM vm_runtime_references').fetchone()[0]==0


def test_changed_command_cannot_overwrite_reference(runtime_process):
    witness,_,command,_,_=runtime_process;reference=witness.reference(command)
    changed=deepcopy(command);changed['definition_sha256']='2'*64
    with pytest.raises(Conflict,match='cannot change'):witness.reference(changed)
    assert witness.reference(command)==reference


def test_snapshot_change_during_capture_closes_only_its_new_pidfd(runtime_process):
    original,_,_,state,make=runtime_process;other=make();read=other.reader.read_process;calls=[]
    def changed(pid):
        value=read(pid);calls.append(pid)
        if len(calls)>1:value['proc_identity'][1]+=1
        return value
    other.reader.read_process=changed
    with pytest.raises(Conflict,match='during capture'):other.start()
    assert other.fd is None
    with pytest.raises(OSError):os.fstat(state['fds'][-1])
    assert original.fd is not None
    assert original.journal.db.execute('SELECT count(*) FROM vm_runtime_epochs').fetchone()[0]==1


def test_current_runtime_witness_drives_tap_tasks(definition,kernel):
    from dnlab_runtime.vm_tap_local import LocalTapEndpoints,worker_command
    from dnlab_runtime.vm_tap_retention import RetainedTapDevice
    from dnlab_runtime.vm_taps import VMTaps
    from dnlab_runtime.vm_tap_tasks import TapTasks
    from xml.etree import ElementTree as ET
    definitions,birth,xml,_,_,_=definition
    _,context,state,factory=kernel;devices=[]
    spaces={name:dict(device=4,inode=index+100) for index,name in enumerate(('pid','mnt','net','user'))}
    spaces['net']={key:context[key] for key in ('device','inode')}
    snapshot=dict(record=dict(boot_id=context['boot_id'],pid=1234,start_ticks=12345,uid=0,gid=0,
        executable_sha256='a'*64,namespace_sha256=fingerprint(spaces)),namespaces=spaces,
        proc_identity=[4,800],cmdline_sha256='b'*64)
    profile=dict(host_id=birth['host_id'],executable_sha256='a'*64,cmdline_sha256='b'*64,
        namespaces=spaces,sources_sha256='c'*64)
    class Poll:
        def register(self,fd,mask):pass
        def poll(self,timeout):return []
    witness=RuntimeProcess(definitions.journal,profile,verify_sources=lambda:'c'*64,
        reader=SimpleNamespace(read_process=lambda pid:deepcopy(snapshot)),process_id=lambda:1234,
        pidfd_open=lambda pid,flags:os.open('/dev/null',os.O_RDONLY),poll_factory=Poll,
        thread_namespaces=lambda:deepcopy(spaces))
    def device_factory(spec,scope,record):
        device=factory(RetainedTapDevice);device.spec=deepcopy(spec);device.context=deepcopy(scope)
        device.record=record;devices.append(device);return device
    provider=LocalTapEndpoints(definitions.journal,read_context=lambda:deepcopy(state['scope']),
        inventory=lambda:deepcopy(list(state['links'].values())),verify_worker=witness.verify,
        device_factory=device_factory,process_id=lambda:1234)
    def preflight(value):
        definition=definitions.read(value['id'])
        return dict(definition_sha256=value['definition_sha256'],session_sha256=definition['session_sha256'],
            context_sha256=fingerprint(context),session_namespace_verified=True,guest_writers_absent=True)
    taps=VMTaps(definitions,endpoints=provider,read_context=lambda:deepcopy(state['scope']),preflight=preflight)
    provider.attach(taps)
    try:
        witness.start()
        requests=[dict(name=target.get('dev'),ifindex=12001+index,nonce=str(index+1)*32,vnet_header=True)
            for index,target in enumerate(ET.fromstring(xml).findall('devices/interface/target'))]
        prepared=taps.prepare(birth['creator_operation_id'],context,requests)
        reference=witness.reference(worker_command(prepared));tasks=TapTasks(taps)
        tasks.submit(prepared['id'],reference)
        assert tasks.execute(prepared['id'])['phase']=='completed'
        assert provider._actor(prepared['id'])['reference']==reference
        assert len(devices)==2
        witness.close()
        with pytest.raises(RuntimeErrorBase):taps.observe(prepared['id'])
        assert tasks.read(prepared['id'])['phase']=='completed'  # historical stage, not present readiness
    finally:
        for device in devices:device.close()
        witness.close()


