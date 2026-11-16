"""Directory lifecycle/fences with an inert filesystem and SDK; no host IO."""
from copy import deepcopy
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.backend_reservations import available, BackendOwnershipConflict
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_xml import OWNER_NS, render_domain
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_directories import VMDirectories
from dnlab_runtime.vm_template import TemplateError
from dnlab_runtime.vm_template_files import identity
from dnlab_runtime.management_barrier import get as get_barrier, put as put_barrier
from test_vm_definition import definition, template, instance
from test_vm_definition_fences import install_fence


@pytest.fixture
def directories(definition,template,instance,tmp_path,request):
    real_files = getattr(request,'param',False)
    original = definition[0];instance = deepcopy(instance)
    root = str(tmp_path/'resource-root') if real_files else '/vm/workloads'
    if real_files:Path(root).mkdir(mode=0o755);Path(root).chmod(0o755)
    instance['domain'].update(name='directory-vd',uuid='87654321-1234-4234-8234-123456789abc',
                              node_id='directory-vd',creator_operation_id='9'*32,nonce='a'*32)
    path = root+'/'+instance['domain']['uuid']
    instance['overlays']['boot'] = path+'/boot.qcow2';instance['console_path'] = path+'/console.sock'
    journal = Journal(tmp_path/'directory-journal')
    definitions = VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)
    birth = {k:instance['domain'][k] for k in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256'] = definition[1]['template_sha256']
    definitions.prepare('directory-define',birth,render_domain(template,**instance))
    parent = identity(Path(root).stat()) if real_files else dict(device=4,inode=44,uid=0,gid=0,mode=0o755)
    context = dict(host_id='worker',boot_id='fake-boot',namespaces={name:dict(device=4,inode=i+100)
                       for i,name in enumerate(('pid','mnt','net','user'))})
    agreement = dict(operation_id=birth['creator_operation_id'],context=deepcopy(context),
                     targets=['directory:'+path],nonce='b'*32)
    state = dict(files={},requests=set(),creates=0,recovers=0,lost=False,context=context,window=True,preflight=True,hook=None)
    class Files:
        def __init__(self):self.journal = journal
        def observe(self,item,operation):return deepcopy(state['files'].get(item['spec']['path']))
        def create(self,item,operation,*,window):
            window.verify(item,operation)
            state['requests'].add((operation,item['nonce']))
            state['creates'] += 1;spec = item['spec']
            proof = dict(intent_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(spec),
                         identity=dict(device=4,inode=1000,kind='directory',uid=spec['uid'],gid=spec['gid'],mode=spec['mode']))
            state['files'][spec['path']] = proof
            window.verify(item,operation)
            if state['lost']:raise OSError('lost original directory reply')
            return deepcopy(proof)
        def recover(self,item,operation,*,window):
            window.verify(item,operation);state['recovers'] += 1
            if item['spec']['path'] not in state['files']:raise Conflict('original directory birth unavailable')
            return self.observe(item,operation)
        def directory_requested(self,item,operation):return (operation,item['nonce']) in state['requests']
    files = InstallationFiles(journal=journal) if real_files else Files()
    window = ProvisioningWindow(agreement,lambda:deepcopy(agreement) if state['window'] else {})
    def preflight(value,*,mutating):
        if state['hook']:state['hook'](value)
        if not state['preflight']:return {}
        result = dict(definition_sha256=value['definition_sha256'],birth_sha256=fingerprint(value['birth']),
                      parent_sha256=fingerprint(dict(root=root,identity=parent)),
                      template_sha256=value['birth']['template_sha256'],assets_verified=True)
        if mutating:result['exclusive_writer'] = True
        return result
    def make():
        return VMDirectories(definitions,root=root,parent_identity=parent,files=files,window=window,
                             read_context=lambda:deepcopy(state['context']),preflight=preflight)
    yield make(),definitions,birth,state,make,definition[-1]
    journal.close()


def test_directory_create_once_and_original_durable_reply(directories):
    driver,definitions,birth,state,make,_ = directories;operation = birth['creator_operation_id']
    prepared = driver.prepare(operation)
    ready = driver.apply(operation)
    assert ready['phase'] == 'ready' and state['creates'] == 1
    assert ready['nonce'] == prepared['nonce']
    assert ready['proof']['identity']['uid'] == definitions.session.profile['uid']
    assert ready['proof']['identity']['mode'] == 0o700
    state['window'] = False  # Readonly directory observation is not provisioning.
    assert make().apply(operation) == ready
    assert driver.observe(operation) == ready and state['creates'] == 1


@pytest.mark.parametrize('directories',[True],indirect=True)
def test_real_tracked_filesystem_adapter_preserves_vm_directory_birth(directories):
    driver,definitions,birth,_,make,_ = directories;operation = birth['creator_operation_id']
    original = driver.prepare(operation);ready = driver.apply(operation)
    path = Path(ready['spec']['path']);info = path.stat()
    assert ready['phase'] == 'ready' and ready['nonce'] == original['nonce']
    assert (info.st_uid,info.st_gid,info.st_mode&0o777) == (
        definitions.session.profile['uid'],definitions.session.profile['gid'],0o700)
    assert info.st_ino == ready['proof']['identity']['inode']
    assert make().apply(operation) == ready and driver.observe(operation) == ready


def test_lost_reply_recovers_same_directory_without_new_create(directories):
    driver,_,birth,state,make,_ = directories;operation = birth['creator_operation_id']
    original = driver.prepare(operation);state['lost'] = True
    with pytest.raises(OSError,match='lost original'):driver.apply(operation)
    with pytest.raises(Conflict,match='explicit recovery'):make().apply(operation)
    ready = make().recover(operation)
    assert ready['phase'] == 'ready' and ready['nonce'] == original['nonce']
    assert state['creates'] == state['recovers'] == 1


@pytest.mark.parametrize('stage',['prepare','apply'])
@pytest.mark.parametrize('fence',['closed','held'])
def test_lab_and_management_fences_block_directory_allocations(directories,stage,fence):
    driver,definitions,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    if stage == 'apply':driver.prepare(operation)
    install_fence(definitions.journal,fence)
    with pytest.raises(Conflict):getattr(driver,stage)(operation)
    assert state['creates'] == state['recovers'] == 0


def test_fence_after_directory_checkpoint_preserves_pending_and_blocks_mkdir(directories,monkeypatch):
    driver,definitions,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation);save = driver._save
    def checkpoint(value):
        save(value)
        if value['phase'] == 'creating':install_fence(definitions.journal,'held')
    monkeypatch.setattr(driver,'_save',checkpoint)
    with pytest.raises(Conflict,match='management operation'):driver.apply(operation)
    assert state['creates'] == 0 and driver.read(operation)['phase'] == 'creating'
    with pytest.raises(Conflict,match='management operation'):driver.recover(operation)
    assert state['recovers'] == 0
    barrier = get_barrier(definitions.journal,birth['lab_id']);barrier['phase'] = 'released'
    put_barrier(definitions.journal,birth['lab_id'],barrier)
    ready = driver.recover(operation)
    assert ready['phase'] == 'ready' and state['creates'] == 1 and state['recovers'] == 0


def test_recovery_does_not_start_a_prepared_directory_operation(directories):
    driver,_,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    prepared = driver.prepare(operation)
    with pytest.raises(Conflict,match='no original.*requested'):driver.recover(operation)
    assert driver.read(operation) == prepared and state['creates'] == state['recovers'] == 0


def test_incomplete_namespace_context_cannot_prepare_directory_admission(directories):
    driver,definitions,_,state,_,_ = directories
    receipt = deepcopy(driver.window.receipt);del receipt['context']['namespaces']
    with pytest.raises(TemplateError,match='VM directory context'):
        VMDirectories(definitions,root=driver.root,parent_identity=driver.parent,files=driver.files,
            window=ProvisioningWindow(receipt,lambda:receipt),read_context=driver.read_context,preflight=driver.preflight)
    assert state['creates'] == 0
    assert definitions.journal.db.execute('SELECT count(*) FROM vm_directory_intents').fetchone()[0] == 0


@pytest.mark.parametrize('fault',['context','parent-or-assets','window'])
def test_changed_prerequisites_refuse_before_allocation(directories,fault):
    driver,_,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation)
    if fault == 'context':state['context']['namespaces']['mnt']['inode'] += 1
    elif fault == 'parent-or-assets':state['preflight'] = False
    else:state['window'] = False
    with pytest.raises((Conflict,TemplateError)):driver.apply(operation)
    assert state['creates'] == 0


def test_domain_appearing_inside_preflight_refuses_before_create(directories):
    driver,definitions,birth,state,_,Domain = directories;operation = birth['creator_operation_id']
    driver.prepare(operation)
    def appeared(value):
        definitions.connection.defineXMLFlags(definitions.read(operation)['xml'],1)
        state['hook'] = None
    state['hook'] = appeared
    with pytest.raises(Conflict,match='already present'):driver.apply(operation)
    assert state['creates'] == 0


def test_no_directory_creation_after_domain_definition(directories):
    driver,definitions,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation);definitions.apply(operation)
    with pytest.raises(TemplateError,match='must precede'):driver.apply(operation)
    assert state['creates'] == 0


def test_missing_or_replaced_original_directory_is_not_recreated(directories):
    driver,_,birth,state,make,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation);ready = driver.apply(operation)
    state['files'].clear()
    with pytest.raises(Conflict,match='missing or replaced'):make().apply(operation)
    assert state['creates'] == 1 and driver.read(operation) == ready


def test_foreign_directory_is_not_adopted_during_prepare(directories):
    driver,definitions,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    path = driver._plan(definitions.read(operation))['path']
    state['files'][path] = dict(foreign='preserve')
    with pytest.raises(Conflict,match='occupied'):driver.prepare(operation)
    assert state['files'][path] == dict(foreign='preserve') and state['creates'] == 0
    assert definitions.journal.db.execute('SELECT count(*) FROM vm_directory_intents').fetchone()[0] == 0


def test_ready_directory_remains_observable_after_define_or_fencing(directories):
    driver,definitions,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation);ready = driver.apply(operation)
    definitions.apply(operation)
    assert driver.observe(operation) == driver.apply(operation) == ready
    install_fence(definitions.journal,'held')
    assert driver.observe(operation) == ready
    with pytest.raises(Conflict,match='management operation'):driver.prepare(operation)
    assert state['creates'] == 1


def test_directory_intent_independently_holds_backend_and_cleanup(directories):
    driver,definitions,birth,_,_,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation)
    definitions.journal.db.execute('DELETE FROM vm_definition_intents WHERE id=?',(operation,))
    with pytest.raises(BackendOwnershipConflict):available(definitions.journal,birth['lab_id'],birth['node_id'],'docker')
    assert 'vm_directory_intents' in cleanup_inventory(definitions.journal,birth['lab_id'])['blocked']


def test_retained_directory_uuid_cannot_be_reused_by_another_node(directories):
    driver,definitions,birth,state,_,_ = directories;operation = birth['creator_operation_id']
    driver.prepare(operation)
    original = definitions.read(operation);xml = ET.fromstring(original['xml'])
    other = deepcopy(birth);other.update(lab_id='other-lab',node_id='other-vd',creator_operation_id='a'*32,nonce='b'*32)
    xml.find('name').text = 'other-vd'
    owner = xml.find('metadata/{'+OWNER_NS+'}owner')
    for key in ('lab_id','node_id','creator_operation_id','nonce'):owner.set(key,other[key])
    # Simulate missing unrelated bookkeeping; the directory intent is enough.
    definitions.journal.db.execute('DELETE FROM vm_definition_intents WHERE id=?',(operation,))
    definitions.journal.db.execute('DELETE FROM resources')
    with pytest.raises(BackendOwnershipConflict):
        definitions.prepare('other-node',other,ET.tostring(xml,encoding='unicode'))
    assert definitions.journal.db.execute('SELECT count(*) FROM vm_definition_intents').fetchone()[0] == 0
    assert state['creates'] == 0


@pytest.mark.parametrize('field',['disk','console'])
def test_disk_and_console_parent_cannot_escape_uuid_scope(directories,field):
    driver,definitions,birth,state,_,_ = directories
    value = definitions.read(birth['creator_operation_id']);root = ET.fromstring(value['xml'])
    if field == 'disk':root.find('devices/disk/source').set('file','/foreign/boot.qcow2')
    else:root.find('devices/serial/source').set('path','/foreign/console.sock')
    value['xml'] = ET.tostring(root,encoding='unicode')
    with pytest.raises(TemplateError,match='direct children'):driver._plan(value)
    assert state['creates'] == 0
