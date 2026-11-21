"""Real two-disk overlays and controllers; domain SDK and network are inert."""
from copy import deepcopy
from pathlib import Path
import uuid

import pytest

from dnlab_runtime.backend_reservations import available
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_xml import render_domain
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_definition_retirement import UnstartedDefinitionRetirement
from dnlab_runtime.vm_storage import VMStorage
from dnlab_runtime.vm_storage_retirement import VMStorageRetirement
from dnlab_runtime.vm_template import template_digest
from test_vm_definition import definition, template, instance
from test_vm_overlay_files import files as overlay_files


@pytest.fixture
def files(tmp_path):
    root = tmp_path/'overlay-fixture';root.mkdir()
    yield from overlay_files.__wrapped__(root)


@pytest.fixture
def cleanup(files,definition,template,instance):
    overlays,_,operation,_,_,root,base = files
    # Keep the real overlay directory outside the immutable bundle root.
    target = root.parent.parent/('disks-'+uuid.uuid4().hex)
    root.rename(target);root = target;overlays.root = str(root)
    template = deepcopy(template);instance = deepcopy(instance)
    template['assets']['base'].update(path=base.name,format='raw',size=base.stat().st_size,
                                      sha256=files[1]['spec']['base_sha256'])
    template['hardware']['disks'].append(dict(id='config',asset='base',bus='virtio',target='vdb',
                                            address=dict(bus=0,slot=7,function=0)))
    instance['bundle_root'] = str(base.parent)
    instance['overlays'] = dict(boot=str(root/'boot.qcow2'),config=str(root/'config.qcow2'))
    instance['domain']['creator_operation_id'] = operation
    source = definition[0]
    definitions = VMDefinitionDriver(overlays.journal,source.connection,source.session,source.preflight,no_domain_code=42)
    birth = {key:instance['domain'][key] for key in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256'] = template_digest(template)
    definitions.prepare('cleanup-create',birth,render_domain(template,**instance))
    state = dict(writers=[],endpoints=True,directory=True)
    storage = VMStorage(definitions,assets=lambda value:dict(template_sha256=birth['template_sha256'],assets_verified=True),
        files=overlays,writers=lambda value:deepcopy(state['writers']))
    ready = storage.prepare(operation,template,str(base.parent));ready = storage.apply(operation)
    original_preflight = definitions.preflight
    def resources(value):
        storage.observe(operation)
        return original_preflight(value)
    definitions.preflight = resources;definitions.apply(operation)
    domain = definitions.connection.lookupByUUIDString(birth['uuid'])
    domain.autostart = lambda:0;domain.hasManagedSaveImage = lambda flags:0
    domain.snapshotNum = lambda flags:0;domain.checkpointCount = lambda:0
    def undefine(flags):
        assert flags == 0;definition[3]['domains'].pop(birth['uuid']);return 0
    domain.undefineFlags = undefine
    def retire_preflight(value):
        return dict(definition_sha256=value.get('retirement',{}).get('definition_sha256',fingerprint(value)),
            session_sha256=value['session_sha256'],never_started=True,writers_absent=True,resources_unchanged=True)
    retirement = UnstartedDefinitionRetirement(definitions,preflight=retire_preflight)
    retirement.prepare('retire-definition',operation);receipt = retirement.apply('retire-definition')
    agreement = dict(operation_id=operation,context={'host_id':'synthetic'},
        targets=['file:'+item['spec']['path'] for item in ready['items']],nonce='e'*32)
    window = ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    def remaining(value):
        return dict(definition_sha256=definitions.read(operation)['request_fingerprint'],
            retirement_sha256=fingerprint(receipt),endpoints_verified=state['endpoints'],directory_verified=state['directory'])
    def make():return VMStorageRetirement(storage,retirement,window=window,preflight=remaining)
    yield make(),operation,storage,retirement,state,make,root,ready


def test_retire_complete_original_disk_set_without_rewriting_storage_history(cleanup):
    driver,operation,storage,_,_,make,root,ready = cleanup
    original = deepcopy(storage.read(operation))
    driver.prepare('remove-disks',operation,'retire-definition')
    result = driver.apply('remove-disks')
    assert result['phase'] == 'removed' and result['proof']['all_overlays_removed'] is True
    assert list(root.iterdir()) == [] and storage.read(operation) == original == ready
    assert make().apply('remove-disks') == result
    assert make().prepare('remove-disks',operation,'retire-definition') == result
    with pytest.raises(Conflict):available(driver.journal,original['birth']['lab_id'],original['birth']['node_id'],'docker')
    assert 'vm_storage_retirements' in cleanup_inventory(driver.journal,original['birth']['lab_id'])['blocked']


def test_last_disk_conflict_prevents_first_disk_removal(cleanup):
    driver,operation,_,_,_,_,root,ready = cleanup
    driver.prepare('remove-disks',operation,'retire-definition')
    path = Path(ready['items'][-1]['spec']['path']);path.rename(root/'retained-original');path.write_bytes(b'foreign')
    before = {p.name:p.read_bytes() for p in root.iterdir()}
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-disks')
    assert {p.name:p.read_bytes() for p in root.iterdir()} == before


def test_partial_set_recovers_without_recreating_or_redeleting_first_disk(cleanup,monkeypatch):
    driver,operation,_,_,state,make,root,ready = cleanup
    driver.prepare('remove-disks',operation,'retire-definition');apply = driver.files.apply
    def stop(item, owner):
        result = apply(item,owner)
        if item == ready['items'][0]:state['endpoints'] = False
        return result
    monkeypatch.setattr(driver.files,'apply',stop)
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-disks')
    assert not Path(ready['items'][0]['spec']['path']).exists()
    assert Path(ready['items'][1]['spec']['path']).exists()
    assert driver.read('remove-disks')['phase'] == 'removing'
    state['endpoints'] = True
    assert make().apply('remove-disks')['phase'] == 'removed' and list(root.iterdir()) == []


@pytest.mark.parametrize('fault',['writer','directory','definition'])
def test_changed_qualified_dependencies_prevent_any_removal(cleanup,fault):
    driver,operation,storage,_,state,_,root,_ = cleanup
    driver.prepare('remove-disks',operation,'retire-definition')
    if fault == 'writer':state['writers'] = [{}]
    elif fault == 'directory':state['directory'] = False
    else:
        current = storage.definitions.read(operation);current['retirement']['id'] = 'foreign'
        with driver.journal.transaction():storage.definitions._save(operation,current)
    before = {p.name:p.read_bytes() for p in root.iterdir()}
    with pytest.raises((RuntimeErrorBase,KeyError)):driver.apply('remove-disks')
    assert {p.name:p.read_bytes() for p in root.iterdir()} == before


def test_storage_retirement_remains_a_cleanup_fence_without_other_intents(cleanup):
    driver,operation,_,_,_,_,_,ready = cleanup
    driver.prepare('remove-disks',operation,'retire-definition');driver.apply('remove-disks')
    with driver.journal.transaction():
        for table in ('vm_definition_intents','vm_storage_intents','vm_definition_retirements'):
            driver.journal.db.execute('DELETE FROM '+table)
    birth = ready['birth']
    with pytest.raises(Conflict):available(driver.journal,birth['lab_id'],birth['node_id'],'docker')
    assert cleanup_inventory(driver.journal,birth['lab_id'])['blocked'] == ['resources','vm_storage_retirements']
