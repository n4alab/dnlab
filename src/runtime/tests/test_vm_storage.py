"""VM overlay ownership and crash boundaries with synthetic disk providers."""
from copy import deepcopy

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_storage import VMStorage
from dnlab_runtime.vm_template import TemplateError
from test_vm_definition import definition, template, instance


@pytest.fixture
def storage(definition, template):
    definitions, birth, _, _, _, _ = definition
    return make_storage(definitions, birth, template)


def make_storage(definitions, birth, template):
    state = dict(files={}, creates=0, recovers=0, lost=False, assets=True, writers=[])

    class Files:
        def observe(self, item, operation):
            return deepcopy(state['files'].get(item['spec']['path']))

        def create(self, item, operation):
            state['creates'] += 1
            assert definitions.journal.db.execute('SELECT payload FROM vm_storage_intents WHERE id=?', (operation,)).fetchone()
            spec = item['spec']
            proof = dict(operation_id=operation, nonce=item['nonce'], spec_sha256=fingerprint(spec),
                         identity=dict(device=4, inode=12345 + state['creates'], uid=spec['uid'], gid=spec['gid'], mode=spec['mode']),
                         creation=dict(request_sha256=fingerprint(dict(operation_id=operation, nonce=item['nonce'], spec=spec)),
                                       worker_reference_sha256='f' * 64, exit_code=0))
            state['files'][spec['path']] = proof
            if state['lost']:raise OSError('lost original format response')
            return deepcopy(proof)

        def recover(self, item, operation):
            state['recovers'] += 1
            proof = self.observe(item, operation)
            if proof is None:raise Conflict('original formatter completion unavailable')
            return proof

    files = Files()
    def make():
        return VMStorage(definitions, assets=lambda value:dict(template_sha256=birth['template_sha256'], assets_verified=state['assets']),
                         files=files, writers=lambda value:deepcopy(state['writers']))
    driver = make()
    value = driver.prepare(birth['creator_operation_id'], template, '/templates/synthetic')
    return driver, value, state, make, definitions


@pytest.fixture
def two_disks(definition, template, instance, tmp_path):
    from dnlab_runtime.journal import Journal
    from dnlab_runtime.libvirt_xml import render_domain
    from dnlab_runtime.vm_definition import VMDefinitionDriver
    from dnlab_runtime.vm_template import template_digest
    original, birth, _, _, _, _ = definition
    template['hardware']['disks'].append(dict(id='config', asset='base', bus='virtio', target='vdb',
                                            address=dict(bus=0, slot=7, function=0)))
    instance['overlays']['config'] = '/persist/lab/vd/config.qcow2'
    birth = deepcopy(birth);birth['template_sha256'] = template_digest(template)
    journal = Journal(tmp_path/'two-disks-journal')
    try:
        definitions = VMDefinitionDriver(journal, original.connection, original.session, original.preflight, no_domain_code=42)
        definitions.prepare('two-disks', birth, render_domain(template, **instance))
        yield make_storage(definitions, birth, template)
    finally:journal.close()


def test_create_once_and_reopen_preserves_overlay_identity(storage):
    driver, value, state, make, _ = storage
    ready = driver.apply(value['id'])
    assert ready['phase'] == 'ready' and state['creates'] == 1
    assert make().apply(value['id']) == ready
    assert driver.prepare(value['id'], value['template'], value['bundle_root']) == ready
    assert state['creates'] == 1 and state['recovers'] == 0
    assert 'vm_storage_intents' in cleanup_inventory(driver.journal, 'lab')['blocked']


def test_lost_format_response_recovers_original_birth_without_new_create(storage):
    driver, value, state, make, _ = storage
    state['lost'] = True
    with pytest.raises(OSError):driver.apply(value['id'])
    assert driver.read(value['id'])['items'][0]['phase'] == 'create_requested'
    ready = make().apply(value['id'])
    assert ready['phase'] == 'ready'
    assert state['creates'] == 1 and state['recovers'] == 1


@pytest.mark.parametrize('fault', ['missing', 'inode', 'nonce'])
def test_ready_overlay_cannot_be_recreated_or_adopted(storage, fault):
    driver, value, state, _, _ = storage
    ready = driver.apply(value['id']);path = ready['items'][0]['spec']['path']
    if fault == 'missing':state['files'].pop(path)
    elif fault == 'inode':state['files'][path]['identity']['inode'] += 1
    else:state['files'][path]['nonce'] = 'a' * 32
    before = driver.journal.db.total_changes
    with pytest.raises(Conflict, match='missing or replaced'):driver.apply(value['id'])
    assert driver.journal.db.total_changes == before and state['creates'] == 1


def test_changed_assets_after_checkpoint_prevent_creation(storage, monkeypatch):
    driver, value, state, _, _ = storage
    save = driver._save
    def changed(current):
        save(current)
        if current['items'][0]['phase'] == 'create_requested':state['assets'] = False
    monkeypatch.setattr(driver, '_save', changed)
    with pytest.raises(TemplateError, match='bundle verification required'):driver.apply(value['id'])
    assert state['creates'] == 0
    assert driver.read(value['id'])['items'][0]['phase'] == 'create_requested'


def test_uncertain_absence_does_not_authorize_another_format(storage, monkeypatch):
    driver, value, state, make, _ = storage
    monkeypatch.setattr(driver.files, 'create', lambda *args:(_ for _ in ()).throw(OSError('unknown format outcome')))
    with pytest.raises(OSError):driver.apply(value['id'])
    with pytest.raises(Conflict, match='completion unavailable'):make().apply(value['id'])
    assert state['creates'] == 0 and state['recovers'] == 1
    assert driver.read(value['id'])['items'][0]['phase'] == 'create_requested'


def writer_record(birth):
    return dict(birth=deepcopy(birth),process=dict(boot_id='synthetic',pid=789,start_ticks=456,executable_sha256='d'*64),
                uid=1001,gid=1001,cmdline_sha256='e'*64,
                namespaces={key:dict(device=4,inode=number) for number,key in enumerate(('pid','mnt','net','user'),1)})


def test_active_original_writer_can_inspect_but_cannot_be_ignored(storage):
    driver, value, state, _, definitions = storage
    ready = driver.apply(value['id'])
    original = definitions.read(value['id']);record = writer_record(original['birth'])
    original['boot'] = dict(process_record=deepcopy(record))
    with driver.journal.transaction():definitions._save(value['id'], original)
    state['writers'] = [record]
    assert driver.apply(value['id']) == ready
    state['writers'] = []
    with pytest.raises(Conflict, match='absence needs verified shutdown'):driver.observe(value['id'])
    assert state['creates'] == 1


@pytest.mark.parametrize('fault', ['foreign', 'multiple'])
def test_foreign_or_multiple_writers_block_creation(storage, fault):
    driver, value, state, _, _ = storage
    record = writer_record(value['birth'])
    state['writers'] = [record] * (2 if fault == 'multiple' else 1)
    with pytest.raises(TemplateError):driver.apply(value['id'])
    assert state['creates'] == 0 and driver.read(value['id'])['phase'] == 'prepared'


def test_storage_reservation_survives_missing_definition_for_container_admission(storage):
    from test_vm_backend_exclusion import native_start
    driver, value, _, _, _ = storage
    driver.journal.db.execute('DELETE FROM vm_definition_intents WHERE id=?', (value['id'],))
    with pytest.raises(Conflict, match='reserved by VM'):driver.journal.submit(native_start())
    assert 'vm_storage_intents' in cleanup_inventory(driver.journal, 'lab')['blocked']


def test_cephfs_cannot_silently_reuse_local_qualification(storage):
    driver, value, _, _, _ = storage
    before = driver.journal.db.total_changes
    with pytest.raises(TemplateError, match='separate qualification'):
        driver.prepare(value['id'], value['template'], value['bundle_root'], storage_type='cephfs')
    assert driver.journal.db.total_changes == before


def test_last_disk_conflict_blocks_every_allocation(two_disks):
    driver, value, state, _, _ = two_disks
    state['files'][value['items'][1]['spec']['path']] = dict(foreign='preserve')
    before = driver.journal.db.total_changes
    with pytest.raises(Conflict, match='already occupied'):driver.apply(value['id'])
    assert state['creates'] == 0 and driver.journal.db.total_changes == before


@pytest.mark.parametrize('boundary', ['before', 'during-preflight', 'checkpoint'])
def test_management_fence_blocks_overlay_creation_at_every_boundary(storage, monkeypatch, boundary):
    from test_vm_definition_fences import install_fence
    driver, value, state, _, _ = storage
    if boundary == 'before':install_fence(driver.journal, 'held')
    elif boundary == 'during-preflight':
        assets = driver.assets
        def changed(current):
            result = assets(current);install_fence(driver.journal, 'held');return result
        monkeypatch.setattr(driver, 'assets', changed)
    else:
        save = driver._save
        def checkpoint(current):
            save(current);install_fence(driver.journal, 'held')
        monkeypatch.setattr(driver, '_save', checkpoint)
    with pytest.raises(Conflict, match='management operation'):driver.apply(value['id'])
    assert state['creates'] == 0


def test_two_overlay_paths_cannot_alias_one_inode(two_disks, monkeypatch):
    driver, value, state, _, _ = two_disks
    original = driver.files.create
    def alias(item, operation):
        proof = original(item, operation)
        if state['creates'] == 2:
            proof['identity']['inode'] -= 1
            state['files'][item['spec']['path']] = deepcopy(proof)
        return proof
    monkeypatch.setattr(driver.files, 'create', alias)
    with pytest.raises(TemplateError, match='distinct original VM overlay inodes'):driver.apply(value['id'])
    assert driver.read(value['id'])['items'][1]['phase'] == 'create_requested'
