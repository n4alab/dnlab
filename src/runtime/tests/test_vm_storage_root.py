"""Administrative VM root on synthetic providers or exclusively temporary files."""
from copy import deepcopy
import os
from types import SimpleNamespace

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_storage_root import VMStorageRoot, LocalStorageParent, parent_spec


def scope(boot='boot-a'):
    return dict(host_id='master', boot_id=boot, namespaces={name:dict(device=4, inode=index+20)
        for index,name in enumerate(('pid', 'mnt', 'net', 'user'))})


@pytest.fixture
def root_case(tmp_path):
    journal = Journal(tmp_path/'journal')
    operation, path = 'storage-root', '/storage/instances'
    identity = dict(device=4, inode=100, uid=0, gid=0, mode=0o755, kind='directory')
    parent = dict(directory=dict(dependency='existing_directory', path='/storage',
        identity=identity, ancestors={'/':dict(identity, inode=1)}), filesystem='ext4')
    agreement = dict(operation_id=operation, context=scope(), targets=['directory:'+path], nonce='a'*32)
    state = dict(context=scope(), parent=deepcopy(parent), proof=None, requested=False,
                 creates=0, recovers=0, window=True, lose=False, before_birth=False)

    class Files:
        root = '/'
        def __init__(self):self.journal = journal
        def observe(self, item, owner):return deepcopy(state['proof'])
        def directory_requested(self, item, owner):return state['requested']
        def create(self, item, owner, *, window):
            window.verify(item, owner)
            state['requested'] = True; state['creates'] += 1
            if state['before_birth']:raise OSError('original birth response unavailable')
            state['proof'] = dict(intent_id=owner, nonce=item['nonce'], spec_sha256=fingerprint(item['spec']),
                identity=dict(device=4, inode=200, uid=0, gid=0, mode=0o755, kind='directory'))
            if state['lose']:raise OSError('original create response lost')
            return deepcopy(state['proof'])
        def recover(self, item, owner, *, window):
            window.verify(item, owner); state['recovers'] += 1
            if state['proof'] is None:raise Conflict('original directory birth missing')
            return deepcopy(state['proof'])

    class Parent:
        root = '/'
        def __call__(self, spec):
            assert spec == parent_spec(path)
            return deepcopy(state['parent'])

    files = Files(); reader = Parent()
    window = ProvisioningWindow(agreement, lambda:deepcopy(agreement) if state['window'] else {})
    def make(*, current=None, selected_window=window, readonly=False):
        return VMStorageRoot(journal, files=files, parent_reader=reader,
            context=state['context'] if current is None else current,
            read_context=lambda:deepcopy(state['context']), window=selected_window, readonly=readonly)
    try:
        yield SimpleNamespace(driver=make(), make=make, journal=journal, files=files, state=state,
                              operation=operation, path=path, parent=parent, agreement=agreement)
    finally:
        journal.close()


def test_create_once_and_closed_window_does_not_prevent_readonly_use(root_case):
    e = root_case; original = e.driver.prepare(e.operation, e.path, e.parent)
    assert original['phase'] == 'prepared' and e.state['creates'] == 0
    ready = e.driver.apply(e.operation)
    assert ready['phase'] == 'ready' and ready['nonce'] == original['nonce']
    e.state['window'] = False
    assert e.make().apply(e.operation) == e.make().observe(e.operation) == ready
    assert e.make().prepare(e.operation, e.path, e.parent) == ready
    assert e.driver.identity(e.operation) == dict(device=4, inode=200, uid=0, gid=0, mode=0o755)
    assert e.state['creates'] == 1 and e.state['recovers'] == 0


def test_lost_create_reply_requires_recovery_of_original_birth(root_case):
    e = root_case; original = e.driver.prepare(e.operation, e.path, e.parent); e.state['lose'] = True
    with pytest.raises(OSError, match='response lost'):e.driver.apply(e.operation)
    with pytest.raises(Conflict, match='explicit recovery'):e.make().apply(e.operation)
    ready = e.make().recover(e.operation)
    assert ready['nonce'] == original['nonce'] and e.state['creates'] == e.state['recovers'] == 1


def test_missing_birth_after_lower_request_never_releases_another_mkdir(root_case):
    e = root_case; e.driver.prepare(e.operation, e.path, e.parent); e.state['before_birth'] = True
    with pytest.raises(OSError):e.driver.apply(e.operation)
    pending = e.driver.read(e.operation)
    with pytest.raises(Conflict, match='birth missing'):e.make().recover(e.operation)
    assert e.driver.read(e.operation) == pending and e.state['creates'] == 1 and e.state['proof'] is None


def test_parent_changed_after_checkpoint_blocks_lower_creation_and_can_resume_original(root_case, monkeypatch):
    e = root_case; original = e.driver.prepare(e.operation, e.path, e.parent); save = e.driver._save
    def changed(value):
        save(value)
        if value['phase'] == 'creating':e.state['parent']['directory']['identity']['inode'] += 1
    monkeypatch.setattr(e.driver, '_save', changed)
    with pytest.raises(RuntimeErrorBase, match='parent replaced'):e.driver.apply(e.operation)
    assert e.state['creates'] == 0 and e.driver.read(e.operation)['phase'] == 'creating'
    e.state['parent'] = deepcopy(e.parent)
    result = e.make().recover(e.operation)
    assert result['nonce'] == original['nonce'] and e.state['creates'] == 1 and e.state['recovers'] == 0


@pytest.mark.parametrize('fault', ['context', 'window', 'parent'])
def test_preflight_conflict_preserves_prepared_intent_without_mkdir(root_case, fault):
    e = root_case; original = e.driver.prepare(e.operation, e.path, e.parent)
    if fault == 'context':e.state['context']['boot_id'] = 'boot-b'
    elif fault == 'window':e.state['window'] = False
    else:e.state['parent']['directory']['identity']['inode'] += 1
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.driver.read(e.operation) == original and e.state['creates'] == 0


def test_ready_root_can_be_observed_in_separately_bound_current_boot_without_rewriting_birth(root_case):
    e = root_case; e.driver.prepare(e.operation, e.path, e.parent); ready = e.driver.apply(e.operation)
    e.state['context'] = scope('boot-b')
    current = e.make(selected_window=None, readonly=True)
    before = e.journal.db.total_changes
    assert current.observe(e.operation) == ready and current.identity(e.operation)['inode'] == 200
    assert ready['context']['boot_id'] == 'boot-a'
    assert e.journal.db.total_changes == before and e.state['creates'] == 1


def test_pending_creation_is_not_adopted_by_a_new_boot_or_window(root_case):
    e = root_case; e.driver.prepare(e.operation, e.path, e.parent); e.state['lose'] = True
    with pytest.raises(OSError):e.driver.apply(e.operation)
    original = e.driver.read(e.operation); e.state['context'] = scope('boot-b')
    agreement = dict(e.agreement, context=scope('boot-b'))
    current = e.make(selected_window=ProvisioningWindow(agreement, lambda:agreement))
    with pytest.raises(RuntimeErrorBase, match='creator context'):current.recover(e.operation)
    assert e.driver.read(e.operation) == original and e.state['recovers'] == 0


def test_target_has_one_original_intent_and_changed_retry_does_not_replace_it(root_case):
    e = root_case; original = e.driver.prepare(e.operation, e.path, e.parent)
    with pytest.raises(RuntimeErrorBase, match='already reserved'):
        e.driver.prepare('another-operation', e.path, e.parent)
    parent = deepcopy(e.parent); parent['directory']['identity']['inode'] += 1
    with pytest.raises(RuntimeErrorBase, match='retry inputs differ'):
        e.driver.prepare(e.operation, e.path, parent)
    assert e.driver.read(e.operation) == original and e.state['creates'] == 0


def test_nonlocal_profile_is_rejected_before_allocations(root_case):
    e = root_case; parent = deepcopy(e.parent); parent['filesystem'] = 'ceph'
    with pytest.raises(RuntimeErrorBase, match='local ext4'):e.driver.prepare(e.operation, e.path, parent)
    assert e.state['creates'] == 0
    assert e.journal.db.execute('SELECT 1 FROM vm_storage_roots').fetchone() is None


def test_changed_window_receipt_cannot_reuse_its_old_hash(root_case):
    e = root_case; original = e.driver.prepare(e.operation, e.path, e.parent)
    e.driver.window.receipt['nonce'] = 'f'*32
    with pytest.raises(RuntimeErrorBase, match='creator context and window'):e.driver.apply(e.operation)
    assert e.state['creates'] == 0 and e.driver.read(e.operation) == original


def test_other_host_cannot_consume_the_original_root_receipt(root_case):
    e = root_case; e.driver.prepare(e.operation, e.path, e.parent); e.driver.apply(e.operation)
    e.state['context']['host_id'] = 'worker'
    with pytest.raises(RuntimeErrorBase, match='host/current context'):
        e.make(selected_window=None, readonly=True).observe(e.operation)


def test_readonly_observer_cannot_prepare_apply_or_recover(root_case):
    e = root_case; e.driver.prepare(e.operation, e.path, e.parent); ready = e.driver.apply(e.operation)
    e.journal.db.execute('PRAGMA query_only=ON')
    current = e.make(readonly=True)
    assert current.observe(e.operation) == ready
    with pytest.raises(RuntimeErrorBase, match='provisioning'):
        current.prepare(e.operation, e.path, e.parent)
    for action in (current.apply, current.recover):
        with pytest.raises(RuntimeErrorBase, match='readonly'):action(e.operation)
    assert e.state['creates'] == 1 and e.state['recovers'] == 0


@pytest.fixture
def temporary_root(tmp_path):
    # Use an exclusive ext4 basetemp for this suite. No host instance path is used.
    tmp_path.chmod(0o755); (tmp_path/'storage').mkdir(mode=0o755)
    journal = Journal(tmp_path/'journal'); files = InstallationFiles(tmp_path, journal=journal)
    parent_reader = LocalStorageParent(files)
    parent = parent_reader(parent_spec('/storage/instances'))
    agreement = dict(operation_id='temporary-root', context=scope(),
                     targets=['directory:/storage/instances'], nonce='c'*32)
    window = ProvisioningWindow(agreement, lambda:deepcopy(agreement))
    driver = VMStorageRoot(journal, files=files, parent_reader=parent_reader,
                           context=scope(), read_context=scope, window=window)
    try:
        yield SimpleNamespace(driver=driver, files=files, parent=parent, path=tmp_path/'storage/instances',
                              operation='temporary-root', journal=journal)
    finally:
        journal.close()


def test_actual_temporary_root_birth_and_existing_adapter_are_reused(temporary_root):
    e = temporary_root; prepared = e.driver.prepare(e.operation, '/storage/instances', e.parent)
    ready = e.driver.apply(e.operation)
    assert ready['nonce'] == prepared['nonce'] and ready['proof']['identity']['inode'] == e.path.stat().st_ino
    assert (e.path.stat().st_uid, e.path.stat().st_gid, e.path.stat().st_mode&0o777) == (0, 0, 0o755)
    assert e.driver.observe(e.operation) == ready
    assert e.files._birth(e.driver._item(ready), e.operation)['phase'] == 'durability_confirmed'


def test_fsync_failure_keeps_original_inode_pending_until_explicit_recovery(temporary_root, monkeypatch):
    e = temporary_root; original = e.driver.prepare(e.operation, '/storage/instances', e.parent)
    fsync = os.fsync; failed = []
    def fault(fd):
        if e.path.exists() and os.fstat(fd).st_ino == e.path.stat().st_ino and not failed:
            failed.append(True); raise OSError('synthetic root fsync failure')
        return fsync(fd)
    monkeypatch.setattr(os, 'fsync', fault)
    with pytest.raises(OSError, match='fsync failure'):e.driver.apply(e.operation)
    inode = e.path.stat().st_ino
    with pytest.raises(RuntimeErrorBase, match='pending'):e.driver.observe(e.operation)
    monkeypatch.setattr(os, 'fsync', fsync)
    ready = e.driver.recover(e.operation)
    assert ready['nonce'] == original['nonce'] and e.path.stat().st_ino == inode


def test_foreign_existing_directory_is_preserved_without_a_new_intent(temporary_root):
    e = temporary_root; e.path.mkdir(); (e.path/'preserve').write_text('foreign')
    with pytest.raises(RuntimeErrorBase, match='birth missing'):
        e.driver.prepare(e.operation, '/storage/instances', e.parent)
    assert (e.path/'preserve').read_text() == 'foreign'
    assert e.journal.db.execute('SELECT 1 FROM vm_storage_roots').fetchone() is None


def test_actual_parent_replacement_blocks_mkdir_without_removing_foreign_parent(temporary_root):
    e = temporary_root; prepared = e.driver.prepare(e.operation, '/storage/instances', e.parent)
    parent = e.path.parent; old = parent.with_name('original-storage'); parent.rename(old); parent.mkdir(mode=0o755)
    (parent/'preserve').write_text('foreign')
    with pytest.raises(RuntimeErrorBase, match='parent replaced'):e.driver.apply(e.operation)
    assert (parent/'preserve').read_text() == 'foreign' and old.is_dir() and not e.path.exists()
    assert e.driver.read(e.operation) == prepared
    assert e.journal.db.execute('SELECT 1 FROM libvirt_install_file_births').fetchone() is None


def test_completed_root_replacement_cannot_be_consumed_as_a_new_birth(temporary_root):
    e = temporary_root; e.driver.prepare(e.operation, '/storage/instances', e.parent)
    ready = e.driver.apply(e.operation); old = e.path.with_name('original-instances'); e.path.rename(old)
    e.path.mkdir(mode=0o755); (e.path/'preserve').write_text('foreign')
    with pytest.raises(RuntimeErrorBase):e.driver.identity(e.operation)
    assert e.driver.read(e.operation) == ready and old.stat().st_ino == ready['proof']['identity']['inode']
    assert (e.path/'preserve').read_text() == 'foreign'
