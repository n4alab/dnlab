"""Real temporary directory births; domain/resource qualification is synthetic."""
from copy import deepcopy
import os
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

from dnlab_runtime.backend_reservations import available
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition_retirement import UnstartedDefinitionRetirement
from dnlab_runtime.vm_directory_retirement import VMDirectoryRetirement
from dnlab_runtime.vm_console import socket_identity
from test_vm_directories import directories as directory_fixture
from test_vm_definition import definition, template, instance


@pytest.fixture
def directories(definition,template,instance,tmp_path):
    yield from directory_fixture.__wrapped__(definition,template,instance,tmp_path,SimpleNamespace(param=True))


@pytest.fixture
def cleanup(directories,definition):
    directories,definitions,birth,_,_,_ = directories;operation = birth['creator_operation_id']
    directories.prepare(operation);ready = directories.apply(operation);definitions.apply(operation)
    domain = definitions.connection.lookupByUUIDString(birth['uuid'])
    domain.autostart = lambda:0;domain.hasManagedSaveImage = lambda flags:0
    domain.snapshotNum = lambda flags:0;domain.checkpointCount = lambda:0
    def undefine(flags):
        assert flags == 0;definition[3]['domains'].pop(birth['uuid']);return 0
    domain.undefineFlags = undefine
    def before(current):
        assert directories.observe(operation) == ready
        return dict(definition_sha256=current.get('retirement',{}).get('definition_sha256',fingerprint(current)),
            session_sha256=current['session_sha256'],never_started=True,writers_absent=True,resources_unchanged=True)
    retirement = UnstartedDefinitionRetirement(definitions,preflight=before)
    retirement.prepare('retire-domain',operation);receipt = retirement.apply('retire-domain')
    agreement = deepcopy(directories.window.receipt);agreement['nonce'] = 'e'*32
    state = dict(window=deepcopy(agreement),storage=True,taps=True,writers=True)
    window = ProvisioningWindow(agreement,lambda:deepcopy(state['window']))
    def preflight(value):
        return dict(definition_sha256=ready['definition_sha256'],retirement_sha256=fingerprint(receipt),
            storage_retirement_sha256='a'*64,tap_retirement_sha256='b'*64,
            storage_removed_verified=state['storage'],taps_absent_verified=state['taps'],writers_absent=state['writers'])
    def make():return VMDirectoryRetirement(directories,retirement,window=window,preflight=preflight)
    driver = make()
    def prepare():return driver.prepare('retire-directory',operation,'retire-domain',
        storage_retirement_sha256='a'*64,tap_retirement_sha256='b'*64)
    return driver,operation,state,make,Path(ready['spec']['path']),ready,prepare


def test_empty_original_directory_is_removed_once_and_history_preserved(cleanup):
    driver,operation,_,make,path,ready,prepare = cleanup
    prepared = prepare();result = driver.apply('retire-directory')
    assert result['phase'] == 'removed' and result['proof']['parent_synced'] is True
    assert not path.exists() and path.parent.is_dir()
    assert driver.directories.read(operation) == ready
    assert driver.files._birth(driver.directories._item(ready),operation) == prepared['file_birth']
    assert make().apply('retire-directory') == result
    assert prepare() == result


@pytest.mark.parametrize('kind',['file','socket'])
def test_unqualified_contents_prevent_quarantine_or_deletion(cleanup,kind):
    driver,_,_,_,path,_,prepare = cleanup
    if kind == 'file':(path/'foreign').write_bytes(b'preserve')
    else:
        fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:stream.bind(f'/proc/self/fd/{fd}/console.sock')
        finally:os.close(fd)
    with pytest.raises(RuntimeErrorBase):prepare()
    assert path.is_dir() and len(list(path.iterdir())) == 1
    assert driver.journal.db.execute('SELECT count(*) FROM vm_directory_retirements').fetchone()[0] == 0


@pytest.mark.parametrize('fault',['storage','taps','writers','window'])
def test_changed_dependencies_prevent_any_filesystem_mutation(cleanup,fault):
    driver,_,state,_,path,_,prepare = cleanup
    prepare()
    if fault == 'window':state['window']['nonce'] = 'f'*32
    else:state[fault] = False
    before = path.stat().st_ino
    with pytest.raises(RuntimeErrorBase):driver.apply('retire-directory')
    assert path.stat().st_ino == before and list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize('boundary',['rename','rmdir','fsync'])
def test_lost_effect_recovers_without_repeating_mutation(cleanup,monkeypatch,boundary):
    driver,_,_,make,path,_,prepare = cleanup
    prepare();calls = []
    with monkeypatch.context() as patch:
        if boundary == 'rename':
            from dnlab_runtime.vm_directory_retirement import rename_siblings
            def lost(*args):
                calls.append(True);rename_siblings(*args);raise OSError('lost rename result')
            patch.setattr('dnlab_runtime.vm_directory_retirement.rename_siblings',lost)
        elif boundary == 'rmdir':
            rmdir = os.rmdir
            def lost(*args,**kwargs):
                calls.append(True);rmdir(*args,**kwargs);raise OSError('lost rmdir result')
            patch.setattr(os,'rmdir',lost)
        else:
            fsync = os.fsync
            def lost(fd):
                if not list(path.parent.iterdir()):
                    calls.append(True);raise OSError('lost parent durability')
                return fsync(fd)
            patch.setattr(os,'fsync',lost)
        with pytest.raises(OSError,match='lost'):driver.apply('retire-directory')
    assert len(calls) == 1
    assert make().apply('retire-directory')['phase'] == 'removed' and list(path.parent.iterdir()) == []


def test_uncertain_unapplied_rename_is_never_repeated(cleanup,monkeypatch):
    driver,_,_,make,path,_,prepare = cleanup
    prepare()
    def failed(*args):raise OSError('uncertain before rename')
    with monkeypatch.context() as patch:
        patch.setattr('dnlab_runtime.vm_directory_retirement.rename_siblings',failed)
        with pytest.raises(OSError):driver.apply('retire-directory')
    with pytest.raises(RuntimeErrorBase,match='no resend'):make().apply('retire-directory')
    assert path.exists()


def test_directory_missing_before_rmdir_intent_is_not_backfilled(cleanup,monkeypatch):
    driver,_,_,make,path,_,prepare = cleanup
    prepare();advance = driver._advance
    def stop(value,phase):
        advance(value,phase)
        if phase == 'empty':raise OSError('stop before rmdir intent')
    with monkeypatch.context() as patch:
        patch.setattr(driver,'_advance',stop)
        with pytest.raises(OSError,match='stop before'):driver.apply('retire-directory')
    original = driver.read('retire-directory');assert original['phase'] == 'empty'
    os.rmdir(path.parent/original['quarantine'])
    with pytest.raises(FileNotFoundError):make().apply('retire-directory')
    assert driver.read('retire-directory') == original


def test_reoccupied_original_path_rolls_back_completion(cleanup,monkeypatch):
    driver,_,_,_,path,_,prepare = cleanup
    prepare();write = driver._write
    def changed(value):
        write(value)
        if value['phase'] == 'removed':path.mkdir();(path/'foreign').write_bytes(b'preserve')
    monkeypatch.setattr(driver,'_write',changed)
    with pytest.raises(RuntimeErrorBase,match='reappeared'):driver.apply('retire-directory')
    assert driver.read('retire-directory')['phase'] == 'rmdir_requested'
    assert (path/'foreign').read_bytes() == b'preserve'


def test_directory_retirement_independently_fences_cleanup_and_backend(cleanup):
    driver,_,_,_,_,ready,prepare = cleanup
    prepare();driver.apply('retire-directory')
    with driver.journal.transaction():
        for table in ('vm_definition_intents','vm_directory_intents','vm_definition_retirements'):
            driver.journal.db.execute('DELETE FROM '+table)
    birth = ready['birth']
    with pytest.raises(Conflict):available(driver.journal,birth['lab_id'],birth['node_id'],'docker')
    assert 'vm_directory_retirements' in cleanup_inventory(driver.journal,birth['lab_id'])['blocked']


def test_administrative_parent_replacement_preserves_original_tree(cleanup):
    driver,_,_,_,path,_,prepare = cleanup
    prepare();root = path.parent;retained = root.with_name('retained-root')
    root.rename(retained);root.mkdir(mode=0o755)
    with pytest.raises(RuntimeErrorBase,match='parent changed'):driver.apply('retire-directory')
    assert (retained/path.name).is_dir() and list(root.iterdir()) == []


def test_contents_policy_matches_exact_socket_and_rejects_hardlink_alias(cleanup):
    # Only the contents matcher is exercised here. This synthetic endpoint
    # value is not persisted and does not authorize an unlink or claim QEMU.
    driver,operation,_,_,path,_,_ = cleanup
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:stream.bind(f'/proc/self/fd/{fd}/console.sock')
        endpoint = socket_identity(fd,'console.sock')
        value = dict(definition=driver.definitions.read(operation),console={'endpoint':endpoint})
        assert driver._contents(fd,value) == ['console.sock']
        alias = path.parent/'aliased-console';os.link(path/'console.sock',alias)
        with pytest.raises(RuntimeErrorBase,match='unaliased'):driver._contents(fd,value)
        assert (path/'console.sock').exists() and alias.exists()
    finally:os.close(fd)
