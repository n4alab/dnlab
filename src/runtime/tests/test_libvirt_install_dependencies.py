"""Temporary directories only; no account changes or host observations."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_install_dependencies import InstallationDirectoryDependencies
from dnlab_runtime.manifest import Conflict
from test_libvirt_service_profile import request_profile


@pytest.fixture
def dependency(tmp_path):
    root = tmp_path/'root'
    path = root/'etc/dnlab'
    path.mkdir(parents=True)
    spec = dict(key='directory:/etc/dnlab', kind='directory', path='/etc/dnlab', uid=0, gid=0, mode=0o755)
    return root, path, spec, InstallationDirectoryDependencies(root, [spec])


def test_explicit_dependency_is_readonly_and_ignores_unrelated_children(dependency):
    root, path, spec, reader = dependency
    receipt = reader(spec)
    (path/'foreign.conf').write_text('preserve')
    assert reader(spec) == receipt
    assert set(receipt['ancestors']) == {'/', '/etc'}
    assert receipt['identity']['kind'] == 'directory'
    assert (path/'foreign.conf').read_text() == 'preserve'
    assert path.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize('fault', ['symlink', 'missing', 'file', 'writable', 'private', 'ancestor'])
def test_foreign_or_unqualified_directory_is_refused_without_repair(dependency, fault):
    root, path, spec, reader = dependency
    if fault in ('symlink', 'missing', 'file'):
        path.rmdir()
        if fault == 'symlink':path.symlink_to(root/'etc', target_is_directory=True)
        elif fault == 'file':path.write_text('preserve')
    elif fault == 'writable':path.chmod(0o777)
    elif fault == 'private':path.chmod(0o700)
    else:path.parent.chmod(0o777)
    with pytest.raises(Conflict):reader(spec)
    if fault == 'symlink':assert path.is_symlink()
    if fault == 'file':assert path.read_text() == 'preserve'
    if fault == 'writable':assert path.stat().st_mode & 0o777 == 0o777


def test_receipt_changes_after_replacement_and_preserves_original(dependency):
    root, path, spec, reader = dependency
    before = reader(spec)
    path.rename(path.with_name('original'))
    path.mkdir()
    assert reader(spec) != before
    assert (root/'etc/original').is_dir()


def test_replacement_between_reads_is_refused(dependency, monkeypatch):
    _, path, spec, reader = dependency
    snapshot = reader._snapshot
    calls = []
    def replacing(value):
        if calls:
            path.rename(path.with_name('original'))
            path.mkdir()
        calls.append(True)
        return snapshot(value)
    monkeypatch.setattr(reader, '_snapshot', replacing)
    with pytest.raises(Conflict, match='changed during observation'):reader(spec)


def test_unselected_spec_is_refused_before_io(dependency, monkeypatch):
    _, _, spec, reader = dependency
    changed = deepcopy(spec);changed['path'] = '/etc/other'
    monkeypatch.setattr(reader, '_snapshot', lambda *a:pytest.fail('unselected read'))
    with pytest.raises(Conflict, match='explicitly selected'):reader(changed)


@pytest.mark.parametrize('field,value', [('mode', 0o777), ('uid', 1), ('path', '/etc/../etc/dnlab')])
def test_invalid_dependency_selection_is_rejected(dependency, field, value):
    root, _, spec, _ = dependency
    changed = deepcopy(spec);changed[field] = value
    with pytest.raises(Conflict):InstallationDirectoryDependencies(root, [changed])


@pytest.fixture
def prepared(dependency, tmp_path, request_profile):
    from dnlab_runtime.journal import Journal
    from dnlab_runtime.libvirt_install import SessionInstaller, targets
    from dnlab_runtime.libvirt_install_adapter import ProvisioningAdapter
    from dnlab_runtime.libvirt_install_files import InstallationFiles
    from dnlab_runtime.libvirt_provisioning import InstallationAccounts, ProvisioningWindow
    from dnlab_runtime.libvirt_service_profile import render_profile
    from test_libvirt_install_adapter import Helper
    root, path, spec, reader = dependency
    journal = Journal(tmp_path/'journal')
    helper = Helper()
    profile = render_profile(**request_profile)
    window_receipt = dict(operation_id='install', context={'boot':'synthetic'},
                          targets=[item['key'] for item in targets(profile)], nonce='b'*32)
    window = ProvisioningWindow(window_receipt, lambda:deepcopy(window_receipt))
    snapshot = dict(context=window_receipt['context'], prerequisites={'provisioning_window_sha256':window.sha256})
    adapter = ProvisioningAdapter(window=window, accounts=InstallationAccounts(journal, helper),
        files=InstallationFiles(root, journal=journal), snapshot=lambda:deepcopy(snapshot), directory_dependency=reader)
    driver = SessionInstaller(journal, adapter)
    value = driver.prepare('install', request_profile, **snapshot, existing_directories={spec['path']:reader(spec)})
    try:yield driver, helper, value, path
    finally:journal.close()


def test_prepare_replay_binds_original_dependency_without_creating_resources(prepared):
    driver, helper, value, path = prepared
    before = driver.journal.db.total_changes
    (path/'foreign.conf').write_text('preserve')
    result = driver.prepare(value['id'], value['request'], context=value['context'],
        prerequisites=value['prerequisites'], existing_directories=value['dependencies'])
    assert result == value and helper.calls == []
    assert driver.journal.db.total_changes == before
    assert (path/'foreign.conf').read_text() == 'preserve'


@pytest.mark.parametrize('fault', ['replace', 'mode', 'ancestor'])
def test_dependency_conflict_blocks_apply_before_account_mutation(prepared, fault):
    driver, helper, value, path = prepared
    if fault == 'replace':
        path.rename(path.with_name('original'))
        path.mkdir()
    elif fault == 'mode':path.chmod(0o777)
    else:path.parent.chmod(0o777)
    before = driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert helper.calls == [] and driver.journal.db.total_changes == before
    assert driver.read(value['id']) == value
