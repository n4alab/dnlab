"""Only temporary filesystem dependencies; no host collection."""
import pytest

from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict
from tools.libvirt_install_parents import collect, parent_paths
from test_libvirt_service_profile import request_profile


@pytest.fixture
def parents(tmp_path, request_profile):
    root = tmp_path/'root'
    root.mkdir()
    profile = render_profile(**request_profile)
    for path in parent_paths(profile):
        (root/path.lstrip('/')).mkdir(parents=True, exist_ok=True)
    return root, profile


def test_dependencies_exclude_planned_directories_and_ignore_child_activity(parents):
    root, profile = parents
    before = collect(root, profile)
    assert set(before) == {'/', '/etc', '/etc/systemd', '/etc/systemd/system', '/run', '/var', '/var/lib'}
    (root/'var/lib/unrelated').write_text('preserve')
    assert collect(root, profile) == before
    assert (root/'var/lib/unrelated').read_text() == 'preserve'


@pytest.mark.parametrize('fault', ['writable', 'inaccessible', 'symlink', 'file', 'absent'])
def test_unqualified_parent_is_refused_without_changes(parents, fault):
    root, profile = parents
    path = root/'var/lib'
    if fault == 'writable':path.chmod(0o777)
    elif fault == 'inaccessible':path.chmod(0o700)
    else:
        path.rmdir()
        if fault == 'symlink':path.symlink_to(root/'etc', target_is_directory=True)
        elif fault == 'file':path.write_text('preserve')
    with pytest.raises(Conflict, match='OS parent'):collect(root, profile)
    if fault == 'file':assert path.read_text() == 'preserve'
    if fault == 'symlink':assert path.is_symlink()


def test_replacement_changes_dependency_identity(parents):
    root, profile = parents
    before = collect(root, profile)
    path = root/'var/lib'
    path.rename(root/'var/original')
    path.mkdir()
    assert collect(root, profile) != before
