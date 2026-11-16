"""Immutable template copies on temporary files; no host images or services."""
import hashlib
import os

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template_files import TemplateAssetFiles, identity


@pytest.fixture
def asset(tmp_path, monkeypatch):
    import dnlab_runtime.vm_template_files as module
    monkeypatch.setattr(module, 'CHUNK', 4096)
    root = tmp_path/'store';root.mkdir(mode=0o755);root.chmod(0o755)
    source = tmp_path/'source.raw';data = bytes(range(251))*80;source.write_bytes(data)
    target = root/'base.raw'
    journal = Journal(tmp_path/'journal')
    parent = identity(root.stat())
    def preflight(request):
        return dict(request_sha256=fingerprint(request), exclusive_writer=True, source_verified=True)
    def make(**options):
        return TemplateAssetFiles(journal, root=str(root), parent_identity=parent,
                                  preflight=preflight, **options)
    files = make()
    request = dict(source=str(source), destination=str(target),
                   sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    yield files, journal, source, target, data, request, make
    journal.close()


def test_copy_is_immutable_idempotent_and_independent_of_staging_source(asset):
    files, _, source, target, data, request, make = asset
    original = files.prepare('import-base', **request)
    assert files.prepare('import-base', **request) == original
    proof = files.apply('import-base')
    assert target.read_bytes() == data and target.stat().st_mode & 0o777 == 0o444
    source.unlink()  # A published template must outlive the build staging area.
    assert files.observe('import-base') == files.apply('import-base') == proof
    observer = make(readonly=True)
    assert observer.observe('import-base') == proof
    with pytest.raises(Conflict, match='readonly'):observer.recover('import-base')


def test_foreign_destination_is_preserved_before_preparing(asset):
    files, journal, _, target, _, request, _ = asset
    target.write_bytes(b'foreign')
    with pytest.raises(Conflict, match='occupied'):files.prepare('import-base', **request)
    assert target.read_bytes() == b'foreign'
    assert journal.db.execute('SELECT count(*) FROM vm_template_asset_files').fetchone()[0] == 0


def test_changed_source_is_rejected_before_destination_birth(asset):
    files, _, source, target, data, request, _ = asset
    files.prepare('import-base', **request)
    other = source.with_suffix('.replacement');other.write_bytes(data);other.replace(source)
    with pytest.raises(Conflict, match='source identity'):files.apply('import-base')
    assert not target.exists() and files.read('import-base')['phase'] == 'prepared'


def interrupt_copy(files, target, monkeypatch):
    import dnlab_runtime.vm_template_files as module
    write = os.write;lost = []
    def uncertain(fd, content):
        if os.readlink('/proc/self/fd/'+str(fd)) == str(target) and not lost:
            lost.append(True);write(fd, content[:17]);raise OSError('lost copy response')
        return write(fd, content)
    with monkeypatch.context() as patch:
        patch.setattr(module.os, 'write', uncertain)
        with pytest.raises(OSError, match='lost copy response'):files.apply('import-base')
    assert lost == [True] and target.stat().st_size == 17


def test_recovery_resumes_only_verified_original_prefix(asset, monkeypatch):
    files, _, _, target, data, request, make = asset
    files.prepare('import-base', **request);interrupt_copy(files, target, monkeypatch)
    inode = target.stat().st_ino
    with pytest.raises(Conflict, match='explicit recovery'):files.apply('import-base')
    with pytest.raises(Conflict, match='durability pending'):files.observe('import-base')
    reopened = make();proof = reopened.recover('import-base')
    assert target.read_bytes() == data and target.stat().st_ino == inode
    assert reopened.observe('import-base') == proof


@pytest.mark.parametrize('fault', ['content', 'inode', 'marker'])
def test_recovery_never_rewrites_foreign_or_corrupt_prefix(asset, monkeypatch, fault):
    from dnlab_runtime.vm_template_files import MARKER
    files, _, _, target, _, request, make = asset
    files.prepare('import-base', **request);interrupt_copy(files, target, monkeypatch)
    if fault == 'content':target.write_bytes(b'corrupt prefix')
    elif fault == 'inode':
        foreign = target.with_suffix('.foreign');foreign.write_bytes(b'foreign');foreign.replace(target)
    else:os.setxattr(target, MARKER, b'foreign-marker')
    before = target.read_bytes();inode = target.stat().st_ino
    with pytest.raises(Conflict):make().recover('import-base')
    assert target.read_bytes() == before and target.stat().st_ino == inode
    assert files.read('import-base')['phase'] == 'copying'


def test_uncertain_fsync_remains_pending_until_explicit_reconfirmation(asset, monkeypatch):
    import dnlab_runtime.vm_template_files as module
    files, _, source, target, data, request, make = asset
    files.prepare('import-base', **request)
    fsync = os.fsync
    def fail(fd):
        if os.readlink('/proc/self/fd/'+str(fd)) == str(target):raise OSError('uncertain fsync')
        return fsync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(module.os, 'fsync', fail)
        with pytest.raises(OSError, match='uncertain fsync'):files.apply('import-base')
    assert files.read('import-base')['phase'] == 'sealing'
    assert target.read_bytes() == data
    source.unlink()  # Complete content can be sealed without recreating its source.
    with pytest.raises(Conflict, match='durability pending'):files.observe('import-base')
    proof = make().recover('import-base')
    assert files.observe('import-base') == proof


def test_missing_birth_does_not_adopt_a_matching_file(asset, monkeypatch):
    files, _, _, target, data, request, make = asset
    files.prepare('import-base', **request)
    original = files._save
    def lost_birth(value):
        if value['phase'] == 'copying':raise OSError('birth not saved')
        return original(value)
    monkeypatch.setattr(files, '_save', lost_birth)
    with pytest.raises(OSError, match='birth not saved'):files.apply('import-base')
    target.write_bytes(data)
    with pytest.raises(Conflict, match='birth missing'):make().recover('import-base')
    assert target.read_bytes() == data and files.read('import-base')['phase'] == 'create_requested'


def test_replaced_parent_does_not_receive_a_copy(asset):
    files, _, _, target, _, request, _ = asset
    files.prepare('import-base', **request)
    root = target.parent;root.rename(root.with_name('original-store'));root.mkdir(mode=0o755)
    with pytest.raises(Conflict, match='parent differs'):files.apply('import-base')
    assert list(root.iterdir()) == []


def test_foreign_destination_appearing_during_preflight_is_preserved(asset):
    files, _, _, target, _, request, _ = asset
    files.prepare('import-base', **request)
    preflight = files.preflight
    def conflict(value):
        target.write_bytes(b'foreign at checkpoint')
        return preflight(value)
    files.preflight = conflict
    with pytest.raises(Conflict, match='occupied'):files.apply('import-base')
    assert target.read_bytes() == b'foreign at checkpoint'
    assert files.read('import-base')['phase'] == 'prepared'


def test_new_link_to_original_inode_blocks_copy_before_writes(asset):
    files, _, _, target, _, request, _ = asset
    files.prepare('import-base', **request)
    preflight = files.preflight;alias = target.with_suffix('.foreign-link')
    def conflict(value):
        if target.exists() and not alias.exists():os.link(target, alias)
        return preflight(value)
    files.preflight = conflict
    with pytest.raises(Conflict, match='inode or metadata'):files.apply('import-base')
    assert target.read_bytes() == alias.read_bytes() == b''
    assert files.read('import-base')['phase'] == 'copying'
