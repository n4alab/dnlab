"""Offline bundle publication on synthetic files, including interrupted copies."""
import hashlib
import os

import pytest

from dnlab_runtime.vm_bundle import read_bundle
from dnlab_runtime.vm_bundle_prepare import prepare_bundle
from dnlab_runtime.vm_template import TemplateError, template_digest
from test_vm_template import template


@pytest.fixture
def preparation(template, tmp_path):
    source = tmp_path / 'original.qcow2'
    data = b'synthetic immutable base'
    source.write_bytes(data)
    template['assets']['base'].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    parent = tmp_path / 'bundles'
    parent.mkdir(mode=0o700)
    root = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(source, os.O_RDONLY)
    try:
        yield template, parent, root, fd, data
    finally:
        os.close(fd)
        os.close(root)
        # pytest cleanup must be able to remove the explicitly sealed fixtures.
        for directory in parent.rglob('*'):
            if directory.is_dir():directory.chmod(0o700)


def test_publish_reuses_no_source_offset_and_is_readable_as_immutable_bundle(preparation):
    template, parent, root, fd, data = preparation
    os.lseek(fd, 3, os.SEEK_SET)
    name = prepare_bundle(root, template, {'base': fd})
    result = read_bundle(parent / name, name)
    assert result['template'] == template
    assert os.lseek(fd, 0, os.SEEK_CUR) == 3
    assert (parent / name / 'disks/base.qcow2').read_bytes() == data
    assert (parent / name / 'disks/base.qcow2').stat().st_mode & 0o777 == 0o444
    assert not (parent / name / '.manifest.pending').exists()


def test_existing_foreign_or_previous_bundle_is_preserved(preparation):
    template, parent, root, fd, _ = preparation
    target = parent / template_digest(template)
    target.mkdir()
    (target / 'foreign').write_bytes(b'preserve')
    with pytest.raises(FileExistsError):prepare_bundle(root, template, {'base': fd})
    assert list(target.iterdir()) == [target / 'foreign']
    assert (target / 'foreign').read_bytes() == b'preserve'


def test_content_mismatch_leaves_attempt_without_published_manifest(preparation):
    template, parent, root, fd, _ = preparation
    template['assets']['base']['sha256'] = 'e' * 64
    with pytest.raises(TemplateError, match='content changed or differs'):
        prepare_bundle(root, template, {'base': fd})
    target = parent / template_digest(template)
    assert (target / 'preparation.json').exists()
    assert not (target / 'manifest.json').exists()
    with pytest.raises(FileExistsError):prepare_bundle(root, template, {'base': fd})


def test_metadata_collision_is_rejected_before_creating_attempt(preparation):
    template, parent, root, fd, _ = preparation
    template['assets']['base']['path'] = 'manifest.json'
    with pytest.raises(TemplateError, match='conflict'):
        prepare_bundle(root, template, {'base': fd})
    assert list(parent.iterdir()) == []


def test_durability_failure_preserves_attempt_without_reuse(preparation, monkeypatch):
    import dnlab_runtime.vm_bundle_prepare as writer
    template, parent, root, fd, _ = preparation

    def fail(descriptor):
        raise OSError('synthetic fsync failure')

    monkeypatch.setattr(writer.os, 'fsync', fail)
    with pytest.raises(OSError, match='synthetic fsync failure'):
        prepare_bundle(root, template, {'base': fd})
    target = parent / template_digest(template)
    assert target.is_dir() and list(target.iterdir()) == []
    with pytest.raises(FileExistsError):prepare_bundle(root, template, {'base': fd})


def test_publication_failure_is_not_reported_as_success(preparation, monkeypatch):
    import dnlab_runtime.vm_bundle_prepare as writer
    template, parent, root, fd, _ = preparation

    def fail(*args):
        raise OSError('synthetic rename failure')

    monkeypatch.setattr(writer, 'rename_siblings', fail)
    with pytest.raises(OSError, match='synthetic rename failure'):
        prepare_bundle(root, template, {'base': fd})
    target = parent / template_digest(template)
    assert (target / '.manifest.pending').exists()
    assert not (target / 'manifest.json').exists()
