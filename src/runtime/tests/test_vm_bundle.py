"""Bundle verification on private synthetic files; never opens a vendor image."""
import hashlib
import json
import os

import pytest

from dnlab_runtime.vm_bundle import read_bundle
from dnlab_runtime.vm_template import TemplateError, template_digest
from test_vm_template import template


@pytest.fixture
def bundle(template, tmp_path):
    root=tmp_path/'bundle';(root/'disks').mkdir(parents=True)
    data=b'synthetic disk data'
    template['assets']['base'].update(sha256=hashlib.sha256(data).hexdigest(),size=len(data))
    (root/'disks/base.qcow2').write_bytes(data)
    (root/'manifest.json').write_text(json.dumps(template))
    return root,template,data


def test_read_bundle_checks_original_assets_without_writes(bundle):
    root,template,data=bundle
    before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    result=read_bundle(root,template_digest(template))
    assert result['template']==template
    assert result['assets']['base']['sha256']==hashlib.sha256(data).hexdigest()
    assert {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}==before


@pytest.mark.parametrize('fault',['manifest','asset-content','asset-size','symlink','directory-symlink','duplicate-key'])
def test_bundle_rejects_changed_or_indirect_assets(bundle,tmp_path,fault):
    root,template,data=bundle;expected=template_digest(template)
    if fault=='manifest':
        changed=dict(template,id='foreign-template');(root/'manifest.json').write_text(json.dumps(changed))
    elif fault=='asset-content':(root/'disks/base.qcow2').write_bytes(b'x'*len(data))
    elif fault=='asset-size':(root/'disks/base.qcow2').write_bytes(data+b'foreign')
    elif fault=='symlink':
        other=tmp_path/'foreign.qcow2';other.write_bytes(data)
        (root/'disks/base.qcow2').unlink();(root/'disks/base.qcow2').symlink_to(other)
    elif fault=='directory-symlink':
        (root/'disks').rename(tmp_path/'moved');(root/'disks').symlink_to(tmp_path/'moved',target_is_directory=True)
    else:
        original=(root/'manifest.json').read_text()
        (root/'manifest.json').write_text('{"schema_version":1,'+original[1:])
    with pytest.raises((TemplateError,OSError)):read_bundle(root,expected)


def test_manifest_change_while_disk_is_read_is_not_reported_as_original_bundle(bundle,monkeypatch):
    import dnlab_runtime.vm_bundle as reader
    root,template,data=bundle
    original_read=os.read;changed=[]
    disk_inode=(root/'disks/base.qcow2').stat().st_ino
    def read(fd,size):
        chunk=original_read(fd,size)
        if chunk and os.fstat(fd).st_ino==disk_inode and not changed:
            changed.append(True)
            value=dict(template,id='changed-during-read')
            (root/'manifest.json').write_text(json.dumps(value))
        return chunk
    monkeypatch.setattr(reader.os,'read',read)
    with pytest.raises(TemplateError,match='member changed'):
        read_bundle(root,template_digest(template))
    assert changed==[True]
