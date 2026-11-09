"""A source hash alone must not qualify a non-executable fixture entrypoint."""
import io
from pathlib import Path
import sys
import tarfile
import hashlib

import pytest

TOOLS=Path(__file__).resolve().parents[2]/'runtime/tools'
if str(TOOLS) not in sys.path:sys.path.insert(0,str(TOOLS))
import prepare_jumphost_candidate as candidate

ENTRY=b'#!/bin/bash\necho fixture\n';INVENTORY=b'print("fixture")\n'
VD=b'#!/bin/bash\necho native-cli\n';CLIENT=b'#!/usr/bin/env python3\nprint("native-client")\n'
EXPECTED={name:hashlib.sha256(value).hexdigest() for name,value in
          {'entrypoint.sh':ENTRY,'inventory.py':INVENTORY,'vd':VD,'vd-relay-client':CLIENT}.items()}


def layer(nodes,entries):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as archive:
        for name,kind,mode,content in entries:
            member=tarfile.TarInfo(name);member.mode=mode;member.uid=member.gid=0
            if kind=='symlink':member.type=tarfile.SYMTYPE;member.linkname=content;archive.addfile(member)
            else:member.size=len(content);archive.addfile(member,io.BytesIO(content))
    stream.seek(0)
    with tarfile.open(fileobj=stream) as archive:candidate.apply_layer(nodes,archive)


def filesystem():
    nodes={}
    layer(nodes,[('bin','symlink',0o777,'usr/bin'),('usr/bin/bash','file',0o755,b'\x7fELFfixture'),
        ('usr/bin/env','file',0o755,b'\x7fELFfixture-env'),
        ('usr/bin/python3','symlink',0o777,'python3.11'),('usr/bin/python3.11','file',0o755,b'\x7fELFfixture-python'),
        ('entrypoint.sh','file',0o755,ENTRY),('usr/local/lib/dnlab-inventory.py','file',0o644,INVENTORY),
        ('usr/local/bin/vd','file',0o755,VD),('usr/local/bin/vd-relay-client','file',0o755,CLIENT)])
    return nodes


def test_audit_merged_usr_interpreter_and_source():
    report=candidate.audit_nodes(filesystem(),EXPECTED)
    assert report['entrypoint_mode']=='0755' and report['interpreter_resolved_path']=='/usr/bin/bash'
    assert report['interpreter_elf'] and report['inventory_mode']=='0644'


def test_new_overlay_nonexecutable_is_refused_even_with_identical_source():
    nodes=filesystem();layer(nodes,[('entrypoint.sh','file',0o644,ENTRY)])
    with pytest.raises(RuntimeError,match='entrypoint mode'):candidate.audit_nodes(nodes,EXPECTED)
    layer(nodes,[('entrypoint.sh','file',0o755,ENTRY)])
    assert candidate.audit_nodes(nodes,EXPECTED)['status']=='passed'


@pytest.mark.parametrize('defect',['interpreter-mode','missing','not-elf','wrong-shebang','changed-source','inventory-mode'])
def test_entrypoint_and_interpreter_negative_cases(defect):
    nodes=filesystem()
    if defect=='interpreter-mode':nodes['/usr/bin/bash']['mode']=0o644
    if defect=='missing':del nodes['/usr/bin/bash']
    if defect=='not-elf':nodes['/usr/bin/bash']['prefix']=b'broken'
    if defect=='wrong-shebang':nodes['/entrypoint.sh']['prefix']=b'#!/missing\n'
    if defect=='changed-source':nodes['/entrypoint.sh']['sha256']='f'*64
    if defect=='inventory-mode':nodes['/usr/local/lib/dnlab-inventory.py']['mode']=0o666
    with pytest.raises(RuntimeError):candidate.audit_nodes(nodes,EXPECTED)


def test_deleted_interpreter_is_not_qualified_from_a_lower_layer():
    nodes=filesystem();layer(nodes,[('usr/bin/.wh.bash','file',0o000,b'')])
    with pytest.raises(RuntimeError,match='interpreter'):candidate.audit_nodes(nodes,EXPECTED)


def test_interpreter_symlink_cycle_is_refused():
    nodes=filesystem();layer(nodes,[('usr/bin/bash','symlink',0o777,'/bin/bash')])
    with pytest.raises(RuntimeError,match='cycle'):candidate.audit_nodes(nodes,EXPECTED)


def test_recipe_does_not_inherit_permissions_from_build_context():
    recipe=candidate.RECIPE.read_text()
    assert 'COPY --chmod=0755 entrypoint.sh /entrypoint.sh' in recipe
    assert 'COPY --chmod=0644 inventory.py /usr/local/lib/dnlab-inventory.py' in recipe
    assert 'COPY --chmod=0755 vd /usr/local/bin/vd' in recipe
    assert 'COPY --chmod=0755 vd-relay-client /usr/local/bin/vd-relay-client' in recipe
    assert 'qualified-relay-inventory-v1' in recipe


@pytest.mark.parametrize('path',['/usr/local/bin/vd','/usr/local/bin/vd-relay-client'])
@pytest.mark.parametrize('defect',['missing','source','mode','owner','shebang'])
def test_native_cli_assets_must_match_exact_source_and_profile(path,defect):
    nodes=filesystem()
    if defect=='missing':del nodes[path]
    if defect=='source':nodes[path]['sha256']='f'*64
    if defect=='mode':nodes[path]['mode']=0o644
    if defect=='owner':nodes[path]['uid']=65534
    if defect=='shebang':nodes[path]['prefix']=b'#!/wrong\n'
    with pytest.raises(RuntimeError):candidate.audit_nodes(nodes,EXPECTED)


@pytest.mark.parametrize('path',['/usr/bin/env','/usr/bin/python3.11'])
@pytest.mark.parametrize('defect',['missing','mode','not-elf','owner'])
def test_native_cli_interpreters_must_be_qualified(path,defect):
    nodes=filesystem()
    if defect=='missing':del nodes[path]
    if defect=='mode':nodes[path]['mode']=0o644
    if defect=='not-elf':nodes[path]['prefix']=b'broken'
    if defect=='owner':nodes[path]['uid']=65534
    with pytest.raises(RuntimeError,match='interpreter'):candidate.audit_nodes(nodes,EXPECTED)


def test_image_without_native_capability_is_rejected_before_archive_export(tmp_path,monkeypatch):
    image='sha256:'+'a'*64
    monkeypatch.setattr(candidate,'inspect_image',lambda value:{'Id':image,'Config':{'Entrypoint':['/entrypoint.sh'],'Labels':{}}})
    monkeypatch.setattr(candidate.tempfile,'mkstemp',lambda *a,**kw:pytest.fail('unexpected image export'))
    with pytest.raises(RuntimeError,match='capability'):candidate.audit_image(image,tmp_path)
