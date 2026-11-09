"""Preflight fixture data only; no host reads or account/service execution."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict
from tools.libvirt_install_preflight import collect
from test_libvirt_service_profile import request_profile


@pytest.fixture
def fixture(tmp_path,request_profile):
    root=tmp_path/'root';root.mkdir()
    def write(name,content):
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content);return path
    write('proc/sys/kernel/random/boot_id','synthetic-boot\n')
    write('etc/passwd','root:x:0:0:root:/root:/bin/sh\n')
    write('etc/group','root:x:0:\nkvm:x:108:\n')
    expected={'libvirt-daemon':'11.3.0-3+deb13u3','libvirt-daemon-lock':'11.3.0-3+deb13u3'}
    write('var/lib/dpkg/status','\n\n'.join('Package: '+n+'\nVersion: '+v+'\nArchitecture: amd64\nStatus: install ok installed' for n,v in expected.items()))
    for role,binary in request_profile['binaries'].items():
        data='synthetic '+role
        write(binary['path'].lstrip('/'),data);binary['sha256']=hashlib.sha256(data.encode()).hexdigest()
    for name in render_profile(**request_profile)['forbidden_vendor_activation']:
        path=root/'etc/systemd/system'/name;path.parent.mkdir(parents=True,exist_ok=True);path.symlink_to('/dev/null')
    return root,request_profile,expected,write


def test_complete_diagnostic_is_readonly_and_never_claims_qualification(fixture,monkeypatch):
    root,request,expected,_=fixture
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('no commands allowed'))
    result=collect(root,request,expected)
    assert result['status']=='collected' and result['qualified'] is False
    assert result['blocking_findings']==[] and result['occupied_targets']==[]
    assert result['account_conflicts']==result['group_conflicts']==[]
    assert result['observed']['boot_id']=='synthetic-boot'
    assert 'root:x:' not in json.dumps(result)


@pytest.mark.parametrize('fault',['name','uid','gid','package','binary','mask','occupied'])
def test_conflicts_are_reported_without_adoption_or_mutation(fixture,fault):
    root,request,expected,write=fixture
    if fault=='name':write('etc/passwd','dnlab-libvirt:x:2000:2001::/x:/bin/sh\n')
    elif fault=='uid':write('etc/passwd','other:x:1001:2001::/x:/bin/sh\n')
    elif fault=='gid':write('etc/group','other:x:1002:\n')
    elif fault=='package':write('var/lib/dpkg/status','')
    elif fault=='binary':write('usr/sbin/libvirtd','foreign')
    elif fault=='mask':(root/'etc/systemd/system/libvirtd.service').unlink()
    else:write('etc/dnlab/libvirt/libvirtd.conf','foreign')
    before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
    result=collect(root,request,expected)
    assert result['blocking_findings'] or result['occupied_targets']
    after={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
    assert after==before and result['qualified'] is False


def test_change_between_snapshots_is_rejected(fixture,monkeypatch):
    import tools.libvirt_install_preflight as module
    root,request,expected,write=fixture;regular=module.regular;count=[]
    def changing(fd,path,limit):
        value=regular(fd,path,limit)
        if path=='etc/group' and not count:
            count.append(True);write('etc/group','root:x:0:\n')
        return value
    monkeypatch.setattr(module,'regular',changing)
    with pytest.raises(Conflict,match='changed during collection'):collect(root,request,expected)


def test_symlink_binary_is_not_followed_or_qualified(fixture):
    root,request,expected,write=fixture
    target=write('foreign','preserve');path=root/'usr/sbin/libvirtd';path.unlink();path.symlink_to(target)
    result=collect(root,request,expected)
    assert any('daemon executable differs' in s for s in result['blocking_findings'])
    assert result['observed']['paths']['/usr/sbin/libvirtd']['followed'] is False
    assert target.read_text()=='preserve'
