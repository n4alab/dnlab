"""Package reader tests use a synthetic root and simulated apt-cache output."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from dnlab_runtime.manifest import Conflict
from tools import vm_package_inventory as inventory


@pytest.fixture
def case(tmp_path):
    root=tmp_path/'root'
    for name in ('usr/lib','usr/bin','var/lib/dpkg','proc/sys/kernel/random'):(root/name).mkdir(parents=True,exist_ok=True)
    boot='11111111-2222-4333-8444-555555555555'
    (root/'proc/sys/kernel/random/boot_id').write_text(boot+'\n')
    release=b'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'
    (root/'usr/lib/os-release').write_bytes(release)
    status='Package: qemu-system-x86\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2.0+test\n\n'
    (root/'var/lib/dpkg/status').write_text(status)
    (root/'usr/bin/apt-cache').write_text('synthetic binary; never executed')
    proof={'status':'collected','qualified':False,'host_id':'master','boot_id':boot,
        'paths':{'usr/lib/os-release':{'kind':'regular','sha256':hashlib.sha256(release).hexdigest()}}}
    output=''.join(name+':\n  Installed: (none)\n  Candidate: 1:2.3.4-5+test\n  Version table:\n'
                   for name in inventory.PACKAGES)
    result={'returncode':0,'stdout':output,'stderr':''};calls=[]
    def query(command):calls.append(command);return deepcopy(result)
    return root,proof,result,calls,query


def test_collect_preserves_inputs_and_only_queries_fixed_policy(case):
    root,proof,_,calls,query=case
    before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    value=inventory.collect(root,proof,query)
    assert value['status']=='collected' and value['qualified'] is False
    assert value['distribution']['VERSION_ID']=='13'
    assert value['installed'][0]['Version']=='1:9.2.0+test'
    assert value['policy']['libvirt-daemon']['Candidate']=='1:2.3.4-5+test'
    assert calls==[inventory.COMMAND] and not value['unresolved']
    assert {str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}==before


@pytest.mark.parametrize('fault',['boot','release'])
def test_old_prerequisite_context_is_refused_before_query(case,fault):
    root,proof,_,calls,query=case
    path=root/('proc/sys/kernel/random/boot_id' if fault=='boot' else 'usr/lib/os-release')
    path.write_text('changed')
    with pytest.raises(Conflict):inventory.collect(root,proof,query)
    assert not calls


@pytest.mark.parametrize('path',['var/lib/dpkg/status','usr/lib/os-release','usr/bin/apt-cache'])
def test_changed_input_during_query_is_not_reported_as_current(case,path):
    root,proof,result,calls,_=case
    def query(command):
        calls.append(command);target=root/path;target.write_bytes(target.read_bytes()+b'changed')
        return deepcopy(result)
    with pytest.raises(Conflict,match='changed during query'):inventory.collect(root,proof,query)
    assert len(calls)==1


def test_query_failure_preserves_diagnostic_without_retry(case):
    root,proof,result,calls,query=case
    result.update(returncode=100,stdout='',stderr='original apt-cache failure')
    value=inventory.collect(root,proof,query)
    assert value['status']=='query-failed' and value['query']['stderr']=='original apt-cache failure'
    assert value['policy'] is None and len(calls)==1


def test_non_debian_distribution_never_falls_back_to_another_package_tool(case):
    root,proof,_,calls,query=case
    release=b'ID=fedora\nVERSION_ID=43\n'
    (root/'usr/lib/os-release').write_bytes(release)
    proof['paths']['usr/lib/os-release']['sha256']=hashlib.sha256(release).hexdigest()
    value=inventory.collect(root,proof,query)
    assert value['status']=='unsupported-distribution' and not calls


def test_parsers_reject_ambiguous_or_executable_looking_input():
    with pytest.raises(Conflict):inventory.distribution(b'ID=debian\nID=ubuntu\n')
    with pytest.raises(Conflict):inventory.distribution(b'ID=debian\nVERSION_ID="$(touch marker)"\n')
    with pytest.raises(Conflict):inventory.policy('libvirt0:\n  Installed: (none)\n  Installed: 1\n  Candidate: 1\n')
    with pytest.raises(Conflict):inventory.policy('foreign-package:\n  Installed: (none)\n  Candidate: 1\n')
    item=b'Package: libvirt0\nArchitecture: amd64\nVersion: 1\nStatus: install ok installed\n\n'
    with pytest.raises(Conflict):inventory.installed(item*2)


def test_host_transport_has_no_shell_and_disables_persistent_caches(monkeypatch):
    calls=[]
    def run(command,**options):
        calls.append((command,options))
        return subprocess.CompletedProcess(command,0,'policy output','')
    monkeypatch.setattr(inventory.subprocess,'run',run)
    value=inventory.host_query(list(inventory.COMMAND))
    command,options=calls[0]
    assert command[0]=='/usr/bin/apt-cache' and command[5]=='policy'
    assert 'Dir::Cache::pkgcache=' in command and 'Dir::Cache::srcpkgcache=' in command
    assert options==dict(capture_output=True,text=True,timeout=15,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'},cwd='/')
    assert value['stdout']=='policy output'
    with pytest.raises(Conflict):inventory.host_query(['/usr/bin/apt-get','install','libvirt-daemon'])
    assert len(calls)==1


def test_isolated_cli_requires_and_uses_policy_fixture(case,tmp_path):
    root,proof,result,_,_=case
    original=tmp_path/'prerequisites.json';original.write_text(json.dumps(proof))
    policy=tmp_path/'policy.json';policy.write_text(json.dumps(result))
    script=Path(inventory.__file__)
    completed=subprocess.run([sys.executable,'-B','-I','-S',str(script),'--fixture-root',str(root),
        '--prerequisites',str(original),'--policy-fixture',str(policy)],capture_output=True,text=True,timeout=10,cwd=tmp_path)
    assert completed.returncode==0,completed.stderr
    assert json.loads(completed.stdout)['qualified'] is False
    assert not list(root.rglob('__pycache__'))
    with pytest.raises(SystemExit):inventory.main(['--fixture-root',str(root),'--prerequisites',str(original)])
