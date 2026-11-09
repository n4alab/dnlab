"""Full coordinator composition, synthetic accounts and temporary filesystem."""
from copy import deepcopy
import os
import stat

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_install import SessionInstaller, targets
from dnlab_runtime.libvirt_install_adapter import ProvisioningAdapter
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow, InstallationAccounts
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_profile import request_profile


class Helper:
    def __init__(self):self.rows={'group':{},'account':{}};self.receipts={};self.calls=[];self.lost=False
    def inspect(self,request):
        expected=request['expected'];kind=request['kind']
        for row in self.rows[kind].values():
            if row['name']==expected['name'] or row['gid' if kind=='group' else 'uid']==expected['gid' if kind=='group' else 'uid']:
                return deepcopy(row)
        return None
    def completion(self,request):return deepcopy(self.receipts.get(fingerprint(request)))
    def create(self,request):
        assert self.inspect(request) is None
        self.calls.append(deepcopy(request));self.rows[request['kind']][request['expected']['name']]=deepcopy(request['expected'])
        self.receipts[fingerprint(request)]=dict(request_sha256=fingerprint(request),exit_code=0,identity=deepcopy(request['expected']))
        if self.lost:raise OSError('synthetic lost helper response')


@pytest.fixture
def installation(tmp_path,request_profile):
    root=tmp_path/'root';root.mkdir()
    for path in ['etc/dnlab','etc/systemd/system','var/lib','run']:(root/path).mkdir(parents=True,exist_ok=True)
    (root/'etc/dnlab').chmod(0o755)
    journal=Journal(tmp_path/'journal');helper=Helper();profile=render_profile(**request_profile)
    receipt=dict(operation_id='install',context={'boot':'synthetic'},targets=[i['key'] for i in targets(profile)],nonce='b'*32)
    current=deepcopy(receipt);window=ProvisioningWindow(receipt,lambda:deepcopy(current))
    snapshot=dict(context=deepcopy(receipt['context']),prerequisites=dict(packages='synthetic',provisioning_window_sha256=window.sha256))
    def dependency(spec):
        path=root/spec['path'].lstrip('/');info=path.lstat()
        assert stat.S_ISDIR(info.st_mode)
        return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
    adapter=ProvisioningAdapter(window=window,accounts=InstallationAccounts(journal,helper),
        files=InstallationFiles(root,journal=journal),snapshot=lambda:deepcopy(snapshot),directory_dependency=dependency)
    driver=SessionInstaller(journal,adapter)
    original=dependency({'path':'/etc/dnlab'})
    value=driver.prepare('install',request_profile,context=snapshot['context'],prerequisites=snapshot['prerequisites'],
        existing_directories={'/etc/dnlab':original})
    yield driver,adapter,helper,value,root,current,snapshot
    journal.close()


def test_complete_installation_is_replayable_and_never_starts_daemons(installation):
    driver,adapter,helper,value,root,_,_=installation
    result=driver.apply(value['id'])
    assert result['phase']=='installed_not_started' and len(helper.calls)==2
    for path,spec in value['profile']['files'].items():
        assert (root/path.lstrip('/')).read_text()==spec['content']
    assert driver.apply(value['id'])==result and len(helper.calls)==2
    assert not list(root.rglob('*.sock'))
    assert [r['kind'] for r in helper.calls]==['group','account']


def test_last_file_conflict_blocks_account_creation(installation):
    driver,_,helper,value,root,_,_=installation
    path=next(i['spec']['path'] for i in reversed(value['items']) if i['spec']['kind']=='file')
    foreign=root/path.lstrip('/');foreign.parent.mkdir(parents=True,exist_ok=True);foreign.write_text('foreign')
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert helper.calls==[] and foreign.read_text()=='foreign'
    assert driver.read(value['id'])==value


def test_lost_account_response_recovery_resumes_original_coordinator(installation):
    driver,adapter,helper,value,_,_,_=installation;helper.lost=True
    with pytest.raises(OSError):driver.apply(value['id'])
    saved=driver.read(value['id']);item=saved['items'][0]
    with pytest.raises(Conflict,match='uncertain'):driver.apply(value['id'])
    helper.lost=False;adapter.recover(item,value['id'])
    assert driver.apply(value['id'])['phase']=='installed_not_started'
    assert len(helper.calls)==2 and helper.calls[0]['nonce']==item['nonce']


@pytest.mark.parametrize('fault',['window','snapshot','dependency'])
def test_changed_window_prerequisite_or_dependency_blocks_without_mutations(installation,fault):
    driver,_,helper,value,root,current,snapshot=installation
    if fault=='window':current['nonce']='f'*32
    elif fault=='snapshot':snapshot['prerequisites']['packages']='changed'
    else:(root/'etc/dnlab').chmod(0o700)
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert helper.calls==[] and driver.journal.db.total_changes==before
