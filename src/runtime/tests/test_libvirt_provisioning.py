"""Accounts use a fake helper; filesystem changes are confined to tmp_path."""
from copy import deepcopy
import os

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow, InstallationAccounts, account_marker
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_install_files import files


def window(item,operation='install'):
    receipt=dict(operation_id=operation,context={'boot':'synthetic'},targets=[item['spec']['key']],nonce='b'*32)
    current=deepcopy(receipt)
    return ProvisioningWindow(receipt,lambda:deepcopy(current)),current


def directory_item():
    return dict(spec=dict(kind='directory',key='directory:/config/private',path='/config/private',
        uid=os.getuid(),gid=os.getgid(),mode=0o700),nonce='c'*32,phase='create_requested',proof=None)


def test_directory_birth_is_durable_under_explicit_window(files):
    adapter,_,root=files;item=directory_item();gate,_=window(item)
    receipt=adapter.create(item,'install',window=gate)
    assert adapter.observe(item,'install')==receipt
    assert (root/'config/private').is_dir()
    with pytest.raises(Conflict,match='held'):adapter.create(item,'install',window=gate)
    assert adapter.recover(item,'install',window=gate)==receipt


def test_directory_crash_before_birth_save_is_never_adopted(files,monkeypatch):
    adapter,_,root=files;item=directory_item();gate,_=window(item);save=adapter._save_birth
    def fail(*args):raise OSError('synthetic crash before original fd identity commit')
    with monkeypatch.context() as patch:
        patch.setattr(adapter,'_save_birth',fail)
        with pytest.raises(OSError):adapter.create(item,'install',window=gate)
    birth=adapter._birth(item,'install')
    assert birth['phase']=='birth_pending' and birth['file'] is None
    assert (root/'config/private').is_dir()
    with pytest.raises(Conflict,match='no adoption'):adapter.recover(item,'install',window=gate)
    with pytest.raises(Conflict,match='held'):adapter.create(item,'install',window=gate)
    assert adapter._save_birth==save


def test_directory_window_closed_after_mkdir_preserves_unqualified_birth(files,monkeypatch):
    adapter,_,root=files;item=directory_item();gate,current=window(item);mkdir=os.mkdir
    def close(*args,**kwargs):
        mkdir(*args,**kwargs);current['nonce']='d'*32
    monkeypatch.setattr(os,'mkdir',close)
    with pytest.raises(Conflict,match='window'):adapter.create(item,'install',window=gate)
    assert adapter._birth(item,'install')['file'] is None
    assert (root/'config/private').is_dir()
    with pytest.raises(OSError):os.getxattr(root/'config/private','user.dnlab.libvirt-install')


def test_directory_pending_durability_recovers_only_in_original_window(files,monkeypatch):
    adapter,_,_=files;item=directory_item();gate,current=window(item)
    with monkeypatch.context() as patch:
        def fail(fd):raise OSError('synthetic fsync failure')
        patch.setattr(os,'fsync',fail)
        with pytest.raises(OSError):adapter.create(item,'install',window=gate)
    with pytest.raises(Conflict,match='durability'):adapter.observe(item,'install')
    current['nonce']='d'*32
    with pytest.raises(Conflict,match='window'):adapter.recover(item,'install',window=gate)
    current['nonce']=gate.receipt['nonce']
    assert adapter.recover(item,'install',window=gate)==adapter.observe(item,'install')


class Helper:
    def __init__(self):self.rows={};self.receipts={};self.calls=[];self.lost=False;self.no_completion=False
    def inspect(self,request):
        expected=request['expected']
        for row in self.rows.values():
            if row['name']==expected['name'] or row.get('uid')==expected.get('uid') and 'uid' in expected or row['gid']==expected['gid']:
                return deepcopy(row)
        return None
    def completion(self,request):return deepcopy(self.receipts.get(fingerprint(request)))
    def create(self,request):
        assert self.inspect(request) is None
        self.calls.append(deepcopy(request));self.rows[request['expected']['name']]=deepcopy(request['expected'])
        if not self.no_completion:
            self.receipts[fingerprint(request)]=dict(request_sha256=fingerprint(request),exit_code=0,identity=deepcopy(request['expected']))
        if self.lost:raise OSError('synthetic helper response lost')


@pytest.fixture(params=['group','account'])
def accounts(tmp_path,request):
    spec=dict(kind=request.param,name='dnlab-libvirt',gid=1002,key=request.param+':dnlab-libvirt')
    if request.param=='account':spec.update(uid=1001,home='/var/lib/dnlab-libvirt',group='dnlab-libvirt',interactive_login=False)
    item=dict(spec=spec,nonce='a'*32,phase='create_requested',proof=None)
    journal=Journal(tmp_path/'journal');helper=Helper();adapter=InstallationAccounts(journal,helper)
    gate,current=window(item)
    yield adapter,helper,item,gate,current
    journal.close()


def test_account_helper_creates_once_and_reopens_original_birth(accounts):
    adapter,helper,item,gate,_=accounts
    assert adapter.observe(item,'install') is None
    receipt=adapter.create(item,'install',window=gate)
    assert receipt==InstallationAccounts(adapter.journal,helper).observe(item,'install')
    assert adapter.recover(item,'install',window=gate)==receipt
    with pytest.raises(Conflict,match='held'):adapter.create(item,'install',window=gate)
    assert len(helper.calls)==1
    if item['spec']['kind']=='account':
        assert receipt['identity']['locked'] is True
        assert receipt['identity']['shell']=='/usr/sbin/nologin'
        assert receipt['identity']['comment']==account_marker('install',item['nonce'])
        assert helper.calls[0]['nonce']==item['nonce']


def test_lost_helper_response_uses_durable_original_completion(accounts):
    adapter,helper,item,gate,_=accounts;helper.lost=True
    with pytest.raises(OSError):adapter.create(item,'install',window=gate)
    with pytest.raises(Conflict,match='uncertain'):adapter.observe(item,'install')
    receipt=adapter.recover(item,'install',window=gate)
    assert receipt==adapter.observe(item,'install') and len(helper.calls)==1


def test_matching_account_without_helper_completion_is_not_adopted(accounts):
    adapter,helper,item,gate,_=accounts;helper.no_completion=True
    with pytest.raises(Conflict,match='completion'):adapter.create(item,'install',window=gate)
    before=adapter._read(item,'install')
    with pytest.raises(Conflict,match='completion'):adapter.recover(item,'install',window=gate)
    assert adapter._read(item,'install')==before and len(helper.calls)==1


def test_preexisting_name_or_numeric_id_is_preserved(accounts):
    adapter,helper,item,gate,_=accounts
    helper.rows['foreign']={'name':'foreign','gid':item['spec']['gid']}
    with pytest.raises(Conflict,match='occupied'):adapter.create(item,'install',window=gate)
    assert helper.calls==[] and adapter._read(item,'install') is None


def test_closed_window_blocks_create_and_uncertain_recovery(accounts):
    adapter,helper,item,gate,current=accounts
    current['nonce']='f'*32
    with pytest.raises(Conflict,match='window'):adapter.create(item,'install',window=gate)
    assert helper.calls==[]
    current['nonce']=gate.receipt['nonce'];helper.lost=True
    with pytest.raises(OSError):adapter.create(item,'install',window=gate)
    current['nonce']='f'*32
    with pytest.raises(Conflict,match='window'):adapter.recover(item,'install',window=gate)
    assert len(helper.calls)==1


def test_replaced_account_blocks_recovery_without_rewrite(accounts):
    adapter,helper,item,gate,_=accounts
    adapter.create(item,'install',window=gate)
    helper.rows[item['spec']['name']]['gid']=9999
    with pytest.raises(Conflict,match='resource differs'):adapter.recover(item,'install',window=gate)
    assert helper.rows[item['spec']['name']]['gid']==9999 and len(helper.calls)==1
