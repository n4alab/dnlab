"""Real installer/helper/identity chain; only temporary files and fake worker/files.

No useradd, groupadd, daemon, subprocess, ownership change or host NSS call.
"""
from copy import deepcopy
from pathlib import Path
import uuid

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_commands import AccountCommandHelper
from dnlab_runtime.libvirt_account_identity import LocalAccountIdentity
from dnlab_runtime.libvirt_install import SessionInstaller,targets
from dnlab_runtime.libvirt_install_adapter import ProvisioningAdapter
from dnlab_runtime.libvirt_provisioning import InstallationAccounts,ProvisioningWindow
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_profile import request_profile


@pytest.fixture
def chain(tmp_path,request_profile):
    root=tmp_path/'root';(root/'etc').mkdir(parents=True)
    def write(name,data):
        path=root/'etc'/name;path.write_text(data);path.chmod(0o640 if name=='shadow' else 0o644)
    write('passwd','root:x:0:0:root:/root:/bin/sh\n');write('group','root:x:0:\n')
    write('shadow','root:!:1:0:99999:7:::\n')
    state=dict(releases=[],arms=[],workers={},files={},lost_role=None,lost_once=False,config='a'*64,active=True)
    def query(database,key):
        rows=[line.split(':') for line in (root/'etc'/database).read_text().splitlines()]
        found=[row for row in rows if (int(row[2])==key if type(key) is int else row[0]==key)]
        if not found:return None
        row=found[0];value=dict(name=row[0],gid=int(row[3] if database=='passwd' else row[2]))
        if database=='passwd':value['uid']=int(row[2])
        return value
    journal=Journal(tmp_path/'journal');identity=LocalAccountIdentity(root,nss_query=query)
    profile=render_profile(**request_profile);context=dict(boot='synthetic')
    window_receipt=dict(operation_id='install',context=context,
        targets=[value['key'] for value in targets(profile)],nonce='e'*32)
    window=ProvisioningWindow(window_receipt,lambda:deepcopy(window_receipt) if state['active'] else {})
    class Worker:
        def arm(self,command):
            token=uuid.uuid4().hex
            ref=dict(token=token,command_sha256=fingerprint(command),process_record=dict(boot_id='synthetic',
                pid=123+len(state['arms']),start_ticks=456,uid=0,gid=0,executable_sha256='b'*64,namespace_sha256='c'*64))
            state['arms'].append(command['binary']['path']);state['workers'][token]=dict(reference=ref,command=deepcopy(command),outcome=None)
            return deepcopy(ref)
        def verify(self,reference,command):
            value=state['workers'][reference['token']]
            return value['reference']==reference and value['command']==command
        def release(self,reference):
            value=state['workers'][reference['token']];assert value['reference']==reference and value['outcome'] is None
            command=value['command'];argv=command['argv'];role=Path(command['binary']['path']).name
            state['releases'].append(role)
            if role=='groupadd':
                write('group',(root/'etc/group').read_text()+f'{argv[-1]}:x:{argv[3]}:\n')
            else:
                def argument(flag):return argv[argv.index(flag)+1]
                write('passwd',(root/'etc/passwd').read_text()+
                    f"{argv[-1]}:x:{argument('--uid')}:{argument('--gid')}:{argument('--comment')}:{argument('--home-dir')}:{argument('--shell')}\n")
                write('shadow',(root/'etc/shadow').read_text()+f"{argv[-1]}:{argument('--password')}:1:0:99999:7:::\n")
            value['outcome']=dict(reference=deepcopy(reference),exit_code=0,stdout='',stderr='')
            if state['lost_role']==role and not state['lost_once']:
                state['lost_once']=True;raise OSError('synthetic response lost after original account creation')
        def outcome(self,reference):return deepcopy(state['workers'][reference['token']]['outcome'])
    binaries={role:dict(path='/usr/sbin/'+role,sha256='d'*64) for role in ('useradd','groupadd')}
    def command_preflight(command):return dict(qualified=True,command_sha256=fingerprint(command),context_sha256=fingerprint(context),inputs_sha256=state['config'])
    helper=AccountCommandHelper(journal,binaries=binaries,runner=Worker(),inspect=identity,preflight=command_preflight)
    accounts=InstallationAccounts(journal,helper)
    class Files:
        def __init__(self):self.journal=journal
        def observe(self,item,operation):return deepcopy(state['files'].get(item['spec']['key']))
        def create(self,item,operation,*,window):
            window.verify(item,operation);key=item['spec']['key'];assert key not in state['files']
            proof=dict(intent_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),identity=dict(synthetic_file=key))
            state['files'][key]=proof;return deepcopy(proof)
    prerequisites=dict(static_config=state['config'],provisioning_window_sha256=window.sha256)
    def snapshot():return dict(context=context,prerequisites=dict(prerequisites,static_config=state['config']))
    adapter=ProvisioningAdapter(window=window,accounts=accounts,files=Files(),snapshot=snapshot,
        directory_dependency=lambda spec:pytest.fail('no existing directories adopted'))
    installer=SessionInstaller(journal,adapter)
    def prepare():return installer.prepare('install',request_profile,context=context,prerequisites=prerequisites)
    yield installer,prepare,accounts,window,state,root,write,helper
    journal.close()


def test_full_synthetic_chain_accepts_only_its_own_group_then_account(chain):
    installer,prepare,accounts,window,state,root,_,_=chain
    value=prepare();assert value['phase']=='prepared' and not state['releases']
    completed=installer.apply('install')
    assert completed['phase']=='installed_not_started'
    assert state['releases']==['groupadd','useradd'] and len(state['arms'])==2
    for item in completed['items'][:2]:
        assert item['proof']==accounts.observe(item,'install')
    assert installer.apply('install')==completed and prepare()==completed
    assert state['releases']==['groupadd','useradd']
    assert '/usr/sbin/nologin' in (root/'etc/passwd').read_text()


@pytest.mark.parametrize('role',['groupadd','useradd'])
def test_lost_response_requires_original_recovery_without_second_execution(chain,role):
    installer,prepare,accounts,window,state,_,_,_=chain
    prepare();state['lost_role']=role
    with pytest.raises(OSError,match='response lost'):installer.apply('install')
    saved=installer.read('install');pending=next(i for i in saved['items'] if i['phase']=='create_requested')
    with pytest.raises(Conflict,match='uncertain'):installer.apply('install')
    accounts.recover(pending,'install',window=window)
    completed=installer.apply('install')
    assert completed['phase']=='installed_not_started' and state['releases']==['groupadd','useradd']
    assert len(state['arms'])==2


@pytest.mark.parametrize('kind',['group','account'])
def test_foreign_identity_blocks_prepare_before_any_mutation(chain,kind):
    _,prepare,_,_,state,root,write,_=chain
    if kind=='group':write('group','root:x:0:\ndnlab-libvirt:x:1002:\n')
    else:write('passwd','root:x:0:0:root:/root:/bin/sh\ndnlab-libvirt:x:1001:1002:foreign:/x:/bin/sh\n')
    before={p.name:p.read_bytes() for p in (root/'etc').iterdir()}
    with pytest.raises(Conflict):prepare()
    assert not state['releases'] and not state['arms'] and not state['files']
    assert before=={p.name:p.read_bytes() for p in (root/'etc').iterdir()}


def test_static_input_change_at_release_checkpoint_keeps_every_target_unallocated(chain,monkeypatch):
    installer,prepare,_,_,state,_,_,helper=chain;prepare();save=helper._save
    def changed(value):
        save(value)
        if value['phase']=='release_requested':state['config']='f'*64
    monkeypatch.setattr(helper,'_save',changed)
    with pytest.raises(Conflict,match='preflight changed'):installer.apply('install')
    assert not state['releases'] and not state['files'] and len(state['arms'])==1
    assert installer.read('install')['phase']=='applying'


def test_replaced_account_after_completion_is_preserved_and_refused(chain):
    installer,prepare,_,_,state,root,write,_=chain;prepare();installer.apply('install')
    replacement=(root/'etc/passwd').read_text().replace('/usr/sbin/nologin','/bin/sh')
    write('passwd',replacement)
    with pytest.raises(Conflict,match='attributes differ'):installer.apply('install')
    assert (root/'etc/passwd').read_text()==replacement and state['releases']==['groupadd','useradd']
