"""Assembly tests use synthetic snapshot files, NSS and worker execution only."""
from copy import deepcopy
from pathlib import Path
import uuid

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_install import targets
from dnlab_runtime.libvirt_install_dependencies import InstallationDirectoryDependencies
from dnlab_runtime.libvirt_install_session import SessionProvisioning
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_install_snapshot import snapshot, fixture, request_profile
from tools.libvirt_install_apply import apply_original


@pytest.fixture
def session(snapshot, tmp_path):
    provider, state, root, write, request, _ = snapshot
    (root/'etc/dnlab').mkdir()
    write('etc/shadow', 'root:!:1:0:99999:7:::\n').chmod(0o640)
    original = provider()
    receipt = dict(operation_id='install', context=original['context'],
        targets=[item['key'] for item in targets(provider.profile)], nonce='e'*32)
    current = deepcopy(receipt)
    window = ProvisioningWindow(receipt, lambda:deepcopy(current))
    spec = next(item for item in targets(provider.profile) if item['key']=='directory:/etc/dnlab')
    dependencies = {'/etc/dnlab':InstallationDirectoryDependencies(root,[spec])(spec)}
    def query(database, key):
        for row in (root/'etc'/database).read_text().splitlines():
            values = row.split(':')
            if (int(values[2]) == key if type(key) is int else values[0] == key):
                value = dict(name=values[0], gid=int(values[3] if database=='passwd' else values[2]))
                if database=='passwd':value['uid'] = int(values[2])
                return value
        return None
    class Worker:
        def __init__(self):self.rows={};self.calls=[]
        def arm(self, command):
            reference = dict(token=uuid.uuid4().hex, command_sha256=fingerprint(command), process_record=dict(
                boot_id='synthetic-boot',pid=123+len(self.rows),start_ticks=456,uid=0,gid=0,
                executable_sha256='b'*64,namespace_sha256='c'*64))
            self.rows[reference['token']] = dict(reference=deepcopy(reference),command=deepcopy(command),outcome=None)
            return reference
        def verify(self, reference, command):
            row = self.rows[reference['token']]
            return row['reference']==reference and row['command']==command
        def release(self, reference):
            row = self.rows[reference['token']];argv=row['command']['argv']
            assert row['outcome'] is None
            role = Path(row['command']['binary']['path']).name
            self.calls.append(role)
            if role=='groupadd':
                write('etc/group',(root/'etc/group').read_text()+f'{argv[-1]}:x:{argv[3]}:\n')
            else:
                def arg(flag):return argv[argv.index(flag)+1]
                write('etc/passwd',(root/'etc/passwd').read_text()+
                    f"{argv[-1]}:x:{arg('--uid')}:{arg('--gid')}:{arg('--comment')}:{arg('--home-dir')}:{arg('--shell')}\n")
                write('etc/shadow',(root/'etc/shadow').read_text()+f'{argv[-1]}:!:1:0:99999:7:::\n').chmod(0o640)
            row['outcome'] = dict(reference=deepcopy(reference),exit_code=0,stdout='',stderr='')
        def outcome(self, reference):return deepcopy(self.rows[reference['token']]['outcome'])
        def completed_outcome(self, reference):return deepcopy(self.rows[reference['token']]['outcome'])
    journal = Journal(tmp_path/'journal');worker=Worker()
    assembled = SessionProvisioning(journal,root=root,request=request,snapshot_provider=provider,
        original_snapshot=original,window=window,runner=worker,nss_query=query,directory_receipts=dependencies)
    try:yield assembled, worker, root, write, current, provider
    finally:journal.close()


def test_prepare_and_replay_do_not_launch_worker_or_create_targets(session):
    assembled, worker, root, _, _, _ = session
    assert worker.rows == {}
    value = assembled.prepare()
    assert value['phase']=='prepared' and assembled.prepare()==value
    assert value['dependencies']==assembled.dependencies
    assert worker.rows=={} and worker.calls==[]
    assert not (root/'etc/dnlab/libvirt').exists()


@pytest.mark.parametrize('fault', ['dependency', 'static', 'window'])
def test_changed_input_blocks_apply_before_worker_launch(session, fault):
    assembled, worker, root, write, current, _ = session
    original=assembled.prepare()
    if fault=='dependency':(root/'etc/dnlab').chmod(0o777)
    elif fault=='static':write('etc/default/useradd','foreign')
    else:current['nonce']='f'*32
    with pytest.raises(Conflict):assembled.apply()
    assert worker.rows=={} and worker.calls==[]
    assert assembled.installer.read('install')==original


def test_complete_assembly_on_temporary_files_preserves_dependency_and_replays(session):
    # Requires mapped fixture UID1001/GID1002 for fchown; account commands stay fake.
    assembled, worker, root, _, _, _ = session
    value=assembled.prepare()
    result=apply_original(assembled,value,journal_identity=assembled.installer.journal.identity)
    assert result['phase']=='installed_not_started'
    assert worker.calls==['groupadd','useradd']
    assert assembled.apply()==result and assembled.prepare()==result
    assert worker.calls==['groupadd','useradd']
    assert result['dependencies']==value['dependencies']
    for path,spec in result['profile']['files'].items():
        assert (root/path.lstrip('/')).read_text()==spec['content']


@pytest.mark.parametrize('fault',['journal','nonce','request','operation'])
def test_apply_original_refuses_wrong_binding_without_mutation(session,fault):
    assembled,worker,_,_,_,_=session
    reference=deepcopy(assembled.prepare())
    identity=assembled.installer.journal.identity
    if fault=='journal':identity='0'*32
    elif fault=='nonce':reference['items'][0]['nonce']='f'*32
    elif fault=='request':reference['request']['account_name']='foreign'
    else:reference['id']='other-install'
    before=assembled.installer.journal.db.total_changes
    with pytest.raises(Conflict):apply_original(assembled,reference,journal_identity=identity)
    assert assembled.installer.journal.db.total_changes==before and worker.rows=={}


@pytest.mark.parametrize('fault',['dependency','late_file','window'])
@pytest.mark.parametrize('checkpoint',['arming_requested','armed','release_requested'])
def test_complete_preflight_is_rechecked_at_account_release_boundary(session, monkeypatch, fault, checkpoint):
    assembled, worker, root, write, current, _ = session
    assembled.prepare()
    check=assembled.helper._check
    injected=[]
    def changed(value):
        if value['phase']==checkpoint and not injected:
            saved=assembled.helper._read(value['request'])
            assert saved['phase']==checkpoint
            injected.append(checkpoint)
            if fault=='dependency':(root/'etc/dnlab').chmod(0o777)
            elif fault=='late_file':write('etc/systemd/system/dnlab-libvirtd.service','foreign target')
            else:current['nonce']='f'*32
        return check(value)
    monkeypatch.setattr(assembled.helper,'_check',changed)
    with pytest.raises(Conflict):assembled.apply()
    assert injected==[checkpoint]
    assert worker.calls==[], 'account worker released after complete preflight became invalid'
    arms=len(worker.rows)
    with pytest.raises(Conflict):assembled.apply()
    assert worker.calls==[] and len(worker.rows)==arms


def test_lost_response_recovery_rechecks_other_targets_without_executing_again(session, monkeypatch):
    assembled, worker, root, write, _, _ = session
    assembled.prepare()
    release=worker.release
    def lost(reference):
        release(reference)
        raise OSError('simulated response lost after original worker completed')
    monkeypatch.setattr(worker,'release',lost)
    with pytest.raises(OSError,match='response lost'):assembled.apply()
    saved=assembled.installer.read('install')
    item=next(item for item in saved['items'] if item['phase']=='create_requested')
    assert worker.calls==['groupadd']
    foreign=write('etc/systemd/system/dnlab-libvirtd.service','foreign target')
    before=assembled.installer.journal.db.total_changes
    with pytest.raises(Conflict):assembled.adapter.recover(item,'install')
    assert assembled.installer.journal.db.total_changes==before
    assert foreign.read_text()=='foreign target' and worker.calls==['groupadd']
    foreign.unlink()
    receipt=assembled.adapter.recover(item,'install')
    assert receipt['nonce']==item['nonce']
    assert worker.calls==['groupadd'] and len(worker.rows)==1
    assert assembled.adapter.recover(item,'install')==receipt


def test_visible_account_without_committed_worker_outcome_blocks_recovery(session, monkeypatch):
    assembled, worker, _, _, _, _ = session
    assembled.prepare()
    release=worker.release
    def lost(reference):
        release(reference)
        raise OSError('simulated lost completion')
    monkeypatch.setattr(worker,'release',lost)
    with pytest.raises(OSError):assembled.apply()
    saved=assembled.installer.read('install')
    item=next(item for item in saved['items'] if item['phase']=='create_requested')
    monkeypatch.setattr(worker,'completed_outcome',lambda reference:None)
    before=assembled.installer.journal.db.total_changes
    with pytest.raises(Conflict):assembled.adapter.recover(item,'install')
    assert assembled.installer.journal.db.total_changes==before
    assert worker.calls==['groupadd'] and len(worker.rows)==1
