"""Synthetic source-view contracts and one complete temporary post-boot revision."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import UNIT,compile_revision
from dnlab_runtime.libvirt_current_session import CurrentSessionView,CurrentSessionPreflight,CurrentConfigurationSession
from dnlab_runtime.libvirt_postboot import PostBootQualification
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow,account_request
from dnlab_runtime.libvirt_volatile_recovery import VolatileDirectories
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_volatile_recovery import recovery
from test_libvirt_postboot import postboot
from test_libvirt_install import install
from test_libvirt_install_session import session
from test_libvirt_install_snapshot import snapshot,fixture,request_profile


@pytest.fixture
def current(recovery):
    recovered,value,installer,observed,_,_,_=recovery
    reference=recovered.prepare('volatile-recovery',value['id']);recovered.apply(reference['id'])
    view=CurrentSessionView(recovered,reference['id']);source=view.read()
    for item in source['items']:
        if item['spec']['kind'] in ('file','directory') and item['spec']['key'] not in value['plan']['volatile']:
            recovered.files.resources[item['spec']['key']]=deepcopy(item['proof'])
    snapshot=dict(context=deepcopy(source['context']),prerequisites=deepcopy(source['prerequisites']))
    provider=CurrentSessionPreflight(view,snapshot=lambda:deepcopy(snapshot),identity=lambda request:deepcopy(request['expected']),
        directory_dependency=lambda spec:pytest.fail('no dependency in this synthetic fixture'))
    request=dict(installation=source,source_sha256=fingerprint(source),plan=compile_revision(source))
    return view,provider,request,snapshot,installer


def test_explicit_view_preserves_historical_source_and_per_item_creators(current):
    view,provider,request,_,installer=current;source=request['installation']
    original=installer.read(source['id'])
    assert original['context']!=source['context'] and 'postboot' not in original
    assert provider(request)['context']==source['context']
    volatile=view.recovery.read(view.operation)['items']
    for item in volatile:
        assert source['postboot']['creators'][item['spec']['key']]==view.operation
    assert source['postboot']['creators']['file:'+UNIT]==original['id']
    assert view.read()==source and installer.read(source['id'])==original
    assert source['postboot']['observation_required'] is True


@pytest.mark.parametrize('fault',['boot','account','persistent','volatile','creator'])
def test_current_preflight_rejects_foreign_context_identity_and_births(current,monkeypatch,fault):
    view,provider,request,snapshot,_=current
    if fault=='boot':snapshot['context']['boot_id']='third-synthetic-boot'
    elif fault=='account':monkeypatch.setattr(provider.accounts,'identity',lambda request:None)
    elif fault in ('persistent','volatile'):
        key=next(item['spec']['key'] for item in request['installation']['items']
            if (item['spec']['key'] in view.recovery.qualification.read(request['installation']['postboot']['qualification_id'])['plan']['volatile'])==(fault=='volatile')
            and item['spec']['kind']=='directory')
        view.files.resources[key]={'foreign':'preserve'}
    else:request['installation']['postboot']['creators']['file:'+UNIT]='foreign'
    with pytest.raises(Conflict):provider(request)


def test_view_cannot_be_constructed_from_pending_directory_recovery(recovery):
    recovered,value,_,_,_,_,_=recovery
    reference=recovered.prepare('volatile-recovery',value['id'])
    with pytest.raises(Conflict,match='completed current-boot'):CurrentSessionView(recovered,reference['id']).read()


def test_complete_native_temporary_postboot_revision_preserves_history(session,monkeypatch):
    # Ownership operations below are only on fixture dirs, NSS/workers stay fake.
    provisioning,worker,root,write,old_window,provider=session
    provisioning.prepare();original=provisioning.apply()
    old_window['nonce']='f'*32
    monkeypatch.setattr(worker,'arm',lambda *a:pytest.fail('post-boot cannot arm account worker'))
    monkeypatch.setattr(worker,'release',lambda *a:pytest.fail('post-boot cannot execute account command'))
    runtime=[item for item in original['items'] if item['spec'].get('path','').startswith('/run/')]
    for item in reversed(runtime):(root/item['spec']['path'].lstrip('/')).rmdir()
    write('proc/sys/kernel/random/boot_id','second-synthetic-boot\n')
    new_snapshot=provider()
    def history(item):
        return dict(kind='historical-account-creation-v1',installation_sha256=fingerprint(original),original_proof=deepcopy(item['proof']),
            creation_context_sha256=fingerprint(original['context']),evidence_sha256='e'*64)
    def observe(request):
        snapshot=provider();persistent={};volatile={}
        for item in original['items']:
            spec=item['spec'];key=spec['key']
            if spec.get('path','').startswith('/run/'):
                volatile[key]={'state':'present_unqualified' if (root/spec['path'].lstrip('/')).exists() else 'absent'}
            elif item['phase']=='dependency':persistent[key]=provisioning.adapter.directory_dependency(spec)
            elif spec['kind'] in ('group','account'):
                expected=account_request(item,original['id'])
                assert provisioning.helper.inspect(expected)==expected['expected']
                persistent[key]=deepcopy(item['proof'])
            else:persistent[key]=provisioning.adapter.files.observe(item,original['id'])
        return dict(context=snapshot['context'],prerequisites=snapshot['prerequisites'],persistent=persistent,volatile=volatile)
    qualifier=PostBootQualification(provisioning.installer.journal,source_reader=provisioning.installer.read,observer=observe,account_history=history)
    qualification=qualifier.prepare('postboot-check',original,new_snapshot['context'])
    qualifier.qualify_persistent(qualification['id'])
    agreement=dict(operation_id='volatile-recovery',context=new_snapshot['context'],targets=qualification['plan']['volatile'],nonce='d'*32)
    recovery_window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    recovery=VolatileDirectories(qualifier,provisioning.adapter.files,window=recovery_window)
    recovered=recovery.prepare('volatile-recovery',qualification['id']);recovery.apply(recovered['id'])
    view=CurrentSessionView(recovery,recovered['id']);source=view.read()
    unit_agreement=dict(operation_id='current-unit-revision',context=new_snapshot['context'],targets=['file:'+UNIT],nonce='c'*32)
    window=ProvisioningWindow(unit_agreement,lambda:deepcopy(unit_agreement))
    revision=CurrentConfigurationSession(view,snapshot=provider,identity=provisioning.helper.inspect,
        directory_dependency=provisioning.adapter.directory_dependency,window=window,journal_identity=provisioning.installer.journal.identity)
    prepared=revision.prepare();effective=revision.apply_original(prepared)
    assert revision.effective()==effective and revision.apply_original(prepared)==effective
    assert 'Requisite=' in (root/UNIT.lstrip('/')).read_text()
    assert (root/prepared['backup'].lstrip('/')).read_text()==original['profile']['files'][UNIT]['content']
    assert provisioning.installer.read(original['id'])==original and view.read()==source
    assert effective['context']==new_snapshot['context'] and effective['context']!=original['context']
    assert worker.calls==['groupadd','useradd'] and not list(root.rglob('*.sock'))
