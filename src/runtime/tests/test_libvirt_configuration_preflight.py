"""Synthetic complete inventories; account birth tests use a temporary journal."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import compile_revision,UNIT
from dnlab_runtime.libvirt_configuration import ConfigurationRevision
from dnlab_runtime.libvirt_configuration_adapter import ConfigurationFileAdapter
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_configuration_preflight import CompletedAccountObserver,ConfigurationPreflight
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_configuration import revision
from test_libvirt_install import install,request_profile
from test_libvirt_provisioning import accounts


@pytest.fixture
def preflight(revision):
    _,_,value,_,_=revision
    value=deepcopy(value);installation=value['installation'];profile=installation['profile']
    installation['prerequisites'].update(profile_sha256=profile['profile_sha256'],services=dict(
        units={name:dict(active_state='inactive',job_id=0) for name in profile['service_order']+profile['forbidden_vendor_activation']},
        dedicated_uid=profile['session']['uid'],processes=[]))
    value.update(plan=compile_revision(installation),source_sha256=fingerprint(installation))
    snapshot=dict(context=deepcopy(installation['context']),prerequisites=deepcopy(installation['prerequisites']))
    resources={item['spec']['key']:deepcopy(item['proof']) for item in installation['items']}
    calls=[]
    class Targets:
        def observe(self,item,creator):
            assert creator==installation['id']
            calls.append(item['spec']['key'])
            return deepcopy(resources[item['spec']['key']])
    reader=Targets()
    provider=ConfigurationPreflight(installation,snapshot=lambda:deepcopy(snapshot),accounts=reader,files=reader,
        directory_dependency=lambda spec:deepcopy(resources[spec['key']]))
    return provider,value,resources,snapshot,calls


def test_all_unchanged_targets_are_rechecked_and_original_request_preserved(preflight):
    provider,value,resources,_,calls=preflight
    before=deepcopy(value)
    result=provider(value)
    keys=set(resources)-{'file:'+UNIT}
    assert set(calls)==keys and all(calls.count(key)==2 for key in keys)
    assert result==dict(context=value['installation']['context'],source_sha256=value['source_sha256'],
        unchanged_sha256=value['plan']['unchanged_sha256'],services_inactive=True)
    assert value==before


@pytest.mark.parametrize('kind',['group','account','directory','file'])
def test_substituted_original_resource_is_rejected(preflight,kind):
    provider,value,resources,_,_=preflight
    item=next(item for item in value['installation']['items'] if item['spec']['kind']==kind and item['spec'].get('path')!=UNIT)
    resources[item['spec']['key']]={'foreign':'preserve'}
    with pytest.raises(Conflict,match='resource differs'):provider(value)
    assert resources[item['spec']['key']]=={'foreign':'preserve'}


@pytest.mark.parametrize('fault',['active','job','process','missing','namespace','package'])
def test_changed_prerequisites_or_services_are_rejected(preflight,fault):
    provider,value,_,snapshot,_=preflight
    service=snapshot['prerequisites']['services'];unit=next(iter(service['units']))
    if fault=='active':service['units'][unit]['active_state']='active'
    elif fault=='job':service['units'][unit]['job_id']=1
    elif fault=='process':service['processes']=[{'pid':999}]
    elif fault=='missing':del service['units'][unit]
    elif fault=='namespace':snapshot['context']['namespace']=321
    else:snapshot['prerequisites']['packages']='changed'
    with pytest.raises(Conflict,match='prerequisites'):provider(value)


def test_snapshot_change_during_resource_reads_is_rejected(preflight,monkeypatch):
    provider,value,_,snapshot,_=preflight;targets=provider._targets
    def changed():
        result=targets();snapshot['prerequisites']['packages']='changed';return result
    monkeypatch.setattr(provider,'_targets',changed)
    with pytest.raises(Conflict):provider(value)


def test_completed_account_observation_needs_no_original_active_window(accounts,monkeypatch):
    adapter,helper,item,window,current=accounts
    item=deepcopy(item);item.update(phase='created',proof=adapter.create(item,'install',window=window))
    read=helper.completion
    monkeypatch.setattr(helper,'preflight_completion',read,raising=False)
    monkeypatch.setattr(helper,'completion',lambda *args:pytest.fail('old window/preflight completion cannot run'))
    current['nonce']='f'*32
    before=adapter.journal.db.total_changes
    adapter.journal.db.execute('PRAGMA query_only=ON')
    assert CompletedAccountObserver(adapter).observe(item,'install')==item['proof']
    assert adapter.journal.db.total_changes==before and len(helper.calls)==1


def test_completed_account_without_original_completion_is_not_adopted(accounts,monkeypatch):
    adapter,helper,item,window,_=accounts
    item=deepcopy(item);item.update(phase='created',proof=adapter.create(item,'install',window=window))
    monkeypatch.setattr(helper,'preflight_completion',lambda request:None,raising=False)
    with pytest.raises(Conflict,match='completion'):CompletedAccountObserver(adapter).observe(item,'install')
    assert len(helper.calls)==1


def test_explicit_directory_dependency_is_rechecked_without_claiming_birth(preflight):
    provider,value,resources,_,_=preflight
    original=deepcopy(value['installation'])
    item=next(item for item in original['items'] if item['spec']['kind']=='directory')
    item['phase']='dependency'
    item['proof']={'dependency':'existing_directory','identity':{'synthetic_directory':123}}
    original['dependencies'][item['spec']['path']]=deepcopy(item['proof'])
    value=deepcopy(value);value.update(installation=original,plan=compile_revision(original),source_sha256=fingerprint(original))
    resources[item['spec']['key']]=item['proof'];calls=[]
    def dependency(spec):
        calls.append(spec['key']);return deepcopy(resources[spec['key']])
    revised=ConfigurationPreflight(original,snapshot=provider.snapshot,accounts=provider.accounts,
        files=provider.files,directory_dependency=dependency)
    assert revised(value)['services_inactive'] is True
    assert calls==[item['spec']['key']]*2
    resources[item['spec']['key']]={'foreign':'directory'}
    with pytest.raises(Conflict,match='resource differs'):revised(value)


def test_complete_preflight_composes_with_real_temporary_file_revision(install,tmp_path):
    installer,_,prepared,_=install;original=installer.apply(prepared['id'])
    root=tmp_path/'native-root';root.mkdir()
    files=InstallationFiles(str(root),journal=installer.journal)
    for item in original['items']:
        if item['spec']['kind']=='file':
            (root/item['spec']['path'].lstrip('/')).parent.mkdir(parents=True,exist_ok=True)
            item['proof']=files.create(item,original['id'])
    profile=original['profile']
    original['prerequisites'].update(profile_sha256=profile['profile_sha256'],services=dict(
        units={name:dict(active_state='inactive',job_id=0) for name in profile['service_order']+profile['forbidden_vendor_activation']},
        dedicated_uid=profile['session']['uid'],processes=[]))
    snapshot=dict(context=deepcopy(original['context']),prerequisites=deepcopy(original['prerequisites']))
    class Resources:
        def observe(self,item,creator):
            assert creator==original['id']
            if item['spec']['kind']=='file':return files.observe(item,creator)
            return deepcopy(item['proof'])  # Accounts/directories stay synthetic.
    resources=Resources()
    preflight=ConfigurationPreflight(original,snapshot=lambda:deepcopy(snapshot),accounts=resources,files=resources,
        directory_dependency=lambda spec:pytest.fail('no dependency in this fixture'))
    receipt=dict(operation_id='policy-revision',context=deepcopy(original['context']),targets=['file:'+UNIT],nonce='e'*32)
    window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    adapter=ConfigurationFileAdapter(files,window=window,preflight=preflight)
    driver=ConfigurationRevision(installer.journal,adapter,window=window)
    value=driver.prepare('policy-revision',original)
    effective=driver.apply(value['id'])
    assert driver.effective(value['id'])==effective
    assert driver.read(value['id'])['installation']==original
    assert (root/UNIT.lstrip('/')).read_text()==effective['profile']['files'][UNIT]['content']
    snapshot['prerequisites']['services']['processes']=[{'pid':999}]
    with pytest.raises(Conflict,match='prerequisites'):driver.effective(value['id'])
