"""Selected installed-package policy; synthetic observations and SQLite only."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_current_session import CurrentSessionView,CurrentSessionPreflight
from dnlab_runtime.libvirt_configuration import compile_revision
from dnlab_runtime.libvirt_package_policy import INSTALLED_PACKAGES
from dnlab_runtime.libvirt_postboot import PostBootQualification,plan
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow,account_request
from dnlab_runtime.libvirt_volatile_recovery import VolatileDirectories
from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from test_libvirt_install import install,request_profile
from test_libvirt_dpkg_diagnosis import FACTS
from test_libvirt_volatile_recovery import Directories


@pytest.fixture
def installed_packages(install):
    installer,adapter,prepared,_=install
    original=installer.apply(prepared['id'])
    spaces={name:dict(device=1,inode=index+10) for index,name in enumerate(('pid','mnt','net','user'))}
    original['context']=dict(host_id='master',boot_id='old-synthetic-boot',namespaces=spaces)
    profile=original['profile']
    original['prerequisites']=dict(profile_sha256=profile['profile_sha256'],packages=deepcopy(FACTS),
        dpkg_status_sha256='a'*64,provisioning_window_sha256='e'*64,
        binaries=dict(libvirtd=dict(path='/synthetic/libvirtd',sha256='b'*64)),
        account_inputs={'synthetic-config':dict(sha256='c'*64)},
        services=dict(dedicated_uid=profile['session']['uid'],processes=[],
            units={name:dict(active_state='inactive',job_id=0)
                   for name in profile['service_order']+profile['forbidden_vendor_activation']}))
    for item in original['items'][:2]:item['proof']['identity']=account_request(item,original['id'])['expected']
    with installer.journal.transaction():installer._save(original)
    current=deepcopy(original['context']);current['boot_id']='current-synthetic-boot'
    layout=plan(original,current)
    prerequisites=deepcopy(original['prerequisites']);prerequisites.pop('provisioning_window_sha256')
    prerequisites['dpkg_status_sha256']='f'*64
    observed=dict(context=deepcopy(current),prerequisites=prerequisites,
        persistent={item['spec']['key']:deepcopy(item['proof']) for item in original['items'] if item['spec']['key'] in layout['persistent']},
        volatile={key:dict(state='absent') for key in layout['volatile']})
    def history(item):
        return dict(kind='historical-account-creation-v1',installation_sha256=fingerprint(original),
            original_proof=deepcopy(item['proof']),creation_context_sha256=fingerprint(original['context']),evidence_sha256='d'*64)
    driver=PostBootQualification(installer.journal,source_reader=installer.read,
        observer=lambda value:deepcopy(observed),account_history=history)
    return driver,original,current,observed,installer,adapter


def test_selected_policy_ignores_only_database_digest_and_keeps_originals(installed_packages):
    driver,original,current,observed,installer,adapter=installed_packages
    calls=list(adapter.calls)
    value=driver.prepare('installed-package-check',original,current,package_policy=INSTALLED_PACKAGES)
    assert value['phase']=='prepared' and value['receipt'] is None
    receipt=driver.qualify_persistent(value['id'])
    assert receipt['qualified'] is False and receipt['package_policy']==INSTALLED_PACKAGES
    assert 'dpkg_status_sha256' not in receipt['observation']['prerequisites']
    assert installer.read(original['id'])==original and adapter.calls==calls
    assert observed['prerequisites']['dpkg_status_sha256']=='f'*64
    observed['prerequisites']['dpkg_status_sha256']='9'*64
    before=driver.journal.db.total_changes
    assert driver.qualify_persistent(value['id'])==receipt
    assert driver.prepare(value['id'],original,current,package_policy=INSTALLED_PACKAGES)==driver.read(value['id'])
    assert driver.journal.db.total_changes==before


def test_historical_policy_stays_strict_and_cannot_be_converted_on_retry(installed_packages):
    driver,original,current,_,_,_=installed_packages
    value=driver.prepare('historical-package-check',original,current)
    assert 'package_policy' not in value
    with pytest.raises(Conflict):driver.qualify_persistent(value['id'])
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='original post-boot request'):
        driver.prepare(value['id'],original,current,package_policy=INSTALLED_PACKAGES)
    assert driver.read(value['id'])==value and driver.journal.db.total_changes==before


@pytest.mark.parametrize('fault',['missing','version','architecture','state','binary','config','context','persistent','active'])
def test_relevant_package_or_resource_changes_still_refuse(installed_packages,fault):
    driver,original,current,observed,_,adapter=installed_packages
    value=driver.prepare('selected-packages',original,current,package_policy=INSTALLED_PACKAGES)
    packages=observed['prerequisites']['packages'];row=next(iter(packages.values()))
    if fault=='missing':packages.clear()
    elif fault=='version':row['Version']='different'
    elif fault=='architecture':row['Architecture']='arm64'
    elif fault=='state':row['Status']='install ok triggers-pending'
    elif fault=='binary':observed['prerequisites']['binaries']['libvirtd']['sha256']='8'*64
    elif fault=='config':observed['prerequisites']['account_inputs']['synthetic-config']['sha256']='8'*64
    elif fault=='context':observed['context']['boot_id']='foreign-synthetic-boot'
    elif fault=='persistent':observed['persistent'][next(iter(observed['persistent']))]={'foreign':True}
    else:next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    calls=list(adapter.calls);before=driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.qualify_persistent(value['id'])
    assert driver.read(value['id'])==value and driver.journal.db.total_changes==before and adapter.calls==calls


def test_digest_change_between_observations_does_not_become_a_package_change(installed_packages,monkeypatch):
    driver,original,current,observed,_,_=installed_packages;calls=[]
    def observe(value):
        calls.append(1);result=deepcopy(observed)
        result['prerequisites']['dpkg_status_sha256']=str(len(calls))*64
        return result
    monkeypatch.setattr(driver,'observer',observe)
    value=driver.prepare('selected-packages',original,current,package_policy=INSTALLED_PACKAGES)
    driver.qualify_persistent(value['id'])
    assert len(calls)==2


def test_policy_is_validated_on_reopen_and_linked_to_receipt(installed_packages):
    driver,original,current,_,_,_=installed_packages
    value=driver.prepare('selected-packages',original,current,package_policy=INSTALLED_PACKAGES)
    driver.qualify_persistent(value['id'])
    stored=driver.read(value['id']);stored['receipt']['package_policy']='different-policy'
    driver.journal.db.execute('UPDATE libvirt_postboot_qualifications SET payload=?,fingerprint=? WHERE id=?',
        (canonical(stored),fingerprint(stored),value['id']))
    with pytest.raises(Conflict,match='package receipt'):driver.read(value['id'])


def test_current_session_keeps_selected_policy_through_directory_recovery(installed_packages):
    driver,original,current,observed,installer,_=installed_packages
    value=driver.prepare('selected-packages',original,current,package_policy=INSTALLED_PACKAGES)
    driver.qualify_persistent(value['id'])
    agreement=dict(operation_id='selected-dirs',context=current,targets=value['plan']['volatile'],nonce='7'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    files=Directories(driver.journal,observed)
    recovery=VolatileDirectories(driver,files,window=window)
    prepared=recovery.prepare('selected-dirs',value['id']);recovery.apply(prepared['id'])
    for item in original['items']:
        if item['spec']['kind'] in ('file','directory') and item['spec']['key'] not in value['plan']['volatile']:
            files.resources[item['spec']['key']]=deepcopy(item['proof'])
    view=CurrentSessionView(recovery,prepared['id']);source=view.read()
    assert source['postboot']['package_policy']==INSTALLED_PACKAGES
    assert 'dpkg_status_sha256' not in source['prerequisites']
    observed['prerequisites']['dpkg_status_sha256']='6'*64
    provider=CurrentSessionPreflight(view,snapshot=lambda:dict(context=current,prerequisites=deepcopy(observed['prerequisites'])),
        identity=lambda request:request['expected'],directory_dependency=lambda spec:pytest.fail('unexpected dependency'))
    request=dict(installation=source,source_sha256=fingerprint(source),plan=compile_revision(source))
    assert provider(request)['context']==current
    assert installer.read(original['id'])==original
