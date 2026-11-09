"""Session provisioning uses only synthetic resources and an injected adapter."""
from copy import deepcopy
from contextlib import contextmanager

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_service_profile import request_profile


class Adapter:
    def __init__(self):
        self.resources={};self.calls=[];self.observations=0;self.hook=lambda value:None
        self.lose=False;self.before_create=False;self.bad_receipt=False
    def observe(self,value):
        self.observations+=1
        self.hook(value)
        return dict(context=deepcopy(value['context']),prerequisites=deepcopy(value['prerequisites']),
            targets={item['spec']['key']:deepcopy(self.resources.get(item['spec']['key'])) for item in value['items']})
    def create(self,item,operation_id):
        key=item['spec']['key'];assert key not in self.resources
        self.calls.append(key)
        if self.before_create:raise OSError('lost before allocation')
        receipt=dict(intent_id=operation_id,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
            identity={'synthetic_id':len(self.calls)})
        self.resources[key]=deepcopy(receipt)
        if self.lose:raise OSError('lost after allocation')
        if self.bad_receipt:receipt['identity']={'synthetic_id':999}
        return receipt


@pytest.fixture
def install(request_profile,tmp_path):
    journal=Journal(tmp_path/'journal');adapter=Adapter();driver=SessionInstaller(journal,adapter)
    value=driver.prepare('install-1',request_profile,context={'boot_id':'synthetic-boot','namespace':123},
        prerequisites={'packages':'qualified-synthetic-packages','vendor_masks':'qualified-synthetic-masks'})
    yield driver,adapter,value,request_profile
    journal.close()


def test_create_only_installs_once_and_never_starts_services(install):
    driver,adapter,value,_=install
    assert adapter.calls==[] and value['phase']=='prepared'
    result=driver.apply(value['id'])
    assert result['phase']=='installed_not_started'
    assert len(adapter.calls)==len(result['items'])==19
    assert all(item['phase']=='created' for item in result['items'])
    calls=list(adapter.calls)
    assert driver.apply(value['id'])==result and adapter.calls==calls
    assert adapter.calls[:2]==['group:dnlab-libvirt','account:dnlab-libvirt']


def test_same_intent_reopen_reuses_nonces_without_writes(install):
    driver,adapter,value,request=install
    reopened=SessionInstaller(driver.journal,adapter)
    before=driver.journal.db.total_changes
    assert reopened.prepare(value['id'],request,context=value['context'],prerequisites=value['prerequisites'])==value
    assert driver.journal.db.total_changes==before and adapter.calls==[]


def test_lost_response_recovers_original_birth_without_second_create(install):
    driver,adapter,value,_=install;adapter.lose=True
    with pytest.raises(OSError):driver.apply(value['id'])
    original=driver.read(value['id']);assert original['items'][0]['phase']=='create_requested'
    adapter.lose=False
    reopened=SessionInstaller(driver.journal,adapter)
    result=reopened.apply(value['id'])
    assert result['phase']=='installed_not_started'
    assert adapter.calls.count('group:dnlab-libvirt')==1
    assert result['items'][0]['nonce']==original['items'][0]['nonce']


def test_uncertain_absence_never_repeats_create_or_discards_intent(install):
    driver,adapter,value,_=install;adapter.before_create=True
    with pytest.raises(OSError):driver.apply(value['id'])
    saved=driver.read(value['id']);adapter.before_create=False
    with pytest.raises(Conflict,match='uncertain create'):driver.apply(value['id'])
    assert driver.read(value['id'])==saved and len(adapter.calls)==1


@pytest.mark.parametrize('fault',['nonce','intent_id','spec_sha256','identity'])
def test_lost_response_with_substituted_resource_blocks_recovery(install,fault):
    driver,adapter,value,_=install;adapter.lose=True
    with pytest.raises(OSError):driver.apply(value['id'])
    receipt=adapter.resources['group:dnlab-libvirt']
    receipt[fault]={} if fault=='identity' else 'different'
    before=driver.read(value['id']);adapter.lose=False
    with pytest.raises(Conflict,match='birth differs'):driver.apply(value['id'])
    assert driver.read(value['id'])==before and len(adapter.calls)==1


def test_full_preflight_blocks_first_mutation_for_last_target_conflict(install):
    driver,adapter,value,_=install
    adapter.resources[value['items'][-1]['spec']['key']]={'foreign':'resource'}
    with pytest.raises(Conflict,match='occupied'):driver.apply(value['id'])
    assert adapter.calls==[] and driver.read(value['id'])==value


def test_recheck_after_intent_commit_prevents_create_on_changed_prerequisites(install,monkeypatch):
    driver,adapter,value,_=install
    observe=adapter.observe
    def changed(value):
        result=observe(value)
        if any(item['phase']=='create_requested' for item in value['items']):
            result['prerequisites']={'packages':'changed'}
        return result
    monkeypatch.setattr(adapter,'observe',changed)
    with pytest.raises(Conflict,match='preflight differs'):driver.apply(value['id'])
    assert adapter.calls==[] and driver.read(value['id'])['items'][0]['phase']=='create_requested'


def test_committed_birth_survives_lost_commit_response(install,monkeypatch):
    driver,adapter,value,_=install;transaction=driver.journal.transaction;lost=[]
    @contextmanager
    def commit():
        with transaction():yield
        if driver.read(value['id'])['items'][0]['phase']=='created' and not lost:
            lost.append(True);raise OSError('lost commit response')
    monkeypatch.setattr(driver.journal,'transaction',commit)
    with pytest.raises(OSError):driver.apply(value['id'])
    assert driver.apply(value['id'])['phase']=='installed_not_started'
    assert adapter.calls.count('group:dnlab-libvirt')==1


def test_created_resource_replacement_is_preserved_without_further_mutations(install):
    driver,adapter,value,_=install
    driver.apply(value['id']);calls=list(adapter.calls)
    adapter.resources['group:dnlab-libvirt']['identity']={'foreign':123}
    with pytest.raises(Conflict,match='replaced'):driver.apply(value['id'])
    assert adapter.calls==calls and adapter.resources['group:dnlab-libvirt']['identity']=={'foreign':123}


def test_explicit_directory_dependency_is_verified_and_never_created(request_profile,tmp_path):
    journal=Journal(tmp_path/'dependency');adapter=Adapter()
    try:
        driver=SessionInstaller(journal,adapter)
        original={'inode':123,'device':4,'uid':0,'gid':0,'mode':0o755}
        adapter.resources['directory:/etc/dnlab']=deepcopy(original)
        value=driver.prepare('with-dependency',request_profile,context={'boot':'same'},prerequisites={'packages':'same'},
            existing_directories={'/etc/dnlab':original})
        driver.apply(value['id'])
        assert 'directory:/etc/dnlab' not in adapter.calls
        adapter.resources['directory:/etc/dnlab']['inode']=456
        with pytest.raises(Conflict,match='replaced'):driver.apply(value['id'])
    finally:journal.close()


def test_original_request_changes_and_other_installer_are_refused(install):
    driver,adapter,value,request=install
    for operation,context in [('other-install',value['context']),('install-1',{'boot':'other'})]:
        before=driver.journal.db.total_changes
        with pytest.raises(Conflict,match='original request differs'):
            driver.prepare(operation,request,context=context,prerequisites=value['prerequisites'])
        assert driver.journal.db.total_changes==before and adapter.calls==[]


def test_create_receipt_must_match_independent_observation(install):
    driver,adapter,value,_=install;adapter.bad_receipt=True
    with pytest.raises(Conflict,match='independently observed'):driver.apply(value['id'])
    assert len(adapter.calls)==1 and driver.read(value['id'])['items'][0]['phase']=='create_requested'


def test_old_prepared_intent_stays_readable_immutable_and_cannot_apply(tmp_path,request_profile):
    from dnlab_runtime.libvirt_install import targets
    from dnlab_runtime.libvirt_service_profile import render_profile
    from dnlab_runtime.manifest import canonical
    legacy=deepcopy(request_profile);legacy.pop('layout_version');legacy.pop('driver_config_root')
    profile=render_profile(**legacy)
    saved=dict(id='legacy-install',request=legacy,profile=profile,context={'boot':'synthetic'},
        prerequisites={'packages':'legacy'},dependencies={},phase='prepared',
        items=[dict(spec=spec,nonce=format(index+1,'032x'),phase='prepared',proof=None)
            for index,spec in enumerate(targets(profile))])
    journal=Journal(tmp_path/'journal');adapter=Adapter();driver=SessionInstaller(journal,adapter)
    try:
        with journal.transaction():
            journal.db.execute('INSERT INTO libvirt_install_intents VALUES(?,?,?,?)',
                (saved['id'],profile['session']['host_id'],canonical(saved),fingerprint(saved)))
        changes=journal.db.total_changes
        assert driver.read(saved['id'])==saved
        with pytest.raises(Conflict,match='layout_version=2'):driver.apply(saved['id'])
        with pytest.raises(Conflict,match='layout_version=2'):
            driver.prepare(saved['id'],legacy,context=saved['context'],prerequisites=saved['prerequisites'])
        with pytest.raises(Conflict,match='original request differs'):
            driver.prepare('new-install',request_profile,context=saved['context'],prerequisites=saved['prerequisites'])
        assert driver.read(saved['id'])==saved and journal.db.total_changes==changes
        assert adapter.calls==[] and adapter.observations==0
    finally:journal.close()
