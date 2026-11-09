"""Only synthetic service receipts; never systemd, processes or libvirt."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import SessionActivation
from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_install import install, request_profile, Adapter


class Services:
    def __init__(self):
        self.rows={};self.calls=[];self.lost=None;self.before=False;self.domains=[]
    def observe(self,value):
        return dict(context=deepcopy(value['installation']['context']),installation_sha256=value['installation_sha256'],
            steps={item['spec']['key']:deepcopy(self.rows.get(item['spec']['key'])) for item in value['items']})
    def apply(self,item,operation):
        key=item['spec']['key'];assert key not in self.rows
        self.calls.append(key)
        if self.before:raise OSError('synthetic response lost before action')
        receipt=dict(activation_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
            identity=dict(synthetic_command_and_generation=len(self.calls)))
        self.rows[key]=deepcopy(receipt)
        if self.lost==key:
            self.lost=None;raise OSError('synthetic response lost after original completion')
        return receipt
    def qualify_empty(self,value):
        return dict(installation_sha256=value['installation_sha256'],domains=deepcopy(self.domains),
            service_proofs_sha256=fingerprint([item['proof'] for item in value['items']]))


@pytest.fixture
def activation(tmp_path,request_profile):
    request=deepcopy(request_profile);request['activation_policy']='requisite-after-v1'
    journal=Journal(tmp_path/'journal')
    installer=SessionInstaller(journal,Adapter())
    prepared=installer.prepare('install',request,context={'boot_id':'synthetic-boot'},prerequisites={'qualified':'synthetic'})
    installed=installer.apply(prepared['id'])
    adapter=Services();driver=SessionActivation(installer.journal,adapter)
    value=driver.prepare('activation',installed)
    try:yield driver,adapter,value,installed
    finally:journal.close()


def test_legacy_installation_cannot_be_activated_or_adopted(install,monkeypatch):
    installer,_,prepared,_=install
    installed=installer.apply(prepared['id'])
    adapter=Services();driver=SessionActivation(installer.journal,adapter)
    monkeypatch.setattr(adapter,'observe',lambda *args:pytest.fail('legacy activation must fail before observation'))
    with pytest.raises(Conflict,match='no implicit profile conversion'):driver.prepare('activation',installed)
    assert adapter.calls==[] and installer.read(prepared['id'])==installed


def test_saved_legacy_activation_stays_readable_but_cannot_apply(install,monkeypatch):
    from dnlab_runtime.libvirt_activation import steps
    from dnlab_runtime.manifest import canonical
    installer,_,prepared,_=install
    installed=installer.apply(prepared['id'])
    adapter=Services();driver=SessionActivation(installer.journal,adapter)
    saved=dict(id='legacy-activation',installation=installed,installation_sha256=fingerprint(installed),
        phase='prepared',empty_proof=None,items=[dict(spec=spec,nonce=format(i+1,'032x'),phase='prepared',proof=None)
            for i,spec in enumerate(steps(installed['profile']))])
    with driver.journal.transaction():
        driver.journal.db.execute('INSERT INTO libvirt_activation_intents VALUES(?,?,?,?)',
            (saved['id'],installed['id'],canonical(saved),fingerprint(saved)))
    before=driver.journal.db.total_changes
    monkeypatch.setattr(adapter,'observe',lambda *args:pytest.fail('legacy apply must stop before observation'))
    assert driver.read(saved['id'])==saved
    with pytest.raises(Conflict,match='no implicit profile conversion'):driver.apply(saved['id'])
    assert driver.read(saved['id'])==saved and driver.journal.db.total_changes==before
    assert adapter.calls==[]


def test_ordered_empty_activation_and_replay_never_restart_services(activation):
    driver,adapter,value,installed=activation
    assert adapter.calls==[]
    result=driver.apply(value['id'])
    assert result['phase']=='ready_empty'
    assert adapter.calls==['manager-reload']+installed['profile']['service_order']
    assert driver.apply(value['id'])==result and driver.prepare(value['id'],installed)==result
    assert len(adapter.calls)==4


@pytest.mark.parametrize('index',range(4))
def test_lost_response_recovers_original_completion_without_another_action(activation,index):
    driver,adapter,value,_=activation
    adapter.lost=value['items'][index]['spec']['key']
    with pytest.raises(OSError):driver.apply(value['id'])
    saved=driver.read(value['id'])
    assert saved['items'][index]['phase']=='requested'
    assert driver.apply(value['id'])['phase']=='ready_empty'
    assert len(adapter.calls)==len(set(adapter.calls))==4


def test_uncertain_absence_stays_pending_without_resend(activation):
    driver,adapter,value,_=activation;adapter.before=True
    with pytest.raises(OSError):driver.apply(value['id'])
    with pytest.raises(Conflict,match='no resend'):driver.apply(value['id'])
    assert adapter.calls==['manager-reload']
    assert driver.read(value['id'])['items'][0]['phase']=='requested'


def test_last_service_conflict_blocks_before_first_action(activation):
    driver,adapter,value,_=activation
    adapter.rows[value['items'][-1]['spec']['key']]={'foreign':'preserve'}
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert adapter.calls==[] and driver.journal.db.total_changes==before


def test_conflict_after_durable_checkpoint_blocks_action(activation,monkeypatch):
    driver,adapter,value,_=activation;save=driver._save
    def changed(current):
        save(current)
        if current['items'][0]['phase']=='requested':
            adapter.rows[current['items'][-1]['spec']['key']]={'foreign':'preserve'}
    monkeypatch.setattr(driver,'_save',changed)
    with pytest.raises(Conflict):driver.apply(value['id'])
    assert adapter.calls==[]


def test_replaced_service_generation_is_refused_without_restart(activation):
    driver,adapter,value,_=activation
    driver.apply(value['id'])
    adapter.rows[value['items'][-1]['spec']['key']]['identity']={'foreign':'preserve'}
    with pytest.raises(Conflict,match='generation'):driver.apply(value['id'])
    assert len(adapter.calls)==4


def test_empty_inventory_failure_preserves_confirmed_services_for_retry(activation):
    driver,adapter,value,_=activation;adapter.domains=['foreign-domain']
    with pytest.raises(Conflict,match='empty session'):driver.apply(value['id'])
    assert all(item['phase']=='confirmed' for item in driver.read(value['id'])['items'])
    adapter.domains=[]
    assert driver.apply(value['id'])['phase']=='ready_empty'
    assert len(adapter.calls)==4
