"""Retirement/generation metadata only; resource proofs and replacement are fake."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT
from dnlab_runtime.libvirt_configuration_retirement import ConfigurationRetirement
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_configuration import revision,Replacement,install,request_profile


@pytest.fixture
def retiring(revision):
    driver,adapter,reference,installer,original=revision
    current=deepcopy(original);current['context']['boot_id']='88888888-8888-4888-8888-888888888888'
    current['postboot']={'synthetic_completed_directory_lineage':True}
    live=[deepcopy(current)];calls=[];fault={}
    receipt=dict(operation_id='retire-old-policy',context=deepcopy(current['context']),targets=['file:'+UNIT],nonce='7'*32)
    window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    def observe(old,source):
        calls.append(True)
        value=dict(context=deepcopy(source['context']),current_source_sha256=fingerprint(source),
            original_unit=deepcopy(old['plan']['source_item']['proof']),staging=dict(path=old['staging'],state='absent'),
            backup=dict(path=old['backup'],state='absent'),services_inactive=True)
        for key,changed in fault.items():value[key]=deepcopy(changed)
        return value
    retirement=ConfigurationRetirement(driver,source_reader=lambda:deepcopy(live[0]),observer=observe,window=window)
    return retirement,driver,adapter,reference,current,live,calls,fault


def test_retirement_preserves_payload_and_rejects_old_actions(retiring):
    retire,driver,adapter,reference,_,_,calls,_=retiring
    before=driver.journal.db.execute('SELECT payload,fingerprint FROM libvirt_configuration_revisions WHERE id=?',(reference['id'],)).fetchone()
    receipt=retire.retire('retire-old-policy',reference)
    assert receipt['reference_sha256']==fingerprint(reference) and len(calls)==2 and adapter.calls==0
    after=driver.journal.db.execute('SELECT payload,fingerprint FROM libvirt_configuration_revisions WHERE id=?',(reference['id'],)).fetchone()
    assert tuple(before)==tuple(after) and driver.read(reference['id'])==reference
    for action in (driver.apply,driver.recover,driver.effective):
        with pytest.raises(Conflict,match='retired'):action(reference['id'])
    with pytest.raises(Conflict,match='retired'):driver.prepare(reference['id'],reference['installation'])


def test_new_generation_requires_retirement_and_exact_completed_source(retiring):
    retire,driver,_,reference,current,_,_,_=retiring
    receipt=dict(operation_id='new-policy',context=deepcopy(current['context']),targets=['file:'+UNIT],nonce='6'*32)
    window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
    new=ConfigurationRevision(driver.journal,Replacement(),window=window,generation_source=lambda:deepcopy(current))
    with pytest.raises(Conflict,match='original configuration revision request differs'):new.prepare('new-policy',current)
    recorded=retire.retire('retire-old-policy',reference)
    prepared=new.prepare('new-policy',current)
    assert prepared['predecessor']==dict(revision_id=reference['id'],retirement_sha256=fingerprint(recorded))
    assert new.prepare('new-policy',current)==prepared and new.read(reference['id'])==reference
    assert new.apply('new-policy')['configuration_revision']['operation_id']=='new-policy'


def test_new_generation_without_current_view_is_refused(retiring):
    retire,driver,_,reference,current,_,_,_=retiring
    retire.retire('retire-old-policy',reference)
    with pytest.raises(Conflict,match='completed current-boot generation source required'):
        driver.prepare('new-policy',current)


@pytest.mark.parametrize('fault',['staging','backup','original_unit','services_inactive'])
def test_conflicting_resource_proof_cannot_retire(retiring,fault):
    retire,driver,adapter,reference,_,_,_,faults=retiring
    faults[fault]=False if fault=='services_inactive' else {'foreign':'preserve'}
    with pytest.raises(Conflict,match='retirement preflight differs'):retire.retire('retire-old-policy',reference)
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==0
    assert driver.read(reference['id'])==reference and adapter.calls==0


def test_started_revision_cannot_retire(retiring):
    retire,driver,adapter,reference,_,_,_,_=retiring;adapter.before=True
    with pytest.raises(OSError):driver.apply(reference['id'])
    with pytest.raises(Conflict,match='original prepared retirement reference differs'):
        retire.retire('retire-old-policy',reference)
    assert driver.read(reference['id'])['phase']=='replace_requested'


def test_lost_retirement_response_replays_same_receipt_without_writes(retiring,monkeypatch):
    import dnlab_runtime.libvirt_configuration_retirement as module
    retire,driver,_,reference,_,_,_,_=retiring;original=module.retirement;calls=[]
    def lost(journal,value):
        result=original(journal,value);calls.append(True)
        if len(calls)==2:raise OSError('synthetic lost retirement response')
        return result
    monkeypatch.setattr(module,'retirement',lost)
    with pytest.raises(OSError,match='lost retirement response'):retire.retire('retire-old-policy',reference)
    monkeypatch.setattr(module,'retirement',original);before=driver.journal.db.total_changes
    assert retire.retire('retire-old-policy',reference)==original(driver.journal,reference)
    assert driver.journal.db.total_changes==before


def test_window_closing_during_observation_blocks_retirement(retiring,monkeypatch):
    retire,driver,_,reference,_,_,_,_=retiring;observe=retire.observer
    def closed(*args):
        value=observe(*args);monkeypatch.setattr(retire.window,'observe',lambda:{});return value
    retire.observer=closed
    with pytest.raises(Conflict,match='window'):retire.retire('retire-old-policy',reference)
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==0
