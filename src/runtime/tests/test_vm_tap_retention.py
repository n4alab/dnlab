"""Original-FD retention with synthetic ioctl replies, including lost replies."""
from copy import deepcopy

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_tap_retention import (
    RetainedTapDevice, TapRetention, COMMANDS, TUNSETPERSIST, ownership,
)
from test_vm_tap_device import kernel


@pytest.fixture
def retained(kernel,tmp_path):
    spec,_,state,factory=kernel
    journal=Journal(tmp_path/'journal')
    def preflight(value):
        return dict(request_sha256=value['request_sha256'],lease_token=value['lease_token'],
            original_birth_sha256=fingerprint(value['birth']),resources_verified=True,
            guest_writers_absent=not state.get('writer'))
    with factory(RetainedTapDevice) as device:
        birth=device.create()
        driver=TapRetention(journal,device,preflight=preflight)
        driver.prepare('retain',birth=birth,uid=1001,gid=1002)
        yield driver,device,birth,state,spec,factory
    journal.close()


def test_retention_release_and_explicit_postclose_absence(retained):
    driver,device,birth,state,_,_=retained
    value=driver.apply('retain')
    assert value['phase']=='retained' and value['birth']==birth
    assert driver.apply('retain')==value
    assert [c for c in state['calls'] if c in COMMANDS]==list(COMMANDS)
    with pytest.raises(RuntimeErrorBase):driver.confirm_absent('retain')
    released=driver.release('retain')
    assert released['phase']=='released' and state['links']
    assert driver.release('retain')==released
    device.close()
    absent=driver.confirm_absent('retain')
    assert absent['phase']=='absent' and absent['proof']['absence_verified']
    assert driver.confirm_absent('retain')==absent
    assert driver.prepare('retain',birth=birth,uid=1001,gid=1002)==absent


@pytest.mark.parametrize('command',COMMANDS)
def test_lost_applied_reply_recovers_without_second_ioctl(retained,command):
    driver,device,_,state,_,_=retained
    state['lost_change']=command
    with pytest.raises(OSError,match='lost'):driver.apply('retain')
    assert driver.read('retain')['phase']=='requested'
    state.pop('lost_change')
    assert driver.apply('retain')['phase']=='retained'
    assert state['calls'].count(command)==1
    driver.release('retain');device.close();driver.confirm_absent('retain')


@pytest.mark.parametrize('command',COMMANDS)
def test_uncertain_unapplied_change_is_never_resent(retained,command):
    driver,_,_,state,_,_=retained
    state['before_change']=command
    with pytest.raises(OSError):driver.apply('retain')
    state.pop('before_change')
    with pytest.raises(RuntimeErrorBase,match='uncertain'):driver.apply('retain')
    assert state['calls'].count(command)==1
    assert driver.read('retain')['phase']=='requested'


def test_release_lost_reply_is_observed_without_resend(retained):
    driver,device,_,state,_,_=retained
    driver.apply('retain');state['lost_change']=TUNSETPERSIST
    with pytest.raises(OSError):driver.release('retain')
    assert driver.read('retain')['phase']=='release_requested'
    state.pop('lost_change')
    driver.release('retain')
    assert state['calls'].count(TUNSETPERSIST)==2
    device.close();driver.confirm_absent('retain')


@pytest.mark.parametrize('fault',['writer','scope','mac','lease','birth'])
def test_preflight_conflicts_prevent_mutations_and_preserve_intent(retained,fault):
    driver,device,_,state,spec,_=retained
    saved=driver.read('retain');calls=state['calls'][:]
    if fault=='writer':state['writer']=True
    elif fault=='scope':state['scope']['inode']+=1
    elif fault=='mac':state['links'][spec['name']]['address']='02:00:00:00:00:aa'
    elif fault=='lease':device._lease_token='b'*32
    else:device._birth_proof=deepcopy(device._birth_proof);device._birth_proof['flags']+=1
    with pytest.raises(RuntimeErrorBase):driver.apply('retain')
    assert driver.read('retain')==saved
    assert not any(c in COMMANDS for c in state['calls'][len(calls):])


def test_different_request_cannot_replace_original_intent(retained):
    driver,_,birth,_,_,_=retained
    saved=driver.read('retain')
    for operation,uid in [('another',1001),('retain',1003)]:
        with pytest.raises(RuntimeErrorBase):driver.prepare(operation,birth=birth,uid=uid,gid=1002)
    assert driver.read('retain')==saved


def test_reappeared_name_blocks_absence_receipt(retained):
    driver,device,_,state,spec,_=retained
    driver.apply('retain');driver.release('retain');device.close()
    state['links'][spec['name']]={'ifname':spec['name'],'ifindex':999,'foreign':True}
    with pytest.raises(RuntimeErrorBase,match='absence'):driver.confirm_absent('retain')
    assert driver.read('retain')['phase']=='released'
    assert state['links'][spec['name']]['foreign']


def test_checkpoint_rechecks_writer_before_first_ioctl(retained,monkeypatch):
    driver,_,_,state,_,_=retained
    original=driver._save
    def save(value):
        original(value)
        if value['phase']=='requested':state['writer']=True
    monkeypatch.setattr(driver,'_save',save)
    with pytest.raises(RuntimeErrorBase):driver.apply('retain')
    assert driver.read('retain')['phase']=='requested'
    assert not any(c in COMMANDS for c in state['calls'])
    state.pop('writer')
    with pytest.raises(RuntimeErrorBase,match='uncertain'):driver.apply('retain')
    assert not any(c in COMMANDS for c in state['calls'])


def test_failed_requested_commit_never_mutates_kernel(retained,monkeypatch):
    driver,_,_,state,_,_=retained
    original=driver._save
    def save(value):
        original(value)
        raise OSError('synthetic journal failure')
    monkeypatch.setattr(driver,'_save',save)
    with pytest.raises(OSError):driver.apply('retain')
    assert driver.read('retain')['phase']=='prepared'
    assert not any(c in COMMANDS for c in state['calls'])


def test_lost_creator_lease_cannot_be_replaced_by_matching_proof(retained):
    driver,_,birth,_,_,factory=retained
    replacement=factory(RetainedTapDevice)
    replacement._birth_proof=deepcopy(birth)
    other=TapRetention(driver.journal,replacement,preflight=driver.preflight)
    with pytest.raises(RuntimeErrorBase,match='lease lost'):other.apply('retain')
    assert other.read('retain')['phase']=='prepared'


def test_uncertain_release_preserves_pending_without_resend(retained):
    driver,_,_,state,_,_=retained
    driver.apply('retain');state['before_change']=TUNSETPERSIST
    with pytest.raises(OSError):driver.release('retain')
    state.pop('before_change')
    with pytest.raises(RuntimeErrorBase,match='uncertain'):driver.release('retain')
    assert state['calls'].count(TUNSETPERSIST)==2
    assert driver.read('retain')['phase']=='release_requested'


def test_failed_birth_record_cannot_authorize_retention(kernel):
    _,_,state,factory=kernel;state['fail_record']='created'
    with factory(RetainedTapDevice) as device:
        with pytest.raises(OSError):device.create()
        assert device._birth_proof is None
        with pytest.raises(RuntimeErrorBase):device._change(TUNSETPERSIST,1)
    assert not any(c in COMMANDS for c in state['calls'])


@pytest.mark.parametrize('data',[{'user':'dnlab-libvirt'},{'group':True},{'persist':True}])
def test_numeric_and_consistent_ownership_evidence_required(retained,data):
    _,_,birth,_,_,_=retained
    proof=deepcopy(birth);proof['link']['linkinfo']['info_data'].update(data)
    with pytest.raises(RuntimeErrorBase):ownership(proof)
