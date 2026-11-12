"""Real provider/retention protocol; actor, SDK and TUN kernel are synthetic."""
from contextlib import contextmanager
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_tap_device import TUNSETIFF, TUNSETIFINDEX
from dnlab_runtime.vm_tap_local import LocalTapEndpoints, worker_command
from dnlab_runtime.vm_tap_retention import RetainedTapDevice, TUNSETOWNER, COMMANDS
from dnlab_runtime.vm_taps import VMTaps
from test_vm_definition import definition, template, instance
from test_vm_tap_device import kernel


@pytest.fixture
def local(definition,kernel):
    definitions,birth,xml,_,_,_=definition
    _,context,state,factory=kernel
    state.update(actor_alive=True,writer=False,actor_checks=0)
    all_devices=[]
    inventory=lambda:deepcopy(list(state['links'].values()))
    def device_factory(spec,scope,record):
        device=factory(RetainedTapDevice);device.spec=deepcopy(spec);device.context=deepcopy(scope)
        device.record=record;all_devices.append(device)
        return device
    def verify(reference,command):
        state['actor_checks']+=1
        return state['actor_alive'] and reference==state['reference'] and command==state['command']
    def make_provider():
        return LocalTapEndpoints(definitions.journal,read_context=lambda:deepcopy(state['scope']),
            inventory=inventory,verify_worker=verify,device_factory=device_factory,process_id=lambda:1234)
    def preflight(value):
        definition=definitions.read(value['id'])
        return dict(definition_sha256=value['definition_sha256'],session_sha256=definition['session_sha256'],
            context_sha256=fingerprint(context),session_namespace_verified=True,guest_writers_absent=not state['writer'])
    def make_sets(provider):
        driver=VMTaps(definitions,endpoints=provider,read_context=lambda:deepcopy(state['scope']),preflight=preflight)
        provider.attach(driver)
        return driver
    provider=make_provider();driver=make_sets(provider)
    requests=[dict(name=target.get('dev'),ifindex=12001+index,nonce=str(index+1)*32,vnet_header=True)
        for index,target in enumerate(ET.fromstring(xml).findall('devices/interface/target'))]
    value=driver.prepare(birth['creator_operation_id'],context,requests)
    command=worker_command(value)
    reference=dict(token='a'*32,command_sha256=fingerprint(command),process_record=dict(
        boot_id=context['boot_id'],pid=1234,start_ticks=12345,uid=0,gid=0,
        executable_sha256='b'*64,namespace_sha256='c'*64))
    state.update(reference=reference,command=command)
    provider.bind(value['id'],reference)
    try:yield driver,provider,value,state,all_devices,make_provider,make_sets
    finally:
        # Only /dev/null descriptors exist in this synthetic kernel. No
        # production cleanup claim is made for the fake persistent links.
        for device in all_devices:device.close()


def test_real_provider_records_original_birth_then_retains_complete_set(local):
    driver,provider,value,state,devices,_,_=local
    retained=driver.apply(value['id'])
    assert retained['phase']=='retained' and state['calls'].count(TUNSETIFF)==len(value['items'])
    assert driver.apply(value['id'])==retained
    for item,device in zip(retained['items'],devices):
        original=provider._read(item['spec']['tap']['nonce'])
        assert [record['phase'] for record in original['records']]==['opened','create_requested','created']
        assert original['records'][-1]['proof']==device._birth_proof
        assert original['lease_token']==device._lease_token
        assert item['proof']['worker_reference_sha256']==fingerprint(state['reference'])
        assert device._fd is not None
    assert state['actor_checks']>0


def test_lost_owner_reply_recovers_same_fd_without_another_create(local):
    driver,_,value,state,devices,_,_=local
    state['lost_change']=TUNSETOWNER
    with pytest.raises(OSError):driver.apply(value['id'])
    fd=devices[0]._fd;birth=deepcopy(devices[0]._birth_proof)
    state.pop('lost_change')
    assert driver.apply(value['id'])['phase']=='retained'
    assert devices[0]._fd==fd and devices[0]._birth_proof==birth
    assert state['calls'].count(TUNSETIFF)==state['calls'].count(TUNSETOWNER)==len(value['items'])


def test_lost_coordinator_commit_recovers_provider_receipt_without_recreate(local,monkeypatch):
    driver,_,value,state,_,_,_=local;save=driver._save;failed=[]
    def lost(current):
        save(current)
        if current['items'][0]['phase']=='retained' and not failed:
            failed.append(True);raise OSError('lost outer commit')
    monkeypatch.setattr(driver,'_save',lost)
    with pytest.raises(OSError):driver.apply(value['id'])
    assert driver.read(value['id'])['items'][0]['phase']=='create_requested'
    assert driver.apply(value['id'])['phase']=='retained'
    assert state['calls'].count(TUNSETIFF)==len(value['items'])


def test_lost_durable_birth_reply_uses_saved_original_ack(local,monkeypatch):
    driver,provider,value,state,devices,_,_=local
    transaction=driver.journal.transaction;failed=[]
    @contextmanager
    def lost_commit():
        with transaction():yield
        original=provider._read(value['items'][0]['spec']['tap']['nonce'])
        if original is not None and original['phase']=='created' and not failed:
            failed.append(True);raise OSError('lost birth commit reply')
    monkeypatch.setattr(driver.journal,'transaction',lost_commit)
    with pytest.raises(OSError):driver.apply(value['id'])
    assert devices[0]._birth_proof is None
    saved=deepcopy(provider._read(value['items'][0]['spec']['tap']['nonce'])['records'][-1]['proof'])
    assert driver.apply(value['id'])['phase']=='retained'
    assert devices[0]._birth_proof==saved and state['calls'].count(TUNSETIFF)==len(value['items'])


def test_non_durable_birth_cannot_be_inferred_from_matching_link(local,monkeypatch):
    driver,provider,value,state,devices,_,_=local;save=provider._save
    def fail(current):
        save(current)
        if current['phase']=='created':raise OSError('birth commit failed')
    monkeypatch.setattr(provider,'_save',fail)
    with pytest.raises(OSError):driver.apply(value['id'])
    assert devices[0]._birth_proof is None and state['links']
    assert provider._read(value['items'][0]['spec']['tap']['nonce'])['phase']=='create_requested'
    with pytest.raises(RuntimeErrorBase,match='no original birth'):driver.apply(value['id'])
    assert state['calls'].count(TUNSETIFF)==1 and not any(c in COMMANDS for c in state['calls'])


@pytest.mark.parametrize('fault',['actor','namespace','writer'])
def test_changed_worker_preflight_refuses_before_device_open(local,fault):
    driver,_,value,state,devices,_,_=local
    if fault=='actor':state['actor_alive']=False
    elif fault=='namespace':state['scope']['inode']+=1
    else:state['writer']=True
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert devices==[] and state['fds']=={} and TUNSETIFF not in state['calls']


def test_new_provider_cannot_adopt_old_descriptors_or_matching_interfaces(local):
    driver,_,value,state,_,make_provider,make_sets=local
    retained=driver.apply(value['id']);count=len(state['calls'])
    other=make_sets(make_provider())
    with pytest.raises(Conflict,match='lease unavailable'):other.apply(value['id'])
    assert state['calls'][count:]==[] and driver.read(value['id'])==retained


def test_worker_binding_is_immutable_even_before_allocation(local):
    _,provider,value,state,devices,_,_=local
    original=provider._actor(value['id']);replacement=deepcopy(state['reference']);replacement['token']='f'*32
    with pytest.raises(RuntimeErrorBase):provider.bind(value['id'],replacement)
    assert provider._actor(value['id'])==original and devices==[]


def test_original_fd_closed_after_retention_does_not_trigger_reopen(local):
    driver,_,value,state,devices,_,_=local;driver.apply(value['id'])
    devices[0].close();calls=state['calls'][:]
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert state['calls']==calls


def test_duplicate_provider_create_is_rejected_without_mutating_ioctl(local):
    driver,provider,value,state,_,_,_=local;ready=driver.apply(value['id']);calls=state['calls'][:]
    with pytest.raises(RuntimeErrorBase):provider.create(ready['items'][0],value['id'])
    assert not any(command in (TUNSETIFF,TUNSETIFINDEX,*COMMANDS) for command in state['calls'][len(calls):])


def test_birth_checkpoint_rechecks_host_before_create_ioctl(local,monkeypatch):
    driver,provider,value,state,_,_,_=local;save=provider._save
    def changed(current):
        save(current)
        if current['phase']=='create_requested':state['writer']=True
    monkeypatch.setattr(provider,'_save',changed)
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert TUNSETIFF not in state['calls'] and TUNSETIFINDEX not in state['calls']
    assert provider._read(value['items'][0]['spec']['tap']['nonce'])['phase']=='create_requested'


def test_malformed_birth_callback_is_not_committed(local,monkeypatch):
    driver,provider,value,state,_,_,_=local;record=provider._record
    def malformed(nonce,current):
        current=deepcopy(current);current['request_sha256']='f'*64
        record(nonce,current)
    monkeypatch.setattr(provider,'_record',malformed)
    with pytest.raises(RuntimeErrorBase,match='callback request'):driver.apply(value['id'])
    original=provider._read(value['items'][0]['spec']['tap']['nonce'])
    assert original['phase']=='opening' and original['records']==[] and TUNSETIFF not in state['calls']


def test_actor_identity_cannot_refer_to_another_process(local,monkeypatch):
    driver,provider,value,state,devices,_,_=local
    monkeypatch.setattr(provider,'process_id',lambda:9999)
    with pytest.raises(RuntimeErrorBase,match='process/context'):driver.apply(value['id'])
    assert devices==[] and TUNSETIFF not in state['calls']


def test_actor_and_creator_independently_protect_lost_vm_records(local):
    from dnlab_runtime.inspection import cleanup_inventory
    from test_vm_tap_reservations import native
    driver,_,value,_,_,_,_=local;driver.apply(value['id'])
    for table in ('vm_definition_intents','resources','vm_tap_intents','vm_tap_ifindices'):
        driver.journal.db.execute('DELETE FROM '+table)
    result=cleanup_inventory(driver.journal,value['birth']['lab_id'])
    assert result==dict(nodes=[value['birth']['node_id']],blocked=['vm_tap_actors','vm_tap_creators'])
    request=native();request.update(lab_id=value['birth']['lab_id'],node_id=value['birth']['node_id'])
    with pytest.raises(Conflict,match='reserved by VM'):driver.journal.submit(request)


def test_missing_original_creator_record_does_not_reopen_device(local):
    driver,_,value,state,devices,_,_=local;driver.apply(value['id'])
    driver.journal.db.execute('DELETE FROM vm_tap_creators WHERE id=?',(value['items'][0]['spec']['tap']['nonce'],))
    count=len(devices);calls=state['calls'][:]
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert len(devices)==count and state['calls']==calls
