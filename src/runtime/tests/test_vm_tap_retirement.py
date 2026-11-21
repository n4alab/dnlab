"""Original actor, descriptors and retention; SDK/kernel effects are synthetic."""
from copy import deepcopy

import pytest

from dnlab_runtime.backend_reservations import available
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition_retirement import UnstartedDefinitionRetirement
from dnlab_runtime.vm_tap_retention import TUNSETPERSIST
from dnlab_runtime.vm_tap_retirement import VMTapRetirement
from test_vm_tap_local import local, definition, template, instance, kernel


@pytest.fixture
def cleanup(local):
    taps,endpoints,value,state,devices,_,_ = local
    operation = value['id'];ready = taps.apply(operation);definitions = taps.definitions
    definitions.apply(operation)
    domain = definitions.connection.lookupByUUIDString(value['birth']['uuid'])
    domain.autostart = lambda:0;domain.hasManagedSaveImage = lambda flags:0
    domain.snapshotNum = lambda flags:0;domain.checkpointCount = lambda:0
    connection = definitions.connection
    original_lookup = connection.lookupByUUIDString
    def undefine(flags):
        assert flags == 0
        # The fake connection owns this closure; replace lookup results only
        # for the acknowledged original domain, without touching host libvirt.
        state['domain_absent'] = True
        return 0
    domain.undefineFlags = undefine
    class Missing(Exception):
        def get_error_code(self):return 42
    name_lookup = connection.lookupByName
    def lookup_uuid(uuid):
        if state.get('domain_absent') and uuid == value['birth']['uuid']:raise Missing()
        return original_lookup(uuid)
    def lookup_name(name):
        if state.get('domain_absent') and name == domain.name():raise Missing()
        return name_lookup(name)
    connection.lookupByUUIDString = lookup_uuid;connection.lookupByName = lookup_name
    def retired_preflight(current):
        assert taps.observe(operation) == ready
        return dict(definition_sha256=current.get('retirement',{}).get('definition_sha256',fingerprint(current)),
            session_sha256=current['session_sha256'],never_started=True,writers_absent=True,resources_unchanged=True)
    retire = UnstartedDefinitionRetirement(definitions,preflight=retired_preflight)
    retire.prepare('retire-domain',operation);receipt = retire.apply('retire-domain')
    state.update(storage=True,directory=True)
    def remaining(current):
        return dict(definition_sha256=ready['definition_sha256'],retirement_sha256=fingerprint(receipt),
                    storage_verified=state['storage'],directory_verified=state['directory'])
    def make():return VMTapRetirement(taps,retire,preflight=remaining)
    return make(),operation,taps,endpoints,state,devices,make,ready


def test_complete_release_uses_original_fds_and_preserves_birth_and_claims(cleanup):
    driver,operation,taps,endpoints,state,devices,make,ready = cleanup
    creators = [deepcopy(endpoints._read(item['spec']['tap']['nonce'])) for item in ready['items']]
    claims = [tuple(row) for row in driver.journal.db.execute('SELECT * FROM vm_tap_ifindices ORDER BY ifindex')]
    driver.prepare('remove-taps',operation,'retire-domain')
    result = driver.apply('remove-taps')
    assert result['phase'] == 'removed' and result['proof']['all_taps_absent'] is True
    assert all(device._fd is None for device in devices) and state['links'] == {}
    assert taps.read(operation) == ready
    assert [endpoints._read(item['spec']['tap']['nonce']) for item in ready['items']] == creators
    assert [tuple(row) for row in driver.journal.db.execute('SELECT * FROM vm_tap_ifindices ORDER BY ifindex')] == claims
    assert make().prepare('remove-taps',operation,'retire-domain') == result
    assert make().apply('remove-taps') == result
    assert state['calls'].count(TUNSETPERSIST) == 2*len(ready['items'])


def test_last_tap_replacement_prevents_first_release(cleanup):
    driver,operation,_,_,state,devices,_,ready = cleanup
    driver.prepare('remove-taps',operation,'retire-domain')
    state['links'][ready['items'][-1]['spec']['tap']['name']]['address'] = '02:00:00:00:00:aa'
    before = state['calls'].count(TUNSETPERSIST)
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-taps')
    assert state['calls'].count(TUNSETPERSIST) == before and all(device._fd is not None for device in devices)


def test_lost_release_reply_recovers_same_lease_without_second_ioctl(cleanup):
    driver,operation,_,_,state,_,make,ready = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');state['lost_change'] = TUNSETPERSIST
    with pytest.raises(OSError):driver.apply('remove-taps')
    assert driver.read('remove-taps')['items'][0]['phase'] == 'releasing'
    state.pop('lost_change')
    assert make().apply('remove-taps')['phase'] == 'removed'
    assert state['calls'].count(TUNSETPERSIST) == 2*len(ready['items'])


def test_unapplied_uncertain_release_is_never_repeated(cleanup):
    driver,operation,_,_,state,_,make,ready = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');state['before_change'] = TUNSETPERSIST
    with pytest.raises(OSError):driver.apply('remove-taps')
    count = state['calls'].count(TUNSETPERSIST);state.pop('before_change')
    with pytest.raises(RuntimeErrorBase,match='no resend'):make().apply('remove-taps')
    assert state['calls'].count(TUNSETPERSIST) == count and len(state['links']) == len(ready['items'])


def test_partial_removal_recovers_without_reopening_closed_devices(cleanup,monkeypatch):
    driver,operation,_,_,state,devices,make,_ = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');advance = driver._advance
    def change(value,child=None,**changes):
        advance(value,child,**changes)
        if child is not None and changes.get('phase') == 'absent':state['storage'] = False
    monkeypatch.setattr(driver,'_advance',change)
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-taps')
    assert devices[0]._fd is None and devices[1]._fd is not None
    state['storage'] = True
    assert make().apply('remove-taps')['phase'] == 'removed'


def test_lost_close_result_observes_absence_without_second_close(cleanup,monkeypatch):
    driver,operation,_,_,_,devices,make,_ = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');close = devices[0].close;calls = []
    def lost():
        calls.append(True);close();raise OSError('lost original close result')
    with monkeypatch.context() as patch:
        patch.setattr(devices[0],'close',lost)
        with pytest.raises(OSError,match='lost original close'):driver.apply('remove-taps')
    assert driver.read('remove-taps')['items'][0]['phase'] == 'close_requested'
    assert devices[0]._fd is None and len(calls) == 1
    assert make().apply('remove-taps')['phase'] == 'removed' and len(calls) == 1


def test_checkpoint_conflict_prevents_first_release_ioctl(cleanup,monkeypatch):
    driver,operation,_,_,state,_,_,_ = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');write = driver._write
    def change(value):
        write(value)
        if value['items'][0]['phase'] == 'releasing':state['storage'] = False
    monkeypatch.setattr(driver,'_write',change);before = state['calls'].count(TUNSETPERSIST)
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-taps')
    assert state['calls'].count(TUNSETPERSIST) == before
    assert driver.read('remove-taps')['items'][0]['phase'] == 'prepared'


@pytest.mark.parametrize('fault',['actor','lease','context','storage'])
def test_changed_dependencies_prevent_release(cleanup,fault):
    driver,operation,_,_,state,devices,_,_ = cleanup
    driver.prepare('remove-taps',operation,'retire-domain')
    if fault == 'actor':state['actor_alive'] = False
    elif fault == 'lease':devices[0]._lease_token = 'f'*32
    elif fault == 'context':state['scope']['inode'] += 1
    else:state['storage'] = False
    before = state['calls'].count(TUNSETPERSIST)
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-taps')
    assert state['calls'].count(TUNSETPERSIST) == before


def test_reappeared_foreign_name_is_preserved_after_close(cleanup,monkeypatch):
    driver,operation,_,_,state,devices,_,ready = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');close = devices[0].close
    name = ready['items'][0]['spec']['tap']['name']
    def change():
        close();state['links'][name] = dict(ifname=name,ifindex=999,foreign=True)
    monkeypatch.setattr(devices[0],'close',change)
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-taps')
    assert driver.read('remove-taps')['items'][0]['phase'] == 'close_requested'
    assert state['links'][name]['foreign'] and devices[1]._fd is not None


def test_retirement_keeps_backend_and_cleanup_fenced_without_other_intents(cleanup):
    driver,operation,_,_,_,_,_,ready = cleanup
    driver.prepare('remove-taps',operation,'retire-domain');driver.apply('remove-taps')
    with driver.journal.transaction():
        for table in ('vm_definition_intents','vm_definition_retirements','vm_tap_intents','vm_tap_ifindices',
                      'vm_tap_actors','vm_tap_creators'):
            driver.journal.db.execute('DELETE FROM '+table)
    birth = ready['birth']
    with pytest.raises(Conflict):available(driver.journal,birth['lab_id'],birth['node_id'],'docker')
    assert 'vm_tap_retirements' in cleanup_inventory(driver.journal,birth['lab_id'])['blocked']
