"""Boot, handoff, original shutdown, undefine and TAP cleanup; effects inert."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition_retirement import StoppedDefinitionRetirement
from dnlab_runtime.vm_tap_device import IFREQ, TUNSETIFF, IFF_TUN_EXCL
from dnlab_runtime.vm_tap_handoff_retirement import VMTapHandoffRetirement
from dnlab_runtime.vm_tap_retention import PERSIST, TUNSETPERSIST
from test_vm_tap_handoff_shutdown import stopped, handed, local, kernel, definition, template, instance, monitor_case
from test_vm_tap_link_events import packet


@pytest.fixture
def cleanup(stopped, monkeypatch):
    s = stopped;e = s.e;definitions = e.handoff.definitions
    s.driver.prepare(s.id,e.operation,s.witness);shutdown = s.driver.apply(s.id,s.witness)
    domain = definitions.connection.lookupByUUIDString(s.running['birth']['uuid'])
    domain.autostart = lambda:0;domain.hasManagedSaveImage = lambda flags:0
    domain.snapshotNum = lambda flags:0;domain.checkpointCount = lambda:0
    connection = definitions.connection;old_uuid,old_name = connection.lookupByUUIDString,connection.lookupByName
    gone = []
    class Missing(Exception):
        def get_error_code(self):return 42
    def undefine(flags):
        assert flags == 0;gone.append(True);return 0
    domain.undefineFlags = undefine
    def uuid(value):
        if gone and value == domain.UUIDString():raise Missing()
        return old_uuid(value)
    def name(value):
        if gone and value == domain.name():raise Missing()
        return old_name(value)
    connection.lookupByUUIDString,connection.lookupByName = uuid,name
    def qualified(value):
        return dict(definition_sha256=fingerprint(s.running),session_sha256=value['session_sha256'],never_started=False,
                    shutdown_sha256=fingerprint(shutdown),writers_absent=True,resources_unchanged=True)
    retire = StoppedDefinitionRetirement(definitions,preflight=qualified)
    retire.prepare('retire-original',e.operation);receipt = retire.apply('retire-original')
    control = dict(storage=True,directory=True)
    def remaining(value):
        return dict(definition_sha256=value['definition']['request_fingerprint'],retirement_sha256=fingerprint(receipt),
                    storage_verified=control['storage'],directory_verified=control['directory'])
    factory = e.handoff.endpoints.device_factory
    def device_factory(spec,context,record):
        device = factory(spec,context,record);ioctl = device.ioctl;close = device.close
        def attach(fd,command,value=None):
            if command != TUNSETIFF:return ioctl(fd,command,value)
            name,flags = IFREQ.unpack(value);name = name.split(b'\0')[0].decode()
            assert not flags & IFF_TUN_EXCL and name == spec['name']
            assert not any(row['link'] is not None for other,row in e.state['fds'].items() if other != fd)
            e.state['calls'].append(command)
            e.state['fds'][fd].update(index=spec['ifindex'],link=e.state['links'][name],flags=flags|PERSIST)
            return value
        def closed():
            existed = spec['name'] in e.state['links'];close()
            if existed and spec['name'] not in e.state['links']:
                e.events['queue'].append(packet(kind=17,name=spec['name'],index=spec['ifindex']))
        device.ioctl,device.close = attach,closed
        return device
    e.handoff.endpoints.device_factory = device_factory
    def make():return VMTapHandoffRetirement(e.handoff,retire,preflight=remaining)
    driver = make();driver.prepare('remove-transferred',e.operation,'retire-original')
    yield driver,s,control,make


def test_whole_set_cleanup_preserves_original_births_and_handoff(cleanup):
    driver,s,control,make = cleanup;e = s.e
    handoff = deepcopy(e.handoff.read(e.operation));taps = deepcopy(e.taps.read(e.operation))
    creators = [deepcopy(e.handoff.endpoints._read(i['spec']['tap']['nonce'])) for i in taps['items']]
    result = driver.apply('remove-transferred')
    assert result['phase'] == 'removed' and result['proof']['all_taps_absent']
    assert e.state['links'] == {} and s.state['calls'] == 1
    assert e.handoff.read(e.operation) == handoff and e.taps.read(e.operation) == taps
    assert [e.handoff.endpoints._read(i['spec']['tap']['nonce']) for i in taps['items']] == creators
    assert make().apply('remove-transferred') == result
    assert e.state['calls'].count(TUNSETIFF) == 2 * len(taps['items'])
    assert e.state['calls'].count(TUNSETPERSIST) == 2 * len(taps['items'])


def test_last_tap_replacement_blocks_first_cleanup_acquisition(cleanup):
    driver,s,_,_ = cleanup;e = s.e
    name = e.taps.read(e.operation)['items'][-1]['spec']['tap']['name']
    e.state['links'][name]['address'] = '02:00:00:00:00:ab'
    before = e.state['calls'][:]
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-transferred')
    assert e.state['calls'] == before


def test_remaining_disk_conflict_preserves_all_taps(cleanup):
    driver,s,control,_ = cleanup;control['storage'] = False
    before = s.e.state['calls'][:]
    with pytest.raises(RuntimeErrorBase):driver.apply('remove-transferred')
    assert s.e.state['calls'] == before and s.e.state['links']


def test_applied_unpersist_reply_loss_recovers_without_second_ioctl(cleanup):
    driver,s,_,_ = cleanup;e = s.e
    e.state['lost_change'] = TUNSETPERSIST
    with pytest.raises(OSError):driver.apply('remove-transferred')
    count = e.state['calls'].count(TUNSETPERSIST);e.state.pop('lost_change')
    assert driver.apply('remove-transferred')['phase'] == 'removed'
    total = len(e.taps.read(e.operation)['items'])
    assert e.state['calls'].count(TUNSETPERSIST) == count + total - 1


def test_missing_live_cleanup_handle_never_reopens_from_saved_metadata(cleanup):
    driver,s,_,make = cleanup;e = s.e;e.state['before_change'] = TUNSETPERSIST
    with pytest.raises(OSError):driver.apply('remove-transferred')
    before = e.state['calls'][:]
    with pytest.raises(RuntimeErrorBase,match='no reopen'):make().apply('remove-transferred')
    assert e.state['calls'] == before


@pytest.mark.parametrize('phase',['cleanup_acquired','cleanup_closed'])
def test_lost_ack_publication_recovers_same_live_receipt_without_reattach(cleanup, monkeypatch, phase):
    driver,s,_,_ = cleanup;e = s.e;write = driver._write;failed = []
    def fail(value):
        records = value['items'][0]['creator']['cleanup']['records']
        if records and records[-1]['phase'] == phase and not failed:
            failed.append(True);raise OSError('synthetic cleanup publication failure')
        return write(value)
    monkeypatch.setattr(driver,'_write',fail)
    with pytest.raises(OSError,match='publication failure'):driver.apply('remove-transferred')
    assert driver.read('remove-transferred')['phase'] == 'removing'
    assert driver.apply('remove-transferred')['phase'] == 'removed'
    total = len(e.taps.read(e.operation)['items'])
    assert e.state['calls'].count(TUNSETIFF) == 2 * total
    assert e.state['calls'].count(TUNSETPERSIST) == 2 * total


def test_deleted_tap_reoccupation_is_rejected_without_new_cleanup_commands(cleanup):
    driver,s,_,_ = cleanup;e = s.e
    driver.apply('remove-transferred')
    tap = e.taps.read(e.operation)['items'][0]['spec']['tap']
    e.events['queue'].append(packet(name=tap['name'],index=tap['ifindex']))
    before = e.state['calls'][:]
    with pytest.raises(RuntimeErrorBase,match='replacement'):driver.apply('remove-transferred')
    assert e.state['calls'] == before


def test_absence_without_durable_cleanup_history_is_not_accepted(cleanup):
    from dnlab_runtime.manifest import canonical
    driver,s,_,_ = cleanup;e = s.e
    result = driver.apply('remove-transferred')
    result['items'][0]['creator']['cleanup'] = dict(lease_token=None,records=[])
    result['proof'] = driver._proof(result)
    with driver.journal.transaction():
        driver.journal.db.execute('UPDATE vm_tap_retirements SET payload=?,fingerprint=? WHERE id=?',
            (canonical(result),fingerprint(result),result['id']))
    before = e.state['calls'][:]
    with pytest.raises(RuntimeErrorBase,match='history does not prove'):driver.apply('remove-transferred')
    assert e.state['calls'] == before


def test_old_retirement_cannot_interpret_transferred_cleanup_mode(cleanup):
    from dnlab_runtime.vm_tap_retirement import VMTapRetirement
    driver,s,_,_ = cleanup;e = s.e
    old = VMTapRetirement(driver.taps,driver.retirement,preflight=driver.preflight)
    before = e.state['calls'][:]
    with pytest.raises(RuntimeErrorBase,match='creator changed'):old.apply('remove-transferred')
    assert e.state['calls'] == before
