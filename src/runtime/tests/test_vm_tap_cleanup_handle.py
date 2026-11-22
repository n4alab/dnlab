"""New cleanup handles; original creator history, TUN and RTNL are synthetic."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_tap_cleanup_handle import TapCleanupHandle
from dnlab_runtime.vm_tap_device import IFREQ, TUNSETIFF, IFF_TUN_EXCL
from dnlab_runtime.vm_tap_retention import RetainedTapDevice, TUNSETPERSIST, PERSIST
from test_vm_tap_retention import retained as retained_fixture, kernel
from test_vm_tap_link_events import case as monitor_case, packet


@pytest.fixture
def cleanup(kernel, monitor_case, tmp_path):
    monitor, events = monitor_case
    source = retained_fixture.__wrapped__(kernel,tmp_path)
    retainer, creator, _, state, spec, factory = next(source)
    original = retainer.apply('retain')
    events['queue'].append(packet(name=spec['name'],index=spec['ifindex']))
    birth = monitor.birth(spec['name'],spec['ifindex'])
    creator.close()  # the persistent original remains; never restore this FD
    records, control = [], dict(qualified=True,fail=None,replace=False)
    def record(value):
        if value['phase'] == control['fail']:raise OSError('synthetic record failure')
        records.append(deepcopy(value))
    device = factory(RetainedTapDevice);device.record = record
    original_ioctl = device.ioctl
    def ioctl(fd, command, value=None):
        if command != TUNSETIFF:return original_ioctl(fd,command,value)
        name, flags = IFREQ.unpack(value);name = name.split(b'\0')[0].decode()
        assert not flags & IFF_TUN_EXCL and name == spec['name']
        state['calls'].append(command)
        assert not any(row['link'] is not None for other,row in state['fds'].items() if other != fd)
        link = state['links'][name]
        if control['replace']:
            link = deepcopy(link);state['links'][name] = link
            events['queue'] += [packet(kind=17,name=name,index=spec['ifindex']),packet(name=name,index=spec['ifindex'])]
        state['fds'][fd].update(index=spec['ifindex'],link=link,flags=flags | PERSIST)
        return value
    device.ioctl = ioctl
    original_close = device.close
    def close():
        before = spec['name'] in state['links'];original_close()
        if before and spec['name'] not in state['links']:
            events['queue'].append(packet(kind=17,name=spec['name'],index=spec['ifindex']))
    device.close = close
    retirement = 'd'*64
    def preflight():
        return dict(retirement_sha256=retirement,tap_birth_sha256=fingerprint(birth),
                    writers_absent=control['qualified'],remaining_resources_verified=True)
    handle = TapCleanupHandle(device,monitor,birth,original['retained_proof'],
                               retirement_sha256=retirement,preflight=preflight,record=record)
    try:
        yield handle,state,control,records,retainer,original,creator,events
    finally:
        device.close();source.close()


def test_separate_handle_removes_original_tap_without_rewriting_creator(cleanup):
    handle,state,control,records,retainer,original,creator,_ = cleanup
    receipt = handle.acquire()
    assert receipt['lease_token'] != creator._lease_token and creator._fd is None
    handle.unpersist();handle.close()
    proof = handle.confirm_absent()
    assert proof['absence_verified'] and proof['removal']['original_removal_verified']
    assert state['links'] == {} and retainer.read('retain') == original
    assert handle.confirm_absent() == proof
    assert handle.device._birth_proof is None  # an attachment is never a creator acknowledgement


def test_replacement_during_attachment_blocks_unpersist(cleanup):
    handle,state,control,_,_,_,_,_ = cleanup
    control['replace'] = True;before = state['calls'].count(TUNSETPERSIST)
    with pytest.raises(RuntimeErrorBase,match='removed, renamed or replaced'):handle.acquire()
    assert state['calls'].count(TUNSETPERSIST) == before


def test_missing_retired_domain_or_writer_proof_blocks_before_open(cleanup):
    handle,state,control,_,_,_,_,_ = cleanup
    control['qualified'] = False;before = state['calls'][:]
    with pytest.raises(RuntimeErrorBase,match='retired domain'):handle.acquire()
    assert handle.device._fd is None and state['calls'] == before


def test_applied_unpersist_reply_loss_observes_without_resend(cleanup):
    handle,state,_,_,_,_,_,_ = cleanup
    handle.acquire();state['lost_change'] = TUNSETPERSIST
    with pytest.raises(OSError):handle.unpersist()
    count = state['calls'].count(TUNSETPERSIST);state.pop('lost_change')
    handle.recover_unpersist();handle.close()
    assert handle.confirm_absent()['absence_verified']
    assert state['calls'].count(TUNSETPERSIST) == count


def test_unapplied_unpersist_is_preserved_without_resend(cleanup):
    handle,state,_,_,_,_,_,_ = cleanup
    handle.acquire();state['before_change'] = TUNSETPERSIST
    with pytest.raises(OSError):handle.unpersist()
    count = state['calls'].count(TUNSETPERSIST);state.pop('before_change')
    with pytest.raises(RuntimeErrorBase,match='no repeated ioctl'):handle.recover_unpersist()
    assert handle.device._fd is not None and state['calls'].count(TUNSETPERSIST) == count


@pytest.mark.parametrize('phase', ['cleanup_acquire_requested','cleanup_unpersist_requested','cleanup_close_requested'])
def test_failed_checkpoint_blocks_its_mutation(cleanup, phase):
    handle,state,control,_,_,_,_,_ = cleanup
    if phase != 'cleanup_acquire_requested':handle.acquire()
    if phase == 'cleanup_close_requested':handle.unpersist()
    mutations = lambda:[command for command in state['calls'] if command in (TUNSETIFF,TUNSETPERSIST)]
    before = mutations();fd = handle.device._fd;control['fail'] = phase
    with pytest.raises(OSError,match='record failure'):
        if phase == 'cleanup_acquire_requested':handle.acquire()
        elif phase == 'cleanup_unpersist_requested':handle.unpersist()
        else:handle.close()
    assert mutations() == before and handle.device._fd == fd
    assert (handle.device._fd is None) == (phase == 'cleanup_acquire_requested')


def test_lost_acquired_record_retains_same_handle_without_reattach(cleanup):
    handle,state,control,_,_,_,_,_ = cleanup
    control['fail'] = 'cleanup_acquired'
    with pytest.raises(OSError):handle.acquire()
    count = state['calls'].count(TUNSETIFF);control['fail'] = None
    assert handle.observe() == handle.retained
    with pytest.raises(RuntimeErrorBase,match='cannot be repeated'):handle.acquire()
    assert state['calls'].count(TUNSETIFF) == count


def test_lost_close_record_recovers_original_absence_without_second_close(cleanup):
    handle,_,control,_,_,_,_,_ = cleanup
    handle.acquire();handle.unpersist();control['fail'] = 'cleanup_closed'
    with pytest.raises(OSError):handle.close()
    control['fail'] = None
    assert handle.confirm_absent()['absence_verified']
    with pytest.raises(RuntimeErrorBase,match='single cleanup close'):handle.close()


def test_reoccupation_after_delete_is_not_qualified_as_original_absence(cleanup):
    handle,state,_,_,_,_,_,events = cleanup
    handle.acquire();handle.unpersist();handle.close()
    assert handle.confirm_absent()['absence_verified']
    events['queue'].append(packet(name=handle.birth['name'],index=handle.birth['ifindex']))
    with pytest.raises(RuntimeErrorBase,match='replacement'):handle.confirm_absent()


def test_writer_appearing_after_unpersist_checkpoint_blocks_ioctl(cleanup):
    handle,state,control,_,_,_,_,_ = cleanup
    handle.acquire();record = handle.record
    def changed(value):
        record(value)
        if value['phase'] == 'cleanup_unpersist_requested':control['qualified'] = False
    handle.record = changed
    before = state['calls'].count(TUNSETPERSIST)
    with pytest.raises(RuntimeErrorBase,match='retired domain'):handle.unpersist()
    assert state['calls'].count(TUNSETPERSIST) == before and handle.device._fd is not None
