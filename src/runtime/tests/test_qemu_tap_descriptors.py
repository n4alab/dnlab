"""Synthetic procfs with original pidfd verification; no process/TUN discovery."""
from copy import deepcopy
import os
import stat
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.qemu_tap_descriptors import QEMUTapDescriptors, tun_name
from test_qemu_process import process, observer, template, instance, closed


@pytest.fixture
def tap_process(process):
    pinned, record, state, root, _, boot, _ = process
    boot_id = '12345678-1234-4234-8234-123456789abc'
    boot.write_text(boot_id + '\n')
    record['process']['boot_id'] = boot_id
    pinned.record = deepcopy(record)
    (root / 'fdinfo').mkdir()
    (root / 'fd').mkdir()
    (root / 'fdinfo/5').write_bytes(b'pos:\t0\nflags:\t0100002\nmnt_id:\t1\nino:\t501\niff:\tdtp-one\n')
    scope = dict(boot_id=boot_id, **record['namespaces']['net'])
    state.update(checks=0, continuous=True, replace=False)
    def verify(names, context):
        state['checks'] += 1
        assert names == ['dtp-one'] and context == scope
        if state['replace'] and state['checks'] == 3:
            path = root / 'fdinfo/5'
            path.write_bytes(path.read_bytes().replace(b'0100002', b'0104002'))
        return dict(names=names, context_sha256=fingerprint(context), continuity_verified=state['continuous'])
    def descriptor(name, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_rdev=os.makedev(10, 200),
                               st_dev=8, st_ino=501)
    value = QEMUTapDescriptors(pinned, verify_links=verify, descriptor=descriptor)
    return value, scope, state, root, pinned


def test_one_original_tun_fd_is_observed_under_pinned_process(tap_process):
    value, scope, state, root, pinned = tap_process
    before = (root / 'fdinfo/5').read_bytes()
    proof = value.observe(['dtp-one'], scope)
    assert proof['process_record_sha256'] == fingerprint(pinned.record)
    assert [row['name'] for row in proof['descriptors']] == ['dtp-one']
    assert proof['descriptors'][0]['fd'] == 5
    assert state['checks'] == 5 and before == (root / 'fdinfo/5').read_bytes()
    closed(state)


@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'foreign', 'inode'])
def test_incomplete_or_foreign_descriptor_set_is_refused(tap_process, fault):
    value, scope, state, root, _ = tap_process
    path = root / 'fdinfo/5'
    if fault == 'missing':
        path.unlink()
    elif fault == 'duplicate':
        (root / 'fdinfo/6').write_bytes(path.read_bytes())
    else:
        path.write_bytes(path.read_bytes().replace(b'dtp-one', b'foreign') if fault == 'foreign'
                         else path.read_bytes().replace(b'501', b'502'))
    with pytest.raises(RuntimeErrorBase):
        value.observe(['dtp-one'], scope)
    closed(state)


def test_mutated_fdinfo_between_observations_is_not_accepted(tap_process):
    value, scope, state, _, _ = tap_process
    state['replace'] = True
    with pytest.raises(RuntimeErrorBase, match='between observations'):
        value.observe(['dtp-one'], scope)
    closed(state)


def test_lost_link_continuity_blocks_before_pidfd_or_proc_read(tap_process):
    value, scope, state, _, _ = tap_process
    state['continuous'] = False
    with pytest.raises(RuntimeErrorBase, match='continuity'):
        value.observe(['dtp-one'], scope)
    assert not state['fds']


def test_foreign_network_namespace_is_refused_before_pidfd(tap_process):
    value, scope, state, _, _ = tap_process
    scope['inode'] += 1
    with pytest.raises(RuntimeErrorBase, match='namespace or process'):
        value.observe(['dtp-one'], scope)
    assert not state['fds']


@pytest.mark.parametrize('raw', [b'iff:\tdtp-one\n', b'ino:\t1\niff:\tdtp-one',
                                b'ino:\t1\niff:\tone\niff:\ttwo\n', b'ino:\t1\niff:\t\n'])
def test_fdinfo_requires_complete_unambiguous_attached_name(raw):
    with pytest.raises(RuntimeErrorBase):
        tun_name(raw)
