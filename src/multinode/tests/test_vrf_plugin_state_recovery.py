"""Commit uncertainty fences the shared ledger, including no-op retries."""
import json
import os
import stat

import pytest

from dnlab_multinode import vrf_plugin as plugin
from tests.test_vrf_plugin import FakeNetworkOps, _network_request, _endpoint_request
from tests.test_vrf_plugin_state_durability_diagnostic import request


def fail_directory(monkeypatch):
    sync = os.fsync
    fault = {'enabled': True, 'calls': 0}
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            fault['calls'] += 1
            if fault['enabled']:
                raise OSError('directory unavailable')
        return sync(fd)
    monkeypatch.setattr(plugin.os, 'fsync', fsync)
    return fault


def test_uncertain_pool_blocks_other_lab_then_recovers_without_duplicate(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json')
    fault = fail_directory(monkeypatch)
    with pytest.raises(OSError):
        store.request_pool(request())
    committed = store.path.read_bytes()
    other = request(); other['Options'] = {'dnlab.tenant': 'another-lab'}
    with pytest.raises(OSError):
        store.request_pool(other)
    assert store.path.read_bytes() == committed
    fault['enabled'] = False
    original = store.request_pool(request())
    assert len(json.loads(store.path.read_bytes())['pools']) == 1
    assert store.request_pool(other)['PoolID'] != original['PoolID']
    assert store._uncertain is None


@pytest.mark.parametrize('change', ['malformed', 'other-valid-state', 'absent'])
def test_uncertain_commit_refuses_unexpected_state(tmp_path, monkeypatch, change):
    store = plugin.PluginStore(tmp_path / 'state.json')
    fault = fail_directory(monkeypatch)
    with pytest.raises(OSError):
        store.request_pool(request())
    if change == 'absent':
        store.path.unlink()
    else:
        store.path.write_text('{' if change == 'malformed' else json.dumps(
            dict(version=2, pools={}, networks={}, endpoints={})))
    before = store.path.read_bytes() if store.path.exists() else None
    fault['enabled'] = False
    with pytest.raises(plugin.PluginError, match='uncertain commit'):
        store.request_pool(request())
    assert (store.path.read_bytes() if store.path.exists() else None) == before
    assert store._uncertain is not None


@pytest.mark.parametrize('after_replace', [False, True])
def test_replace_failure_recovers_only_possible_outcome(tmp_path, monkeypatch, after_replace):
    store = plugin.PluginStore(tmp_path / 'state.json')
    replace = os.replace
    def interrupted(*args):
        if after_replace:
            replace(*args)
        raise OSError('replace interrupted')
    with monkeypatch.context() as patch:
        patch.setattr(plugin.os, 'replace', interrupted)
        with pytest.raises(OSError):
            store.request_pool(request())
    result = store.request_pool(request())
    assert result['PoolID']
    assert len(store._load()['pools']) == 1
    assert not list(tmp_path.glob('.state.json.*'))


def test_restart_reestablishes_barrier_even_for_existing_pool(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json')
    fault = fail_directory(monkeypatch)
    with pytest.raises(OSError):
        store.request_pool(request())
    restarted = plugin.PluginStore(store.path)
    with pytest.raises(OSError):
        restarted.request_pool(request())
    fault['enabled'] = False
    assert restarted.request_pool(request())['PoolID']


def test_duplicate_ip_remains_conflict_after_uncertain_commit(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json')
    pool = store.request_pool(request())['PoolID']
    allocation = {'PoolID': pool, 'Address': '198.18.90.2'}
    # Fail only the post-replace directory barrier, not the read preflight.
    sync = store._sync_directory
    calls = 0
    def fail_commit():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('commit uncertain')
        sync()
    with monkeypatch.context() as patch:
        patch.setattr(store, '_sync_directory', fail_commit)
        with pytest.raises(OSError):
            store.request_address(allocation)
    with pytest.raises(plugin.IPAMError, match='already allocated'):
        store.request_address(allocation)
    assert store._load()['pools'][pool]['allocated'] == ['198.18.90.2']


@pytest.mark.parametrize('kind', ['network', 'endpoint', 'release-pool'])
def test_noop_retry_and_delete_require_durable_recovery(tmp_path, monkeypatch, kind):
    store = plugin.PluginStore(tmp_path / 'state.json')
    ops = FakeNetworkOps()
    pool = store.request_pool(request())['PoolID']
    if kind == 'endpoint':
        store.create_network(_network_request('n1'), ops)
    def operation():
        if kind == 'network':
            return store.create_network(_network_request('n1'), ops)
        if kind == 'endpoint':
            return store.create_endpoint(_endpoint_request('n1', 'e1', '172.20.20.2/29'))
        return store.release_pool({'PoolID': pool})
    sync = store._sync_directory
    count = 0
    def fail_commit():
        nonlocal count
        count += 1
        if count >= 2:
            raise OSError('directory unavailable')
        sync()
    with monkeypatch.context() as patch:
        patch.setattr(store, '_sync_directory', fail_commit)
        with pytest.raises(OSError): operation()
        before = store.path.read_bytes()
        with pytest.raises(OSError): operation()
        assert store.path.read_bytes() == before
    assert operation() == {}
    assert store._uncertain is None


def test_kernel_mutation_blocked_while_state_uncertain(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json'); ops = FakeNetworkOps()
    store.create_network(_network_request('n1'), ops)
    store.create_endpoint(_endpoint_request('n1', 'e1', '172.20.20.2/29'))
    store.join({'NetworkID': 'n1', 'EndpointID': 'e1'}, ops)
    before = dict(ops.links)
    fault = fail_directory(monkeypatch)
    with pytest.raises(OSError): store.leave({'NetworkID': 'n1', 'EndpointID': 'e1'}, ops)
    assert ops.links == before
    fault['enabled'] = False
    store.leave({'NetworkID': 'n1', 'EndpointID': 'e1'}, ops)
    assert not ops.links


def test_changed_network_retry_is_not_adopted_after_recovery(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json'); ops = FakeNetworkOps()
    fault = fail_directory(monkeypatch)
    with pytest.raises(OSError): store.create_network(_network_request('n1'), ops)
    before = store.path.read_bytes(); fault['enabled'] = False
    with pytest.raises(plugin.NetworkDriverError, match='configuration changed'):
        store.create_network(_network_request('n1', bridge='foreign'), ops)
    assert store.path.read_bytes() == before


def test_new_state_directory_entry_is_synced_before_commit(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'new' / 'nested' / 'state.json')
    sync = os.fsync; seen = []
    def traced(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            seen.append(os.readlink(f'/proc/self/fd/{fd}'))
        sync(fd)
    monkeypatch.setattr(plugin.os, 'fsync', traced)
    store.request_pool(request())
    directory = store.path.parent
    assert seen == [str(directory)] + [str(parent) for parent in directory.parents]


def test_file_sync_failure_before_replace_preserves_previous_state(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json')
    store.request_pool(request()); before = store.path.read_bytes()
    sync = os.fsync; calls = 0
    def failed(fd):
        nonlocal calls
        if stat.S_ISREG(os.fstat(fd).st_mode):
            calls += 1
            if calls == 2: raise OSError('temporary file sync failed')
        sync(fd)
    other = request(); other['Options'] = {'dnlab.tenant': 'other'}
    with monkeypatch.context() as patch:
        patch.setattr(plugin.os, 'fsync', failed)
        with pytest.raises(OSError): store.request_pool(other)
    assert store.path.read_bytes() == before
    assert store.request_pool(other)['PoolID']
    assert len(store._load()['pools']) == 2


def test_noop_retry_refuses_failed_file_barrier(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json'); store.request_pool(request())
    before = store.path.read_bytes(); sync = os.fsync
    def failed(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode): raise OSError('ledger file sync failed')
        sync(fd)
    monkeypatch.setattr(plugin.os, 'fsync', failed)
    with pytest.raises(OSError, match='ledger file sync failed'): store.request_pool(request())
    assert store.path.read_bytes() == before


def test_recovery_rechecks_file_after_sync(tmp_path, monkeypatch):
    store = plugin.PluginStore(tmp_path / 'state.json')
    store.request_pool(request()); before = store.path.read_bytes()
    sync = store._sync_directory
    def changed():
        sync(); store.path.write_bytes(before + b' ')
    monkeypatch.setattr(store, '_sync_directory', changed)
    with pytest.raises(plugin.PluginError, match='changed during recovery'):
        store.request_pool(request())
    assert store.path.read_bytes() == before + b' '
