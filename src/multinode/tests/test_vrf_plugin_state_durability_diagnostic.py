"""No-host fault injection at the next shared-provider persistence boundary.

No power loss or data loss is simulated; these tests check commit ordering and
whether a failed directory durability barrier can be acknowledged as success.
"""
import os
import stat

import pytest

from dnlab_multinode import vrf_plugin


def request():
    return dict(AddressSpace='dnlab-vrf-local',Pool='198.18.90.0/24',V6=False,Options={'dnlab.tenant':'durability-fixture'})


def test_provider_pool_ack_follows_file_replace_and_directory_fsync(tmp_path,monkeypatch):
    store=vrf_plugin.PluginStore(tmp_path/'state.json');events=[];sync=os.fsync;replace=os.replace
    def fsync(fd):
        events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
        return sync(fd)
    def replace_file(*args,**kwargs):events.append('replace');return replace(*args,**kwargs)
    monkeypatch.setattr(vrf_plugin.os,'fsync',fsync);monkeypatch.setattr(vrf_plugin.os,'replace',replace_file)
    result=store.request_pool(request());assert result['PoolID']
    assert events==['file','replace']+['directory']*(len(store.path.parent.parents)+1),'provider acknowledged pool without durable directory commit'


def test_provider_does_not_ack_pool_when_directory_fsync_fails(tmp_path,monkeypatch):
    store=vrf_plugin.PluginStore(tmp_path/'state.json');sync=os.fsync
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('injected directory fsync failure')
        return sync(fd)
    monkeypatch.setattr(vrf_plugin.os,'fsync',fsync)
    with pytest.raises(OSError,match='directory fsync failure'):store.request_pool(request())
