"""Legacy teardown must resolve long altnames without touching nearby resources."""
import copy
import json

import pytest

from dnlab_multinode.services.vxlan import _delete_vxlan_iface

ENDPOINT = 'rt-0123456789ab'
NAME = 'vx-' + ENDPOINT


def link(name='clab-12345678', *, kind='vxlan', vni=3001, index=20):
    return {'ifname': name, 'ifindex': index, 'altnames': [NAME],
            'linkinfo': {'info_kind': kind, 'info_data': {'id': vni}}}


class Client:
    def __init__(self, links, *, deletion_error=False, change=False):
        self.links = copy.deepcopy(links)
        self.deleted = []
        self.reads = 0
        self.deletion_error = deletion_error
        self.change = change

    def run(self, command):
        assert command == 'ip -j -d link show'
        self.reads += 1
        if self.change and self.reads == 2:
            self.links[0]['ifindex'] += 1
        return json.dumps(self.links)

    def run_no_check(self, command):
        self.deleted.append(command)
        if self.deletion_error:
            return 1, '', 'permission denied'
        self.links = [x for x in self.links if NAME not in x.get('altnames', []) and x['ifname'] != NAME]
        return 0, '', ''


def test_full_altname_preserves_truncated_collision_and_retry_is_idempotent():
    foreign = {'ifname': NAME[:15], 'ifindex': 21, 'linkinfo': {'info_kind': 'dummy'}}
    client = Client([link(), foreign])
    _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)
    _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)
    assert client.deleted == [f'ip link delete dev {NAME}']
    assert client.links == [foreign]


@pytest.mark.parametrize('record', [link(kind='dummy'), link(vni=3002)])
def test_foreign_type_or_vni_is_preserved(record):
    client = Client([record])
    with pytest.raises(RuntimeError, match='refusing'):
        _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)
    assert not client.deleted


def test_identity_replacement_is_preserved():
    client = Client([link()], change=True)
    with pytest.raises(RuntimeError, match='identity changed'):
        _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)
    assert not client.deleted


def test_delete_failure_is_reported():
    client = Client([link()], deletion_error=True)
    with pytest.raises(RuntimeError, match='incomplete.*permission denied'):
        _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)


def test_absent_is_idempotent():
    client = Client([])
    _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)
    assert not client.deleted


def test_short_primary_name_supported():
    client = Client([{'ifname': 'vx-short', 'ifindex': 30,
                     'linkinfo': {'info_kind': 'vxlan', 'info_data': {'id': 3001}}}])
    client.run_no_check = lambda cmd: (client.links.clear() or (0, '', ''))
    _delete_vxlan_iface(client, 'short', 'worker', vxlan_id=3001)


def test_conflicting_containerlab_owner_is_preserved():
    record = link()
    record['altnames'].append('clab-o-foreign')
    client = Client([record])
    with pytest.raises(RuntimeError, match='unexpected ownership'):
        _delete_vxlan_iface(client, ENDPOINT, 'worker', vxlan_id=3001)
    assert not client.deleted
