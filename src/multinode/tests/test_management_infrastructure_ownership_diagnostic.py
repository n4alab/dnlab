"""No-host regressions for management infrastructure admission and cleanup."""
from unittest.mock import MagicMock

import pytest

from dnlab_multinode.services.netsetup import setup_mgmt_infra, teardown_mgmt_infra
from dnlab_multinode.utils import naming


class Host:
    def __init__(self):
        self.commands=[];self.links={};self.reject_add=False

    def run(self,command,*,check=True,**kwargs):
        self.commands.append(command)
        if command.startswith('ip link add ') and self.reject_add:
            if check:raise RuntimeError('kernel allocation refused')
            return ''
        if command.startswith('ip link delete '):
            self.links.pop(command.split()[3],None)
        return ''


def test_failed_first_allocation_does_not_continue_or_report_setup_complete(topo_factory):
    topo=topo_factory(name='demo',num_workers=0);host=Host();host.reject_add=True
    plan=MagicMock(vrf_table_id=42000,mgmt_vxlan_id=3000)
    with pytest.raises(RuntimeError):
        setup_mgmt_infra(topo,plan,host,'master',{'master':'192.0.2.10'})
    assert not any('type bridge' in command or 'type vxlan' in command or command.startswith('iptables') for command in host.commands)


def test_teardown_does_not_remove_foreign_bridge_with_matching_name(topo_factory):
    topo=topo_factory(name='demo',num_workers=0);host=Host()
    foreign={'ifname':topo.mgmt.bridge,'ifindex':87,'ifalias':'owned-by-other-lab','address':'02:ff:00:00:00:87'}
    host.links[topo.mgmt.bridge]=foreign.copy()
    try:
        with pytest.raises(RuntimeError):teardown_mgmt_infra(topo.name,topo.mgmt.bridge,host,'master')
    finally:
        assert host.links.get(topo.mgmt.bridge)==foreign,'foreign management bridge was removed solely by name'
