"""Tests for the DNS container service (non-SSH pure logic)."""

from unittest.mock import MagicMock

import pytest

from dnlab_multinode.services.dns import (
    compute_dns_mgmt_ip, deploy_dns, dns_container_name, hosts_file_path, _merge_entries,
)
from dnlab_multinode.services.hostsfile import HostEntry


def test_dns_container_name():
    assert dns_container_name("triangle") == "dnlab-triangle-dns"


def test_hosts_file_path():
    assert hosts_file_path("triangle") == "/tmp/dnlab-triangle-dns-hosts"


def test_compute_dns_mgmt_ip_slash24():
    """In a /24 the DNS gets .253 (penultimate usable)."""
    assert compute_dns_mgmt_ip("192.168.200.0/24") == "192.168.200.253"


def test_compute_dns_mgmt_ip_slash16():
    assert compute_dns_mgmt_ip("10.0.0.0/16") == "10.0.255.253"


def test_compute_dns_mgmt_ip_small_supported_subnet():
    assert compute_dns_mgmt_ip("10.0.0.0/29") == "10.0.0.5"


def test_compute_dns_mgmt_ip_too_small():
    """/30 has no room for Docker gateway, DNS, jumphost, and VDs."""
    with pytest.raises(ValueError):
        compute_dns_mgmt_ip("10.0.0.0/30")


def test_dns_ip_differs_from_jumphost():
    """DNS must not collide with the jumphost IP (.254 in /24)."""
    from dnlab_multinode.services.jumphost import _compute_jumphost_mgmt_ip
    subnet = "192.168.200.0/24"
    assert compute_dns_mgmt_ip(subnet) != _compute_jumphost_mgmt_ip(subnet)


def test_merge_entries_keeps_first_name_mapping():
    merged = _merge_entries(
        [HostEntry("R1", "172.20.0.11", "A")],
        [
            HostEntry("R1", "172.20.0.99", "A"),
            HostEntry("clab-dnlab-lab-R1-R1", "172.20.0.11", "A"),
        ],
    )

    by_name = {entry.name: entry.ip for entry in merged}
    assert by_name["R1"] == "172.20.0.11"
    assert by_name["clab-dnlab-lab-R1-R1"] == "172.20.0.11"


def test_deploy_dns_uses_jumphost_network_not_lab_mgmt(topo_factory, monkeypatch):
    topo = topo_factory(name="lab")
    master = MagicMock()

    def run_no_check(cmd, *_, **__):
        if "docker image inspect" in cmd:
            return 0, "", ""
        if "docker network inspect -f" in cmd and topo.jumphost_net.network in cmd:
            if ".IPAM.Config" in cmd:
                return 0, topo.jumphost_net.ipv4_subnet, ""
            if ".Containers" in cmd:
                return 0, "", ""
        if "docker inspect -f" in cmd:
            return 0, "true", ""
        return 0, "", ""

    def run(cmd, *_, **__):
        if "cat /etc/hosts" in cmd:
            return ""
        if "resolv.conf" in cmd:
            return "nameserver 8.8.8.8"
        return ""

    master.run_no_check.side_effect = run_no_check
    master.run.side_effect = run

    calls = []
    def guard(client, lab, action, config=None, content=None):
        calls.append((action, config, content))
        return {"phase": "absent" if action == "preflight" else "active"}
    monkeypatch.setattr("dnlab_multinode.services.dns._guard", guard)
    monkeypatch.setattr("dnlab_multinode.services.dns.ensure_jumphost_network", lambda *args: {"status": "active", "network_id": "a"*64})
    container, resolver_ip, upstream, entries = deploy_dns(
        topo, master, {"master": master},
        extra_entries=[HostEntry("R1", "172.20.0.11", "A")],
    )

    config = calls[-1][1]
    assert container == "dnlab-lab-dns"
    assert resolver_ip == "10.100.0.2"
    assert upstream == ["8.8.8.8"]
    assert entries == 1
    assert config["network"]["name"] == topo.jumphost_net.network
    assert config["network"]["name"] != topo.mgmt.network
