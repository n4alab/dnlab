import pytest
import yaml

from dnlab_multinode.services.config import (
    ConfigError, assign_sticky_mgmt_ipv4, parse_topology,
)


def _hosts_file(tmp_path):
    hosts = tmp_path / "hosts.yml"
    hosts.write_text("""
infrastructure:
  master:
    host: 10.0.0.10
    ssh_user: root
    ssh_key: ~/.ssh/id
  workers: {}
  underlay_iface: eth0
defaults:
  mgmt:
    ipv4_subnet: 172.20.20.0/24
    ipv4_gw: 172.20.20.1
""")
    return hosts


def _topology_file(tmp_path, name="lab", mgmt=None):
    data = {
        "name": name,
        "topology": {
            "nodes": {
                "r1": {"kind": "linux", "image": "alpine"},
            },
        },
    }
    if mgmt is not None:
        data["mgmt"] = mgmt
    topo = tmp_path / f"{name}.yml"
    topo.write_text(yaml.safe_dump(data))
    return topo


def _topology_file_with_node_mgmt(tmp_path, mgmt_ipv4):
    data = {
        "name": "lab",
        "mgmt": {"ipv4-subnet": "172.20.20.0/24"},
        "topology": {
            "nodes": {
                "r1": {
                    "kind": "linux",
                    "image": "alpine",
                    "mgmt-ipv4": mgmt_ipv4,
                },
            },
        },
    }
    topo = tmp_path / "reserved.yml"
    topo.write_text(yaml.safe_dump(data))
    return topo


def test_default_mgmt_subnet_does_not_move_for_cross_lab_overlap(tmp_path):
    topo = parse_topology(_topology_file(tmp_path), hosts_file=_hosts_file(tmp_path))

    assert topo.mgmt.ipv4_subnet == "172.20.20.0/24"
    assert topo.mgmt.docker_ipv4_gw == "172.20.20.1"
    assert topo.mgmt.ipv4_gw == "172.20.20.254"
    assert topo.mgmt.ipv6_subnet == "3fff:172:20:20::/64"
    assert topo.mgmt.ipv6_gw == "3fff:172:20:20:ffff:ffff:ffff:ffff"
    assert topo.mgmt.dhcp is False


def test_custom_mgmt_subnet_overlap_is_allowed(tmp_path):
    topo = parse_topology(
        _topology_file(tmp_path, mgmt={
            "ipv4-subnet": "172.20.20.0/24",
            "ipv4-gw": "172.20.20.1",
        }),
        hosts_file=_hosts_file(tmp_path),
    )

    assert topo.mgmt.ipv4_subnet == "172.20.20.0/24"


def test_custom_mgmt_subnet_uses_requested_subnet(tmp_path):
    topo = parse_topology(
        _topology_file(tmp_path, mgmt={
            "ipv4-subnet": "172.20.20.0/24",
            "ipv4-gw": "172.20.20.1",
        }),
        hosts_file=_hosts_file(tmp_path),
    )

    assert topo.mgmt.ipv4_subnet == "172.20.20.0/24"
    assert topo.mgmt.ipv4_gw == "172.20.20.254"


def test_sticky_mgmt_reservations_survive_node_set_changes(tmp_path):
    data = {
        "name": "lab",
        "mgmt": {"ipv4-subnet": "172.20.20.0/24"},
        "topology": {
            "nodes": {
                "aaa-new": {"kind": "linux", "image": "alpine"},
                "r1": {"kind": "linux", "image": "alpine"},
            },
        },
    }
    topo_file = tmp_path / "lab.yml"
    topo_file.write_text(yaml.safe_dump(data))

    topo = parse_topology(topo_file, hosts_file=_hosts_file(tmp_path))
    reservations = assign_sticky_mgmt_ipv4(
        topo.nodes,
        topo.mgmt,
        {
            "r1": "172.20.20.20",
            "removed-node": "172.20.20.21",
        },
    )

    assert topo.nodes["r1"].mgmt_ipv4 == "172.20.20.20"
    assert topo.nodes["aaa-new"].mgmt_ipv4 not in {
        "172.20.20.20",
        "172.20.20.21",
    }
    assert reservations["removed-node"] == "172.20.20.21"


def test_custom_ipv6_subnet_sets_last_address_as_gateway(tmp_path):
    topo = parse_topology(
        _topology_file(tmp_path, mgmt={
            "ipv4-subnet": "172.20.30.0/24",
            "ipv6-subnet": "2001:db8:30::/120",
        }),
        hosts_file=_hosts_file(tmp_path),
    )

    assert topo.mgmt.ipv6_subnet == "2001:db8:30::/120"
    assert topo.mgmt.ipv6_gw == "2001:db8:30::ff"


def test_legacy_ipv4_mapped_ipv6_subnet_is_normalized(tmp_path):
    topo = parse_topology(
        _topology_file(tmp_path, mgmt={
            "ipv4-subnet": "172.20.21.0/24",
            "ipv6-subnet": "::ffff:172.20.21.0/120",
            "ipv6-gw": "::ffff:172.20.21.255",
        }),
        hosts_file=_hosts_file(tmp_path),
    )

    assert topo.mgmt.ipv6_subnet == "3fff:172:20:21::/64"
    assert topo.mgmt.ipv6_gw == "3fff:172:20:21:ffff:ffff:ffff:ffff"


def test_legacy_node_mgmt_addressing_is_ignored_with_migration_warning(tmp_path, caplog):
    data = {
        "name": "lab",
        "topology": {"nodes": {"r1": {
            "kind": "linux", "image": "alpine", "mgmt-addressing": "dhcp",
        }}},
    }
    topology = tmp_path / "legacy.yml"
    topology.write_text(yaml.safe_dump(data))

    topo = parse_topology(topology, hosts_file=_hosts_file(tmp_path))

    assert "mgmt-addressing" not in topo.nodes["r1"].extra
    assert "mgmt-addressing is ignored" in caplog.text


def test_too_small_mgmt_subnet_raises(tmp_path):
    with pytest.raises(ConfigError, match="too small"):
        parse_topology(
            _topology_file(tmp_path, mgmt={"ipv4-subnet": "172.20.30.0/30"}),
            hosts_file=_hosts_file(tmp_path),
        )


def test_invalid_ipv6_subnet_raises(tmp_path):
    with pytest.raises(ConfigError, match="Invalid mgmt.ipv6-subnet"):
        parse_topology(
            _topology_file(tmp_path, mgmt={
                "ipv4-subnet": "172.20.30.0/24",
                "ipv6-subnet": "not-ipv6",
            }),
            hosts_file=_hosts_file(tmp_path),
        )


@pytest.mark.parametrize("ip", [
    "172.20.20.1",
    "172.20.20.252",
    "172.20.20.253",
    "172.20.20.254",
])
def test_explicit_node_mgmt_ip_cannot_use_reserved_addresses(tmp_path, ip):
    with pytest.raises(ConfigError, match="reserved"):
        parse_topology(
            _topology_file_with_node_mgmt(tmp_path, ip),
            hosts_file=_hosts_file(tmp_path),
        )
