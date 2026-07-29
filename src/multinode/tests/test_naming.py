"""Tests for interface naming utilities."""

from dnlab_multinode.utils import naming


def test_shorten_iface_eth():
    assert naming.shorten_iface("eth1") == "e1"
    assert naming.shorten_iface("eth10") == "e10"


def test_shorten_iface_ge_xe():
    assert naming.shorten_iface("ge-0/0/0") == "g000"
    assert naming.shorten_iface("xe-0/0/1") == "x001"


def test_shorten_iface_ethernet():
    assert naming.shorten_iface("Ethernet1/10") == "E110"


def test_iface_name_max_15():
    """Host-side VxLAN interface must never exceed 15 chars."""
    cases = [
        ("R1", "eth1"),
        ("bigrouter42", "GigabitEthernet0/0/0/1"),
        ("verylongnodename", "Ethernet1/10"),
        ("x", "xe-0/0/0"),
    ]
    for node, iface in cases:
        name = naming.vxlan_host_iface("lab-alpha", node, iface)
        assert len(name) <= 15, f"{node}:{iface} → {name} ({len(name)} chars)"


def test_vxlan_host_iface_is_lab_scoped():
    """Identical VD/interface names in different labs must not collide."""
    first = naming.vxlan_host_iface("lab-alpha", "host2", "eth1")
    second = naming.vxlan_host_iface("lab-beta", "host2", "eth1")
    assert first != second
    assert len(first) <= 15
    assert len(second) <= 15


def test_mgmt_vxlan_iface_max_15():
    for lab in ["triangle", "x", "a-very-long-lab-name"]:
        assert len(naming.mgmt_vxlan_iface(lab)) <= 15


def test_mgmt_resource_names_distinguish_long_lab_names():
    first = "abcdefghijkl-first"
    second = "abcdefghijkl-second"

    assert naming.mgmt_network_name(first) != naming.mgmt_network_name(second)
    assert naming.mgmt_bridge_name(first) != naming.mgmt_bridge_name(second)
    assert naming.mgmt_vxlan_iface(first) != naming.mgmt_vxlan_iface(second)
    assert naming.vrf_name(first) != naming.vrf_name(second)


def test_ensure_unique_no_collision():
    names = ["a", "b", "c"]
    assert naming.ensure_unique(names) == ["a", "b", "c"]


def test_ensure_unique_with_collision():
    names = ["a", "b", "a", "a"]
    result = naming.ensure_unique(names)
    # All unique
    assert len(set(result)) == len(result)
    # All within 15 chars
    assert all(len(n) <= 15 for n in result)


def test_ensure_unique_per_node():
    """Same interface on different nodes should still be unique host-wide."""
    raw = [
        naming.vxlan_host_iface("lab-alpha", "R1", "eth1"),
        naming.vxlan_host_iface("lab-alpha", "R2", "eth1"),
    ]
    unique = naming.ensure_unique(raw)
    assert len(set(unique)) == 2


def test_runtime_relay_name():
    assert naming.runtime_relay_container_name("demo") == "dnlab-demo-runtime-relay"


def test_vd_container_name_matches_clab_convention():
    """Containerlab names VD containers as clab-<lab>-<node>."""
    assert naming.vd_container_name("demo", "NX1") == "clab-demo-NX1"
    assert naming.vd_container_name("triangle", "r1") == "clab-triangle-r1"


def test_micro_topology_names():
    assert naming.micro_topology_name("demo", "r1") == "dnlab-demo-r1"
    assert (
        naming.micro_vd_container_name("demo", "r1")
        == "clab-dnlab-demo-r1-r1"
    )
    assert (
        naming.micro_topology_file("demo", "r1", "worker1")
        == "/tmp/dnlab-demo-r1-worker1.clab.yml"
    )


def test_runtime_host_endpoint_max_15_and_deterministic():
    first = naming.runtime_host_endpoint("demo", "verylongnode", "Ethernet1/10", 12)
    second = naming.runtime_host_endpoint("demo", "verylongnode", "Ethernet1/10", 12)
    assert first == second
    assert len(first) <= 15


def test_sanitize_lab_name():
    assert naming.sanitize_lab_name("triangle") == "triangle"
    assert naming.sanitize_lab_name("Triangle") == "triangle"
    assert naming.sanitize_lab_name("my_lab") == "my-lab"
    assert naming.sanitize_lab_name("my lab!") == "my-lab"
    assert naming.sanitize_lab_name("--a--b--") == "a-b"
    assert naming.sanitize_lab_name("") == "lab"
    assert naming.sanitize_lab_name("___") == "lab"


def test_mgmt_network_name_length_and_determinism():
    for lab in ["a", "triangle", "hub-spoke", "a-very-long-lab-name", "MixedCase_42"]:
        net = naming.mgmt_network_name(lab)
        assert len(net) <= 12, f"{lab!r} → {net!r} ({len(net)} chars)"
        assert naming.mgmt_network_name(lab) == net  # deterministic
        # bridge-safe character set
        assert all(c.isalnum() or c == "-" for c in net)
        assert net == net.lower()


def test_mgmt_bridge_name_length_and_prefix():
    for lab in ["a", "triangle", "a-very-long-lab-name", "WEIRD name!!!"]:
        br = naming.mgmt_bridge_name(lab)
        assert len(br) <= 15, f"{lab!r} → {br!r} ({len(br)} chars)"
        assert br.startswith("br-")
        assert br == f"br-{naming.mgmt_network_name(lab)}"


def test_mgmt_names_truncate_at_boundary():
    # exactly 12 chars
    assert naming.mgmt_network_name("abcdefghijkl") == "abcdefghijkl"
    assert naming.mgmt_bridge_name("abcdefghijkl") == "br-abcdefghijkl"
    # Longer names retain a stable suffix instead of colliding by truncation.
    long_name = naming.mgmt_network_name("abcdefghijklm")
    assert len(long_name) == 12
    assert long_name.startswith("abcde-")
