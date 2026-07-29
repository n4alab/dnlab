"""Tests for deployment state persistence."""

from pathlib import Path

from dnlab_multinode.models.state import (
    DeploymentState, MgmtState, JumphostState, DnsState, HostScheduleState,
    VxlanLinkState, NodeRuntimeState, RuntimeLinkState, MgmtAnchorState,
    RuntimeRelayState,
)
from dnlab_multinode.services.state import (
    save_state, load_state, delete_state, state_file_path,
)


def _sample_state() -> DeploymentState:
    return DeploymentState(
        lab_name="triangle",
        topology_file="/tmp/triangle.yml",
        deployed_at="2026-01-01T00:00:00",
        vrf_table_id=100,
        mgmt=MgmtState(
            subnet="172.20.0.0/24", gateway="172.20.0.1",
            bridge="br-triangle", vrf="vrf-triangle",
            vxlan_id=2001, vxlan_iface="vx-triangle-m",
            network="triangle", network_driver="dnlab-vrf", ipam_driver="dnlab-vrf",
        ),
        jumphost=JumphostState(
            node="master", container="dnlab-triangle-jumphost",
            mgmt_ip="172.20.0.254", host_ip="192.168.100.1/24",
            ext_network="jh-triangle-ext", password="abcd1234EFGH",
            resolver="172.20.0.253",
        ),
        dns=DnsState(
            node="master", container="dnlab-triangle-dns",
            mgmt_ip="172.20.0.253",
            upstream=["192.168.1.1", "1.1.1.1"],
            hosts_file="/tmp/dnlab-triangle-dns-hosts",
            entries=5,
        ),
        scheduling={
            "master": HostScheduleState(
                host="10.0.0.10", topology_file="/tmp/t-master.yml",
                vd=["R1"], resources_used={"cpu": 2, "ram_mb": 4096},
            ),
        },
        vxlan_dataplane=[
            VxlanLinkState(
                id=3001, link="R1:e1 <-> R2:e1",
                side_a={"node": "master", "iface": "R1-e1-vx"},
                side_b={"node": "worker1", "iface": "R2-e1-vx"},
                status="up",
            ),
        ],
        phases_completed=["mgmt", "dnlab", "vxlan", "dns", "jumphost"],
    )


def test_save_and_load_roundtrip(tmp_path: Path):
    state = _sample_state()
    state.teardown_requested = True
    save_state(state, tmp_path)

    loaded = load_state("triangle", tmp_path)
    assert loaded is not None
    assert loaded.lab_name == state.lab_name
    assert loaded.vrf_table_id == state.vrf_table_id
    assert loaded.mgmt.subnet == state.mgmt.subnet
    assert loaded.mgmt.network == "triangle"
    assert loaded.mgmt.network_driver == "dnlab-vrf"
    assert loaded.mgmt.ipam_driver == "dnlab-vrf"
    assert loaded.jumphost.password == "abcd1234EFGH"
    assert loaded.jumphost.resolver == "172.20.0.253"
    assert loaded.dns is not None
    assert loaded.dns.mgmt_ip == "172.20.0.253"
    assert loaded.dns.upstream == ["192.168.1.1", "1.1.1.1"]
    assert loaded.dns.entries == 5
    assert "master" in loaded.scheduling
    assert loaded.scheduling["master"].vd == ["R1"]
    assert len(loaded.vxlan_dataplane) == 1
    assert loaded.vxlan_dataplane[0].id == 3001
    assert loaded.dnlab_deployed is True
    assert loaded.teardown_requested is True
    assert loaded.node_runtime["R1"].container == "clab-triangle-R1"
    assert loaded.node_runtime["R1"].state == "running"
    assert loaded.phases_completed == ["mgmt", "dnlab", "vxlan", "dns", "jumphost"]


def test_load_missing_returns_none(tmp_path: Path):
    assert load_state("nonexistent", tmp_path) is None


def test_delete_state(tmp_path: Path):
    state = _sample_state()
    save_state(state, tmp_path)
    path = state_file_path("triangle", tmp_path)
    assert path.exists()

    delete_state("triangle", tmp_path)
    assert not path.exists()


def test_state_file_naming():
    path = state_file_path("my-lab", Path("/tmp"))
    assert path.name == ".my-lab.multinode.json"


def test_teardown_order_from_phases():
    """phases_completed must preserve order for reverse teardown.

    Jumphost comes down first, then DNS (so the jumphost has a live resolver
    for its whole lifetime), then dnlab, vxlan, mgmt.
    """
    state = _sample_state()
    order = list(reversed(state.phases_completed))
    assert order == ["jumphost", "dns", "vxlan", "dnlab", "mgmt"]


def test_runtime_relay_roundtrip(tmp_path: Path):
    state = _sample_state()
    state.runtime_relays = {
        "worker1": RuntimeRelayState(
            host="worker1",
            container="dnlab-triangle-runtime-relay",
            bind_ip="10.0.0.11",
            port=23042,
            api_key="relay-secret",
            allowed=["clab-dnlab-triangle-R1-R1", "clab-dnlab-triangle-R2-R2"],
        ),
    }

    save_state(state, tmp_path)
    loaded = load_state("triangle", tmp_path)

    relay = loaded.runtime_relays["worker1"]
    assert relay.host == "worker1"
    assert relay.container == "dnlab-triangle-runtime-relay"
    assert relay.bind_ip == "10.0.0.11"
    assert relay.port == 23042
    assert relay.api_key == "relay-secret"
    assert relay.allowed == [
        "clab-dnlab-triangle-R1-R1", "clab-dnlab-triangle-R2-R2",
    ]


def test_node_runtime_and_runtime_links_roundtrip(tmp_path: Path):
    state = _sample_state()
    state.node_runtime = {
        "R1": NodeRuntimeState(
            node="R1",
            state="stopped",
            host="worker1",
            container="clab-dnlab-triangle-R1-R1",
            topology_file="/tmp/dnlab-triangle-R1-worker1.clab.yml",
            kind="linux",
            image="alpine",
            mgmt_ipv4="172.20.0.11",
            last_error="manual stop",
        ),
    }
    state.mgmt_ip_reservations = {
        "R1": "172.20.0.11",
        "removed-node": "172.20.0.12",
    }
    state.mgmt_anchors = {
        "worker1": MgmtAnchorState(
            host="worker1",
            container="clab-dnlab-triangle-mgmt-worker1-mgmt-anchor",
            topology_file="/tmp/dnlab-triangle-mgmt-worker1.clab.yml",
        ),
    }
    state.runtime_links = [
        RuntimeLinkState(
            id="R1:eth1--R2:eth1",
            link_type="cross_host",
            endpoint_a={"node": "R1", "iface": "eth1"},
            endpoint_b={"node": "R2", "iface": "eth1"},
            host_a="worker1",
            host_b="worker2",
            host_endpoint_a="rt-R1-e1-001",
            host_endpoint_b="rt-R2-e1-001",
            vxlan_id=3001,
            state="partial",
        ),
    ]

    save_state(state, tmp_path)
    loaded = load_state("triangle", tmp_path)

    assert loaded.node_runtime["R1"].state == "stopped"
    assert loaded.node_runtime["R1"].container == "clab-dnlab-triangle-R1-R1"
    assert loaded.mgmt_ip_reservations["removed-node"] == "172.20.0.12"
    assert loaded.mgmt_anchors["worker1"].container == (
        "clab-dnlab-triangle-mgmt-worker1-mgmt-anchor"
    )
    assert loaded.runtime_links[0].link_type == "cross_host"
    assert loaded.runtime_links[0].state == "partial"


def test_runtime_mode_is_inferred_for_pre_field_per_vd_state():
    state = DeploymentState.from_dict({
        "lab_name": "demo",
        "topology_file": "/tmp/demo.yml",
        "node_runtime": {
            "R1": {
                "node": "R1",
                "container": "clab-dnlab-demo-R1-R1",
            },
        },
    })

    assert state.runtime_mode == "per-vd"


def test_runtime_mode_is_conservative_for_legacy_state():
    state = DeploymentState.from_dict({
        "lab_name": "demo",
        "topology_file": "/tmp/demo.yml",
        "scheduling": {
            "master": {
                "host": "10.0.0.10",
                "topology_file": "/tmp/demo-master.yml",
                "vd": ["R1"],
                "resources_used": {},
            },
        },
    })

    assert state.runtime_mode == "legacy"
    assert state.teardown_requested is False
