"""Tests for per-VD runtime link reconciliation."""

import pytest

from dnlab_multinode.models.schedule import SchedulePlan, HostAssignment, CrossHostLink
from dnlab_multinode.models.state import RuntimeLinkState
from dnlab_multinode.models.topology import VDNode, Link, RealNet, RealNetLink
from dnlab_multinode.services import runtime_links


class FakeClient:
    def __init__(self):
        self.commands = []

    def run(self, cmd, check=True):
        self.commands.append((cmd, check))
        return ""


def test_build_runtime_links_same_cross_and_realnet(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="x"),
        "R2": VDNode(name="R2", kind="linux", image="x"),
        "R3": VDNode(name="R3", kind="linux", image="x"),
    }
    local = Link("R1", "eth1", "R2", "eth1")
    topo = topo_factory(nodes=nodes, links=[local], num_workers=1)
    topo.real_nets = {"access": RealNet(name="access", ipv4="192.0.2.1/24")}
    topo.real_net_links = [
        RealNetLink(
            real_net="access", node="R3", iface="eth1",
            host="worker1", bridge_iface="rn-R3-e1",
        )
    ]
    cross = CrossHostLink(
        vxlan_id=3001,
        source_node="R2", source_iface="eth2",
        target_node="R3", target_iface="eth2",
        source_host="master", target_host="worker1",
        source_host_iface="R2-e2-vx",
        target_host_iface="R3-e2-vx",
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.1", vd_names=["R1", "R2"]),
            "worker1": HostAssignment("worker1", "10.0.0.2", vd_names=["R3"]),
        },
        local_links=[local],
        cross_host_links=[cross],
    )

    links = runtime_links.build_runtime_links(topo, plan)

    assert [link.link_type for link in links] == ["same_host", "cross_host", "real_net"]
    assert links[0].host_a == "master"
    assert links[1].host_endpoint_a == "R2-e2-vx"
    assert links[1].vxlan_id == 3001
    assert links[2].host_endpoint_b.startswith("br")


def test_create_and_delete_same_host_link():
    client = FakeClient()
    link = RuntimeLinkState(
        id="l0",
        link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master",
        host_b="master",
        host_endpoint_a="rt-R1-e1-0",
        host_endpoint_b="rt-R2-e1-0",
    )

    runtime_links.create_link(link, {"master": client}, running_nodes={"R1", "R2"})
    runtime_links.delete_link(link, {"master": client})

    commands = [cmd for cmd, _ in client.commands]
    assert any("type bridge" in cmd for cmd in commands)
    assert any("iptables -C FORWARD -i br-rt-" in cmd for cmd in commands)
    assert any("iptables -C FORWARD -o br-rt-" in cmd for cmd in commands)
    assert any("master br-rt-" in cmd for cmd in commands)
    assert "tc qdisc add dev rt-R1-e1-0 clsact 2>/dev/null" in commands
    assert "tc qdisc add dev rt-R2-e1-0 clsact 2>/dev/null" in commands
    assert (
        "tc filter replace dev rt-R1-e1-0 ingress pref 49140 "
        "protocol 0x88cc flower action mirred egress redirect dev rt-R2-e1-0"
    ) in commands
    assert (
        "tc filter replace dev rt-R2-e1-0 ingress pref 49140 "
        "protocol 0x88cc flower action mirred egress redirect dev rt-R1-e1-0"
    ) in commands
    assert (
        "tc filter replace dev rt-R1-e1-0 ingress pref 49141 "
        "protocol 0x8809 flower action mirred egress redirect dev rt-R2-e1-0"
    ) in commands
    assert (
        "tc filter replace dev rt-R2-e1-0 ingress pref 49141 "
        "protocol 0x8809 flower action mirred egress redirect dev rt-R1-e1-0"
    ) in commands
    assert (
        "tc filter del dev rt-R1-e1-0 ingress pref 49140 "
        "protocol 0x88cc 2>/dev/null"
    ) in commands
    assert (
        "tc filter del dev rt-R2-e1-0 ingress pref 49141 "
        "protocol 0x8809 2>/dev/null"
    ) in commands
    assert "tc qdisc del dev rt-R1-e1-0 clsact 2>/dev/null" in commands
    assert "tc qdisc del dev rt-R2-e1-0 clsact 2>/dev/null" in commands
    assert any("iptables -D FORWARD -i br-rt-" in cmd for cmd in commands)
    assert any("iptables -D FORWARD -o br-rt-" in cmd for cmd in commands)
    assert any("ip link delete br-rt-" in cmd for cmd in commands)


def test_cross_host_link_uses_containerlab_vxlan_create_and_delete():
    left = FakeClient()
    right = FakeClient()
    link = RuntimeLinkState(
        id="vx0",
        link_type="cross_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="worker1",
        host_b="worker2",
        host_endpoint_a="R1-e1-vx",
        host_endpoint_b="R2-e1-vx",
        vxlan_id=3499,
    )

    runtime_links.create_link(
        link,
        {"worker1": left, "worker2": right},
        underlay_ips={"worker1": "10.0.0.1", "worker2": "10.0.0.2"},
        running_nodes={"R1", "R2"},
    )
    runtime_links.delete_link(link, {"worker1": left, "worker2": right})

    assert left.commands[0][0] == (
        "ip link show vx-R1-e1-vx >/dev/null 2>&1 || "
        "containerlab tools vxlan create --remote 10.0.0.2 "
        "--id 3499 --link R1-e1-vx"
    )
    assert right.commands[0][0] == (
        "ip link show vx-R2-e1-vx >/dev/null 2>&1 || "
        "containerlab tools vxlan create --remote 10.0.0.1 "
        "--id 3499 --link R2-e1-vx"
    )
    assert any("ip link delete vx-R1-e1-vx" in cmd for cmd, _ in left.commands)
    assert any("ip link delete vx-R2-e1-vx" in cmd for cmd, _ in right.commands)


def test_cross_host_link_keeps_full_containerlab_vxlan_altname():
    left = FakeClient()
    right = FakeClient()
    link = RuntimeLinkState(
        id="vx0",
        link_type="cross_host",
        endpoint_a={"node": "lab1", "iface": "eth2"},
        endpoint_b={"node": "host1", "iface": "eth1"},
        host_a="worker1",
        host_b="worker2",
        host_endpoint_a="vx9e3-lab1-e2",
        host_endpoint_b="vx9e3-host-e1",
        vxlan_id=3235,
    )

    runtime_links.create_link(
        link,
        {"worker1": left, "worker2": right},
        underlay_ips={"worker1": "10.0.0.1", "worker2": "10.0.0.2"},
        running_nodes={"lab1", "host1"},
    )
    runtime_links.delete_link(link, {"worker1": left, "worker2": right})

    assert left.commands[0][0].startswith("ip link show vx-vx9e3-lab1-e2 ")
    assert right.commands[0][0].startswith("ip link show vx-vx9e3-host-e1 ")
    assert any("ip link delete vx-vx9e3-lab1-e2" in cmd for cmd, _ in left.commands)
    assert any("ip link delete vx-vx9e3-host-e1" in cmd for cmd, _ in right.commands)


def test_create_link_marks_partial_if_peer_stopped():
    client = FakeClient()
    link = RuntimeLinkState(
        id="l0",
        link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master",
        host_b="master",
    )

    runtime_links.create_link(link, {"master": client}, running_nodes={"R1"})

    assert link.state == "partial"
    assert "R2" in link.last_error
    assert client.commands == []


def test_warm_carrier_is_enabled_after_host_attach_and_disabled_before_delete():
    client = FakeClient()
    link = RuntimeLinkState(
        id="l0",
        link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master",
        host_b="master",
        host_endpoint_a="wp-e1-left",
        host_endpoint_b="wp-e1-right",
        container_a="clab-dnlab-lab-R1-R1",
        warm_a=True,
    )

    runtime_links.create_link(link, {"master": client}, running_nodes={"R1", "R2"})
    commands = [cmd for cmd, _ in client.commands]
    carrier_up = commands.index(
        "docker exec clab-dnlab-lab-R1-R1 dnlab-linkctl eth1 up"
    )
    assert carrier_up > max(i for i, cmd in enumerate(commands) if " master br-rt-" in cmd)

    before_delete = len(client.commands)
    runtime_links.delete_link(link, {"master": client})
    delete_commands = [cmd for cmd, _ in client.commands[before_delete:]]
    assert delete_commands[0] == (
        "docker exec clab-dnlab-lab-R1-R1 dnlab-linkctl eth1 down"
    )
    assert any("ip link delete br-rt-" in cmd for cmd in delete_commands[1:])


def test_full_teardown_removes_warm_link_without_waiting_for_carrier():
    client = FakeClient()
    link = RuntimeLinkState(
        id="l0",
        link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master",
        host_b="master",
        host_endpoint_a="wp-e1-left",
        host_endpoint_b="wp-e1-right",
        container_a="clab-dnlab-lab-R1-R1",
        warm_a=True,
    )

    runtime_links.delete_link(
        link,
        {"master": client},
        set_carriers=False,
    )

    commands = [cmd for cmd, _ in client.commands]
    assert not any("dnlab-linkctl" in cmd for cmd in commands)
    assert "tc qdisc del dev wp-e1-left clsact 2>/dev/null" in commands
    assert "tc qdisc del dev wp-e1-right clsact 2>/dev/null" in commands
    assert any("iptables -D FORWARD -i br-rt-" in cmd for cmd in commands)
    assert any("ip link delete br-rt-" in cmd for cmd in commands)
    assert link.state == "down"


def test_warm_attach_failure_rolls_carrier_down_and_removes_bridge():
    class FailingClient(FakeClient):
        def run(self, cmd, check=True):
            super().run(cmd, check)
            if cmd.endswith("dnlab-linkctl eth1 up"):
                raise RuntimeError("carrier failed")
            return ""

    client = FailingClient()
    link = RuntimeLinkState(
        id="l0", link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master", host_b="master",
        host_endpoint_a="wp-e1-left", host_endpoint_b="wp-e1-right",
        container_a="clab-dnlab-lab-R1-R1", warm_a=True,
    )

    with pytest.raises(RuntimeError, match="carrier failed"):
        runtime_links.create_link(link, {"master": client}, running_nodes={"R1", "R2"})

    commands = [cmd for cmd, _ in client.commands]
    assert "docker exec clab-dnlab-lab-R1-R1 dnlab-linkctl eth1 down" in commands
    assert any("ip link delete br-rt-" in cmd for cmd in commands)


def test_warm_carrier_waits_for_link_controller_socket(monkeypatch):
    class StartingClient(FakeClient):
        attempts = 0

        def run(self, cmd, check=True):
            super().run(cmd, check)
            if cmd.endswith("dnlab-linkctl eth1 up"):
                self.attempts += 1
                if self.attempts < 3:
                    raise RuntimeError("stderr: ERROR [Errno 2] No such file or directory")
            return ""

    monkeypatch.setattr(runtime_links.time, "sleep", lambda _seconds: None)
    client = StartingClient()
    link = RuntimeLinkState(
        id="l0", link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master", host_b="master",
        host_endpoint_a="wp-left", host_endpoint_b="wp-right",
        container_a="clab-dnlab-lab-R1-R1", warm_a=True,
    )

    runtime_links.create_link(link, {"master": client}, running_nodes={"R1", "R2"})

    assert client.attempts == 3
    assert link.state == "up"


def test_initial_reconcile_can_defer_warm_carrier_until_guest_is_ready():
    client = FakeClient()
    link = RuntimeLinkState(
        id="l0", link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master", host_b="master",
        host_endpoint_a="wp-left", host_endpoint_b="wp-right",
        container_a="clab-lab-R1", warm_a=True,
    )

    runtime_links.reconcile_all_links(
        [link], {"master": client}, {}, {"R1", "R2"},
        defer_warm_carriers=True,
    )

    commands = [cmd for cmd, _ in client.commands]
    deferred = next(cmd for cmd in commands if "dnlab-linkctl eth1 up" in cmd)
    assert deferred.startswith("docker exec -d clab-lab-R1 sh -c ")
    assert "while [ ! -S /run/dnlab-link-control.sock ]" in deferred
    assert link.state == "up"


def test_cross_host_partial_attach_rolls_back_both_carriers_and_vxlans():
    class FailingPeer(FakeClient):
        def run(self, cmd, check=True):
            super().run(cmd, check)
            if "containerlab tools vxlan create" in cmd:
                raise RuntimeError("remote vxlan failed")
            return ""

    left = FakeClient()
    right = FailingPeer()
    link = RuntimeLinkState(
        id="vx0", link_type="cross_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="worker1", host_b="worker2",
        host_endpoint_a="wp-left", host_endpoint_b="wp-right",
        container_a="clab-lab-R1", container_b="clab-lab-R2",
        warm_a=True, warm_b=True, vxlan_id=3499,
    )

    with pytest.raises(RuntimeError, match="remote vxlan failed"):
        runtime_links.create_link(
            link,
            {"worker1": left, "worker2": right},
            underlay_ips={"worker1": "10.0.0.1", "worker2": "10.0.0.2"},
            running_nodes={"R1", "R2"},
        )

    left_commands = [cmd for cmd, _ in left.commands]
    right_commands = [cmd for cmd, _ in right.commands]
    assert "docker exec clab-lab-R1 dnlab-linkctl eth1 down" in left_commands
    assert "docker exec clab-lab-R2 dnlab-linkctl eth1 down" in right_commands
    assert any("ip link delete vx-wp-left" in cmd for cmd in left_commands)
    assert any("ip link delete vx-wp-right" in cmd for cmd in right_commands)


def test_node_stop_start_reconciles_warm_link_idempotently():
    client = FakeClient()
    link = RuntimeLinkState(
        id="l0", link_type="same_host",
        endpoint_a={"node": "R1", "iface": "eth1"},
        endpoint_b={"node": "R2", "iface": "eth1"},
        host_a="master", host_b="master",
        host_endpoint_a="wp-left", host_endpoint_b="wp-right",
        container_a="clab-lab-R1", container_b="clab-lab-R2",
        warm_a=True, warm_b=True,
    )

    runtime_links.reconcile_node_links(
        "R1", [link], {"master": client}, {}, {"R1", "R2"},
    )
    assert link.state == "up"
    runtime_links.delete_node_links("R1", [link], {"master": client})
    assert link.state == "down"
    commands_before_partial = len(client.commands)
    runtime_links.reconcile_node_links(
        "R1", [link], {"master": client}, {}, {"R2"},
    )
    assert link.state == "partial"
    assert len(client.commands) == commands_before_partial

    runtime_links.reconcile_node_links(
        "R1", [link], {"master": client}, {}, {"R1", "R2"},
    )
    assert link.state == "up"
    commands = [cmd for cmd, _ in client.commands]
    assert commands.count("docker exec clab-lab-R1 dnlab-linkctl eth1 up") == 2
    assert commands.count("docker exec clab-lab-R2 dnlab-linkctl eth1 up") == 2


def test_merge_runtime_links_preserves_existing_ids_when_link_order_changes(topo_factory):
    nodes = {
        name: VDNode(name=name, kind="linux", image="x")
        for name in ("R1", "R2", "R3")
    }
    first = Link("R1", "eth1", "R2", "eth1")
    second = Link("R2", "eth2", "R3", "eth1")
    topo = topo_factory(nodes=nodes, links=[first, second], num_workers=0)
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.1", vd_names=list(nodes)),
        },
        local_links=[first, second],
    )
    previous = runtime_links.build_runtime_links(topo, plan)
    previous[0].id = "l7"
    previous[0].host_endpoint_a = "stable-a"
    previous[0].host_endpoint_b = "stable-b"

    plan.local_links = [second, first]
    rebuilt = runtime_links.merge_runtime_links(
        runtime_links.build_runtime_links(topo, plan), previous,
    )
    by_key = {runtime_links.canonical_key(link): link for link in rebuilt}

    kept = by_key[runtime_links.canonical_key(previous[0])]
    assert kept.id == "l7"
    assert kept.host_endpoint_a == "stable-a"
    assert kept.host_endpoint_b == "stable-b"


def test_pending_runtime_link_is_kept_for_node_not_started(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="x"),
        "R2": VDNode(name="R2", kind="linux", image="x"),
    }
    topo = topo_factory(
        nodes=nodes, links=[Link("R1", "eth1", "R2", "eth2")], num_workers=0,
    )

    links = runtime_links.pending_runtime_links(topo, {"R1"})

    assert len(links) == 1
    assert links[0].link_type == "pending"
    assert links[0].state == "partial"
    assert "R2" in links[0].last_error
