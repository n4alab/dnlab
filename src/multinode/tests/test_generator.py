"""Tests for per-host topology file generation."""

import yaml

from dnlab_multinode.models.topology import VDNode, Link, RealNet, RealNetLink
from dnlab_multinode.models.schedule import (
    SchedulePlan, HostAssignment, CrossHostLink,
)
from dnlab_multinode.services.generator import (
    generate_topology_files,
    generate_micro_topology_files,
    generate_mgmt_anchor_topology_files,
    _needs_persist_bind,
    render_node_feature_files,
)


def _plan_single_host(topo, host_name, vd_names, local_links=None):
    return SchedulePlan(
        lab_name=topo.name,
        assignments={
            host_name: HostAssignment(
                host_name=host_name, host_ip="10.0.0.10",
                vd_names=vd_names,
            ),
        },
        local_links=local_links or [],
    )


def test_generate_produces_yaml(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="alpine"),
        "R2": VDNode(name="R2", kind="linux", image="alpine"),
    }
    links = [Link("R1", "eth1", "R2", "eth1")]
    topo = topo_factory(nodes=nodes, links=links, num_workers=0)

    plan = _plan_single_host(topo, "master", ["R1", "R2"], local_links=links)
    files = generate_topology_files(topo, plan)

    assert "master" in files
    parsed = yaml.safe_load(files["master"])
    assert parsed["name"] == topo.name
    assert "R1" in parsed["topology"]["nodes"]
    assert "R2" in parsed["topology"]["nodes"]


def test_local_link_preserved(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="x"),
        "R2": VDNode(name="R2", kind="linux", image="x"),
    }
    links = [Link("R1", "eth1", "R2", "eth1")]
    topo = topo_factory(nodes=nodes, links=links, num_workers=0)

    plan = _plan_single_host(topo, "master", ["R1", "R2"], local_links=links)
    files = generate_topology_files(topo, plan)
    parsed = yaml.safe_load(files["master"])

    links_out = parsed["topology"]["links"]
    assert len(links_out) == 1
    eps = links_out[0]["endpoints"]
    assert "R1:eth1" in eps
    assert "R2:eth1" in eps


def test_crosshost_link_terminated_on_host(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="x"),
        "R2": VDNode(name="R2", kind="linux", image="x"),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=1)

    cl = CrossHostLink(
        vxlan_id=3000,
        source_node="R1", source_iface="eth1",
        target_node="R2", target_iface="eth1",
        source_host="master", target_host="worker1",
        source_host_iface="R1-e1-vx",
        target_host_iface="R2-e1-vx",
    )

    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master":  HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
        },
        cross_host_links=[cl],
    )

    files = generate_topology_files(topo, plan)
    master_yaml = yaml.safe_load(files["master"])
    worker_yaml = yaml.safe_load(files["worker1"])

    master_ep = master_yaml["topology"]["links"][0]["endpoints"]
    assert "R1:eth1" in master_ep
    assert "host:R1-e1-vx" in master_ep

    worker_ep = worker_yaml["topology"]["links"][0]["endpoints"]
    assert "R2:eth1" in worker_ep
    assert "host:R2-e1-vx" in worker_ep


def test_mgmt_section_injected(topo_factory):
    nodes = {"R1": VDNode(name="R1", kind="linux", image="x")}
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)

    plan = _plan_single_host(topo, "master", ["R1"])
    files = generate_topology_files(topo, plan)
    parsed = yaml.safe_load(files["master"])

    assert "mgmt" in parsed
    assert parsed["mgmt"] == {
        "network": topo.mgmt.network,
        "bridge": topo.mgmt.bridge,
        "ipv4-subnet": topo.mgmt.ipv4_subnet,
        "ipv4-gw": topo.mgmt.docker_ipv4_gw or topo.mgmt.ipv4_gw,
        "external-access": False,
    }
    assert "driver-opts" not in parsed["mgmt"]


def test_persist_bind_requires_dnlab_suffix(topo_factory):
    nodes = {
        "raw": VDNode(name="raw", kind="linux", image="vrnetlab/cisco_xrv9k:25.2.2"),
        "patched": VDNode(
            name="patched",
            kind="linux",
            image="quay.io/frrouting/frr:10.2.6-dnlab",
        ),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)

    plan = _plan_single_host(topo, "master", ["raw", "patched"])
    parsed = yaml.safe_load(generate_topology_files(topo, plan)["master"])

    raw_node = parsed["topology"]["nodes"]["raw"]
    patched_node = parsed["topology"]["nodes"]["patched"]

    assert "binds" not in raw_node
    assert any(bind.endswith(":/persist") for bind in patched_node["binds"])


def test_persist_bind_uses_stable_persist_id(topo_factory):
    nodes = {
        "renamed": VDNode(
            name="renamed",
            kind="linux",
            image="quay.io/frrouting/frr:10.2.6-dnlab",
            persist_id="f0ef9a68-3eb9-4b89-bb8d-4f5afbc33591",
        ),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)

    plan = _plan_single_host(topo, "master", ["renamed"])
    parsed = yaml.safe_load(generate_topology_files(topo, plan)["master"])

    binds = parsed["topology"]["nodes"]["renamed"]["binds"]
    assert (
        "/var/lib/docker/dnlab-backups/lab/"
        "f0ef9a68-3eb9-4b89-bb8d-4f5afbc33591:/persist"
    ) in binds


def test_needs_persist_bind_uses_image_tag_suffix():
    assert _needs_persist_bind("vrnetlab/cisco_n9kv_v2:10.5-dnlab")
    assert _needs_persist_bind("vrnetlab/n4alab_flinos:1.2.3-dnlab")
    assert _needs_persist_bind("quay.io/frrouting/frr:10.2.6-dnlab")
    assert _needs_persist_bind("vrnetlab/dnlab_frr:10.6.1")
    assert _needs_persist_bind("registry.example/dnlab_custom:latest")
    assert not _needs_persist_bind("vrnetlab/cisco_n9kv_v2:10.5")
    assert not _needs_persist_bind("quay.io/frrouting/frr:10.2.6")


def test_render_node_feature_persist_bool_file(topo_factory):
    nodes = {
        "R1": VDNode(
            name="R1",
            kind="linux",
            image="quay.io/frrouting/frr:10.2.6-dnlab",
            persist_id="stable-r1",
        ),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)
    topo.node_features = {
        "R1": {
            "frr_daemons": {
                "state": {"bgpd": False, "ospfd": True},
                "materialize": {
                    "type": "persist-key-value-bool-file",
                    "path": "frr/daemons",
                    "true": "yes",
                    "false": "no",
                },
            },
        },
    }

    files = render_node_feature_files(topo, "R1")

    assert files == {
        "/var/lib/docker/dnlab-backups/lab/stable-r1/frr/daemons": "bgpd=no\nospfd=yes\n",
    }


def test_vm_guest_dhcp_flag_is_preserved_and_runtime_identity_is_stable(topo_factory):
    node = VDNode(
        name="R1", kind="linux", image="vrnetlab/example:latest",
        mgmt_ipv4="172.20.0.11", mgmt_ipv6="2001:db8::11",
        mgmt_mac="02:00:00:00:00:11", mgmt_duid="0001000112345678",
        mgmt_iaid="305419896", env={"CLAB_MGMT_DHCP": "true"},
    )
    topo = topo_factory(nodes={"R1": node}, links=[], num_workers=0)
    plan = _plan_single_host(topo, "master", ["R1"])

    for enabled in (False, True):
        topo.mgmt.dhcp = enabled
        rendered = yaml.safe_load(generate_topology_files(topo, plan)["master"])
        env = rendered["topology"]["nodes"]["R1"]["env"]
        assert env["CLAB_MGMT_DHCP"] == "true"
        assert env["CLAB_MGMT_PASSTHROUGH"] == "true"
        assert env["CLAB_MGMT_MAC"] == "02:00:00:00:00:11"
        assert env["CLAB_MGMT_DUID"] == "0001000112345678"
        assert env["CLAB_MGMT_IAID"] == "305419896"


def test_endpoints_flow_style_in_text(topo_factory):
    """Endpoints should be emitted in YAML flow style (one-liner)."""
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="x"),
        "R2": VDNode(name="R2", kind="linux", image="x"),
    }
    links = [Link("R1", "Ethernet1/10", "R2", "Ethernet1/10")]
    topo = topo_factory(nodes=nodes, links=links, num_workers=0)

    plan = _plan_single_host(topo, "master", ["R1", "R2"], local_links=links)
    text = generate_topology_files(topo, plan)["master"]

    # Look for the flow-style marker on the endpoints line
    assert "endpoints: [" in text


def test_realnet_link_materializes_bridge_node(topo_factory):
    nodes = {"R1": VDNode(name="R1", kind="linux", image="x")}
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)
    topo.real_nets = {
        "real_net1": RealNet(name="real_net1", ipv4="192.168.50.1/24")
    }
    topo.real_net_links = [
        RealNetLink(
            real_net="real_net1", node="R1", iface="eth1",
            host="master", bridge_iface="rn-R1-e1",
        )
    ]

    plan = _plan_single_host(topo, "master", ["R1"])
    files = generate_topology_files(topo, plan)
    parsed = yaml.safe_load(files["master"])

    bridge_nodes = [
        name for name, cfg in parsed["topology"]["nodes"].items()
        if cfg.get("kind") == "bridge"
    ]
    assert bridge_nodes
    eps = parsed["topology"]["links"][0]["endpoints"]
    assert "R1:eth1" in eps
    assert any(ep.startswith(f"{bridge_nodes[0]}:") for ep in eps)


def test_micro_topologies_split_local_link_to_host_endpoints(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="alpine:3"),
        "R2": VDNode(name="R2", kind="linux", image="alpine:3"),
    }
    links = [Link("R1", "eth1", "R2", "eth1")]
    topo = topo_factory(nodes=nodes, links=links, num_workers=0)
    plan = _plan_single_host(topo, "master", ["R1", "R2"], local_links=links)

    files = generate_micro_topology_files(topo, plan)

    assert set(files["master"]) == {"R1", "R2"}
    r1 = yaml.safe_load(files["master"]["R1"])
    r2 = yaml.safe_load(files["master"]["R2"])

    assert r1["name"] == "dnlab-lab-R1"
    assert list(r1["topology"]["nodes"]) == ["R1"]
    assert list(r2["topology"]["nodes"]) == ["R2"]

    r1_eps = r1["topology"]["links"][0]["endpoints"]
    r2_eps = r2["topology"]["links"][0]["endpoints"]
    assert "R1:eth1" in r1_eps
    assert any(ep.startswith("host:") for ep in r1_eps)
    assert "R2:eth1" in r2_eps
    assert any(ep.startswith("host:") for ep in r2_eps)
    assert "R2:eth1" not in r1_eps
    assert "R1:eth1" not in r2_eps
    expected_mgmt = {
        "network": topo.mgmt.network,
        "bridge": topo.mgmt.bridge,
        "ipv4-subnet": topo.mgmt.ipv4_subnet,
        "ipv4-gw": topo.mgmt.docker_ipv4_gw or topo.mgmt.ipv4_gw,
        "external-access": False,
    }
    assert r1["mgmt"] == expected_mgmt
    assert r2["mgmt"] == expected_mgmt


def test_mgmt_anchor_topology_uses_precreated_mgmt_network(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="alpine:3"),
        "R2": VDNode(name="R2", kind="linux", image="alpine:3"),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=1)
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
        },
    )

    anchors = generate_mgmt_anchor_topology_files(topo, plan)

    assert set(anchors) == {"master", "worker1"}
    parsed = yaml.safe_load(anchors["master"])
    assert parsed["name"] == "dnlab-lab-mgmt-master"
    assert parsed["mgmt"] == {
        "network": topo.mgmt.network,
        "bridge": topo.mgmt.bridge,
        "ipv4-subnet": topo.mgmt.ipv4_subnet,
        "ipv4-gw": topo.mgmt.docker_ipv4_gw or topo.mgmt.ipv4_gw,
        "external-access": False,
    }
    node = parsed["topology"]["nodes"]["mgmt-anchor"]
    assert node["kind"] == "linux"
    assert node["image"] == "dnlab-mgmt-anchor:latest"
    assert node["mgmt-ipv4"] == "172.20.0.252"
    assert node["env"]["CLAB_MGMT_PASSTHROUGH"] == "true"


def test_mgmt_anchor_topology_is_per_active_host_not_per_vd(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="alpine:3"),
        "R2": VDNode(name="R2", kind="linux", image="alpine:3"),
        "R3": VDNode(name="R3", kind="linux", image="alpine:3"),
        "R4": VDNode(name="R4", kind="linux", image="alpine:3"),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=2)
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
            "worker2": HostAssignment("worker2", "10.0.0.12", vd_names=["R3", "R4"]),
        },
    )

    anchors = generate_mgmt_anchor_topology_files(topo, plan)

    assert set(anchors) == {"master", "worker1", "worker2"}
    assert len(anchors) == 3
    assert yaml.safe_load(anchors["worker2"])["name"] == "dnlab-lab-mgmt-worker2"


def test_micro_topologies_preserve_node_details(topo_factory):
    nodes = {
        "R1": VDNode(
            name="R1",
            kind="linux",
            image="quay.io/frrouting/frr:10.2.6-dnlab",
            mgmt_ipv4="172.20.0.11",
            env={"FOO": "bar"},
            extra={"ports": ["8443:443/tcp"]},
        ),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)
    plan = _plan_single_host(topo, "master", ["R1"])

    parsed = yaml.safe_load(generate_micro_topology_files(topo, plan)["master"]["R1"])
    node = parsed["topology"]["nodes"]["R1"]

    assert node["kind"] == "linux"
    assert node["mgmt-ipv4"] == "172.20.0.11"
    assert node["env"] == {"FOO": "bar"}
    assert "8443:443/tcp" in node["ports"]
    assert any(bind.endswith(":/persist") for bind in node["binds"])


def test_micro_crosshost_link_uses_vxlan_host_ifaces(topo_factory):
    nodes = {
        "R1": VDNode(name="R1", kind="linux", image="x"),
        "R2": VDNode(name="R2", kind="linux", image="x"),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=1)
    cl = CrossHostLink(
        vxlan_id=3000,
        source_node="R1", source_iface="eth1",
        target_node="R2", target_iface="eth1",
        source_host="master", target_host="worker1",
        source_host_iface="R1-e1-vx",
        target_host_iface="R2-e1-vx",
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
        },
        cross_host_links=[cl],
    )

    files = generate_micro_topology_files(topo, plan)
    r1 = yaml.safe_load(files["master"]["R1"])
    r2 = yaml.safe_load(files["worker1"]["R2"])

    assert r1["topology"]["links"][0]["endpoints"] == ["R1:eth1", "host:R1-e1-vx"]
    assert r2["topology"]["links"][0]["endpoints"] == ["R2:eth1", "host:R2-e1-vx"]


def test_micro_realnet_link_uses_host_endpoint(topo_factory):
    nodes = {"R1": VDNode(name="R1", kind="linux", image="x")}
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)
    topo.real_nets = {
        "access": RealNet(name="access", ipv4="192.168.50.1/24")
    }
    topo.real_net_links = [
        RealNetLink(
            real_net="access", node="R1", iface="eth1",
            host="master", bridge_iface="rn-R1-e1",
        )
    ]
    plan = _plan_single_host(topo, "master", ["R1"])

    parsed = yaml.safe_load(generate_micro_topology_files(topo, plan)["master"]["R1"])

    assert list(parsed["topology"]["nodes"]) == ["R1"]
    assert parsed["topology"]["links"][0]["endpoints"] == ["R1:eth1", "host:rn-R1-e1"]
