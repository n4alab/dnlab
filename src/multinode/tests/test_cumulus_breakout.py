from __future__ import annotations

import pytest
import yaml

from dnlab_multinode.models.schedule import HostAssignment, SchedulePlan
from dnlab_multinode.models.topology import Link, VDNode
from dnlab_multinode.services import warm_links
from dnlab_multinode.services.generator import (
    generate_micro_topology_files,
    render_node_override_files,
)


def _plan(topo, nodes):
    return SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=nodes)
        },
    )


def _cumulus_node() -> VDNode:
    node = VDNode(
        name="leaf1",
        kind="nvidia_cumulusvx",
        image="vrnetlab/nvidia_cumulusvx:5.16.1-vx-amd64-dnlab",
    )
    warm_links.apply_image_labels(
        node,
        {
            "org.dnlab.capabilities": "warm-links-v1",
            "org.dnlab.warm-links.status": "experimental",
        },
    )
    return node


def test_cumulus_breakout_capacity_keeps_flat_ports_and_adds_lane_slots(topo_factory):
    node = _cumulus_node()
    topo = topo_factory(nodes={"leaf1": node}, links=[], num_workers=0)
    topo.node_overrides = {
        "leaf1": {
            "type": "cumulus_breakout",
            "flat_ports": 32,
            "breakouts": [
                {"parent": 20, "lanes": 2},
                {"parent": 10, "lanes": 4},
            ],
        }
    }

    assert warm_links.capacity_for_node(topo, "leaf1") == 64

    files = render_node_override_files(topo, "leaf1")
    assert len(files) == 1
    ports_path, ports_conf = next(iter(files.items()))
    assert ports_path.endswith("/dnlab-assets/lab/leaf1/ports.conf")
    assert len(ports_conf.splitlines()) == 32
    assert "10=4x" in ports_conf.splitlines()
    assert "20=2x" in ports_conf.splitlines()

    text = generate_micro_topology_files(
        topo, _plan(topo, ["leaf1"])
    )["master"]["leaf1"]
    parsed = yaml.safe_load(text)
    rendered = parsed["topology"]["nodes"]["leaf1"]
    assert rendered["env"]["DNLAB_WARM_PORTS"] == "64"
    assert any(
        bind.endswith("/ports.conf:/config/ports.conf:ro")
        for bind in rendered["binds"]
    )
    node_endpoints = {
        endpoint
        for link in parsed["topology"]["links"]
        for endpoint in link["endpoints"]
        if endpoint.startswith("leaf1:")
    }
    assert "leaf1:eth1" in node_endpoints
    assert "leaf1:eth32" in node_endpoints
    assert "leaf1:eth33" in node_endpoints
    assert "leaf1:eth38" in node_endpoints
    assert len(node_endpoints) == 64


def test_cumulus_breakout_rejects_capacity_beyond_profile_limit(topo_factory):
    node = _cumulus_node()
    topo = topo_factory(nodes={"leaf1": node}, links=[], num_workers=0)
    topo.node_overrides = {
        "leaf1": {
            "type": "cumulus_breakout",
            "breakouts": [
                {"parent": parent, "lanes": 8}
                for parent in range(1, 6)
            ],
        }
    }

    with pytest.raises(ValueError, match="requires 72 NICs; maximum is 64"):
        warm_links.capacity_for_node(topo, "leaf1")


def test_cumulus_breakout_preallocates_slots_beyond_active_lanes(topo_factory):
    node = _cumulus_node()
    peer = VDNode(name="peer", kind="linux", image="alpine")
    topo = topo_factory(
        nodes={"leaf1": node, "peer": peer},
        links=[Link("leaf1", "eth37", "peer", "eth1")],
        num_workers=0,
    )
    topo.node_overrides = {
        "leaf1": {
            "type": "cumulus_breakout",
            "breakouts": [{"parent": 10, "lanes": 4}],
        }
    }

    assert warm_links.capacity_for_node(topo, "leaf1") == 64
