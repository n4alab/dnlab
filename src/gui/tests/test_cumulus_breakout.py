from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from app.controllers.topology_controller import TopologyController
from app.models.node import Node
from app.models.topology import Topology
from app.services.containerlab_service import ContainerLabService


def _sidecar(text: str) -> dict:
    prefix = "# dnlab-gui-node-overrides: "
    line = next(item for item in text.splitlines() if item.startswith(prefix))
    return json.loads(line[len(prefix):])


def _cumulus_node() -> Node:
    return Node(
        name="leaf1",
        kind="nvidia_cumulusvx",
        image="vrnetlab/nvidia_cumulusvx:5.16.1-vx-amd64-dnlab",
    )


def test_cumulus_catalog_matches_enhanced_hardware_profile():
    catalog_path = (
        Path(__file__).parents[1]
        / "app"
        / "views"
        / "static"
        / "config"
        / "devices.json"
    )
    device = json.loads(catalog_path.read_text())["kinds"]["nvidia_cumulusvx"]

    assert device["env"]["VCPU"] == "1"
    assert device["env"]["RAM"] == "4096"
    assert device["env"]["DNLAB_WARM_PORTS"] == "64"


def test_cumulus_add_preserves_32_flat_ports_and_materializes_ports_conf(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(path, Topology(name="lab"))

    ctrl.add_node_by_path(path, "lab", _cumulus_node())

    data = yaml.safe_load(path.read_text())
    ports_path = tmp_path / "node-assets" / "lab" / "leaf1" / "ports.conf"
    assert data["topology"]["nodes"]["leaf1"]["binds"] == [
        f"{ports_path}:/config/ports.conf:ro"
    ]
    assert ports_path.read_text().splitlines() == [
        f"{port}=1x" for port in range(1, 33)
    ]
    assert _sidecar(path.read_text())["leaf1"] == {
        "type": "cumulus_breakout",
        "flat_ports": 32,
        "breakouts": [],
    }


def test_cumulus_breakouts_are_sorted_deduplicated_and_additive(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(
        path,
        Topology(name="lab", nodes=[_cumulus_node()]),
    )

    ctrl.update_node_by_path(
        path,
        "lab",
        "leaf1",
        {
            "node_overrides": {
                "type": "cumulus_breakout",
                "breakouts": [
                    {"parent": 20, "lanes": 2},
                    {"parent": 10, "lanes": 2},
                    {"parent": 10, "lanes": 4},
                ],
            }
        },
    )

    topology = ContainerLabService().load_topology_from_file(path)
    assert topology.gui_node_overrides_state["leaf1"]["breakouts"] == [
        {"parent": 10, "lanes": 4},
        {"parent": 20, "lanes": 2},
    ]
    lines = (
        tmp_path / "node-assets" / "lab" / "leaf1" / "ports.conf"
    ).read_text().splitlines()
    assert len(lines) == 32
    assert lines[9] == "10=4x"
    assert lines[19] == "20=2x"
    assert lines[31] == "32=1x"


def test_cumulus_breakout_rejects_more_than_64_physical_slots(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(
        path,
        Topology(name="lab", nodes=[_cumulus_node()]),
    )

    with pytest.raises(ValueError, match="requires 72 NICs; maximum is 64"):
        ctrl.update_node_by_path(
            path,
            "lab",
            "leaf1",
            {
                "node_overrides": {
                    "type": "cumulus_breakout",
                    "breakouts": [
                        {"parent": parent, "lanes": 8}
                        for parent in range(1, 6)
                    ],
                }
            },
        )


def test_canvas_snapshot_preserves_cumulus_override_state():
    static_js = Path(__file__).parents[1] / "app" / "views" / "static" / "js"
    canvas_js = (static_js / "canvas.js").read_text(encoding="utf-8")
    app_js = (static_js / "app.js").read_text(encoding="utf-8")

    assert "node_overrides_state: n.data('node_overrides_state') || null" in canvas_js
    assert (
        "const updatedOverride = (updatedTopo.gui_node_overrides_state || {})[name] || null"
        in app_js
    )
    assert "node_overrides_state: updatedOverride" in app_js
    assert "function _resolveVendorIface(kind, linuxName, nodeData = null)" in app_js
    assert "nodeData: nodeData || {}" in app_js
    assert "return formatInterfaceLabel(node.data('kind') || '', iface, node.data())" in canvas_js
    assert "_refreshEdgeLabels(node.connectedEdges())" in canvas_js


def test_cumulus_breakout_controls_are_locked_while_vd_is_active():
    plugin_path = (
        Path(__file__).parents[1]
        / "app"
        / "views"
        / "static"
        / "js"
        / "node_plugins"
        / "cumulus_breakout.js"
    )
    plugin_js = plugin_path.read_text(encoding="utf-8")

    assert "cumulusBreakoutLocked(nodeData)" in plugin_js
    assert "Stop the VD before changing breakout ports." in plugin_js
    assert "['stopped', 'error', 'missing'].includes(state)" in plugin_js


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not available")
def test_cumulus_interface_plugin_keeps_flat_ports_and_adds_ordered_lanes():
    plugin_path = (
        Path(__file__).parents[1]
        / "app"
        / "views"
        / "static"
        / "js"
        / "node_plugins"
        / "cumulus_breakout.js"
    )
    script = """
const fs = require('fs');
const vm = require('vm');
const plugins = {};
const context = { NodeOverridePlugins: { register: plugin => { plugins[plugin.key] = plugin; } } };
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const result = plugins.cumulus_breakout.interfaces({
  nodeData: { node_overrides_state: { breakouts: [
    { parent: 20, lanes: 2 },
    { parent: 10, lanes: 4 },
  ] } },
  override: { max_total_ports: 64 },
  baseInterfaces: [
    { linux: 'eth1', vendor: 'swp1' },
    { linux: 'eth32', vendor: 'swp32' },
  ],
});
process.stdout.write(JSON.stringify(result));
"""
    completed = subprocess.run(
        ["node", "-e", script, str(plugin_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == [
        {"linux": "eth1", "vendor": "swp1"},
        {"linux": "eth32", "vendor": "swp32"},
        {"linux": "eth33", "vendor": "swp10s0"},
        {"linux": "eth34", "vendor": "swp10s1"},
        {"linux": "eth35", "vendor": "swp10s2"},
        {"linux": "eth36", "vendor": "swp10s3"},
        {"linux": "eth37", "vendor": "swp20s0"},
        {"linux": "eth38", "vendor": "swp20s1"},
    ]
