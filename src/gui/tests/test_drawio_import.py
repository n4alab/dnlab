from pathlib import Path

from app.models.link import Link
from app.models.node import Node, NodePosition
from app.models.topology import Topology
from app.services.drawio_service import DrawioService


def test_import_exported_drawio_fixture_preserves_dnlab_metadata():
    xml = Path("/root/import-test.drawio").read_text()

    topo = DrawioService().from_xml(xml, "target-lab")

    assert topo.name == "target-lab"
    assert len(topo.nodes) == 5
    assert len(topo.links) == 10
    assert topo.extra["mgmt"]["ipv4-subnet"] == "172.20.24.0/24"
    assert topo.extra["mgmt"]["canvas_pos"] == {"x": 120.0, "y": 120.0}

    cumulus = topo.get_node("cumulu1")
    assert cumulus is not None
    assert cumulus.kind == "nvidia_cumulusvx"
    assert cumulus.image == "vrnetlab/nvidia_cumulusvx:5.16.1-vx-amd64-dnlab"
    assert cumulus.extra["env"]["CLAB_MGMT_PASSTHROUGH"] == "true"

    realnet = topo.get_node("net1")
    assert realnet is not None
    assert realnet.kind == "_real_net"
    assert realnet.extra["ipv4"] == "100.81.149.1/24"

    realnet_links = [
        lk for lk in topo.links
        if lk.source == "cumulu1" and lk.target == "net1"
        or lk.source == "cumulu2" and lk.target == "net1"
    ]
    assert len(realnet_links) == 2
    assert {(lk.source_iface, lk.target_iface) for lk in realnet_links} == {("eth5", "real")}


def test_import_round_trip_preserves_dnlab_topology_data():
    original = Topology(
        name="source-lab",
        nodes=[
            Node(
                name="r1",
                kind="cisco_xrv9k",
                image="vrnetlab/cisco_xrv9k:latest",
                position=NodePosition(x=10, y=20),
                extra={"env": {"RAM": "4096"}, "mgmt-ipv4": "172.20.20.10"},
            ),
            Node(
                name="wan",
                kind="_real_net",
                image="",
                position=NodePosition(x=200, y=20),
                extra={"ipv4": "192.0.2.1/24", "nat": True},
            ),
        ],
        links=[
            Link(source="r1", source_iface="eth1", target="wan", target_iface="real"),
            Link(source="r1", source_iface="eth2", target="wan", target_iface="real"),
        ],
        extra={"mgmt": {"ipv4-subnet": "172.20.20.0/24", "canvas_pos": {"x": 80, "y": 80}}},
        gui_link_styles_state={
            "r1:eth1|wan:real": {"color": "#22c55e"},
        },
        gui_canvas_annotations_state=[
            {
                "id": "note-1",
                "type": "note",
                "text": "WAN edge",
                "position": {"x": 20, "y": 40},
                "width": 180,
                "height": 80,
                "layer": "above_vd",
                "z_index": 3,
                "style": {"fill_color": "#fef9c3"},
            }
        ],
    )

    xml = DrawioService().to_xml(original)
    imported = DrawioService().from_xml(xml, "target-lab")

    assert imported.name == "target-lab"
    assert imported.extra == original.extra
    assert [node.model_dump() for node in imported.nodes] == [node.model_dump() for node in original.nodes]
    assert [link.model_dump() for link in imported.links] == [link.model_dump() for link in original.links]
    assert imported.gui_link_styles_state == original.gui_link_styles_state
    assert imported.gui_canvas_annotations_state == original.gui_canvas_annotations_state


def test_import_legacy_drawio_without_dnlab_metadata_still_uses_style_and_label_fallback():
    xml = """
<mxGraphModel>
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />
    <mxCell id="2" value="r1" style="shape=mxgraph.cisco.routers.router;" vertex="1" parent="1">
      <mxGeometry x="10" y="20" width="60" height="60" as="geometry" />
    </mxCell>
    <mxCell id="3" value="sw1" style="shape=mxgraph.cisco.switches.layer_3;" vertex="1" parent="1">
      <mxGeometry x="100" y="20" width="60" height="60" as="geometry" />
    </mxCell>
    <mxCell id="4" value="Gi0/0 – Ethernet1" edge="1" source="2" target="3" parent="1">
      <mxGeometry relative="1" as="geometry" />
    </mxCell>
  </root>
</mxGraphModel>
"""

    topo = DrawioService().from_xml(xml, "legacy")

    assert [(node.name, node.kind, node.image, node.extra) for node in topo.nodes] == [
        ("r1", "cisco_xrv9k", "", {}),
        ("sw1", "cisco_n9kv", "", {}),
    ]
    assert [link.model_dump() for link in topo.links] == [
        {"source": "r1", "source_iface": "Gi0/0", "target": "sw1", "target_iface": "Ethernet1"}
    ]


def test_import_malformed_dnlab_json_falls_back_to_empty_metadata():
    xml = """
<mxGraphModel>
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />
    <mxCell id="dnlab_meta" parent="0" dnlab_mgmt="{bad json" />
    <mxCell id="2" value="r1" style="shape=image;" vertex="1" parent="1"
            dnlab_kind="linux" dnlab_image="alpine:latest" dnlab_extra="{bad json">
      <mxGeometry x="10" y="20" width="56" height="56" as="geometry" />
    </mxCell>
  </root>
</mxGraphModel>
"""

    topo = DrawioService().from_xml(xml, "bad-json")

    assert topo.extra == {}
    assert len(topo.nodes) == 1
    assert topo.nodes[0].kind == "linux"
    assert topo.nodes[0].image == "alpine:latest"
    assert topo.nodes[0].extra == {}
