import json
from pathlib import Path

from app.models.link import Link
from app.models.node import Node
from app.models.topology import Topology
from app.services.containerlab_service import ContainerLabService
from app.controllers.topology_controller import TopologyController


def test_canvas_annotation_layers_are_ordered_around_vd_icons():
    canvas_js = (Path(__file__).parents[1] / "app" / "views" / "static" / "js" / "canvas.js").read_text()

    vd_layer = canvas_js[
        canvas_js.index("selector: 'node'") : canvas_js.index("selector: 'node.canvas-annotation'")
    ]
    annotation_layer = canvas_js[
        canvas_js.index("selector: 'node.canvas-annotation'") : canvas_js.index(
            "selector: 'node.canvas-annotation:selected'"
        )
    ]
    handle_layer = canvas_js[
        canvas_js.index("selector: 'node.canvas-annotation-resize-handle'") : canvas_js.index(
            "selector: 'node:selected'"
        )
    ]

    assert "'z-index-compare': 'manual'" in vd_layer
    assert "'z-index': VD_Z_INDEX" in vd_layer
    assert "'z-index-compare': 'manual'" in annotation_layer
    assert "'z-index': 'data(cy_z_index)'" in annotation_layer
    assert "const VD_Z_INDEX = 10" in canvas_js
    assert "function moveAnnotationLayer(id, direction)" in canvas_js
    assert "function _reindexAnnotationLayers(below, above)" in canvas_js
    assert "z_index: zIndex" in canvas_js
    assert "'z-index-compare': 'manual'" in handle_layer
    assert "'z-index': 'data(cy_z_index)'" in handle_layer


def test_save_load_preserves_link_styles_and_canvas_annotations(tmp_path):
    path = tmp_path / "lab.yml"
    topo = Topology(
        name="lab",
        nodes=[
            Node(name="r1", kind="linux", image="alpine:latest"),
            Node(name="r2", kind="linux", image="alpine:latest"),
        ],
        links=[Link(source="r1", source_iface="eth1", target="r2", target_iface="eth2")],
        gui_link_styles_state={
            "r1:eth1|r2:eth2": {"color": "#22c55e", "label_color": "#16a34a"},
            "r1:eth9|r2:eth9": {"color": "#ef4444"},
        },
        gui_canvas_annotations_state=[
            {
                "id": "note-1",
                "type": "note",
                "text": "Core path",
                "position": {"x": 10, "y": 20},
                "width": 180,
                "height": 90,
                "style": {
                    "stroke_color": "#64748b",
                    "fill_color": "#fef9c3",
                    "text_color": "#111827",
                    "font_size": 14,
                    "font_family": "Arial",
                    "font_weight": "700",
                    "font_style": "italic",
                    "border_width": 2,
                    "opacity": 0.9,
                },
                "layer": "below_vd",
                "z_index": -2,
            }
        ],
    )

    ContainerLabService().save_topology_to(path, topo)
    text = path.read_text()

    assert "# dnlab-gui-link-styles:" in text
    assert "# dnlab-gui-canvas-annotations:" in text
    assert "r1:eth9|r2:eth9" not in text

    loaded = ContainerLabService().load_topology_from_file(path)

    assert loaded.gui_link_styles_state == {
        "r1:eth1|r2:eth2": {"color": "#22c55e", "label_color": "#16a34a"}
    }
    assert loaded.gui_canvas_annotations_state[0]["id"] == "note-1"
    assert loaded.gui_canvas_annotations_state[0]["text"] == "Core path"
    assert loaded.gui_canvas_annotations_state[0]["layer"] == "below_vd"
    assert loaded.gui_canvas_annotations_state[0]["z_index"] == -2
    assert loaded.gui_canvas_annotations_state[0]["style"]["font_weight"] == "700"
    assert loaded.gui_canvas_annotations_state[0]["style"]["font_style"] == "italic"


def test_annotation_z_indexes_migrate_legacy_layers_and_keep_custom_layers(tmp_path):
    path = tmp_path / "layers.yml"
    topo = Topology(
        name="layers",
        gui_canvas_annotations_state=[
            {"id": "legacy-back", "type": "rectangle", "layer": "below_vd"},
            {"id": "legacy-front", "type": "ellipse", "layer": "above_vd"},
            {"id": "custom-back", "type": "note", "layer": "above_vd", "z_index": -4},
            {"id": "custom-front", "type": "note", "layer": "below_vd", "z_index": 7},
        ],
    )

    ContainerLabService().save_topology_to(path, topo)
    loaded = ContainerLabService().load_topology_from_file(path)

    layers = {annotation["id"]: (annotation["layer"], annotation["z_index"])
              for annotation in loaded.gui_canvas_annotations_state}
    assert layers == {
        "legacy-back": ("below_vd", -1),
        "legacy-front": ("above_vd", 1),
        "custom-back": ("below_vd", -4),
        "custom-front": ("above_vd", 7),
    }


def test_load_ignores_malformed_canvas_sidecars(tmp_path):
    path = tmp_path / "lab.yml"
    path.write_text(
        "\n".join([
            "name: lab",
            "topology:",
            "  nodes:",
            "    r1:",
            "      kind: linux",
            "      image: alpine:latest",
            "  links: []",
            '# dnlab-gui-link-styles: {"bad": {"color": "red"}}',
            "# dnlab-gui-canvas-annotations: " + json.dumps([{"type": "triangle"}]),
        ])
    )

    loaded = ContainerLabService().load_topology_from_file(path)

    assert loaded.gui_link_styles_state == {}
    assert loaded.gui_canvas_annotations_state == []


def test_node_rename_migrates_link_style_keys(tmp_path):
    path = tmp_path / "lab.yml"
    topo = Topology(
        name="lab",
        nodes=[
            Node(name="r1", kind="linux", image="alpine:latest"),
            Node(name="r2", kind="linux", image="alpine:latest"),
        ],
        links=[Link(source="r1", source_iface="eth1", target="r2", target_iface="eth2")],
        gui_link_styles_state={"r1:eth1|r2:eth2": {"color": "#22c55e"}},
    )
    ContainerLabService().save_topology_to(path, topo)

    updated = TopologyController().update_node_by_path(path, "lab", "r1", {"new_name": "core1"})

    assert updated.gui_link_styles_state == {"core1:eth1|r2:eth2": {"color": "#22c55e"}}
