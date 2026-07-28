"""Topology model representing a full ContainerLab topology."""

from typing import Any
from pydantic import BaseModel, Field
from .node import Node
from .link import Link


class Topology(BaseModel):
    name: str
    nodes: list[Node] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    # Free-form extra top-level clab keys (mgmt, prefix, etc.)
    extra: dict[str, Any] = Field(default_factory=dict)
    # Sidecar Web UI: GUI source of truth for ports to expose via
    # clab ``ports:`` al deploy time. Serializzato come commento YAML
    # ``# dnlab-gui-webui:`` (vedi containerlab_service); NON entra nel
    # body del YAML clab. Schema entry for node:
    # ``{container_port:int, scheme:str, path:str, label:str,
    #    source:"catalog"|"user"}``. Le ``host_port`` allocate vivono
    # nel state multinode (non qui).
    gui_webui_state: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    # Sidecar override GUI for impostazioni speciali per-kind. Il body
    # clab resta pulito: i controller traducono questi desiderata in
    # campi clab-native come binds/env/file generati.
    gui_node_overrides_state: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # Sidecar feature GUI data-driven. Le feature sono dichiarate nel
    # catalogo dispositivi e il deploy/materializer puo tradurle in file
    # runtime senza vincolare il body Containerlab.
    gui_node_features_state: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # Stable VD identity used by dnlab-multinode for persistent disk paths.
    # Keyed by current display node name and serialized as
    # ``# dnlab-gui-node-ids:`` so renaming a VD does not change its disk.
    gui_node_ids_state: dict[str, str] = Field(default_factory=dict)
    # GUI-only per-link visual styles. Keys are canonical endpoint pairs:
    # ``node:iface|node:iface`` sorted lexicographically.
    gui_link_styles_state: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # GUI-only canvas decorations (notes, rectangles, ellipses). These do
    # not become ContainerLab nodes and are ignored by deploy/runtime logic.
    gui_canvas_annotations_state: list[dict[str, Any]] = Field(default_factory=list)

    def get_node(self, name: str) -> Node | None:
        return next((n for n in self.nodes if n.name == name), None)

    def add_node(self, node: Node) -> None:
        if self.get_node(node.name):
            raise ValueError(f"Node '{node.name}' already exists")
        self.nodes.append(node)

    def remove_node(self, name: str) -> None:
        self.nodes = [n for n in self.nodes if n.name != name]
        self.links = [
            lk for lk in self.links
            if lk.source != name and lk.target != name
        ]
        self.gui_webui_state.pop(name, None)
        self.gui_node_overrides_state.pop(name, None)
        self.gui_node_features_state.pop(name, None)
        self.gui_node_ids_state.pop(name, None)
        self.gui_link_styles_state = {
            key: style
            for key, style in self.gui_link_styles_state.items()
            if not key.startswith(f"{name}:") and f"|{name}:" not in key
        }

    def add_link(self, link: Link) -> None:
        self.links.append(link)

    def to_clab_dict(self) -> dict[str, Any]:
        nodes_dict: dict[str, Any] = {n.name: n.to_clab_dict() for n in self.nodes}
        links_list = [lk.to_clab_dict() for lk in self.links]
        d: dict[str, Any] = {
            "name": self.name,
            "topology": {
                "nodes": nodes_dict,
                "links": links_list,
            },
        }
        d.update(self.extra)
        return d
