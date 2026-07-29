"""
draw.io / mxGraph XML import-export service.

draw.io XML format uses mxCell elements:
  - vertex="1"  → network node
  - edge="1"    → link between nodes
"""

import json
import math
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any

from app.models.node import Node, NodePosition
from app.models.link import Link
from app.models.topology import Topology
from app.services import device_catalog
from app.services.drawio_icons import NODE_ICON_SIZE, node_icon_data_uri

PARALLEL_EDGE_STEP_PX = 40.0

# Map draw.io style keywords → clab kind (kind names match containerlab 0.74)
_STYLE_KIND_MAP: dict[str, str] = {
    "cisco.routers.router":      "cisco_xrv9k",
    "cisco.routers.cisco_router":"cisco_xrv9k",
    "cisco.switches.layer_3":    "cisco_n9kv",
    "cisco.switches.multilayer": "cisco_n9kv",
    "cisco.firewalls":           "cisco_vios",
    "juniper.router":            "juniper_vmx",
    "juniper.ex_switch":         "juniper_vjunosswitch",
    "arista":                    "arista_ceos",
    "nokia":                     "nokia_srlinux",
    "linux":                     "linux",
    "server":                    "linux",
    "router":                    "cisco_xrv9k",
    "switch":                    "cisco_n9kv",
    "firewall":                  "cisco_vios",
}


class DrawioService:
    """Convert between Topology models and draw.io XML."""

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def from_xml(self, xml_str: str, topology_name: str = "imported") -> Topology:
        """Parse draw.io XML and return a Topology."""
        root = ET.fromstring(xml_str)
        # Support both root <mxGraphModel> and wrapped <mxfile><diagram>...
        graph_model = root if root.tag == "mxGraphModel" else root.find(".//mxGraphModel")
        if graph_model is None:
            raise ValueError("No mxGraphModel element found in XML")

        cells = {
            cell.get("id"): cell
            for cell in graph_model.iter("mxCell")
        }

        nodes: list[Node] = []
        links: list[Link] = []
        extra: dict[str, Any] = {}
        link_styles: dict[str, dict[str, Any]] = {}
        annotations: list[dict[str, Any]] = []
        meta = cells.get("dnlab_meta")
        if meta is not None:
            mgmt = self._json_attr_or(meta.get("dnlab_mgmt"), {})
            if isinstance(mgmt, dict) and mgmt:
                extra["mgmt"] = mgmt

        # First pass: vertices (nodes) and dNLab canvas annotations.
        vertex_ids: dict[str, str] = {}  # mxCell id → node name
        for cell_id, cell in cells.items():
            if cell.get("vertex") == "1" and cell.get("parent") not in ("", None, "0"):
                if cell.get("dnlab_annotation") == "1":
                    annotation = self._annotation_from_cell(cell)
                    if annotation:
                        annotations.append(annotation)
                    continue
                label = cell.get("value") or cell_id
                node_name = self._sanitize_name(label)
                style = cell.get("style", "")
                kind = cell.get("dnlab_kind") or self._style_to_kind(style)
                image = cell.get("dnlab_image") or ""
                extra_data = self._json_attr_or(cell.get("dnlab_extra"), {})
                if not isinstance(extra_data, dict):
                    extra_data = {}

                geo = cell.find("mxGeometry")
                x = float(geo.get("x", 100)) if geo is not None else 100.0
                y = float(geo.get("y", 100)) if geo is not None else 100.0

                nodes.append(
                    Node(
                        name=node_name,
                        kind=kind,
                        image=image,
                        position=NodePosition(x=x, y=y),
                        extra=extra_data,
                    )
                )
                vertex_ids[cell_id] = node_name

        # Second pass: edges (links)
        for cell in cells.values():
            if cell.get("edge") == "1":
                src_id = cell.get("source", "")
                tgt_id = cell.get("target", "")
                if src_id in vertex_ids and tgt_id in vertex_ids:
                    src_iface = cell.get("dnlab_source_iface")
                    tgt_iface = cell.get("dnlab_target_iface")
                    if src_iface is None and tgt_iface is None:
                        label = cell.get("value") or ""
                        src_iface, tgt_iface = self._parse_link_label(label)
                    link = Link(
                        source=vertex_ids[src_id],
                        source_iface=src_iface or "",
                        target=vertex_ids[tgt_id],
                        target_iface=tgt_iface or "",
                    )
                    links.append(link)
                    style_data = self._json_attr_or(cell.get("dnlab_link_style"), {})
                    if isinstance(style_data, dict) and style_data:
                        link_styles[self._link_style_key_for_link(link)] = style_data

        return Topology(
            name=topology_name,
            nodes=nodes,
            links=links,
            extra=extra,
            gui_link_styles_state=link_styles,
            gui_canvas_annotations_state=annotations,
        )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def to_xml(self, topology: Topology) -> str:
        """Serialize a Topology to draw.io XML."""
        graph_model = ET.Element(
            "mxGraphModel",
            dx="1422", dy="762", grid="1", gridSize="10",
            guides="1", tooltips="1", connect="1", arrows="1",
            fold="1", page="1", pageScale="1",
            pageWidth="1169", pageHeight="827",
            math="0", shadow="0",
        )
        root_el = ET.SubElement(graph_model, "root")
        ET.SubElement(root_el, "mxCell", id="0")
        ET.SubElement(root_el, "mxCell", id="1", parent="0")
        self._append_dnlab_metadata(root_el, topology)

        node_ids: dict[str, str] = {}
        cell_id = 2
        annotations = list(topology.gui_canvas_annotations_state or [])
        indexed_annotations = list(enumerate(annotations))
        below_annotations = sorted(
            ((idx, annotation) for idx, annotation in indexed_annotations if self._annotation_z_index(annotation) < 0),
            key=lambda item: (self._annotation_z_index(item[1]), item[0]),
        )
        above_annotations = sorted(
            ((idx, annotation) for idx, annotation in indexed_annotations if self._annotation_z_index(annotation) > 0),
            key=lambda item: (self._annotation_z_index(item[1]), item[0]),
        )

        for _, annotation in below_annotations:
            cid = str(cell_id)
            cell_id += 1
            self._append_annotation(root_el, cid, annotation)

        for node in topology.nodes:
            cid = str(cell_id)
            node_ids[node.name] = cid
            cell_id += 1

            style = self._node_style(node.kind)

            attrs = {
                "id": cid,
                "value": node.name,
                "style": style,
                "vertex": "1",
                "parent": "1",
                "dnlab_kind": node.kind,
                "dnlab_image": node.image or "",
                "dnlab_extra": self._json_attr(node.extra or {}),
            }
            mgmt_ipv4 = node.mgmt_ipv4 or (node.extra or {}).get("mgmt-ipv4") or ""
            mgmt_ipv6 = node.mgmt_ipv6 or (node.extra or {}).get("mgmt-ipv6") or ""
            if mgmt_ipv4:
                attrs["dnlab_mgmt_ipv4"] = str(mgmt_ipv4)
            if mgmt_ipv6:
                attrs["dnlab_mgmt_ipv6"] = str(mgmt_ipv6)

            cell = ET.SubElement(root_el, "mxCell", **attrs)
            ET.SubElement(
                cell, "mxGeometry",
                x=str(node.position.x), y=str(node.position.y),
                width=str(NODE_ICON_SIZE), height=str(NODE_ICON_SIZE), **{"as": "geometry"},
            )

        parallel_groups = self._parallel_link_groups(topology.links)

        for link in topology.links:
            src_id = node_ids.get(link.source)
            tgt_id = node_ids.get(link.target)
            if not src_id or not tgt_id:
                continue

            source_node = topology.get_node(link.source)
            target_node = topology.get_node(link.target)
            label = self._link_label(link, source_node, target_node)
            link_type = self._link_type(source_node, target_node)
            link_style = (topology.gui_link_styles_state or {}).get(
                self._link_style_key_for_link(link),
                {},
            )

            cid = str(cell_id)
            cell_id += 1

            edge_attrs = {
                "id": cid, "value": label,
                "style": self._edge_style(link_style),
                "edge": "1", "source": src_id, "target": tgt_id, "parent": "1",
                "dnlab_source_iface": link.source_iface or "",
                "dnlab_target_iface": link.target_iface or "",
                "dnlab_link_type": link_type,
            }
            if link_style:
                edge_attrs["dnlab_link_style"] = self._json_attr(link_style)
            cell = ET.SubElement(
                root_el, "mxCell",
                **edge_attrs,
            )
            geometry = ET.SubElement(cell, "mxGeometry", relative="1", **{"as": "geometry"})
            waypoint = self._parallel_link_waypoint(link, topology, parallel_groups)
            if waypoint is not None:
                points = ET.SubElement(geometry, "Array", **{"as": "points"})
                ET.SubElement(
                    points,
                    "mxPoint",
                    x=self._fmt_float(waypoint[0]),
                    y=self._fmt_float(waypoint[1]),
                )

        for _, annotation in above_annotations:
            cid = str(cell_id)
            cell_id += 1
            self._append_annotation(root_el, cid, annotation)

        return ET.tostring(graph_model, encoding="unicode", xml_declaration=False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_name(label: str) -> str:
        """Convert a label to a valid ContainerLab node name."""
        import re
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", label.strip())
        return name or "node"

    @staticmethod
    def _style_to_kind(style: str) -> str:
        style_lower = style.lower()
        for fragment, kind in _STYLE_KIND_MAP.items():
            if fragment.lower() in style_lower:
                return kind
        return "linux"

    @staticmethod
    def _parse_link_label(label: str) -> tuple[str, str]:
        """Extract interface names from an edge label like 'eth1 – eth2'."""
        separators = [" – ", " - ", "/", ":"]
        for sep in separators:
            if sep in label:
                parts = label.split(sep, 1)
                return parts[0].strip(), parts[1].strip()
        return "", ""

    @staticmethod
    def _json_attr(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _json_attr_or(value: str | None, fallback: Any) -> Any:
        if not value:
            return fallback
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return fallback

    def _append_dnlab_metadata(self, root_el: ET.Element, topology: Topology) -> None:
        attrs = {
            "id": "dnlab_meta",
            "parent": "0",
            "dnlab_version": "1",
            "dnlab_topology_name": topology.name,
        }
        mgmt = (topology.extra or {}).get("mgmt")
        if mgmt:
            attrs["dnlab_mgmt"] = self._json_attr(mgmt)
        ET.SubElement(root_el, "mxCell", **attrs)

    @staticmethod
    def _node_style(kind: str | None) -> str:
        image = node_icon_data_uri(kind)
        return (
            "shape=image;"
            "html=1;"
            "imageAspect=0;"
            "aspect=fixed;"
            f"image={image};"
            "verticalLabelPosition=bottom;"
            "verticalAlign=top;"
            "align=center;"
        )

    @staticmethod
    def _edge_style(style_data: dict[str, Any] | None = None) -> str:
        style_data = style_data or {}
        color = style_data.get("color")
        label_color = style_data.get("label_color") or color
        style = (
            "html=1;"
            "rounded=0;"
            "curved=1;"
            "startArrow=none;"
            "endArrow=none;"
            "sourceArrow=none;"
            "targetArrow=none;"
        )
        if isinstance(color, str) and color.startswith("#"):
            style += f"strokeColor={color};"
        if isinstance(label_color, str) and label_color.startswith("#"):
            style += f"fontColor={label_color};"
        return style

    @staticmethod
    def _link_type(source_node: Node | None, target_node: Node | None) -> str:
        if (
            (source_node and source_node.kind == "_real_net")
            or (target_node and target_node.kind == "_real_net")
        ):
            return "real_net"
        return "data"

    @classmethod
    def _link_label(cls, link: Link, source_node: Node | None, target_node: Node | None) -> str:
        source_label = cls._display_iface(source_node, link.source_iface)
        target_label = cls._display_iface(target_node, link.target_iface)
        if source_node and source_node.kind == "_real_net":
            return target_label
        if target_node and target_node.kind == "_real_net":
            return source_label
        label_parts = []
        if source_label:
            label_parts.append(source_label)
        if target_label:
            label_parts.append(target_label)
        return " – ".join(label_parts)

    @classmethod
    def _display_iface(cls, node: Node | None, linux_name: str | None) -> str:
        """Return the same vendor-facing interface label shown on the canvas."""
        if not linux_name:
            return ""
        if not node or node.kind == "_real_net":
            return linux_name
        info = cls._interface_info_for_kind(node.kind)
        if not info:
            return linux_name
        try:
            count = int(info.get("count") or 8)
        except (TypeError, ValueError):
            count = 8
        linux_fmt = str(info.get("linux_fmt") or "eth{n}")
        vendor_fmt = str(info.get("vendor_fmt") or linux_fmt)
        for n in range(1, max(0, count) + 1):
            i = n - 1
            if cls._fmt_iface(linux_fmt, n, i) == linux_name:
                return cls._fmt_iface(vendor_fmt, n, i)
        return linux_name

    @staticmethod
    def _interface_info_for_kind(kind: str | None) -> dict[str, Any] | None:
        interface_map = device_catalog.interface_map()
        raw = (kind or "").strip()
        normalized = raw.lower()
        aliases = {
            "mikrotik": "mikrotik_ros",
            "routeros": "mikrotik_ros",
        }
        alias = aliases.get(raw) or aliases.get(normalized)
        info = interface_map.get(raw) or interface_map.get(normalized) or (interface_map.get(alias) if alias else None)
        if isinstance(info, dict):
            return info
        fallback = interface_map.get("linux")
        return fallback if isinstance(fallback, dict) else None

    @staticmethod
    def _fmt_iface(fmt: str, n: int, i: int) -> str:
        import re

        module = n // 4
        port = n % 4

        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            offset = int(match.group(2) or 0)
            values = {
                "module": module,
                "port": port,
                "n": n,
                "i": i,
            }
            return str(values[key] + offset)

        return re.sub(r"\{(module|port|n|i)([+-]\d+)?\}", repl, str(fmt or ""))

    @classmethod
    def _parallel_link_groups(cls, links: list[Link]) -> dict[tuple[str, str], list[Link]]:
        groups: dict[tuple[str, str], list[Link]] = defaultdict(list)
        for link in links:
            groups[cls._link_pair_key(link)].append(link)
        return {
            key: sorted(group, key=cls._link_sort_key)
            for key, group in groups.items()
            if len(group) > 1
        }

    @staticmethod
    def _link_pair_key(link: Link) -> tuple[str, str]:
        return tuple(sorted((link.source, link.target)))

    @staticmethod
    def _link_sort_key(link: Link) -> tuple[str, str, str, str]:
        return (link.source, link.target, link.source_iface or "", link.target_iface or "")

    @classmethod
    def _link_style_key_for_link(cls, link: Link) -> str:
        endpoints = [
            f"{link.source}:{link.source_iface or ''}",
            f"{link.target}:{link.target_iface or ''}",
        ]
        return "|".join(sorted(endpoints))

    def _append_annotation(self, root_el: ET.Element, cid: str, annotation: dict[str, Any]) -> None:
        ann_type = annotation.get("type")
        if ann_type not in ("note", "rectangle", "ellipse"):
            return
        z_index = self._annotation_z_index(annotation)
        annotation = {
            **annotation,
            "layer": self._annotation_layer(annotation),
            "z_index": z_index,
        }
        pos = annotation.get("position") if isinstance(annotation.get("position"), dict) else {}
        style_data = annotation.get("style") if isinstance(annotation.get("style"), dict) else {}
        value = annotation.get("text") or ""
        cell = ET.SubElement(
            root_el,
            "mxCell",
            id=cid,
            value=str(value),
            style=self._annotation_style(ann_type, style_data),
            vertex="1",
            parent="1",
            dnlab_annotation="1",
            dnlab_annotation_data=self._json_attr(annotation),
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            x=self._fmt_float(float(pos.get("x", 100))),
            y=self._fmt_float(float(pos.get("y", 100))),
            width=self._fmt_float(float(annotation.get("width", 160))),
            height=self._fmt_float(float(annotation.get("height", 80))),
            **{"as": "geometry"},
        )

    @staticmethod
    def _annotation_style(ann_type: str, style_data: dict[str, Any]) -> str:
        shape = "text" if ann_type == "note" else ("ellipse" if ann_type == "ellipse" else "rectangle")
        stroke = style_data.get("stroke_color") or ("none" if ann_type == "note" else "#64748b")
        fill = style_data.get("fill_color") or ("none" if ann_type == "note" else "#fef3c7")
        font = style_data.get("text_color") or "#111827"
        font_size = style_data.get("font_size") or 14
        border_width = style_data.get("border_width") if style_data.get("border_width") is not None else (0 if ann_type == "note" else 2)
        opacity = style_data.get("opacity") if style_data.get("opacity") is not None else 1
        font_family = style_data.get("font_family") or "Arial"
        font_style_bits = 0
        if str(style_data.get("font_weight") or "") in ("600", "700"):
            font_style_bits += 1
        if style_data.get("font_style") == "italic":
            font_style_bits += 2
        return (
            f"shape={shape};html=1;whiteSpace=wrap;rounded=0;"
            f"strokeColor={stroke};fillColor={fill};fontColor={font};"
            f"fontSize={font_size};fontFamily={font_family};fontStyle={font_style_bits};"
            f"strokeWidth={border_width};opacity={float(opacity) * 100:g};"
        )

    def _annotation_from_cell(self, cell: ET.Element) -> dict[str, Any] | None:
        data = self._json_attr_or(cell.get("dnlab_annotation_data"), {})
        if not isinstance(data, dict):
            return None
        geo = cell.find("mxGeometry")
        if geo is not None:
            data["position"] = {
                "x": float(geo.get("x", data.get("position", {}).get("x", 100))),
                "y": float(geo.get("y", data.get("position", {}).get("y", 100))),
            }
            data["width"] = float(geo.get("width", data.get("width", 160)))
            data["height"] = float(geo.get("height", data.get("height", 80)))
        if not data.get("id"):
            data["id"] = cell.get("id") or "annotation"
        if not data.get("text"):
            data["text"] = cell.get("value") or ""
        data["z_index"] = self._annotation_z_index(data)
        data["layer"] = self._annotation_layer(data)
        return data

    @staticmethod
    def _annotation_layer(annotation: dict[str, Any]) -> str:
        return "below_vd" if DrawioService._annotation_z_index(annotation) < 0 else "above_vd"

    @staticmethod
    def _annotation_z_index(annotation: dict[str, Any]) -> int:
        raw_z_index = annotation.get("z_index") if isinstance(annotation, dict) else None
        legacy_layer = annotation.get("layer") if isinstance(annotation, dict) else None
        legacy_below = legacy_layer in ("back", "background", "below_vd")
        if (
            isinstance(raw_z_index, (int, float))
            and not isinstance(raw_z_index, bool)
            and math.isfinite(raw_z_index)
        ):
            z_index = int(round(raw_z_index))
        else:
            z_index = -1 if legacy_below else 1
        z_index = max(-999, min(999, z_index))
        if z_index == 0:
            z_index = -1 if legacy_below else 1
        return z_index

    @classmethod
    def _parallel_link_waypoint(
        cls,
        link: Link,
        topology: Topology,
        parallel_groups: dict[tuple[str, str], list[Link]],
    ) -> tuple[float, float] | None:
        siblings = parallel_groups.get(cls._link_pair_key(link))
        if not siblings:
            return None
        idx = next((i for i, sibling in enumerate(siblings) if sibling is link), -1)
        if idx < 0:
            return None

        pair = cls._link_pair_key(link)
        source = topology.get_node(pair[0])
        target = topology.get_node(pair[1])
        if not source or not target:
            return None

        offset = (idx - ((len(siblings) - 1) / 2)) * PARALLEL_EDGE_STEP_PX
        x0, y0 = source.position.x, source.position.y
        x1, y1 = target.position.x, target.position.y
        dx = x1 - x0
        dy = y1 - y0
        length = math.hypot(dx, dy)
        if length <= 0:
            nx, ny = 0.0, 1.0
        else:
            nx, ny = -dy / length, dx / length

        return ((x0 + x1) / 2 + nx * offset, (y0 + y1) / 2 + ny * offset)

    @staticmethod
    def _fmt_float(value: float) -> str:
        return f"{value:.1f}".rstrip("0").rstrip(".")
