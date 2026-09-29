"""NVIDIA Cumulus VX breakout-port override plugin."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.models.node import Node


OVERRIDE_KEY = "cumulus_breakout"
FLAT_PORTS = 32
MAX_TOTAL_PORTS = 64
ALLOWED_LANES = {2, 4, 8}


class CumulusBreakoutPlugin:
    key = OVERRIDE_KEY

    def applies(self, kind: str | None, image: str | None = None) -> bool:
        kind_s = (kind or "").lower()
        image_s = (image or "").lower()
        return kind_s == "nvidia_cumulusvx" or "nvidia_cumulusvx" in image_s

    def default_state(self, kind: str | None, image: str | None = None) -> dict[str, Any] | None:
        if not self.applies(kind, image):
            return None
        return {"type": self.key, "flat_ports": FLAT_PORTS, "breakouts": []}

    def apply_state(self, node: Node, state: dict[str, Any] | None) -> dict[str, Any] | None:
        if not self.applies(node.kind, node.image):
            self.cleanup_node(node)
            return None
        clean = clean_state(state)
        if clean is None:
            clean = self.default_state(node.kind, node.image)
        self.cleanup_node(node)
        return clean

    def cleanup_node(self, node: Node) -> None:
        binds = [
            str(bind)
            for bind in (node.extra.get("binds") or [])
            if ":/config/ports.conf" not in str(bind)
        ]
        if binds:
            node.extra["binds"] = binds
        else:
            node.extra.pop("binds", None)

    def materialize(self, node: Node, state: dict[str, Any], topology_path: Path, lab_name: str) -> None:
        clean = clean_state(state)
        if clean is None:
            self.cleanup_node(node)
            return
        asset_dir = topology_path.parent / "node-assets" / lab_name / node.name
        asset_dir.mkdir(parents=True, exist_ok=True)
        ports_path = asset_dir / "ports.conf"
        ports_path.write_text(render_ports_conf(clean), encoding="utf-8")
        self.cleanup_node(node)
        binds = list(node.extra.get("binds") or [])
        binds.append(f"{ports_path}:/config/ports.conf:ro")
        node.extra["binds"] = binds


def clean_state(state: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        return None
    raw_breakouts = state.get("breakouts") or []
    if not isinstance(raw_breakouts, list):
        raw_breakouts = []
    by_parent: dict[int, int] = {}
    for item in raw_breakouts:
        if not isinstance(item, dict):
            continue
        try:
            parent = int(item.get("parent"))
            lanes = int(item.get("lanes"))
        except (TypeError, ValueError):
            continue
        if 1 <= parent <= FLAT_PORTS and lanes in ALLOWED_LANES:
            by_parent[parent] = lanes
    breakouts = [
        {"parent": parent, "lanes": lanes}
        for parent, lanes in sorted(by_parent.items())
    ]
    total = FLAT_PORTS + sum(item["lanes"] for item in breakouts)
    if total > MAX_TOTAL_PORTS:
        raise ValueError(
            f"Cumulus breakout requires {total} NICs; maximum is {MAX_TOTAL_PORTS}"
        )
    return {"type": OVERRIDE_KEY, "flat_ports": FLAT_PORTS, "breakouts": breakouts}


def render_ports_conf(state: dict[str, Any]) -> str:
    clean = clean_state(state)
    if clean is None:
        clean = {"breakouts": []}
    lanes_by_parent = {
        item["parent"]: item["lanes"] for item in clean["breakouts"]
    }
    return "\n".join(
        f"{port}={lanes_by_parent.get(port, 1)}x"
        for port in range(1, FLAT_PORTS + 1)
    ) + "\n"


PLUGIN = CumulusBreakoutPlugin()
