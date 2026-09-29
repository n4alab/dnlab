"""Registry for per-node override plugins.

Override plugins own device-specific GUI state that must be validated and
translated before it can affect Containerlab-facing node data.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, Any

from app.models.node import Node


class NodeOverridePlugin(Protocol):
    key: str

    def applies(self, kind: str | None, image: str | None = None) -> bool:
        ...

    def default_state(self, kind: str | None, image: str | None = None) -> dict[str, Any] | None:
        ...

    def apply_state(self, node: Node, state: dict[str, Any] | None) -> dict[str, Any] | None:
        ...

    def cleanup_node(self, node: Node) -> None:
        ...


def _plugins() -> list[NodeOverridePlugin]:
    from app.services.node_override_plugins import cat9kv_vswitch, cumulus_breakout

    return [
        cat9kv_vswitch.PLUGIN,
        cumulus_breakout.PLUGIN,
    ]


def all_plugins() -> Iterable[NodeOverridePlugin]:
    return tuple(_plugins())


def get(key: str | None) -> NodeOverridePlugin | None:
    if not key:
        return None
    key_s = str(key)
    return next((plugin for plugin in _plugins() if plugin.key == key_s), None)


def for_kind(kind: str | None, image: str | None = None) -> NodeOverridePlugin | None:
    return next((plugin for plugin in _plugins() if plugin.applies(kind, image)), None)


def for_state(
    state: dict[str, Any] | None,
    kind: str | None = None,
    image: str | None = None,
) -> NodeOverridePlugin | None:
    if isinstance(state, dict):
        plugin = get(state.get("type"))
        if plugin:
            return plugin
    return for_kind(kind, image)

