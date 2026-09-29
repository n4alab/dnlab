"""Runtime registry for device-specific node override plugins."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, Any


class RuntimeNodePlugin(Protocol):
    key: str
    managed_targets: tuple[str, ...]

    def render_assets(self, state: dict[str, Any]) -> dict[str, tuple[str, str, bool]]:
        ...

    def warm_capacity(self, state: dict[str, Any]) -> int | None:
        ...


def _plugins() -> tuple[RuntimeNodePlugin, ...]:
    from dnlab_multinode.services.node_plugins import cat9kv_vswitch, cumulus_breakout
    return (cat9kv_vswitch.PLUGIN, cumulus_breakout.PLUGIN)


def all_plugins() -> Iterable[RuntimeNodePlugin]:
    return _plugins()


def for_state(state: dict[str, Any] | None) -> RuntimeNodePlugin | None:
    if not isinstance(state, dict):
        return None
    key = str(state.get("type") or "")
    return next((plugin for plugin in _plugins() if plugin.key == key), None)


def managed_targets() -> set[str]:
    return {
        target
        for plugin in _plugins()
        for target in plugin.managed_targets
    }
