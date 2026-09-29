"""Runtime materializer and capacity policy for Cumulus VX breakout ports."""

from __future__ import annotations

from typing import Any


FLAT_PORTS = 32
MAX_TOTAL_PORTS = 64
ALLOWED_LANES = {2, 4, 8}


def normalize_breakouts(state: dict[str, Any]) -> list[tuple[int, int]]:
    raw = state.get("breakouts") or []
    if not isinstance(raw, list):
        raise ValueError("Cumulus breakouts must be a list")
    by_parent: dict[int, int] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Cumulus breakout entries must be mappings")
        try:
            parent = int(item.get("parent"))
            lanes = int(item.get("lanes"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Cumulus breakout parent and lanes must be integers") from exc
        if not 1 <= parent <= FLAT_PORTS:
            raise ValueError(f"Cumulus breakout parent must be between 1 and {FLAT_PORTS}")
        if lanes not in ALLOWED_LANES:
            raise ValueError("Cumulus breakout lanes must be one of 2, 4, or 8")
        by_parent[parent] = lanes
    breakouts = sorted(by_parent.items())
    total = FLAT_PORTS + sum(lanes for _, lanes in breakouts)
    if total > MAX_TOTAL_PORTS:
        raise ValueError(
            f"Cumulus breakout requires {total} NICs; maximum is {MAX_TOTAL_PORTS}"
        )
    return breakouts


class CumulusBreakoutRuntimePlugin:
    key = "cumulus_breakout"
    managed_targets = ("/config/ports.conf",)

    def render_assets(self, state: dict[str, Any]) -> dict[str, tuple[str, str, bool]]:
        breakouts = dict(normalize_breakouts(state))
        content = "\n".join(
            f"{port}={breakouts.get(port, 1)}x"
            for port in range(1, FLAT_PORTS + 1)
        ) + "\n"
        return {"ports.conf": ("/config/ports.conf", content, True)}

    def warm_capacity(self, state: dict[str, Any]) -> int | None:
        normalize_breakouts(state)
        return MAX_TOTAL_PORTS


PLUGIN = CumulusBreakoutRuntimePlugin()
