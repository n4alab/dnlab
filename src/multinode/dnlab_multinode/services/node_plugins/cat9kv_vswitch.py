"""Runtime materializer for Catalyst 9000V vswitch overrides."""

from __future__ import annotations

import re
from typing import Any


class Cat9kvVswitchRuntimePlugin:
    key = "cat9kv_vswitch"
    managed_targets = ("/vswitch.xml",)

    def render_assets(self, state: dict[str, Any]) -> dict[str, tuple[str, str, bool]]:
        platform = str(state.get("platform") or "UADP").upper()
        if platform not in {"UADP", "Q200"}:
            platform = "UADP"
        try:
            port_count = max(1, min(int(state.get("port_count") or 24), 256))
        except (TypeError, ValueError):
            port_count = 24
        serial = re.sub(r"[^A-Za-z0-9]", "", str(state.get("serial_number") or "")).upper()[:12]
        content = (
            "<vswitch>\n"
            f"  <asic_type>{platform}</asic_type>\n"
            f"  <port_count>{port_count}</port_count>\n"
            f"  <serial_number>{serial}</serial_number>\n"
            f"  <prod_serial_number>{serial}</prod_serial_number>\n"
            "</vswitch>\n"
        )
        return {"vswitch.xml": ("/vswitch.xml", content, False)}

    def warm_capacity(self, state: dict[str, Any]) -> int | None:
        return None


PLUGIN = Cat9kvVswitchRuntimePlugin()
