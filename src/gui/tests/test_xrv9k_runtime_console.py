import json
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

from app.models.lab import ContainerInfo
from app.services.console_service import ConsoleService


def test_console_prefers_launcher_declared_port():
    service = ConsoleService()
    service._run_in_container = AsyncMock(return_value="5000")
    container = ContainerInfo(name="xrv9k1", kind="cisco_xrv9k")

    assert asyncio.run(service._discover_loopback_port(container, None)) == 5000
    service._run_in_container.assert_awaited_once()


def test_xrv9k_catalog_exposes_full_default_warm_profile():
    config = Path(__file__).parents[1] / "app/views/static/config/devices.json"
    devices = json.loads(config.read_text(encoding="utf-8"))

    assert devices["kinds"]["cisco_xrv9k"]["interfaces"] == {
        "linux_fmt": "eth{n}",
        "vendor_fmt": "GigabitEthernet0/0/0/{i}",
        "count": 16,
    }


def test_flinos_catalog_exposes_n4alab_switch_profile():
    config = Path(__file__).parents[1] / "app/views/static/config/devices.json"
    devices = json.loads(config.read_text(encoding="utf-8"))

    assert devices["vendors"]["n4alab"] == {
        "title": "N4ALab",
        "color": "#001f3f",
    }
    assert devices["kinds"]["flinos"]["vendor"] == "n4alab"
    assert devices["kinds"]["flinos"]["type"] == "switch"
    assert devices["kinds"]["flinos"]["deploy_kind"] == "generic_vm"
    assert devices["kinds"]["flinos"]["mgmt_iface"] == "mgmt"
    assert devices["kinds"]["flinos"]["env"] == {
        "VCPU": "2",
        "RAM": "4096",
        "CLAB_MGMT_PASSTHROUGH": "true",
    }
    assert devices["kinds"]["flinos"]["interfaces"] == {
        "linux_fmt": "eth{n-1}",
        "vendor_fmt": "eth{n-1}",
        "vendor_names": {"1": "mgmt"},
        "count": 9,
    }
    assert devices["kinds"]["flinos"]["image_patterns"] == [
        "vrnetlab/n4alab_flinos",
        "vrnetlab/n4alab_flinos-dev",
    ]


def test_console_open_uses_a_fresh_browser_window():
    console_js = (
        Path(__file__).parents[1] / "app/views/static/js/console.js"
    ).read_text(encoding="utf-8")

    assert "WindowManager.open(url, '_blank'" in console_js
    assert "dnlab-console-${labId}-${nodeName}" not in console_js
