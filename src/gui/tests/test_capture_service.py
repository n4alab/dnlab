import asyncio
import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from starlette.requests import Request

from app.models.link import Link
from app.models.node import Node
from app.models.topology import Topology
from app.services.containerlab_service import ContainerLabService
from app.services.lab_resolver import ResolvedLab
from app.services import capture_service as capture_mod
from app.views.api import capture_routes as capture_routes_mod


def _lab(tmp_path, topo):
    lab_id = uuid4()
    path = tmp_path / f"{lab_id}.yml"
    ContainerLabService().save_topology_to(path, topo)
    return ResolvedLab(
        id=lab_id,
        display_name="demo",
        netname="dnlab-demo",
        bridge="br-demo",
        yaml_path=path,
        owner=None,
    )


def _runtime():
    return {
        "nodes": {
            "r1": {
                "state": "running",
                "container": "clab-dnlab-demo-r1",
                "host": "master",
                "duplicate_hosts": [],
            },
            "r2": {
                "state": "running",
                "container": "clab-dnlab-demo-r2",
                "host": "worker1",
                "duplicate_hosts": [],
            },
        }
    }


def _request(headers=None) -> Request:
    raw_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    return Request({
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "server": ("127.0.0.1", 8080),
        "client": ("127.0.0.1", 50000),
        "root_path": "",
        "path": "/api/labs/lab/captures/launch",
        "query_string": b"",
        "headers": raw_headers,
    })


def test_capture_public_base_url_uses_forwarded_headers(monkeypatch):
    monkeypatch.setattr(capture_routes_mod.settings, "PUBLIC_BASE_URL", "")
    request = _request({
        "host": "127.0.0.1:8080",
        "x-forwarded-proto": "https",
        "x-forwarded-host": "dnlab.example.com",
    })

    assert capture_routes_mod._public_base_url(request) == "https://dnlab.example.com/"


def test_capture_public_base_url_uses_first_forwarded_host(monkeypatch):
    monkeypatch.setattr(capture_routes_mod.settings, "PUBLIC_BASE_URL", "")
    request = _request({
        "x-forwarded-proto": "https, http",
        "x-forwarded-host": "dnlab.example.com, internal.local",
    })

    assert capture_routes_mod._public_base_url(request) == "https://dnlab.example.com/"


def test_capture_public_base_url_prefers_configured_url(monkeypatch):
    monkeypatch.setattr(capture_routes_mod.settings, "PUBLIC_BASE_URL", "https://public.example.com/gui/")
    request = _request({
        "x-forwarded-proto": "https",
        "x-forwarded-host": "dnlab.example.com",
    })

    assert capture_routes_mod._public_base_url(request) == "https://public.example.com/gui/"


def test_capture_public_base_url_falls_back_to_request_base(monkeypatch):
    monkeypatch.setattr(capture_routes_mod.settings, "PUBLIC_BASE_URL", "")
    request = _request()

    assert capture_routes_mod._public_base_url(request) == "http://127.0.0.1:8080/"


def test_capture_targets_include_link_realnet_and_mgmt(tmp_path, monkeypatch):
    topo = Topology(
        name="dnlab-demo",
        nodes=[
            Node(name="r1", kind="linux", image="alpine"),
            Node(name="r2", kind="linux", image="alpine"),
            Node(name="real_net", kind="_real_net", image=""),
        ],
        links=[
            Link(source="r1", source_iface="eth1", target="r2", target_iface="eth1"),
            Link(source="real_net", source_iface="real", target="r1", target_iface="eth2"),
        ],
    )
    lab = _lab(tmp_path, topo)

    async def fake_status(_lab, emit_events=False):
        return _runtime()

    svc = capture_mod.CaptureService()
    monkeypatch.setattr(capture_mod.multinode, "status", fake_status)
    monkeypatch.setattr(svc, "_known_host_names", lambda: {"master", "worker1"})

    targets = asyncio.run(svc.targets(lab))
    by_id = {t["id"]: t for t in targets}

    assert by_id["link:r1:eth1:r2:eth1:source"]["enabled"] is True
    assert by_id["link:r1:eth1:r2:eth1:target"]["host"] == "worker1"
    assert by_id["realnet:r1:eth2:real_net:vd"]["enabled"] is True
    assert by_id["mgmt:r1:eth0:mgmt"]["enabled"] is True


def test_capture_targets_keep_linux_iface_and_expose_vendor_display_label(tmp_path, monkeypatch):
    topo = Topology(
        name="dnlab-demo",
        nodes=[
            Node(name="r1", kind="cisco_xrv9k", image="vrnetlab/cisco_xrv9k:latest"),
            Node(name="r2", kind="cisco_n9kv", image="vrnetlab/cisco_n9kv:latest"),
        ],
        links=[Link(source="r1", source_iface="eth2", target="r2", target_iface="eth2")],
    )
    lab = _lab(tmp_path, topo)

    async def fake_status(_lab, emit_events=False):
        return _runtime()

    async def fake_validate_filter(_filter):
        return None

    svc = capture_mod.CaptureService()
    monkeypatch.setattr(capture_mod.multinode, "status", fake_status)
    monkeypatch.setattr(svc, "_known_host_names", lambda: {"master", "worker1"})
    monkeypatch.setattr(svc, "_validate_bpf_if_possible", fake_validate_filter)
    monkeypatch.setattr(capture_mod.settings, "TOPOLOGIES_DIR", tmp_path)

    targets = asyncio.run(svc.targets(lab))
    source = next(t for t in targets if t["id"] == "link:r1:eth2:r2:eth2:source")

    assert source["iface"] == "eth2"
    assert source["display_iface"] == "GigabitEthernet0/0/0/1"
    assert source["label"] == "r1 GigabitEthernet0/0/0/1 -> r2"

    launch = asyncio.run(svc.launch(
        lab=lab,
        user_id=1,
        target_id="link:r1:eth2:r2:eth2:source",
        side="source",
        bpf_filter="",
        snaplen=0,
        promisc=False,
        base_url="https://dnlab.example.com/",
    ))
    query = parse_qs(urlparse(launch["handler_url"]).query)

    assert launch["target"]["iface"] == "eth2"
    assert launch["target"]["display_iface"] == "GigabitEthernet0/0/0/1"
    assert query["title"] == ["Capture from VD r1 - interface GigabitEthernet0/0/0/1"]


def test_capture_target_disabled_when_duplicate_hosts(tmp_path, monkeypatch):
    topo = Topology(
        name="dnlab-demo",
        nodes=[
            Node(name="r1", kind="linux", image="alpine"),
            Node(name="r2", kind="linux", image="alpine"),
        ],
        links=[Link(source="r1", source_iface="eth1", target="r2", target_iface="eth1")],
    )
    lab = _lab(tmp_path, topo)
    runtime = _runtime()
    runtime["nodes"]["r1"]["duplicate_hosts"] = ["master", "worker1"]

    async def fake_status(_lab, emit_events=False):
        return runtime

    svc = capture_mod.CaptureService()
    monkeypatch.setattr(capture_mod.multinode, "status", fake_status)
    monkeypatch.setattr(svc, "_known_host_names", lambda: {"master", "worker1"})

    targets = asyncio.run(svc.targets(lab))
    source = next(t for t in targets if t["id"] == "link:r1:eth1:r2:eth1:source")

    assert source["enabled"] is False
    assert source["disabled_reason"] == "Node exists on duplicate hosts."
    assert capture_mod._disabled_code(source["disabled_reason"]) == "target_disabled"


def test_capture_launch_status_and_browser_handler(tmp_path, monkeypatch):
    topo = Topology(
        name="dnlab-demo",
        nodes=[
            Node(name="r1", kind="linux", image="alpine"),
            Node(name="r2", kind="linux", image="alpine"),
        ],
        links=[Link(source="r1", source_iface="eth1", target="r2", target_iface="eth1")],
    )
    lab = _lab(tmp_path, topo)

    async def fake_status(_lab, emit_events=False):
        return _runtime()

    async def fake_validate_filter(_filter):
        return None

    svc = capture_mod.CaptureService()
    monkeypatch.setattr(capture_mod.multinode, "status", fake_status)
    monkeypatch.setattr(svc, "_known_host_names", lambda: {"master", "worker1"})
    monkeypatch.setattr(svc, "_validate_bpf_if_possible", fake_validate_filter)
    monkeypatch.setattr(capture_mod.settings, "TOPOLOGIES_DIR", tmp_path)

    launch = asyncio.run(svc.launch(
        lab=lab,
        user_id=1,
        target_id="link:r1:eth1:r2:eth1:source",
        side="source",
        bpf_filter="",
        snaplen=0,
        promisc=False,
        base_url="https://dnlab.example.com/",
    ))
    token = launch["stream_url"].split("/api/captures/", 1)[1].split("/stream", 1)[0]
    status = asyncio.run(svc.token_status(token))

    assert status["ok"] is True
    assert status["target"]["id"] == "link:r1:eth1:r2:eth1:source"
    assert launch["handler_url"].startswith("dnlab-capture://open?")
    assert launch["status_url"].startswith("https://dnlab.example.com/api/captures/")
    assert launch["stream_url"].startswith("https://dnlab.example.com/api/captures/")
    assert "https%3A%2F%2Fdnlab.example.com%2Fapi%2Fcaptures%2F" in launch["handler_url"]
    assert "status_url=" in launch["handler_url"]
    assert "stream_url=" in launch["handler_url"]
    assert "status" in launch["status_url"]
    assert "commands" not in launch
    assert "launcher_download_urls" not in launch


def test_capture_reserve_cleans_stale_sessions():
    svc = capture_mod.CaptureService()
    for idx in range(capture_mod.MAX_USER_CAPTURES):
        session_id = f"stale-{idx}"
        svc._active[session_id] = capture_mod.ActiveCapture(
            session_id=session_id,
            user_id=1,
            lab_id="lab",
            target_id=f"target-{idx}",
            target={"id": f"target-{idx}"},
            started_at=0,
            deadline=0,
        )

    session_id = asyncio.run(svc._reserve(1, "lab", "target-live", {"id": "target-live"}))

    assert session_id in svc._active
    assert len(svc._active) == 1


def test_capture_active_captures_returns_target_summary():
    svc = capture_mod.CaptureService()
    svc._active["live"] = capture_mod.ActiveCapture(
        session_id="live",
        user_id=7,
        lab_id="lab",
        target_id="link:r1:eth1:r2:eth1:source",
        target={
            "id": "link:r1:eth1:r2:eth1:source",
            "node": "r1",
            "iface": "eth1",
            "side": "source",
            "kind": "link",
            "link": {
                "source": "r1",
                "source_iface": "eth1",
                "target": "r2",
                "target_iface": "eth1",
            },
        },
        started_at=time.monotonic(),
        deadline=999999999,
    )

    active = asyncio.run(svc.active_captures(lab_id="lab", user_id=7))

    assert len(active) == 1
    assert active[0]["target_id"] == "link:r1:eth1:r2:eth1:source"
    assert active[0]["link"]["source"] == "r1"
