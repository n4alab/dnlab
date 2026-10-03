from types import SimpleNamespace
import asyncio
from uuid import uuid4

import pytest
from starlette.requests import Request

from app.services import webui_service as webui_service_mod
from app.services.webui_service import WebUITunnel
from app.views.api import webui_routes
from app.views.api.webui_routes import (
    _find_jumphost_ssh_port,
    _is_valid_webui_hostname,
    _is_logout_path,
    _prepare_upstream_headers,
    WebUIOpenRequest,
    open_webui,
    webui_unavailable_page,
)


def _request(headers=None):
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "query_string": b"",
            "headers": raw_headers,
            "client": ("192.0.2.10", 12345),
            "server": ("token.example.test", 443),
        }
    )


def _tunnel():
    return WebUITunnel(
        token="abc123",
        lab_id="lab-1",
        lab_name="labnet",
        node_name="node1",
        vd_ip="10.0.0.5",
        vd_port=443,
        scheme="https",
        local_port=12345,
        process=SimpleNamespace(),
        user_id=1,
        opened_at=1.0,
        last_used_at=1.0,
    )


def test_prepare_headers_remembers_browser_authorization():
    tun = _tunnel()
    headers = _prepare_upstream_headers(
        _request({"Authorization": "Basic dXNlcjpwYXNz"}),
        tun,
    )

    assert headers["Authorization"] == "Basic dXNlcjpwYXNz"
    assert "authorization" not in headers
    assert tun.upstream_authorization == "Basic dXNlcjpwYXNz"


def test_prepare_headers_replays_saved_authorization_for_followup_assets():
    tun = _tunnel()
    tun.upstream_authorization = "Basic dXNlcjpwYXNz"

    headers = _prepare_upstream_headers(_request(), tun)

    assert headers["Authorization"] == "Basic dXNlcjpwYXNz"


def test_prepare_headers_filters_gui_cookie_while_replaying_auth(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "SESSION_COOKIE_NAME", "dnlab_session")
    tun = _tunnel()
    tun.upstream_authorization = "Basic dXNlcjpwYXNz"

    headers = _prepare_upstream_headers(
        _request({"Cookie": "dnlab_session=gui; Auth=device; theme=dark"}),
        tun,
    )

    assert headers["Cookie"] == "Auth=device; theme=dark"
    assert headers["Authorization"] == "Basic dXNlcjpwYXNz"


def test_prepare_headers_canonicalizes_csrf_and_rewrites_origin():
    tun = _tunnel()

    headers = _prepare_upstream_headers(
        _request({
            "Origin": "https://abc123.example.test",
            "x-csrf-token": "token-123",
        }),
        tun,
    )

    assert headers["Origin"] == "https://10.0.0.5"
    assert headers["X-Csrf-Token"] == "token-123"
    assert "origin" not in headers
    assert "x-csrf-token" not in headers


def test_prepare_headers_deduplicates_stale_deleted_cookie(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "SESSION_COOKIE_NAME", "dnlab_session")
    tun = _tunnel()

    headers = _prepare_upstream_headers(
        _request({
            "Cookie": "dnlab_session=gui; Auth=deleted; theme=dark; Auth=device"
        }),
        tun,
    )

    assert headers["Cookie"] == "theme=dark; Auth=device"


def test_logout_path_detection_is_generic():
    assert _is_logout_path("/webui/logout")
    assert _is_logout_path("api/v1/signout")
    assert _is_logout_path("/user/logoff")
    assert not _is_logout_path("/webui/login/assets/logout-icon.svg")


@pytest.mark.parametrize("hostname", ["dnlab.example.test", "lab.internal.example"])
def test_webui_proxy_hostname_validator_accepts_fqdn(hostname):
    assert _is_valid_webui_hostname(hostname)


@pytest.mark.parametrize("hostname", [
    "192.0.2.10", "2001:db8::10", "localhost", "dnlab", ".dnlab.example",
    "dnlab.example.", "dnlab..example", "bad_name.example",
])
def test_webui_proxy_hostname_validator_rejects_non_fqdn(hostname):
    assert not _is_valid_webui_hostname(hostname)


@pytest.mark.parametrize("host_suffix", [
    "192.0.2.10", "2001:db8::10", "localhost", "bad_name.example",
])
def test_open_webui_rejects_unavailable_suffix_before_creating_tunnel(
    monkeypatch, host_suffix,
):
    from app.config import settings

    async def forbidden_resolve(*args, **kwargs):
        raise AssertionError("a Web UI tunnel must not be considered in IP mode")

    monkeypatch.setattr(settings, "WEBUI_HOST_SUFFIX", host_suffix)
    monkeypatch.setattr(webui_routes, "resolve_for_read", forbidden_resolve)

    with pytest.raises(webui_routes.HTTPException) as exc_info:
        asyncio.run(open_webui(
            lab_id=uuid4(),
            node_name="node1",
            req=WebUIOpenRequest(scheme="https", port=443, path="/", label="Web UI"),
            request=_request({"Host": host_suffix}),
            db=SimpleNamespace(),
            user=SimpleNamespace(id=7),
        ))

    assert exc_info.value.status_code == 409
    assert "wildcard DNS" in exc_info.value.detail


def test_webui_unavailable_page_lists_only_safe_admin_contacts():
    captured = {}

    class FakeResult:
        def all(self):
            # The real query filters role and active status.  This response
            # represents the rows it returns, including a blank address that
            # must still be suppressed.
            return [
                ("alpha", "alpha@example.test"),
                ("unsafe<name>", "unsafe@example.test"),
                ("blank", "   "),
            ]

    class FakeDb:
        async def execute(self, statement):
            captured["statement"] = statement
            return FakeResult()

    response = asyncio.run(webui_unavailable_page(
        db=FakeDb(),
        _user=SimpleNamespace(id=7),
    ))

    body = response.body.decode("utf-8")
    query = str(captured["statement"])
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "Device Web UI is unavailable" in body
    assert "Please contact your administrator:" in body
    assert 'href="mailto:alpha@example.test"' in body
    assert "unsafe&lt;name&gt;" in body
    assert "blank" not in body
    assert "users.role" in query
    assert "users.is_active IS true" in query
    assert "users.email IS NOT NULL" in query


def test_openwrt_webui_uses_mgmt_ip_not_runtime_relay(monkeypatch):
    lab_id = uuid4()
    lab = SimpleNamespace(id=lab_id, netname="labnet", display_name="OpenWrt lab")
    opened = {}

    async def fake_resolve_for_read(db, requested_lab_id, user):
        assert requested_lab_id == lab_id
        return lab

    async def fake_status(resolved_lab, *, emit_events=False):
        assert resolved_lab is lab
        return {
            "nodes": {
                "openwrt1": {
                    "kind": "openwrt",
                    "container": "clab-dnlab-labnet-openwrt1-openwrt1",
                    "mgmt_ipv4": "172.20.42.10",
                }
            }
        }

    async def forbidden_relay(*args, **kwargs):
        raise AssertionError("WebUI must not use the runtime relay")

    def fake_open(**kwargs):
        opened.update(kwargs)
        return WebUITunnel(
            token="tok-openwrt",
            lab_id=str(lab_id),
            lab_name="labnet",
            node_name="openwrt1",
            vd_ip=kwargs["vd_ip"],
            vd_port=kwargs["vd_port"],
            scheme=kwargs["scheme"],
            local_port=18080,
            process=SimpleNamespace(),
            user_id=kwargs["user_id"],
            opened_at=1.0,
            last_used_at=1.0,
        )

    monkeypatch.setattr(webui_routes, "resolve_for_read", fake_resolve_for_read)
    monkeypatch.setattr(webui_routes.multinode_mod.multinode, "status", fake_status)
    monkeypatch.setattr(webui_routes.multinode_mod.multinode, "resolve_runtime_relay", forbidden_relay)
    monkeypatch.setattr(webui_routes.webui_service, "open", fake_open)

    response = asyncio.run(open_webui(
        lab_id=lab_id,
        node_name="openwrt1",
        req=WebUIOpenRequest(scheme="http", port=80, path="/cgi-bin/luci", label="LuCI"),
        request=_request({"Host": "dnlab.example.test", "X-Forwarded-Proto": "https"}),
        db=SimpleNamespace(),
        user=SimpleNamespace(id=7),
    ))

    assert opened["vd_ip"] == "172.20.42.10"
    assert opened["vd_port"] == 80
    assert opened["scheme"] == "http"
    assert response.url == "https://tok-openwrt.example.test/cgi-bin/luci"


def test_find_jumphost_ssh_port_reads_infra_block():
    report = {"infra": {"jumphost": {"ssh_port": 2200}}}
    assert _find_jumphost_ssh_port(report) == 2200


def test_find_jumphost_ssh_port_missing_or_invalid_returns_none():
    assert _find_jumphost_ssh_port({}) is None
    assert _find_jumphost_ssh_port({"infra": {}}) is None
    assert _find_jumphost_ssh_port({"infra": {"jumphost": {}}}) is None
    assert _find_jumphost_ssh_port({"infra": {"jumphost": {"ssh_port": None}}}) is None
    assert _find_jumphost_ssh_port({"infra": {"jumphost": {"ssh_port": 0}}}) is None
    assert _find_jumphost_ssh_port({"infra": {"jumphost": {"ssh_port": "nope"}}}) is None


def test_open_webui_passes_jumphost_ssh_port(monkeypatch):
    lab_id = uuid4()
    lab = SimpleNamespace(id=lab_id, netname="labnet", display_name="lab")
    opened = {}

    async def fake_resolve_for_read(db, requested_lab_id, user):
        return lab

    async def fake_status(resolved_lab, *, emit_events=False):
        return {
            "nodes": {"node1": {"kind": "opnsense", "mgmt_ipv4": "10.0.0.5"}},
            "infra": {"jumphost": {"ssh_port": 2200}},
        }

    def fake_open(**kwargs):
        opened.update(kwargs)
        return _tunnel()

    monkeypatch.setattr(webui_routes, "resolve_for_read", fake_resolve_for_read)
    monkeypatch.setattr(webui_routes.multinode_mod.multinode, "status", fake_status)
    monkeypatch.setattr(webui_routes.webui_service, "open", fake_open)

    asyncio.run(open_webui(
        lab_id=lab_id,
        node_name="node1",
        req=WebUIOpenRequest(scheme="https", port=443, path="/", label="OPNsense"),
        request=_request({"Host": "dnlab.example.test"}),
        db=SimpleNamespace(),
        user=SimpleNamespace(id=7),
    ))

    assert opened["jh_port"] == 2200
    assert opened["vd_ip"] == "10.0.0.5"


def test_webui_service_builds_ssh_command_with_published_port(monkeypatch):
    """With jh_port the tunnel targets the jumphost's published port on
    the master host (``-p <port> labuser@<JUMPHOST_HOST>``)."""
    from app.config import settings

    recorded = {}

    class _FakeProc:
        returncode = None

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_popen(cmd, **kwargs):
        recorded["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(webui_service_mod, "_pick_free_port", lambda: 40000)
    monkeypatch.setattr(webui_service_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(webui_service_mod, "_wait_for_bind", lambda *a, **k: None)
    monkeypatch.setattr(settings, "JUMPHOST_HOST", "host.docker.internal")
    monkeypatch.setattr(settings, "JUMPHOST_USER", "labuser")

    svc = webui_service_mod.WebUIService()
    svc.open(
        lab_id="lab-1", lab_name="labnet", node_name="node1",
        vd_ip="10.0.0.5", vd_port=443, scheme="https", user_id=1,
        jh_port=2200,
    )

    cmd = recorded["cmd"]
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "2200"
    assert cmd[-1] == "labuser@host.docker.internal"
    assert "-L" in cmd
    assert cmd[cmd.index("-L") + 1] == "127.0.0.1:40000:10.0.0.5:443"
    # Throwaway known_hosts: jumphost host keys rotate per redeploy and
    # /root/.ssh is read-only, so persist nothing and stay quiet.
    assert "UserKnownHostsFile=/dev/null" in cmd
    assert "LogLevel=ERROR" in cmd


def test_webui_service_falls_back_to_container_name_without_port(monkeypatch):
    """Without jh_port (legacy GUI-on-master) the tunnel resolves the
    jumphost by container name and adds no ``-p``."""
    from app.config import settings

    recorded = {}

    class _FakeProc:
        returncode = None

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_popen(cmd, **kwargs):
        recorded["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(webui_service_mod, "_pick_free_port", lambda: 40000)
    monkeypatch.setattr(webui_service_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(webui_service_mod, "_wait_for_bind", lambda *a, **k: None)
    monkeypatch.setattr(settings, "JUMPHOST_USER", "labuser")

    svc = webui_service_mod.WebUIService()
    svc.open(
        lab_id="lab-1", lab_name="labnet", node_name="node1",
        vd_ip="10.0.0.5", vd_port=443, scheme="https", user_id=1,
    )

    cmd = recorded["cmd"]
    assert "-p" not in cmd
    assert cmd[-1] == "labuser@dnlab-labnet-jumphost"


def test_openwrt_webui_without_mgmt_ip_still_returns_409(monkeypatch):
    lab_id = uuid4()
    lab = SimpleNamespace(id=lab_id, netname="labnet", display_name="OpenWrt lab")

    async def fake_resolve_for_read(db, requested_lab_id, user):
        return lab

    async def fake_status(resolved_lab, *, emit_events=False):
        return {"nodes": {"openwrt1": {"kind": "openwrt", "mgmt_ipv4": ""}}}

    monkeypatch.setattr(webui_routes, "resolve_for_read", fake_resolve_for_read)
    monkeypatch.setattr(webui_routes.multinode_mod.multinode, "status", fake_status)

    with pytest.raises(webui_routes.HTTPException) as exc:
        asyncio.run(open_webui(
            lab_id=lab_id,
            node_name="openwrt1",
            req=WebUIOpenRequest(scheme="http", port=80, path="/", label="LuCI"),
            request=_request({"Host": "dnlab.example.test"}),
            db=SimpleNamespace(),
            user=SimpleNamespace(id=7),
        ))

    assert exc.value.status_code == 409
