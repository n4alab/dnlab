"""Reverse proxy verso la Web UI dei VD, stile console Proxmox/vmware.

Routing:

* ``POST /api/labs/{lab_id}/nodes/{node_name}/webui/open`` — open (or
  riusa) un tunnel SSH verso ``<vd_ip>:<port>`` attraverso il jumphost
  of the lab and returns the relative URL ``/webui/<token>/<path>`` to open
  in una nuova scheda.
* ``POST /api/labs/{lab_id}/nodes/{node_name}/webui/close`` — closes
  il tunnel (opzionale: l'idle timeout lo fa comunque).
* ``ANY /webui/{token}/{path:path}`` — reverse proxy HTTP: inoltra
  richieste e risposte a ``127.0.0.1:<local_port>`` (l'endpoint
  locale del tunnel ssh), con ``verify=False`` sul TLS upstream
  (certificato self-signed del VD muore qui, il browser vede il cert
  Apache davanti alla GUI → A3).
* ``WS /webui/{token}/{path:path}`` — WebSocket proxy full-duplex.

Step iniziale (questo commit): solo HTTP con rewriting del ``Location``
header. HTML/CSS body rewrite + WebSocket proxy arrivano negli step
successivi.
"""

from __future__ import annotations

import asyncio
from html import escape
import ipaddress
import logging
import re
import ssl as _ssl
from typing import Annotated, Optional
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID

import httpx
import websockets
from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import HTMLResponse, PlainTextResponse

from app.auth.db import AsyncSessionLocal, get_session
from app.auth.deps import authenticate_ws, get_current_user
from app.auth.models import Role, User
from app.config import settings
from app.security import reject_if_bad_origin
from app.services import multinode_service as multinode_mod
from app.services.lab_resolver import resolve_for_read
from app.services.shutdown_registry import shutdown_registry
from app.services.webui_service import (
    WebUITunnel, WebUITunnelError, webui_service,
)

log = logging.getLogger(__name__)
router = APIRouter()

# Header che NON devono essere inoltrati (hop-by-hop o sensibili).
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
    # Non propaghiamo l'Host (lo riscriviamo) e non passiamo avanti il
    # nostro cookie di sessione: il VD non lo capisce e potrebbe
    # reject it, and it is noise anyway.
    "host", "cookie",
}
_RESPONSE_STRIP = {
    "content-length", "content-encoding", "transfer-encoding", "connection",
    # Non vogliamo che il VD possa dettare CSP/XFO al browser sul
    # nostro hostname: riscriviamo i rischi in header sicuri di default.
    "content-security-policy", "content-security-policy-report-only",
    "x-frame-options",
}

_WEBUI_FQDN_REQUIRED = (
    "Device Web UI proxying requires a DNS hostname, wildcard DNS, and a TLS "
    "certificate covering the hostname and its wildcard subdomain."
)


class WebUIHostProxyMiddleware:
    """Host-based WebUI proxy for ``<token>.<webui-host-suffix>``.

    Path-prefix proxying is kept for compatibility, but the host-based
    mode is the production path for device UIs because it preserves
    root-relative URLs, cookies and websocket endpoints exactly as the
    device expects them.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        token = _webui_token_from_scope(scope)
        if not token:
            await self.app(scope, receive, send)
            return

        path = (scope.get("path") or "/").lstrip("/")
        if scope["type"] == "websocket":
            websocket = WebSocket(scope, receive=receive, send=send)
            await _proxy_websocket(
                websocket, token, path,
                require_user=False,
                host_mode=True,
            )
            return

        request = Request(scope, receive=receive)
        try:
            response = await _proxy_http(
                token, path, request,
                user=None,
                require_owner=False,
                host_mode=True,
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            response = PlainTextResponse(detail, status_code=exc.status_code)
        await response(scope, receive, send)


# ── Open / Close ─────────────────────────────────────────────────────

class WebUIOpenRequest(BaseModel):
    scheme: str = "https"
    port: int = 443
    path: str = "/"
    label: str = ""


class WebUIOpenResponse(BaseModel):
    token: str
    url: str            # "/webui/<token>/<path>"
    local_port: int
    expires_in_s: int
    label: str


@router.get("/webui/unavailable", response_class=HTMLResponse, include_in_schema=False)
async def webui_unavailable_page(
    db: Annotated[AsyncSession, Depends(get_session)],
    _user: Annotated[User, Depends(get_current_user)],
) -> HTMLResponse:
    """Explain why a browser VD Web UI cannot be opened in IP mode.

    This is intentionally a normal authenticated GUI page.  The tunnel-open
    API remains responsible for returning 409 before it can start an SSH
    process.
    """
    rows = (await db.execute(
        select(User.username, User.email)
        .where(
            User.role == Role.admin,
            User.is_active.is_(True),
            User.email.is_not(None),
        )
        .order_by(User.username)
    )).all()
    contacts = [
        (username, email.strip()) for username, email in rows if email and email.strip()
    ]
    contact_html = ""
    if contacts:
        items = "".join(
            "<li><a href=\"mailto:{mailto}\">{email}</a>"
            " <span>({username})</span></li>".format(
                mailto=escape(quote(email, safe="@._+-"), quote=True),
                email=escape(email),
                username=escape(username),
            )
            for username, email in contacts
        )
        contact_html = (
            "<p>Please contact your administrator:</p>"
            f"<ul>{items}</ul>"
        )
    else:
        contact_html = "<p>Please contact your administrator.</p>"

    return HTMLResponse(
        content=(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>Device Web UI unavailable</title>"
            "<style>body{margin:0;background:#f5f7fb;color:#18212f;font:16px/1.5 "
            "system-ui,sans-serif}main{max-width:680px;margin:10vh auto;padding:32px;"
            "background:#fff;border-radius:10px;box-shadow:0 4px 18px #0002}"
            "h1{margin-top:0;color:#9d2736}a{color:#175fa8}</style></head><body><main>"
            "<h1>Device Web UI is unavailable</h1>"
            "<p>Device Web UI proxying requires a DNS hostname, wildcard DNS, and "
            "a TLS certificate covering the hostname and its wildcard subdomain.</p>"
            "<p>The dNLab GUI, consoles, and logs remain available with the current "
            "configuration.</p>"
            f"{contact_html}</main></body></html>"
        ),
        headers={"Cache-Control": "no-store"},
    )


@router.post(
    "/api/labs/{lab_id}/nodes/{node_name}/webui/open",
    response_model=WebUIOpenResponse,
)
async def open_webui(
    lab_id: UUID,
    node_name: str,
    req: WebUIOpenRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> WebUIOpenResponse:
    if not _webui_proxy_is_available(request):
        raise HTTPException(409, _WEBUI_FQDN_REQUIRED)

    lab = await resolve_for_read(db, lab_id, user)

    # Recuperiamo l'IP mgmt del VD dal report live del multinode. Non
    # we can derive it from the topology file: it is assigned by containerlab
    # quando deploya.
    try:
        live = await multinode_mod.multinode.status(lab, emit_events=False)
    except multinode_mod.MultinodeServiceError as exc:
        raise HTTPException(404, f"lab non attivo o non trovato: {exc}") from exc
    vd_ip = _find_node_ip(live, node_name)
    if not vd_ip:
        raise HTTPException(
            409,
            f"node '{node_name}' non in esecuzione o senza IP mgmt — "
            f"the tunnel can only be opened when the lab is started",
        )

    # The dockerized GUI shares no docker network with the per-lab
    # jumphost, so it reaches it through the SSH port the jumphost
    # publishes on the master host. ``ssh_port`` is exposed in the live
    # report's ``infra.jumphost`` block. When absent (legacy GUI-on-master
    # deployments) webui_service falls back to resolving by container name.
    jh_port = _find_jumphost_ssh_port(live)

    try:
        tun = webui_service.open(
            lab_id=str(lab_id),
            lab_name=lab.netname,
            node_name=node_name,
            vd_ip=vd_ip,
            vd_port=req.port,
            scheme=req.scheme,
            user_id=user.id,
            path=req.path or "/",
            label=req.label,
            jh_port=jh_port,
        )
    except WebUITunnelError as exc:
        raise HTTPException(502, str(exc)) from exc

    path = req.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    from app.services.webui_service import IDLE_TIMEOUT_S
    return WebUIOpenResponse(
        token=tun.token,
        url=_public_webui_url(request, tun, path),
        local_port=tun.local_port,
        expires_in_s=IDLE_TIMEOUT_S,
        label=req.label or node_name,
    )


@router.post("/api/labs/{lab_id}/nodes/{node_name}/webui/close")
async def close_webui(
    lab_id: UUID,
    node_name: str,
    port: int,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    # Leggere il lab serve solo a enforce-are i permessi.
    await resolve_for_read(db, lab_id, user)
    closed = webui_service.close_by_key(str(lab_id), node_name, port)
    return {"closed": bool(closed)}


# ── Reverse proxy ────────────────────────────────────────────────────

@router.api_route(
    "/webui/{token}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def webui_proxy(
    token: str,
    path: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    return await _proxy_http(
        token, path, request,
        user=user,
        require_owner=True,
        host_mode=False,
    )


async def _proxy_http(
    token: str,
    path: str,
    request: Request,
    *,
    user: User | None,
    require_owner: bool,
    host_mode: bool,
) -> Response:
    tun = _get_tunnel_or_404(token)
    if require_owner and (user is None or tun.user_id != user.id):
        # Tunnel exists but belongs to another operator: do not leak it.
        raise HTTPException(404, "tunnel non trovato")
    webui_service.touch(token)

    upstream_url = _upstream_url(tun, path, request.url.query, host_mode=host_mode)
    if _is_logout_path(path):
        tun.upstream_authorization = None
    headers = _prepare_upstream_headers(request, tun, host_mode=host_mode)
    body = await request.body()

    try:
        async with httpx.AsyncClient(
            verify=False,          # A3: intercettiamo il self-signed del VD
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=False,
        ) as client:
            r = await client.request(
                request.method, upstream_url,
                content=body or None,
                headers=headers,
            )
    except httpx.ConnectTimeout as exc:
        log.warning("webui proxy: connect timeout token=%s: %s", token, exc)
        raise HTTPException(504, "upstream connection timeout") from exc
    except httpx.ReadTimeout as exc:
        log.warning("webui proxy: read timeout token=%s: %s", token, exc)
        raise HTTPException(504, "upstream timeout") from exc
    except httpx.TimeoutException as exc:
        log.warning("webui proxy: timeout token=%s: %s", token, exc)
        raise HTTPException(504, "upstream timeout") from exc
    except httpx.ConnectError as exc:
        log.warning("webui proxy: connect error token=%s: %s", token, exc)
        raise HTTPException(502, f"upstream unreachable: {exc}") from exc
    except httpx.RequestError as exc:
        log.warning("webui proxy: request error token=%s: %s", token, exc)
        raise HTTPException(502, f"upstream request failed: {exc}") from exc

    if r.status_code == 401:
        tun.upstream_authorization = None

    # Body: for text/html and text/css, rewrite absolute URLs so
    # che il browser resti sotto /webui/<tok>/. Altri content-type (json,
    # js, images, font…) passano invariati.
    body_bytes = r.content  # httpx has already decompressed gzip/deflate/br
    ct = r.headers.get("content-type", "")
    encoding = r.headers.get("content-encoding", "").lower()
    rewritten = False
    if _is_rewritable(ct) and not encoding.startswith(("br",)):
        try:
            charset = _extract_charset(ct) or "utf-8"
            text = body_bytes.decode(charset, errors="replace")
            text = _rewrite_body(text, ct, tun, host_mode=host_mode)
            body_bytes = text.encode(charset, errors="replace")
            rewritten = True
        except Exception as exc:
            log.warning("webui proxy: body rewrite failed for %s: %s",
                        upstream_url, exc)

    resp = Response(content=body_bytes, status_code=r.status_code)
    # raw_headers preserva ordine + duplicati (necessario for multi
    # Set-Cookie che starlette non gestisce via dict).
    resp.raw_headers = _build_response_headers(
        r.headers, tun,
        host_mode=host_mode,
        new_length=len(body_bytes) if rewritten else None,
    )
    return resp


# ── Helpers ──────────────────────────────────────────────────────────

def _get_tunnel_or_404(token: str) -> WebUITunnel:
    tun = webui_service.get(token)
    if not tun:
        raise HTTPException(404, "tunnel non trovato o scaduto")
    return tun


def _public_webui_url(request: Request, tun: WebUITunnel, path: str) -> str:
    host = _external_host(request)
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    suffix = _webui_host_suffix(host)
    if not suffix:
        # Dev/loopback fallback: no valid wildcard host can be derived.
        return f"/webui/{tun.token}{path}"
    return f"{scheme}://{tun.token}.{suffix}{path}"


def _external_host(request: Request) -> str:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    # X-Forwarded-Host may contain a comma-separated chain.
    host = host.split(",", 1)[0].strip().lower()
    if host.startswith("["):
        return host
    return host.split(":", 1)[0]


def _webui_host_suffix(gui_host: str) -> str:
    configured = settings.WEBUI_HOST_SUFFIX
    if configured:
        return configured.lower()
    host = (gui_host or "").strip(".").lower()
    if not host or host in ("localhost", "127.0.0.1") or host.startswith("127."):
        return ""
    if host.startswith("webui."):
        return host[len("webui."):]
    if ".webui." in host:
        return host.split(".webui.", 1)[1]
    parts = host.split(".", 1)
    return parts[1] if len(parts) == 2 else host


def _webui_proxy_is_available(request: Request) -> bool:
    """Whether this request can mint a wildcard-host Web UI URL."""
    suffix = settings.WEBUI_HOST_SUFFIX or _webui_host_suffix(_external_host(request))
    return _is_valid_webui_hostname(suffix)


def _is_valid_webui_hostname(value: str) -> bool:
    """Return true only for an FQDN suitable for token subdomains."""
    host = (value or "").strip()
    if host.startswith(".") or host.endswith("."):
        return False
    if not host or len(host) > 253 or host.lower() == "localhost":
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    if not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+",
        host,
    ):
        return False
    return bool(re.search(r"[A-Za-z]", host))


def _webui_token_from_scope(scope) -> str | None:
    host = ""
    for k, v in scope.get("headers") or []:
        if k.lower() == b"host":
            host = v.decode("latin-1", errors="ignore").split(":", 1)[0].lower()
            break
    if not host:
        return None

    suffix = settings.WEBUI_HOST_SUFFIX.lower() if settings.WEBUI_HOST_SUFFIX else ""
    if suffix:
        tail = "." + suffix
        if not host.endswith(tail):
            return None
        token = host[:-len(tail)]
    else:
        marker = ".webui."
        if marker in host:
            token = host.split(marker, 1)[0]
        else:
            token = host.split(".", 1)[0]

    # One DNS label only. Tokens are hex, so this is intentionally tight.
    if re.fullmatch(r"[a-f0-9]{16,64}", token or ""):
        return token
    return None


'''def _find_node_ip(live_report: dict, node_name: str) -> Optional[str]:
    # Il report del multinode espone le containers come lista di dict
    # con chiavi "node_name" e "ipv4_address" (vedi
    # app/services/containerlab_service.py).
    for c in (live_report or {}).get("containers", []) or []:
        if c.get("node_name") == node_name and c.get("ipv4_address"):
            return c["ipv4_address"]
    # Alcuni report espongono "nodes" con "name"/"ipv4" — proviamo come
    # fallback.
    for n in (live_report or {}).get("nodes", []) or []:
        if n.get("name") == node_name and n.get("ipv4"):
            return n["ipv4"]
    return None'''

def _find_node_ip(live_report: dict, node_name: str) -> Optional[str]:
    # Formato usato dagli snapshot Lab/ContainerInfo: lista di dict
    # con "node_name" e "ipv4_address".
    for c in (live_report or {}).get("containers", []) or []:
        if not isinstance(c, dict):
            continue
        if c.get("node_name") == node_name and c.get("ipv4_address"):
            return c["ipv4_address"]

    # Formato reale di dnlab_multinode.status().to_dict():
    # "nodes" is a dict {node_name: node_status}, and the mgmt IP is
    # esposto come "mgmt_ipv4".
    nodes = (live_report or {}).get("nodes") or {}
    if isinstance(nodes, dict):
        n = nodes.get(node_name) or {}
        if isinstance(n, dict):
            return n.get("mgmt_ipv4") or n.get("ipv4") or None

    # Compatibility with possible legacy reports where "nodes" era una
    # lista di dict con "name"/"ipv4".
    if isinstance(nodes, list):
        for n in nodes:
            if not isinstance(n, dict):
                continue
            if n.get("name") == node_name:
                return n.get("mgmt_ipv4") or n.get("ipv4") or None

    return None


def _find_jumphost_ssh_port(live_report: dict) -> Optional[int]:
    """Return the jumphost SSH port published on the master, if any.

    Comes from ``infra.jumphost.ssh_port`` in the multinode status report
    (see StatusController). Returns ``None`` when the lab has no jumphost
    block or the port is unset, in which case callers fall back to
    container-name resolution.
    """
    jh = ((live_report or {}).get("infra") or {}).get("jumphost") or {}
    if not isinstance(jh, dict):
        return None
    port = jh.get("ssh_port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _upstream_url(
    tun: WebUITunnel,
    path: str,
    query: str,
    *,
    host_mode: bool = False,
) -> str:
    # Path normalization (the endpoint path is the part "after" /webui/<tok>/)
    upstream_path = "/" + path.lstrip("/")
    # Se for qualche motivo il client attacca "/webui/<tok>" dentro il path
    # (esempio: redirect assoluto non riscritto a monte), lo normalizziamo.
    prefix = f"/webui/{tun.token}"
    if not host_mode and upstream_path.startswith(prefix):
        upstream_path = upstream_path[len(prefix):] or "/"
    url = f"{tun.scheme}://127.0.0.1:{tun.local_port}{upstream_path}"
    if query:
        url += f"?{query}"
    return url


def _prepare_upstream_headers(
    request: Request,
    tun: WebUITunnel,
    *,
    host_mode: bool = False,
) -> dict[str, str]:
    hdr = {}
    for k, v in request.headers.items():
        if k.lower() in _HOP_BY_HOP:
            continue
        lk = k.lower()
        if lk == "referer":
            # Lo rimettiamo esplicitamente sotto via _rewrite_referer_to_upstream;
            # senza saltarlo qui finiremmo con due chiavi distinte (case-sensitive
            # in dict Python: "referer" del browser + "Referer" riscritto), che
            # httpx serializza entrambe e i backend tipo OPNsense/PHP fondono
            # con virgola, rompendo il check del Referer.
            continue
        if lk == "origin":
            continue
        if lk in _CSRF_HEADER_NAMES:
            continue
        if lk == "authorization":
            continue
        hdr[k] = v
    # Il VD si aspetta l'Host di chi lo ospita (l'IP del VD stesso +
    # port). Many UIs validate the Host header or use it to build
    # URL assoluti nelle risposte.
    host_hdr = f"{tun.vd_ip}:{tun.vd_port}" if tun.vd_port not in (80, 443) else tun.vd_ip
    hdr["Host"] = host_hdr
    # Ricostruiamo X-Forwarded-* for VD-side traceability (alcuni UI
    # li loggano ma non li usano for security).
    fwd = request.headers.get("x-forwarded-for")
    peer = request.client.host if request.client else ""
    hdr["X-Forwarded-For"] = f"{fwd}, {peer}" if fwd else peer
    hdr["X-Forwarded-Proto"] = request.url.scheme
    # Ricostruiamo anche un Referer coerente col punto di vista del VD
    # se il browser ne ha mandato uno.
    ref = request.headers.get("referer")
    if ref:
        hdr["Referer"] = _rewrite_referer_to_upstream(ref, tun, host_mode=host_mode)
    origin = request.headers.get("origin")
    if origin:
        hdr["Origin"] = _rewrite_origin_to_upstream(origin, tun)
    _apply_csrf_headers(request, hdr)
    # Cookie forwarding: passiamo tutti i cookie ECCETTO il nostro
    # `dnlab_session` — that is for the GUI, not the VD.
    cookie_hdr = request.headers.get("cookie")
    if cookie_hdr:
        from app.config import settings as _s
        filtered = _strip_cookie(cookie_hdr, _s.SESSION_COOKIE_NAME)
        if filtered:
            hdr["Cookie"] = filtered
    _apply_upstream_authorization(request, tun, hdr)
    return hdr


_CSRF_HEADER_NAMES = {
    "x-csrf-token": "X-Csrf-Token",
    "x-xsrf-token": "X-XSRF-Token",
    "csrf-token": "Csrf-Token",
}


def _apply_csrf_headers(request: Request, hdr: dict[str, str]) -> None:
    """Forward common CSRF headers with canonical casing.

    HTTP headers are case-insensitive, but several appliance UIs are backed by
    older stacks that are picky when custom headers arrive in lowercase through
    a proxy. Keep this generic and value-preserving.
    """
    for incoming, outgoing in _CSRF_HEADER_NAMES.items():
        value = request.headers.get(incoming)
        if value:
            hdr[outgoing] = value


def _apply_upstream_authorization(
    request: Request,
    tun: WebUITunnel,
    hdr: dict[str, str],
) -> None:
    """Remember per-tunnel upstream auth and replay it for follow-up assets.

    Some device UIs authenticate through an XHR carrying ``Authorization``
    and then load scripts, CSS or API resources without repeating the header.
    Browsers do not necessarily promote that XHR header to later requests, so
    the proxy keeps it only in memory for the tunnel lifetime.
    """
    auth = request.headers.get("authorization")
    if auth:
        tun.upstream_authorization = auth
        hdr["Authorization"] = auth
    elif tun.upstream_authorization and "Authorization" not in hdr:
        hdr["Authorization"] = tun.upstream_authorization


def _is_logout_path(path: str) -> bool:
    segments = [seg for seg in (path or "").lower().split("/") if seg]
    logout_names = ("logout", "logoff", "signout")
    return any(
        seg in logout_names or any(seg.startswith(f"{name}.") for name in logout_names)
        for seg in segments
    )


def _build_response_headers(
    upstream: httpx.Headers,
    tun: WebUITunnel,
    *,
    host_mode: bool = False,
    new_length: int | None = None,
) -> list[tuple[bytes, bytes]]:
    """Costruisce i ``raw_headers`` for la Response inoltrata al browser.

    Return a list of (name, value) byte pairs so
    duplicates are preserved (typically Set-Cookie: the VD can send more than one and
    `dict[str,str]` li collasserebbe).
    """
    out: list[tuple[bytes, bytes]] = []
    seen_length = False
    for k, v in upstream.multi_items():  # preserva duplicati
        lk = k.lower()
        if lk in _RESPONSE_STRIP:
            continue
        if lk == "location":
            out.append((k.encode("latin-1"),
                        _rewrite_location(v, tun, host_mode=host_mode).encode("latin-1")))
            continue
        if lk == "set-cookie":
            out.append((k.encode("latin-1"),
                        _rewrite_cookie_attrs(v, tun, host_mode=host_mode).encode("latin-1")))
            continue
        if lk == "content-length" and new_length is not None:
            out.append((b"content-length", str(new_length).encode("ascii")))
            seen_length = True
            continue
        out.append((k.encode("latin-1"), v.encode("latin-1", errors="replace")))
    if new_length is not None and not seen_length:
        out.append((b"content-length", str(new_length).encode("ascii")))
    return out


# ── Body rewriting (html/css) ────────────────────────────────────────

_REWRITABLE_CT = (
    "text/html", "text/css",
    "application/xhtml+xml", "application/xml+xhtml",
)


def _is_rewritable(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in _REWRITABLE_CT)


def _extract_charset(content_type: str) -> str | None:
    m = re.search(r"charset\s*=\s*([A-Za-z0-9_\-:.+]+)", content_type or "", re.I)
    return m.group(1) if m else None


_HTML_ATTR_RE = re.compile(
    r'''(?ix)
    \b
    (?P<attr>href|src|action|formaction|data|poster|cite|longdesc|background|srcset|manifest)
    \s*=\s*
    (?P<quote>["'])(?P<val>[^"']*)(?P=quote)
    '''
)
_CSS_URL_RE = re.compile(
    r'''url\(\s*(?P<quote>["']?)(?P<val>[^)"']+)(?P=quote)\s*\)''', re.I,
)
_HTML_META_REFRESH_RE = re.compile(
    r'''(?ix)
    (<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*)
    (?P<val>[^"']+)
    ''',
)


def _rewrite_body(
    text: str,
    content_type: str,
    tun: WebUITunnel,
    *,
    host_mode: bool = False,
) -> str:
    """Riscrive gli URL assoluti (all'upstream) e root-relativi dentro
    HTML/CSS so the browser stays under ``/webui/<tok>/``.

    Casi trattati:

    * ``href="/login"``                → ``href="/webui/<tok>/login"``
    * ``href="https://<vd_ip>/foo"``   → ``href="/webui/<tok>/foo"``
    * ``url(/static/x.css)`` (CSS)     → ``url("/webui/<tok>/static/x.css")``
    * ``srcset="/a.jpg 1x, /b.jpg 2x"``→ ogni URL riscritto
    * ``<meta http-equiv=refresh … url=/foo>`` → ditto

    URL protocol-relative ``//cdn.example.com/...``, assoluti a host
    esterni, ``data:``, ``javascript:`` e frammenti ``#xyz`` vengono
    lasciati invariati.
    """
    prefix = "" if host_mode else f"/webui/{tun.token}"
    ct = (content_type or "").lower()

    def fix_url(raw: str) -> str:
        v = raw.strip()
        if not v or v.startswith("#"):
            return raw
        low = v.lower()
        # Scheme non-http (data:, javascript:, mailto:, blob:, tel:…)
        if ":" in v[:20] and not low.startswith(("http://", "https://")):
            return raw
        # protocol-relative: cdn esterno, lasciamo stare
        if v.startswith("//"):
            return raw
        if prefix and v.startswith(prefix):
            return raw  # already rewritten (idempotency)
        m = _ABS_URL.match(v)
        if m:
            _, host, rest = m.groups()
            if _is_upstream_host(host, tun):
                return f"{prefix}{rest or '/'}"
            return raw
        if v.startswith("/"):
            if host_mode:
                return raw
            return f"{prefix}{v}"
        return raw  # relative: delegato al browser

    if "text/css" in ct:
        return _CSS_URL_RE.sub(
            lambda m: f'url("{fix_url(m.group("val"))}")', text,
        )

    def _attr_sub(m: re.Match) -> str:
        attr = m.group("attr")
        q = m.group("quote")
        val = m.group("val")
        if attr.lower() == "srcset":
            parts = []
            for item in val.split(","):
                item = item.strip()
                if not item:
                    continue
                url_part, *desc = item.split(None, 1)
                parts.append(" ".join([fix_url(url_part), *desc]).strip())
            return f'{attr}={q}{", ".join(parts)}{q}'
        return f'{attr}={q}{fix_url(val)}{q}'

    text = _HTML_ATTR_RE.sub(_attr_sub, text)
    text = _CSS_URL_RE.sub(
        lambda m: f'url("{fix_url(m.group("val"))}")', text,
    )
    text = _HTML_META_REFRESH_RE.sub(
        lambda m: f"{m.group(1)}{fix_url(m.group('val'))}", text,
    )
    return text


def _is_upstream_host(host: str, tun: WebUITunnel) -> bool:
    """True se ``host`` (potenzialmente con :port) coincide con il VD."""
    h = host.split(":")[0].lower()
    if h == tun.vd_ip.lower():
        return True
    if h in ("localhost", "127.0.0.1"):
        return True
    return False


# Il rewrite del Location: accettiamo tre casi.
#
# 1. URL assoluto verso il VD:
#      https://10.0.0.5/login   →   /webui/<tok>/login
#    (the host can be the VD private IP or the name the VD puts
#    nei suoi header: in entrambi i casi lo spostiamo sotto il nostro
#    prefix).
#
# 2. URL relativo al root:
#      /login   →   /webui/<tok>/login
#
# 3. URL relative to the current path:
#      ./foo  o  foo   →   lo lasciamo invariato, il browser lo
#    will resolve from the current URL (`/webui/<tok>/<...>`) e will work.

_ABS_URL = re.compile(r"^(https?)://([^/]+)(/.*)?$", re.IGNORECASE)

def _rewrite_location(
    value: str,
    tun: WebUITunnel,
    *,
    host_mode: bool = False,
) -> str:
    v = value.strip()
    m = _ABS_URL.match(v)
    if m:
        _, host, rest = m.groups()
        if host_mode and not _is_upstream_host(host, tun):
            return value
        new_path = rest or "/"
        if host_mode:
            return new_path
        return f"/webui/{tun.token}{new_path}"
    if v.startswith("/"):
        if host_mode:
            return value
        return f"/webui/{tun.token}{v}"
    return value  # relative: delegate to browser


def _rewrite_referer_to_upstream(
    referer: str,
    tun: WebUITunnel,
    *,
    host_mode: bool = False,
) -> str:
    """Se l'operatore sta navigando dentro /webui/<tok>/, il browser
    sends Referer with our prefix. The VD will expect a Referer
    che inizia con il suo scheme+host — lo spoofiamo."""
    try:
        parts = urlsplit(referer)
    except ValueError:
        return referer
    prefix = f"/webui/{tun.token}"
    path = parts.path
    if not host_mode and path.startswith(prefix):
        path = path[len(prefix):] or "/"
    host = f"{tun.vd_ip}:{tun.vd_port}" if tun.vd_port not in (80, 443) else tun.vd_ip
    return urlunsplit((tun.scheme, host, path, parts.query, parts.fragment))


def _rewrite_origin_to_upstream(origin: str, tun: WebUITunnel) -> str:
    """Rewrite Origin to the upstream origin while preserving bad values."""
    try:
        parts = urlsplit(origin)
    except ValueError:
        return origin
    if not parts.scheme or not parts.netloc:
        return origin
    host = f"{tun.vd_ip}:{tun.vd_port}" if tun.vd_port not in (80, 443) else tun.vd_ip
    return urlunsplit((tun.scheme, host, "", "", ""))


def _rewrite_cookie_attrs(
    cookie: str,
    tun: WebUITunnel,
    *,
    host_mode: bool = False,
) -> str:
    """Il Set-Cookie del VD contiene Path/Domain propri: li
    adjust them so the browser sends them back on our URLs.

    - Path: force it to /webui/<tok>/ so the cookie only travels
      sotto il tunnel, non su tutto il sito.
    - Domain: removed (otherwise the cookie is rejected because
      non matcha il nostro hostname).
    - SameSite: left unchanged (but if it was "None" and Secure is missing,
      browser behavior will handle the rejection).
    """
    parts = [p.strip() for p in cookie.split(";")]
    if not parts:
        return cookie
    name_value = parts[0]
    out = [name_value]
    path_set = False
    for p in parts[1:]:
        if not p:
            continue
        low = p.lower()
        if low.startswith("path="):
            out.append("Path=/" if host_mode else f"Path=/webui/{tun.token}/")
            path_set = True
        elif low.startswith("domain="):
            continue  # drop
        else:
            out.append(p)
    if not path_set:
        out.append("Path=/" if host_mode else f"Path=/webui/{tun.token}/")
    return "; ".join(out)


def _strip_cookie(cookie_header: str, name: str) -> str:
    parts = [p.strip() for p in cookie_header.split(";")]
    kept: dict[str, tuple[int, str]] = {}
    fallback_deleted: dict[str, tuple[int, str]] = {}
    order = 0
    for part in parts:
        if not part or "=" not in part:
            continue
        cookie_name, cookie_value = part.split("=", 1)
        if cookie_name == name:
            continue
        item = (order, part)
        order += 1
        # Browsers can keep stale duplicate cookies after appliance logout
        # flows. If there is a usable value for the same cookie name, prefer it
        # over common deletion sentinels.
        if cookie_value.lower() in {"deleted", "delete", "expired"}:
            fallback_deleted[cookie_name] = item
            continue
        kept[cookie_name] = item
    for cookie_name, item in fallback_deleted.items():
        kept.setdefault(cookie_name, item)
    return "; ".join(part for _, part in sorted(kept.values()))


# ── WebSocket proxy ──────────────────────────────────────────────────
#
# The VD can use WebSocket for its modern UIs (es. terminale nel
# browser, notifiche push). Accettiamo l'upgrade dal client, apriamo
# un WS verso l'upstream (via il local_port del tunnel) e facciamo
# bidirectional piping until one side closes.

_WS_HOP_BY_HOP = {
    "connection", "upgrade", "sec-websocket-key", "sec-websocket-version",
    "sec-websocket-extensions", "sec-websocket-accept", "host", "cookie",
}


@router.websocket("/webui/{token}/{path:path}")
async def webui_ws_proxy(websocket: WebSocket, token: str, path: str):
    await _proxy_websocket(
        websocket, token, path,
        require_user=True,
        host_mode=False,
    )


async def _proxy_websocket(
    websocket: WebSocket,
    token: str,
    path: str,
    *,
    require_user: bool,
    host_mode: bool,
) -> None:
    # Validazione Origin come for gli altri WS della GUI — se fallisce
    # chiudiamo con 4403 senza MAI chiamare accept().
    if require_user and await reject_if_bad_origin(websocket):
        return
    tun = webui_service.get(token)
    if require_user:
        async with AsyncSessionLocal() as db:
            user = await authenticate_ws(websocket)
            if user is None:
                await websocket.close(code=4401)
                return
            if not tun or tun.user_id != user.id:
                await websocket.close(code=4404)
                return
    elif not tun:
        await websocket.close(code=4404)
        return
    # Refresh idle timeout.
    webui_service.touch(token)

    # Subprotocols: se il client ne ha indicati, li propaghiamo
    # all'upstream e accettiamo col primo che il server sceglie.
    requested = websocket.headers.get("sec-websocket-protocol", "")
    subprotocols = [p.strip() for p in requested.split(",") if p.strip()] if requested else None

    # Header da propagare all'upstream (filtrati dai hop-by-hop).
    upstream_headers = []
    for k, v in websocket.headers.items():
        if k.lower() in _WS_HOP_BY_HOP:
            continue
        upstream_headers.append((k, v))
    # Host: il VD si aspetta il suo.
    host_hdr = f"{tun.vd_ip}:{tun.vd_port}" if tun.vd_port not in (80, 443) else tun.vd_ip
    upstream_headers.append(("Host", host_hdr))
    # Cookie: togli la sessione GUI.
    cookie_hdr = websocket.headers.get("cookie")
    if cookie_hdr:
        from app.config import settings as _s
        filtered = _strip_cookie(cookie_hdr, _s.SESSION_COOKIE_NAME)
        if filtered:
            upstream_headers.append(("Cookie", filtered))

    # Upstream URL: schema ws/wss a seconda del tunnel.
    up_scheme = "wss" if tun.scheme == "https" else "ws"
    up_path = "/" + path.lstrip("/")
    query = websocket.url.query or ""
    upstream_url = f"{up_scheme}://127.0.0.1:{tun.local_port}{up_path}"
    if query:
        upstream_url += f"?{query}"

    ssl_ctx = None
    if up_scheme == "wss":
        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = _ssl.CERT_NONE  # A3: self-signed OK

    label = f"webui/ws/{token}"
    async with shutdown_registry.track(label):
        try:
            async with websockets.connect(
                upstream_url,
                additional_headers=upstream_headers,
                subprotocols=subprotocols or None,
                ssl=ssl_ctx,
                ping_interval=30,
                ping_timeout=30,
                max_size=2 ** 24,
                open_timeout=10,
                close_timeout=5,
            ) as upstream:
                # Accetta il WS del client solo dopo l'upstream: se
                # l'upstream fallisce restituiamo un error HTTP (no accept).
                accepted_sub = upstream.subprotocol
                await websocket.accept(subprotocol=accepted_sub)
                await _ws_bridge(websocket, upstream)
        except asyncio.CancelledError:
            with contextlib_suppress():
                await websocket.close()
        except websockets.InvalidStatusCode as exc:
            # L'upstream ha rifiutato l'upgrade → non abbiamo ancora
            # accettato lato client, possiamo closesre con codice dedicato.
            log.info("webui ws: upstream rejected upgrade (status=%s)", exc.status_code)
            try:
                await websocket.close(code=1011)
            except Exception:
                pass
        except Exception as exc:
            log.warning("webui ws proxy error token=%s: %s", token, exc)
            try:
                await websocket.close(code=1011)
            except Exception:
                pass


async def _ws_bridge(client: WebSocket, upstream) -> None:
    """Piping bidirezionale fra il browser e l'upstream."""
    from starlette.websockets import WebSocketDisconnect

    async def client_to_upstream():
        try:
            while True:
                msg = await client.receive()
                t = msg.get("type")
                if t == "websocket.disconnect":
                    return
                if "bytes" in msg and msg["bytes"] is not None:
                    await upstream.send(msg["bytes"])
                elif "text" in msg and msg["text"] is not None:
                    await upstream.send(msg["text"])
        except WebSocketDisconnect:
            return
        except Exception:
            return

    async def upstream_to_client():
        try:
            async for data in upstream:
                if isinstance(data, bytes):
                    await client.send_bytes(data)
                else:
                    await client.send_text(data)
        except Exception:
            return

    t1 = asyncio.create_task(client_to_upstream())
    t2 = asyncio.create_task(upstream_to_client())
    done, pending = await asyncio.wait(
        {t1, t2}, return_when=asyncio.FIRST_COMPLETED,
    )
    for t in pending:
        t.cancel()
    with contextlib_suppress():
        await upstream.close()
    with contextlib_suppress():
        await client.close()


import contextlib as _contextlib

def contextlib_suppress():
    return _contextlib.suppress(Exception)
