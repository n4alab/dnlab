"""On-demand SSH tunnels + reverse-proxy registry for la Web UI dei VD.

Modello:

* a **tunnel** is a process ``ssh -N -L 127.0.0.1:<port>:<vd_ip>:<vd_port>
  labuser@<jumphost>`` that lives while the browser uses it.
* il :mod:`webui_routes` fa da reverse proxy HTTP/WS: il browser
  dell'operatore chiede ``/webui/<token>/<path>``, la GUI trasmette
  a ``127.0.0.1:<local_port>`` where the tunnel is already running, la risposta
  returns to the browser re-signed by the app certificate (TLS
  termination fatta da Apache davanti alla GUI).
* token URL-safe random → no guessable URLs; each tunnel is
  appaiato all'``user_id`` che l'ha aperto (controllo lato routes).

Politiche:

* 10-minute idle timeout -> background cleanup task closes
  tunnel fermi, so non accumuliamo processi ssh.
* soft cap su numero di tunnel attivi for evitare abuso.

Note (A1): stiamo usando ssh -L su TCP — MSS/MTU sono gestiti dal
kernel sul socket di loopback, non richiedono flag speciali. Se in
futuro avremo problemi di path MTU tra master e container possiamo
add ``-o TCPKeepAlive=yes`` (already present) or reduce the MTU
della bridge docker.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import socket
import subprocess
import time
from dataclasses import dataclass
from threading import Lock
from typing import Optional

from app.config import settings
from app.services.webui_listener import Listener, ListenerError

log = logging.getLogger(__name__)


IDLE_TIMEOUT_S = 600        # 10 min senza richieste → chiudi
CLEANUP_INTERVAL_S = 60     # quanto spesso scansioniamo
MAX_TUNNELS = 32            # soft cap globale
BIND_WAIT_S = 6.0           # attesa del forward prima di dichiarare error


class WebUITunnelError(RuntimeError):
    """Raised when a tunnel cannot be opened or is misconfigured."""


@dataclass
class WebUITunnel:
    token: str
    lab_id: str          # UUID serializzato come str
    lab_name: str        # netname del lab (usato for il nome container jumphost)
    node_name: str
    vd_ip: str
    vd_port: int
    scheme: str          # "http" | "https"
    local_port: int
    process: subprocess.Popen
    user_id: int
    opened_at: float
    last_used_at: float
    path: str = "/"      # path by default della UI (es. "/login" for qualche vendor)
    label: str = ""      # nome amichevole — solo for log / UX
    upstream_authorization: str | None = None
    ssh_host: str | None = None
    ssh_port: int | None = None
    ssh_user: str | None = None
    ssh_key: str | None = None


class WebUIService:
    def __init__(self) -> None:
        self._tunnels: dict[str, WebUITunnel] = {}
        # Secondary key to find an already-open tunnel for the same
        # (lab_id, node_name, vd_port): evitiamo di accumulare duplicati
        # when the user clicks "open" multiple times.
        self._by_key: dict[tuple[str, str, int], str] = {}
        self._lock = Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    # ── Lifecycle dei tunnel ──────────────────────────────────────────

    def open(
        self,
        *,
        lab_id: str,
        lab_name: str,
        node_name: str,
        vd_ip: str,
        vd_port: int,
        scheme: str,
        user_id: int,
        path: str = "/",
        label: str = "",
        jh_host: str | None = None,
        jh_port: int | None = None,
    ) -> WebUITunnel:
        """Open (or reuse) a tunnel and return the record.

        The tunnel SSHes into the lab jumphost and forwards to
        ``vd_ip:vd_port`` from there. When ``jh_port`` is given the GUI
        reaches the jumphost through its SSH port published on the master
        host (``jh_host``, default :data:`settings.JUMPHOST_HOST`) — this
        is the dockerized-GUI path. When ``jh_port`` is omitted we fall
        back to resolving the jumphost by container name
        (``dnlab-<lab>-jumphost``), which only works when the GUI shares
        the jumphost's docker network (legacy GUI-on-master).
        """
        if scheme not in ("http", "https"):
            raise WebUITunnelError(f"scheme '{scheme}' non supportato (usa http/https)")
        if not (1 <= vd_port <= 65535):
            raise WebUITunnelError(f"port {vd_port} fuori range")

        # Resolve the endpoint before cache lookup; defaults can change too.
        ssh_host = (jh_host or settings.JUMPHOST_HOST) if jh_port else f"dnlab-{lab_name}-jumphost"
        ssh_port = jh_port or 22
        ssh_user = settings.JUMPHOST_USER
        ssh_key = settings.GUI_SSH_KEY
        key = (lab_id, node_name, vd_port)
        with self._lock:
            existing_token = self._by_key.get(key)
            if existing_token:
                t = self._tunnels.get(existing_token)
                if (t and t.user_id == user_id and t.lab_name == lab_name
                        and t.vd_ip == vd_ip and t.scheme == scheme
                        and (t.ssh_host, t.ssh_port, t.ssh_user, t.ssh_key)
                            == (ssh_host, ssh_port, ssh_user, ssh_key)
                        and _alive(t.process)):
                    t.last_used_at = time.time()
                    t.path = path
                    t.label = label
                    return t
                # Stale: processo, owner o destinazione diversi →
                # lo puliamo prima di aprirne uno nuovo.
                if t:
                    self._close_locked(t.token)

        with self._lock:
            if len(self._tunnels) >= MAX_TUNNELS:
                raise WebUITunnelError(
                    f"troppi tunnel attivi ({MAX_TUNNELS}); aspetta il cleanup "
                    f"o chiudi quelli che non usi"
                )

        local_port = _pick_free_port()
        # Where to SSH: the jumphost's published port on the master host
        # (dockerized GUI), or the jumphost container by name (legacy).
        if jh_port:
            port_args = ["-p", str(jh_port)]
        else:
            port_args = []
        ssh_cmd = [
            "ssh", "-N", "-T",
            *port_args,
            # The jumphost host key rotates on every lab redeploy, and the
            # GUI's /root/.ssh is mounted read-only, so use a throwaway
            # known_hosts: every connect is "new" (accepted via
            # accept-new), nothing is persisted → no host-key mismatch and
            # no "Failed to add the host to known_hosts" noise. LogLevel
            # ERROR hides the "Permanently added" line while still
            # surfacing real connection/auth errors for rc=255 diagnosis.
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "TCPKeepAlive=yes",
            "-o", "BatchMode=yes",
            "-i", ssh_key,
            "-L", f"127.0.0.1:{local_port}:{vd_ip}:{vd_port}",
            f"{ssh_user}@{ssh_host}",
        ]
        log.info(
            "webui: opening tunnel lab=%s node=%s %s://%s:%d → 127.0.0.1:%d via %s:%s",
            lab_id, node_name, scheme, vd_ip, vd_port, local_port,
            ssh_host, jh_port or "name",
        )
        try:
            proc = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as exc:
            raise WebUITunnelError("impossibile avviare il tunnel SSH") from exc
        try:
            _wait_for_bind("127.0.0.1", local_port, proc, timeout=BIND_WAIT_S)
        except Exception:
            proc.terminate()
            with contextlib.suppress(Exception):
                proc.wait(timeout=2.0)
            raise

        # DNS-safe because the host-based proxy exposes tunnels as
        # <token>.<webui-host-suffix>. Hex avoids "_" from token_urlsafe().
        token = secrets.token_hex(18)
        now = time.time()
        tun = WebUITunnel(
            token=token, lab_id=lab_id, lab_name=lab_name, node_name=node_name,
            vd_ip=vd_ip, vd_port=vd_port, scheme=scheme,
            local_port=local_port, process=proc, user_id=user_id,
            opened_at=now, last_used_at=now, path=path, label=label,
            ssh_host=ssh_host, ssh_port=ssh_port, ssh_user=ssh_user, ssh_key=ssh_key,
        )
        with self._lock:
            self._tunnels[token] = tun
            self._by_key[key] = token
        log.info("webui: tunnel opened token=%s local_port=%d", token, local_port)
        return tun

    def get(self, token: str) -> WebUITunnel | None:
        with self._lock:
            return self._tunnels.get(token)

    def touch(self, token: str) -> None:
        with self._lock:
            t = self._tunnels.get(token)
            if t:
                t.last_used_at = time.time()

    def close(self, token: str) -> bool:
        with self._lock:
            return self._close_locked(token)

    def close_by_key(self, lab_id: str, node_name: str, vd_port: int) -> bool:
        with self._lock:
            tok = self._by_key.get((lab_id, node_name, vd_port))
            if not tok:
                return False
            return self._close_locked(tok)

    def close_lab(self, lab_id: str) -> int:
        """Close every tunnel belonging to a lab lifecycle instance."""
        with self._lock:
            tokens = [
                token for token, tunnel in self._tunnels.items()
                if tunnel.lab_id == lab_id
            ]
        closed = 0
        for token in tokens:
            if self.close(token):
                closed += 1
        return closed

    def list(self) -> list[WebUITunnel]:
        with self._lock:
            return list(self._tunnels.values())

    def _close_locked(self, token: str) -> bool:
        t = self._tunnels.pop(token, None)
        if not t:
            return False
        key = (t.lab_id, t.node_name, t.vd_port)
        if self._by_key.get(key) == token:
            self._by_key.pop(key, None)
        try:
            t.process.terminate()
            try:
                t.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                t.process.kill()
                with contextlib.suppress(Exception):
                    t.process.wait(timeout=1.0)
        except Exception as exc:
            log.warning("webui: close %s: %s", token, exc)
        log.info("webui: tunnel closed token=%s", token)
        return True

    def shutdown(self) -> None:
        """Termina tutti i tunnel (chiamato allo shutdown FastAPI)."""
        with self._lock:
            tokens = list(self._tunnels.keys())
        for tok in tokens:
            self.close(tok)

    # ── Cleanup loop ──────────────────────────────────────────────────

    def start_cleanup_task(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = loop.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(CLEANUP_INTERVAL_S)
                now = time.time()
                dead: list[str] = []
                idle: list[str] = []
                with self._lock:
                    for tok, t in self._tunnels.items():
                        if not _alive(t.process):
                            dead.append(tok)
                        elif now - t.last_used_at > IDLE_TIMEOUT_S:
                            idle.append(tok)
                for tok in dead:
                    log.info("webui: reaping dead tunnel %s", tok)
                    self.close(tok)
                for tok in idle:
                    log.info("webui: closing idle tunnel %s (>%ds)", tok, IDLE_TIMEOUT_S)
                    self.close(tok)
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("webui: cleanup loop error")


# ── Helpers ──────────────────────────────────────────────────────────

def _pick_free_port() -> int:
    """Bind a socket to :0, close it, and return the port assigned by the kernel.

    Race window teoricamente presente (un altro processo potrebbe
    steal the port before ssh re-binds it), practically sufficient
    for i nostri carichi."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_bind(
    host: str, port: int, proc: subprocess.Popen, *, timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    try:
        with Listener(proc) as listener:
            while time.monotonic() < deadline:
                before = listener.proof(host, port)
                if before is not None:
                    connected = False
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(0.3)
                            sock.connect((host, port))
                            connected = True
                    except OSError:
                        pass
                    if listener.proof(host, port) != before:
                        raise ListenerError("original listener changed during local connection")
                    if connected:
                        return
                time.sleep(0.1)
    except (OSError, ValueError, ListenerError) as exc:
        raise WebUITunnelError(f"cannot qualify original SSH listener: {exc}") from exc
    raise WebUITunnelError(
        f"ssh tunnel did not bind on {host}:{port} within {timeout:.1f}s"
    )


def _alive(proc: subprocess.Popen) -> bool:
    return proc.poll() is None


# Singleton esposto al resto della app.
webui_service = WebUIService()
