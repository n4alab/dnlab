"""Wireshark capture broker for lab links.

The GUI never streams packets through JavaScript. It asks this service to
resolve a graph-side capture target, mint a short-lived capability token, and
then the user's local Wireshark pulls a raw pcap stream from a token URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import secrets
import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator
from urllib.parse import urlencode
from uuid import UUID

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import settings
from app.services import device_catalog
from app.services.containerlab_service import ContainerLabService
from app.services.lab_resolver import ResolvedLab
from app.services.multinode_service import MultinodeServiceError, multinode

log = logging.getLogger(__name__)

TOKEN_TTL_SECONDS = 10 * 60
MAX_CAPTURE_SECONDS = 30 * 60
MAX_USER_CAPTURES = 3
MAX_LAB_CAPTURES = 10
MAX_FILTER_LENGTH = 512
MAX_SNAPLEN = 262144
CAPTURE_STARTUP_GRACE_SECONDS = 15

_REAL_NET_KINDS = {"_real_net"}


class CaptureError(RuntimeError):
    """Raised for user-facing capture failures."""

    def __init__(self, detail: str, code: str = "capture_error") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class CaptureTarget:
    id: str
    kind: str
    enabled: bool
    disabled_reason: str
    label: str
    node: str
    peer: str
    side: str
    iface: str
    display_iface: str
    container: str
    host: str
    runtime_state: str
    link: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "enabled": self.enabled,
            "disabled_reason": self.disabled_reason,
            "label": self.label,
            "node": self.node,
            "peer": self.peer,
            "side": self.side,
            "iface": self.iface,
            "display_iface": self.display_iface,
            "container": self.container,
            "host": self.host,
            "runtime_state": self.runtime_state,
            "link": self.link,
        }


@dataclass
class ActiveCapture:
    session_id: str
    user_id: int
    lab_id: str
    target_id: str
    target: dict[str, Any]
    started_at: float
    deadline: float
    process: asyncio.subprocess.Process | None = None

    def to_dict(self) -> dict[str, Any]:
        started_at = datetime.fromtimestamp(self.started_at_wall, tz=timezone.utc)
        expires_at = datetime.fromtimestamp(self.expires_at_wall, tz=timezone.utc)
        return {
            "session_id": self.session_id,
            "target_id": self.target_id,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "target": self.target,
            **self.target,
        }

    @property
    def started_at_wall(self) -> float:
        return time.time() - max(0, time.monotonic() - self.started_at)

    @property
    def expires_at_wall(self) -> float:
        return self.started_at_wall + MAX_CAPTURE_SECONDS


class CaptureService:
    def __init__(self) -> None:
        self._clab = ContainerLabService()
        self._serializer = URLSafeTimedSerializer(
            settings.SESSION_SECRET,
            salt="dnlab-capture-stream-v1",
        )
        self._active: dict[str, ActiveCapture] = {}
        self._lock = asyncio.Lock()

    async def targets(self, lab: ResolvedLab) -> list[dict[str, Any]]:
        return [target.to_dict() for target in await self._build_targets(lab)]

    async def token_status(self, token: str) -> dict[str, Any]:
        payload = self.validate_token(token)
        lab = self._lab_from_payload(payload)
        target = await self.resolve_target(
            lab,
            str(payload["target_id"]),
            str(payload.get("side") or ""),
        )
        await self._ensure_capacity(
            int(payload.get("user_id") or 0),
            str(payload.get("lab_id") or ""),
        )
        return {
            "ok": True,
            "expires_at": self._expires_at(payload),
            "target": target.to_dict(),
        }

    async def launch(
        self,
        *,
        lab: ResolvedLab,
        user_id: int,
        target_id: str,
        side: str | None,
        bpf_filter: str,
        snaplen: int,
        promisc: bool,
        base_url: str,
    ) -> dict[str, Any]:
        bpf_filter = self._validate_filter_text(bpf_filter)
        snaplen = self._normalize_snaplen(snaplen)
        await self._validate_bpf_if_possible(bpf_filter)

        target = await self.resolve_target(lab, target_id, side)
        now = int(time.time())
        payload = {
            "typ": "capture-stream",
            "lab_id": str(lab.id),
            "lab_display_name": lab.display_name,
            "lab_netname": lab.netname,
            "user_id": int(user_id),
            "target_id": target.id,
            "node": target.node,
            "peer": target.peer,
            "side": target.side,
            "iface": target.iface,
            "filter": bpf_filter,
            "snaplen": snaplen,
            "promisc": bool(promisc),
            "iat": now,
        }
        token = self._serializer.dumps(payload)
        stream_url = self._absolute(base_url, f"/api/captures/{token}/stream")
        status_url = self._absolute(base_url, f"/api/captures/{token}/status")
        expires_at = datetime.fromtimestamp(now + TOKEN_TTL_SECONDS, tz=timezone.utc)
        handler_url = "dnlab-capture://open?" + urlencode({
            "status_url": status_url,
            "stream_url": stream_url,
            "title": f"Capture from VD {target.node} - interface {target.display_iface or target.iface}",
        })

        return {
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "handler_url": handler_url,
            "stream_url": stream_url,
            "status_url": status_url,
            "target": target.to_dict(),
        }

    async def active_captures(self, *, lab_id: str, user_id: int) -> list[dict[str, Any]]:
        async with self._lock:
            self._cleanup_active_locked()
            return [
                cap.to_dict()
                for cap in self._active.values()
                if cap.lab_id == lab_id and cap.user_id == user_id
            ]

    async def stop_capture(self, *, lab_id: str, user_id: int, session_id: str) -> dict[str, Any]:
        async with self._lock:
            active = self._active.get(session_id)
            if active is None or active.lab_id != lab_id or active.user_id != user_id:
                raise CaptureError("active capture not found", "target_not_found")
            proc = active.process
        if proc is not None:
            await self._stop_process(proc)
        await self._release(session_id)
        return {"ok": True, "session_id": session_id}

    async def resolve_target(
        self,
        lab: ResolvedLab,
        target_id: str,
        side: str | None = None,
    ) -> CaptureTarget:
        targets = await self._build_targets(lab)
        matches = [t for t in targets if t.id == target_id]
        if not matches and side:
            matches = [t for t in targets if t.id == f"{target_id}:{side}"]
        if not matches:
            raise CaptureError("capture target not found", "target_not_found")
        target = matches[0]
        if side and target.side and side != target.side:
            raise CaptureError("capture side does not match target", "target_not_found")
        if not target.enabled:
            raise CaptureError(
                target.disabled_reason or "capture target is disabled",
                _disabled_code(target.disabled_reason),
            )
        return target

    def validate_token(self, token: str) -> dict[str, Any]:
        try:
            payload = self._serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
        except SignatureExpired as exc:
            raise CaptureError("capture token expired", "token_expired") from exc
        except BadSignature as exc:
            raise CaptureError("capture token is invalid", "token_invalid") from exc
        if payload.get("typ") != "capture-stream":
            raise CaptureError("capture token type is invalid", "token_invalid")
        return payload

    async def open_stream(self, token: str) -> AsyncIterator[bytes]:
        payload = self.validate_token(token)
        lab = self._lab_from_payload(payload)
        target = await self.resolve_target(lab, str(payload["target_id"]), str(payload.get("side") or ""))

        user_id = int(payload.get("user_id") or 0)
        lab_id = str(payload.get("lab_id") or "")
        session_id = await self._reserve(user_id, lab_id, str(payload["target_id"]), target.to_dict())
        try:
            cmd = await self._capture_command(target, payload)
        except Exception:
            await self._release(session_id)
            raise
        return self._stream_process(cmd, target, user_id, lab_id, session_id)

    async def _stream_process(
        self,
        cmd: list[str],
        target: CaptureTarget,
        user_id: int,
        lab_id: str,
        session_id: str,
    ) -> AsyncIterator[bytes]:
        proc: asyncio.subprocess.Process | None = None
        try:
            log.info(
                "capture stream start lab=%s node=%s iface=%s host=%s user=%s",
                lab_id, target.node, target.iface, target.host, user_id,
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self._attach_process(session_id, proc)
            assert proc.stdout is not None
            deadline = time.monotonic() + MAX_CAPTURE_SECONDS
            while True:
                if time.monotonic() >= deadline:
                    break
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=1.0)
                except asyncio.TimeoutError:
                    if proc.returncode is not None:
                        break
                    continue
                if not chunk:
                    break
                yield chunk
        finally:
            if proc is not None:
                await self._stop_process(proc)
            await self._release(session_id)

    async def _build_targets(self, lab: ResolvedLab) -> list[CaptureTarget]:
        if not lab.yaml_path.exists():
            raise CaptureError("topology file not found", "target_not_found")
        topo = self._clab.load_topology_from_file(lab.yaml_path)
        try:
            status = await multinode.status(lab, emit_events=False)
        except MultinodeServiceError as exc:
            log.debug("capture targets status failed for %s: %s", lab.netname, exc)
            status = {}
        nodes_runtime = status.get("nodes") if isinstance(status, dict) else {}
        nodes_runtime = nodes_runtime if isinstance(nodes_runtime, dict) else {}
        host_names = await self._known_host_names_async()

        targets: list[CaptureTarget] = []
        for link in topo.links:
            src_node = topo.get_node(link.source)
            tgt_node = topo.get_node(link.target)
            if not src_node or not tgt_node:
                continue
            link_dict = {
                "source": link.source,
                "source_iface": link.source_iface,
                "target": link.target,
                "target_iface": link.target_iface,
            }
            if src_node.kind in _REAL_NET_KINDS or tgt_node.kind in _REAL_NET_KINDS:
                if src_node.kind in _REAL_NET_KINDS:
                    node, peer, iface = link.target, link.source, link.target_iface
                else:
                    node, peer, iface = link.source, link.target, link.source_iface
                targets.append(self._target_for_node(
                    kind="realnet", lab=lab, node=node, peer=peer, side="vd",
                    iface=iface, runtime=nodes_runtime.get(node) or {},
                    host_names=host_names, link=link_dict,
                    node_kind=tgt_node.kind if src_node.kind in _REAL_NET_KINDS else src_node.kind,
                ))
                continue
            targets.append(self._target_for_node(
                kind="link", lab=lab, node=link.source, peer=link.target, side="source",
                iface=link.source_iface, runtime=nodes_runtime.get(link.source) or {},
                host_names=host_names, link=link_dict, node_kind=src_node.kind,
            ))
            targets.append(self._target_for_node(
                kind="link", lab=lab, node=link.target, peer=link.source, side="target",
                iface=link.target_iface, runtime=nodes_runtime.get(link.target) or {},
                host_names=host_names, link=link_dict, node_kind=tgt_node.kind,
            ))

        for node in topo.nodes:
            if node.kind in {"_real_net", "_mgmt"}:
                continue
            iface = _mgmt_linux_iface_for_kind(node.kind)
            if not iface:
                runtime = nodes_runtime.get(node.name) or {}
                targets.append(self._target_for_node(
                    kind="mgmt", lab=lab, node=node.name, peer="mgmt", side="mgmt",
                    iface="", runtime=runtime, host_names=host_names, link=None,
                    node_kind=node.kind,
                    forced_reason="management interface cannot be resolved",
                ))
                continue
            targets.append(self._target_for_node(
                kind="mgmt", lab=lab, node=node.name, peer="mgmt", side="mgmt",
                iface=iface, runtime=nodes_runtime.get(node.name) or {},
                host_names=host_names, link=None, node_kind=node.kind,
            ))
        return targets

    def _target_for_node(
        self,
        *,
        kind: str,
        lab: ResolvedLab,
        node: str,
        peer: str,
        side: str,
        iface: str,
        runtime: dict[str, Any],
        host_names: set[str],
        link: dict[str, str] | None,
        node_kind: str = "",
        forced_reason: str = "",
    ) -> CaptureTarget:
        state = str(runtime.get("state") or "")
        container = str(runtime.get("container") or "")
        host = str(runtime.get("host") or runtime.get("scheduled_host") or "")
        duplicate_hosts = runtime.get("duplicate_hosts") or []
        reason = forced_reason
        if not reason and state != "running":
            reason = "Node is not running." if state else "Lab is not running."
        if not reason and not container:
            reason = "Container cannot be resolved."
        if not reason and duplicate_hosts:
            reason = "Node exists on duplicate hosts."
        if not reason and not iface:
            reason = "Interface cannot be resolved."
        if not reason and not self._host_known(host, host_names):
            reason = "Host cannot be resolved."
        target_id = _target_id(kind, node, iface, peer, side, link)
        display_iface = _display_iface(node_kind, iface)
        return CaptureTarget(
            id=target_id,
            kind=kind,
            enabled=not reason,
            disabled_reason=reason,
            label=self._target_label(kind, node, display_iface or iface, peer, side),
            node=node,
            peer=peer,
            side=side,
            iface=iface,
            display_iface=display_iface,
            container=container,
            host=host or "master",
            runtime_state=state,
            link=link,
        )

    async def _capture_command(self, target: CaptureTarget, payload: dict[str, Any]) -> list[str]:
        base = [
            "ip", "netns", "exec", target.container,
            "tcpdump", "-U", "-nn",
        ]
        if not bool(payload.get("promisc")):
            base.append("-p")
        base.extend(["-i", target.iface])
        snaplen = self._normalize_snaplen(int(payload.get("snaplen") or 0))
        if snaplen:
            base.extend(["-s", str(snaplen)])
        base.extend(["-w", "-"])
        bpf_filter = self._validate_filter_text(str(payload.get("filter") or ""))
        if bpf_filter:
            base.extend(shlex.split(bpf_filter))

        host = await self._infra_host(target.host)
        if host is None:
            return base
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-i", settings.GUI_SSH_KEY,
            f"{host.ssh_user}@{host.host}",
            shlex.join(base),
        ]

    async def _infra_host(self, host_name: str):
        if settings.DNLAB_MULTINODE_API_URL:
            try:
                inventory = await multinode.list_hosts()
            except MultinodeServiceError as exc:
                raise CaptureError(str(exc), "host_unresolved") from exc
            master = inventory.get("master") if isinstance(inventory, dict) else {}
            master_name = master.get("name") if isinstance(master, dict) else "master"
            if not host_name or host_name in {"master", master_name}:
                return None
            workers = inventory.get("workers") if isinstance(inventory, dict) else []
            for worker in workers if isinstance(workers, list) else []:
                if isinstance(worker, dict) and worker.get("name") == host_name:
                    return SimpleNamespace(**worker)
            raise CaptureError(f"unknown worker host: {host_name}", "host_unresolved")

        def _load():
            from dnlab_multinode import load_hosts_config
            from dnlab_multinode.services.hosts_config import HostsConfigError

            try:
                cfg = load_hosts_config(settings.DNLAB_MULTINODE_HOSTS)
            except HostsConfigError as exc:
                raise CaptureError(str(exc), "host_unresolved") from exc
            if not host_name or host_name in {"master", cfg.master.name}:
                return None
            host = cfg.workers.get(host_name)
            if host is None:
                raise CaptureError(f"unknown worker host: {host_name}", "host_unresolved")
            return host
        return await asyncio.to_thread(_load)

    async def _known_host_names_async(self) -> set[str]:
        if not settings.DNLAB_MULTINODE_API_URL:
            return self._known_host_names()
        try:
            inventory = await multinode.list_hosts()
        except Exception:
            return {"master"}
        names = {"master"}
        master = inventory.get("master") if isinstance(inventory, dict) else {}
        if isinstance(master, dict) and master.get("name"):
            names.add(str(master["name"]))
        workers = inventory.get("workers") if isinstance(inventory, dict) else []
        for worker in workers if isinstance(workers, list) else []:
            if isinstance(worker, dict) and worker.get("name"):
                names.add(str(worker["name"]))
        return names

    def _known_host_names(self) -> set[str]:
        try:
            from dnlab_multinode import load_hosts_config

            cfg = load_hosts_config(settings.DNLAB_MULTINODE_HOSTS)
        except Exception:
            return {"master"}
        return {"master", cfg.master.name, *cfg.workers.keys()}

    @staticmethod
    def _host_known(host: str, names: set[str]) -> bool:
        return not host or host in names

    def _lab_from_payload(self, payload: dict[str, Any]) -> ResolvedLab:
        lab_id = UUID(str(payload["lab_id"]))
        yaml_path = settings.TOPOLOGIES_DIR / f"{lab_id}.yml"
        return ResolvedLab(
            id=lab_id,
            display_name=str(payload.get("lab_display_name") or payload.get("lab_netname") or lab_id),
            netname=str(payload.get("lab_netname") or ""),
            bridge="",
            yaml_path=Path(yaml_path),
            owner=None,
        )

    async def _reserve(self, user_id: int, lab_id: str, target_id: str, target: dict[str, Any]) -> str:
        async with self._lock:
            self._cleanup_active_locked()
            active_user = sum(1 for cap in self._active.values() if cap.user_id == user_id)
            active_lab = sum(1 for cap in self._active.values() if cap.lab_id == lab_id)
            self._raise_if_at_capacity(active_user, active_lab)
            session_id = secrets.token_hex(8)
            now = time.monotonic()
            self._active[session_id] = ActiveCapture(
                session_id=session_id,
                user_id=user_id,
                lab_id=lab_id,
                target_id=target_id,
                target=target,
                started_at=now,
                deadline=now + MAX_CAPTURE_SECONDS,
            )
            log.debug(
                "capture reserve session=%s user=%s lab=%s active_user=%d active_lab=%d",
                session_id, user_id, lab_id, active_user + 1, active_lab + 1,
            )
            return session_id

    async def _ensure_capacity(self, user_id: int, lab_id: str) -> None:
        async with self._lock:
            self._cleanup_active_locked()
            active_user = sum(1 for cap in self._active.values() if cap.user_id == user_id)
            active_lab = sum(1 for cap in self._active.values() if cap.lab_id == lab_id)
            self._raise_if_at_capacity(active_user, active_lab)

    @staticmethod
    def _raise_if_at_capacity(active_user: int, active_lab: int) -> None:
        if active_user >= MAX_USER_CAPTURES:
            raise CaptureError("too many active captures for this user", "capture_limit_exceeded")
        if active_lab >= MAX_LAB_CAPTURES:
            raise CaptureError("too many active captures for this lab", "capture_limit_exceeded")

    async def _attach_process(self, session_id: str, proc: asyncio.subprocess.Process) -> None:
        async with self._lock:
            active = self._active.get(session_id)
            if active is not None:
                active.process = proc

    async def _release(self, session_id: str) -> None:
        async with self._lock:
            active = self._active.pop(session_id, None)
            if active is not None:
                log.debug(
                    "capture release session=%s user=%s lab=%s",
                    session_id, active.user_id, active.lab_id,
                )

    def _cleanup_active_locked(self) -> None:
        now = time.monotonic()
        stale: list[str] = []
        for session_id, active in self._active.items():
            proc = active.process
            if proc is not None and proc.returncode is not None:
                stale.append(session_id)
                continue
            if proc is None and now - active.started_at > CAPTURE_STARTUP_GRACE_SECONDS:
                stale.append(session_id)
                continue
            if now > active.deadline + CAPTURE_STARTUP_GRACE_SECONDS:
                if proc is not None and proc.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        proc.terminate()
                stale.append(session_id)
        for session_id in stale:
            active = self._active.pop(session_id, None)
            if active is not None:
                log.warning(
                    "capture cleanup stale session=%s user=%s lab=%s target=%s",
                    session_id, active.user_id, active.lab_id, active.target_id,
                )

    async def _stop_process(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        proc.terminate()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return
        proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()

    def _validate_filter_text(self, value: str) -> str:
        value = (value or "").strip()
        if len(value) > MAX_FILTER_LENGTH:
            raise CaptureError("BPF filter is too long", "invalid_filter")
        if any(ord(ch) < 32 for ch in value):
            raise CaptureError("BPF filter contains control characters", "invalid_filter")
        return value

    async def _validate_bpf_if_possible(self, bpf_filter: str) -> None:
        if not bpf_filter:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                "tcpdump", "-d", *shlex.split(bpf_filter),
                stdout=subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return
        try:
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        except asyncio.TimeoutError as exc:
            await self._stop_process(proc)
            raise CaptureError("BPF validation timed out", "invalid_filter") from exc
        if proc.returncode != 0:
            raise CaptureError(
                (stderr or b"invalid BPF filter").decode(errors="replace").strip(),
                "invalid_filter",
            )

    @staticmethod
    def _expires_at(payload: dict[str, Any]) -> str:
        iat = int(payload.get("iat") or time.time())
        expires_at = datetime.fromtimestamp(iat + TOKEN_TTL_SECONDS, tz=timezone.utc)
        return expires_at.isoformat().replace("+00:00", "Z")

    @staticmethod
    def _normalize_snaplen(value: int) -> int:
        if value <= 0:
            return 0
        return max(64, min(int(value), MAX_SNAPLEN))

    @staticmethod
    def _absolute(base_url: str, path: str) -> str:
        return base_url.rstrip("/") + path

    @staticmethod
    def _target_label(kind: str, node: str, iface: str, peer: str, side: str) -> str:
        if kind == "mgmt":
            return f"{node} {iface} -> mgmt"
        return f"{node} {iface} -> {peer}" if iface else f"{node} -> {peer}"


def _target_id(
    kind: str,
    node: str,
    iface: str,
    peer: str,
    side: str,
    link: dict[str, str] | None,
) -> str:
    if kind == "mgmt":
        return f"mgmt:{node}:{iface}:{side}"
    if kind == "realnet":
        return f"realnet:{node}:{iface}:{peer}:{side}"
    if link:
        return (
            f"link:{link.get('source', '')}:{link.get('source_iface', '')}:"
            f"{link.get('target', '')}:{link.get('target_iface', '')}:{side}"
        )
    return f"link:{node}:{iface}:{peer}:{side}"


def _disabled_code(reason: str) -> str:
    normalized = (reason or "").lower()
    if "duplicate host" in normalized or "duplicate hosts" in normalized:
        return "target_disabled"
    if "not running" in normalized or "lab is not running" in normalized:
        return "node_not_running"
    if "container" in normalized:
        return "container_unresolved"
    if "interface" in normalized or "management interface" in normalized:
        return "iface_unresolved"
    if "host" in normalized:
        return "host_unresolved"
    return "target_disabled"


def _mgmt_linux_iface_for_kind(kind: str) -> str:
    entry = device_catalog.kind_entry(kind)
    catalog = _raw_catalog()
    defaults = catalog.get("defaults") if isinstance(catalog, dict) else {}
    mgmt = entry.get("mgmt_iface") if "mgmt_iface" in entry else (defaults or {}).get("mgmt_iface", "eth0")
    if not mgmt:
        return ""
    interfaces = entry.get("interfaces")
    if not isinstance(interfaces, dict):
        return str(mgmt)
    linux_fmt = str(interfaces.get("linux_fmt") or "eth{n}")
    vendor_fmt = str(interfaces.get("vendor_fmt") or linux_fmt)
    count = int(interfaces.get("count") or 8)
    mgmt_norm = _norm_iface(str(mgmt))
    for n in range(1, count + 1):
        i = n - 1
        linux = _fmt_iface(linux_fmt, n, i)
        vendor = _fmt_iface(vendor_fmt, n, i)
        if _norm_iface(linux) == mgmt_norm or _norm_iface(vendor) == mgmt_norm:
            return linux
    return str(mgmt)


def _display_iface(kind: str, linux_name: str) -> str:
    if not linux_name:
        return ""
    if kind in _REAL_NET_KINDS:
        return linux_name
    info = _interface_info_for_kind(kind)
    if not info:
        return linux_name
    try:
        count = int(info.get("count") or 8)
    except (TypeError, ValueError):
        count = 8
    linux_fmt = str(info.get("linux_fmt") or "eth{n}")
    vendor_fmt = str(info.get("vendor_fmt") or linux_fmt)
    for n in range(1, max(0, count) + 1):
        i = n - 1
        if _fmt_iface(linux_fmt, n, i) == linux_name:
            return _fmt_iface(vendor_fmt, n, i)
    return linux_name


def _interface_info_for_kind(kind: str | None) -> dict[str, Any] | None:
    interface_map = device_catalog.interface_map()
    raw = (kind or "").strip()
    normalized = raw.lower()
    aliases = {
        "mikrotik": "mikrotik_ros",
        "routeros": "mikrotik_ros",
    }
    alias = aliases.get(raw) or aliases.get(normalized)
    info = interface_map.get(raw) or interface_map.get(normalized) or (interface_map.get(alias) if alias else None)
    if isinstance(info, dict):
        return info
    fallback = interface_map.get("linux")
    return fallback if isinstance(fallback, dict) else None


def _raw_catalog() -> dict[str, Any]:
    path = settings.STATIC_DIR / "config" / "devices.json"
    try:
        import json

        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _fmt_iface(fmt: str, n: int, i: int) -> str:
    module = n // 4
    port = n % 4

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        offset = int(match.group(2) or 0)
        values = {
            "module": module,
            "port": port,
            "n": n,
            "i": i,
        }
        return str(values[key] + offset)

    return re.sub(r"\{(module|port|n|i)([+-]\d+)?\}", repl, str(fmt or ""))


def _norm_iface(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    return safe or "capture"


capture_service = CaptureService()
