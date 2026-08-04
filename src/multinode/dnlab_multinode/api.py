"""Internal HTTP API for dnlab-multinode.

The API is intentionally a thin wrapper around the existing synchronous
controllers. It is meant for the dockerized GUI transition: local Python
imports can remain as a fallback while the GUI learns to call this service.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shlex
import subprocess
import threading
from collections import defaultdict, deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from dnlab_multinode.controllers.deploy import DeployController
from dnlab_multinode.controllers.destroy import DestroyController
from dnlab_multinode.controllers.node import NodeLifecycleController
from dnlab_multinode.controllers.plan import PlanController
from dnlab_multinode.controllers.realnet import RealNetLifecycleController
from dnlab_multinode.controllers.status import StatusController
from dnlab_multinode.controllers.sync import SyncController
from dnlab_multinode.services.hosts_config import HostsConfigError, load_hosts_config
from dnlab_multinode.services.follow_rabbit import (
    FlowFilter,
    FollowRabbitError,
    follow_rabbit_manager,
)
from dnlab_multinode.services.image_sync import read_state_file
from dnlab_multinode.services.lab_cleanup import (
    read_state_file as read_lab_cleanup_state_file,
    reconcile_once as reconcile_lab_cleanup_once,
)
from dnlab_multinode.services import state as state_svc
from dnlab_multinode.services.config import parse_topology
from dnlab_multinode.services.logging_config import setup_service_logging
from dnlab_multinode.services.paths import PATHS, persist_dir_for_node
from dnlab_multinode.services.persistence import placement_file_path
from dnlab_multinode.services.progress import ProgressEvent
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.services import realnet as realnet_svc
from dnlab_multinode.models.topology import RealNetInfraCfg


class LabRequest(BaseModel):
    topology_file: str = Field(min_length=1)
    hosts_file: str | None = None
    lab_id: str | None = None
    lab_name: str | None = None


class PlanRequest(LabRequest):
    no_cache: bool = False


class NodeRequest(LabRequest):
    node: str = Field(min_length=1)


class LinkRequest(LabRequest):
    source: str = Field(min_length=1)
    source_iface: str = Field(min_length=1)
    target: str = Field(min_length=1)
    target_iface: str = Field(min_length=1)


class RealNetRequest(LabRequest):
    realnet: str = Field(min_length=1)


class FollowRabbitStartRequest(LabRequest):
    source_node: str = Field(min_length=1)
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    protocol: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    timeout_seconds: int | None = None


class HostsRequest(BaseModel):
    hosts_file: str | None = None


class HostsValidateRequest(BaseModel):
    content: str = Field(min_length=1)


app = FastAPI(title="dNLab Multinode API", version="0.1.0")
_mutating_lock = asyncio.Lock()
_events: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=500))
_subscribers: dict[str, set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]]] = defaultdict(set)


@dataclasses.dataclass
class _ActiveNodeStart:
    cancel: threading.Event
    done: asyncio.Event
    phase: str = "queued"
    controller: NodeLifecycleController | None = None


_active_node_starts: dict[tuple[str, str], _ActiveNodeStart] = {}


def _node_operation_key(req: NodeRequest) -> tuple[str, str]:
    return str(Path(req.topology_file).resolve()), req.node


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/hosts")
async def hosts(req: HostsRequest) -> dict[str, Any]:
    def _load() -> dict[str, Any]:
        cfg = load_hosts_config(req.hosts_file)
        return {
            "source_path": str(cfg.source_path) if cfg.source_path else None,
            "underlay_iface": cfg.underlay_iface,
            "master": _host(cfg.master, is_master=True),
            "workers": [_host(w, is_master=False) for w in cfg.workers.values()],
            "mgmt_defaults": dataclasses.asdict(cfg.mgmt_defaults),
            "image_sync": dataclasses.asdict(cfg.image_sync),
            "lab_cleanup": dataclasses.asdict(cfg.lab_cleanup),
            "persistence": dataclasses.asdict(cfg.persistence),
            "webui_ports": dataclasses.asdict(cfg.webui_ports),
            "realnet": dataclasses.asdict(cfg.realnet),
            "follow_the_rabbit": dataclasses.asdict(cfg.follow_the_rabbit),
        }

    try:
        return await asyncio.to_thread(_load)
    except HostsConfigError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/hosts/validate")
async def hosts_validate(req: HostsValidateRequest) -> dict[str, bool]:
    try:
        await asyncio.to_thread(_validate_hosts_content, req.content)
        return {"ok": True}
    except HostsConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


def _image_sync_api_url() -> str | None:
    """Base URL of the dedicated image-sync container, if configured."""
    url = os.getenv("DNLAB_IMAGE_SYNC_API_URL")
    return url.rstrip("/") if url else None


def _http_json(method: str, url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Minimal stdlib JSON call (avoids adding an httpx dependency)."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = resp.read().decode("utf-8") or "{}"
    return json.loads(body)


@app.get("/image-sync/status")
async def image_sync_status(state_file: str | None = None) -> dict[str, Any]:
    # Dockerized: proxy to the dedicated image-sync container.
    base = _image_sync_api_url()
    if base and not state_file:
        try:
            return await asyncio.to_thread(_http_json, "GET", f"{base}/status")
        except Exception:
            return {"available": False}
    # Bare-metal fallback: read the state file written by the systemd unit.
    state = await asyncio.to_thread(read_state_file, Path(state_file or PATHS.image_sync_state))
    if state is None:
        return {"available": False}
    return {"available": True, "state": state}


@app.post("/image-sync/reconcile")
async def image_sync_reconcile(unit: str = "dnlab-image-sync.service") -> dict[str, Any]:
    # Dockerized: ask the image-sync container to reconcile via its HTTP API.
    base = _image_sync_api_url()
    if base:
        try:
            return await asyncio.to_thread(_http_json, "POST", f"{base}/reconcile")
        except Exception as exc:
            raise HTTPException(503, str(exc)) from exc

    # Bare-metal fallback: signal the systemd unit (SIGUSR1 = "reconcile now").
    def _signal() -> dict[str, Any]:
        active = subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False)
        if active.returncode != 0:
            raise RuntimeError(f"{unit} is not active")
        proc = subprocess.run(
            ["systemctl", "kill", "--kill-whom=main", "-s", "SIGUSR1", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"failed to signal {unit}")
        return {"triggered": True, "unit": unit}

    try:
        return await asyncio.to_thread(_signal)
    except Exception as exc:
        raise HTTPException(503, str(exc)) from exc


@app.get("/lab-cleanup/status")
async def lab_cleanup_status(state_file: str | None = None) -> dict[str, Any]:
    state = await asyncio.to_thread(
        read_lab_cleanup_state_file,
        Path(state_file or PATHS.lab_cleanup_state),
    )
    if state is None:
        return {"available": False}
    return {"available": True, "state": state}


@app.post("/lab-cleanup/reconcile")
async def lab_cleanup_reconcile(
    hosts_file: str | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            hosts = await asyncio.to_thread(load_hosts_config, hosts_file)
            report = await asyncio.to_thread(
                reconcile_lab_cleanup_once,
                hosts,
                dry_run=dry_run,
            )
            return report.to_dict()
        except HostsConfigError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(503, str(exc)) from exc


@app.get("/docker/images")
async def docker_images() -> dict[str, list[dict[str, str]]]:
    try:
        return {"images": await asyncio.to_thread(_docker_images)}
    except Exception as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/realnet/rr/reconcile")
async def realnet_rr_reconcile(req: HostsRequest) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_ensure_realnet_rr, req.hosts_file)
    except HostsConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/realnet/rr/status")
async def realnet_rr_status(req: HostsRequest) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_realnet_rr_status_from_hosts, req.hosts_file)
    except HostsConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/labs/plan")
async def lab_plan(req: PlanRequest) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(
            lambda: dataclasses.asdict(
                PlanController(
                    req.topology_file,
                    no_cache=req.no_cache,
                    hosts_file=req.hosts_file,
                ).run()
            )
        )
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/status")
async def lab_status(req: LabRequest) -> dict[str, Any]:
    try:
        report = await asyncio.to_thread(
            lambda: StatusController(
                req.topology_file,
                hosts_file=req.hosts_file,
            ).run().to_dict()
        )
        topo_path = str(Path(req.topology_file).resolve())
        for (active_topology, node), operation in list(_active_node_starts.items()):
            if active_topology != topo_path or operation.done.is_set():
                continue
            info = (report.get("nodes") or {}).get(node)
            if info is not None:
                active = operation.phase != "stopped"
                info.update({
                    "state": operation.phase,
                    "can_start": not active,
                    "can_stop": active,
                    "operation_active": active,
                })
        return report
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/deploy")
async def lab_deploy(req: LabRequest) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            state = await asyncio.to_thread(
                lambda: DeployController(
                    req.topology_file,
                    hosts_file=req.hosts_file,
                    progress=_progress(req),
                ).run()
            )
            return state.to_dict() if hasattr(state, "to_dict") else {}
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


@app.post("/labs/destroy")
async def lab_destroy(req: LabRequest) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            await asyncio.to_thread(
                lambda: DestroyController(
                    req.topology_file,
                    hosts_file=req.hosts_file,
                    progress=_progress(req),
                ).run()
            )
            return {"destroyed": True}
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


@app.post("/labs/sync-images")
async def lab_sync_images(req: LabRequest) -> dict[str, list[str]]:
    try:
        return await asyncio.to_thread(
            lambda: SyncController(
                req.topology_file,
                hosts_file=req.hosts_file,
                progress=_progress(req),
            ).run()
        )
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/nodes")
async def lab_nodes(req: LabRequest) -> dict[str, Any]:
    try:
        nodes = await asyncio.to_thread(
            lambda: NodeLifecycleController(
                req.topology_file,
                hosts_file=req.hosts_file,
            ).list_nodes()
        )
        return {"nodes": {name: dataclasses.asdict(runtime) for name, runtime in nodes.items()}}
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/nodes/resolve-host")
async def lab_node_resolve_host(req: NodeRequest) -> dict[str, Any]:
    try:
        host = await asyncio.to_thread(_resolve_node_host, req)
        return {"host": _host(host, is_master=False) if host is not None else None}
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/nodes/start")
async def lab_node_start(req: NodeRequest) -> dict[str, Any]:
    key = _node_operation_key(req)
    existing = _active_node_starts.get(key)
    if existing and not existing.done.is_set():
        raise HTTPException(409, f"Start already active for node {req.node!r}")
    operation = _ActiveNodeStart(threading.Event(), asyncio.Event())
    _active_node_starts[key] = operation
    try:
        async with _mutating_lock:
            def _phase(value: str) -> None:
                operation.phase = value

            def _run():
                ctrl = NodeLifecycleController(
                    req.topology_file,
                    hosts_file=req.hosts_file,
                    cancel_event=operation.cancel,
                    phase_callback=_phase,
                )
                operation.controller = ctrl
                return ctrl.start(req.node)

            state = await asyncio.to_thread(_run)
            result = state.to_dict()
            result["_operation_outcome"] = (
                "cancelled" if operation.cancel.is_set() else "completed"
            )
            return result
    except Exception as exc:
        if operation.cancel.is_set():
            return {
                "_operation_outcome": "cancelled",
                "cancelled": True,
                "node": req.node,
            }
        raise HTTPException(422, str(exc)) from exc
    finally:
        operation.done.set()
        _active_node_starts.pop(key, None)


@app.post("/labs/nodes/stop")
async def lab_node_stop(req: NodeRequest) -> dict[str, Any]:
    operation = _active_node_starts.get(_node_operation_key(req))
    cancelled_start = False
    if operation and not operation.done.is_set():
        cancelled_start = True
        controller = operation.controller
        if controller is not None:
            controller.request_cancel()
        else:
            operation.cancel.set()
        previous_phase = operation.phase
        if previous_phase == "queued":
            operation.phase = "stopped"
        else:
            operation.phase = "cancelling"
        return {
            "_operation_outcome": "cancelled",
            "cancelled": True,
            "node": req.node,
        }
    result = await _node_mutation(req, "stop", force=True)
    if cancelled_start:
        result["cancelled"] = True
    return result


@app.post("/labs/nodes/remove")
async def lab_node_remove(req: NodeRequest) -> dict[str, Any]:
    return await _node_mutation(req, "remove", force=True)


@app.post("/labs/nodes/restart")
async def lab_node_restart(req: NodeRequest) -> dict[str, Any]:
    return await _node_mutation(req, "restart")


@app.post("/labs/nodes/reconcile")
async def lab_node_reconcile(req: NodeRequest) -> dict[str, Any]:
    return await _node_mutation(req, "reconcile")


@app.post("/labs/links/reconcile")
async def lab_link_reconcile(req: LinkRequest) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            def _run():
                ctrl = NodeLifecycleController(req.topology_file, hosts_file=req.hosts_file)
                source_is_node = req.source in ctrl.topo.nodes
                target_is_node = req.target in ctrl.topo.nodes
                if source_is_node and target_is_node:
                    return ctrl.reconcile_link(
                        req.source, req.source_iface, req.target, req.target_iface,
                    )
                if source_is_node:
                    return ctrl.reconcile_link(
                        req.source, req.source_iface, real_net=req.target,
                    )
                if target_is_node:
                    return ctrl.reconcile_link(
                        req.target, req.target_iface, real_net=req.source,
                    )
                raise ValueError("link must contain at least one VD endpoint")

            link = await asyncio.to_thread(_run)
            return dataclasses.asdict(link)
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


@app.post("/labs/realnet/reconcile")
async def lab_realnet_reconcile(req: RealNetRequest) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            state = await asyncio.to_thread(
                lambda: RealNetLifecycleController(
                    req.topology_file,
                    hosts_file=req.hosts_file,
                ).reconcile(req.realnet)
            )
            return state.to_dict()
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


@app.post("/labs/jumphost/password")
async def lab_jumphost_password(req: LabRequest) -> dict[str, Any]:
    try:
        return {"password": await asyncio.to_thread(_jumphost_password, req)}
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/runtime-relay")
async def lab_runtime_relay(req: NodeRequest) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_runtime_relay, req)
    except Exception as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/labs/follow-rabbit/sessions")
async def follow_rabbit_start(req: FollowRabbitStartRequest) -> dict[str, Any]:
    try:
        flow = FlowFilter(
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
            protocol=req.protocol or "",
            src_port=req.src_port or 0,
            dst_port=req.dst_port or 0,
        )
        return await follow_rabbit_manager.start(
            topology_file=req.topology_file,
            hosts_file=req.hosts_file,
            source_node=req.source_node,
            flow=flow,
            timeout_seconds=req.timeout_seconds or 60,
            emit=_follow_rabbit_progress(req),
        )
    except FollowRabbitError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/labs/follow-rabbit/sessions/list")
async def follow_rabbit_list(req: LabRequest) -> dict[str, Any]:
    try:
        return {"sessions": await follow_rabbit_manager.list_sessions(req.lab_name)}
    except Exception as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/labs/follow-rabbit/sessions/stop")
async def follow_rabbit_stop(req: LabRequest, session_id: str) -> dict[str, Any]:
    try:
        return await follow_rabbit_manager.stop(session_id, emit=_follow_rabbit_progress(req))
    except FollowRabbitError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/labs/persistence/clean")
async def lab_persistence_clean(req: LabRequest) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            return await asyncio.to_thread(_clean_persist_dirs, req)
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


@app.post("/labs/persistence/wipe-node")
async def lab_persistence_wipe_node(req: NodeRequest) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            return await asyncio.to_thread(_wipe_node_persist_dir, req)
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


@app.websocket("/ws/events/{topic}")
async def events_ws(ws: WebSocket, topic: str) -> None:
    await ws.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    loop = asyncio.get_running_loop()
    subscriber = (loop, q)
    _subscribers[topic].add(subscriber)
    for event in list(_events[topic]):
        await ws.send_json(event)
    try:
        while True:
            await ws.send_json(await q.get())
    except (WebSocketDisconnect, asyncio.CancelledError):
        return
    finally:
        _subscribers[topic].discard(subscriber)


async def _node_mutation(
    req: NodeRequest, action: str, *, force: bool = False,
) -> dict[str, Any]:
    async with _mutating_lock:
        try:
            def _run():
                ctrl = NodeLifecycleController(req.topology_file, hosts_file=req.hosts_file)
                if action == "start":
                    return ctrl.start(req.node)
                if action == "stop":
                    return ctrl.stop(req.node, force=force)
                if action == "restart":
                    return ctrl.restart(req.node)
                if action == "remove":
                    return ctrl.remove(req.node)
                return ctrl.reconcile(req.node)

            state = await asyncio.to_thread(_run)
            return state.to_dict()
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc


def _progress(req: LabRequest):
    topic = _topic(req)

    def _publish(evt: ProgressEvent) -> None:
        event = evt.to_dict()
        event["topic"] = topic
        _events[topic].append(event)
        for loop, q in list(_subscribers[topic]):
            try:
                loop.call_soon_threadsafe(_queue_event, q, event)
            except RuntimeError:
                _subscribers[topic].discard((loop, q))

    return _publish


def _follow_rabbit_progress(req: LabRequest):
    topic = _topic(req)

    def _publish(event: dict[str, Any]) -> None:
        event["topic"] = topic
        _events[topic].append(event)
        for loop, q in list(_subscribers[topic]):
            try:
                loop.call_soon_threadsafe(_queue_event, q, event)
            except RuntimeError:
                _subscribers[topic].discard((loop, q))

    return _publish


def _docker_images() -> list[dict[str, str]]:
    proc = subprocess.run(
        ["docker", "image", "ls", "--format", "{{json .}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "docker image ls failed")
    images: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        repository = row.get("Repository") or ""
        tag = row.get("Tag") or "latest"
        if not repository or repository == "<none>":
            continue
        # Kind/vendor classification is owned by the GUI (devices.json catalog);
        # this endpoint only returns the raw image inventory.
        images.append({
            "repository": repository,
            "tag": tag,
            "image_id": row.get("ID") or row.get("ImageID") or "",
        })
    return images


def _validate_hosts_content(content: str) -> None:
    import tempfile

    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as fh:
            fh.write(content)
            tmp = fh.name
        load_hosts_config(tmp)
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _resolve_node_host(req: NodeRequest):
    cfg = load_hosts_config(req.hosts_file)
    try:
        status = StatusController(req.topology_file, hosts_file=req.hosts_file).run()
        if status.deployed:
            node = status.nodes.get(req.node)
            if node is None:
                raise RuntimeError(f"node {req.node!r} not found in live status")
            if node.duplicate_hosts:
                raise RuntimeError(
                    f"container {node.container} exists on multiple hosts "
                    f"({', '.join(node.duplicate_hosts)}); refusing to guess"
                )
            host_name = node.host or node.scheduled_host
            if not host_name or host_name == cfg.master.name:
                return None
            host = cfg.workers.get(host_name)
            if host is None:
                raise RuntimeError(f"node {req.node!r} resolved to unknown worker {host_name!r}")
            return host
    except RuntimeError:
        raise
    except Exception:
        pass

    plan = PlanController(req.topology_file, hosts_file=req.hosts_file).run()
    host_name = plan.host_for_vd(req.node)
    if not host_name or host_name == cfg.master.name:
        return None
    return cfg.workers.get(host_name)


def _lab_name(req: LabRequest) -> str:
    if req.lab_name:
        return req.lab_name
    return Path(req.topology_file).stem


def _lab_state(req: LabRequest):
    lab_name = _lab_name(req)
    state = state_svc.load_state(lab_name, Path(req.topology_file).parent)
    if state is None:
        raise RuntimeError(f"lab {lab_name} not deployed")
    return state


def _runtime_aliases(value: str) -> set[str]:
    value = str(value or "").strip()
    aliases = {value} if value else set()
    upper = value.upper()
    if upper.startswith("NEW-") and len(value) > 4:
        aliases.add(value[4:])
    elif value:
        aliases.add(f"NEW-{value}")
    return {alias for alias in aliases if alias}


def _resolve_runtime_node_key(state, requested: str) -> str:
    runtimes = state.node_runtime or {}
    if requested in runtimes:
        return requested

    requested_aliases = {alias.lower() for alias in _runtime_aliases(requested)}
    matches = []
    for key, runtime in runtimes.items():
        key_aliases = {alias.lower() for alias in _runtime_aliases(key)}
        container = str(getattr(runtime, "container", "") or "")
        container_aliases = {alias.lower() for alias in _runtime_aliases(container)}
        if (
            requested.lower() == str(getattr(runtime, "node", "") or "").lower()
            or requested.lower() == container.lower()
            or requested_aliases & key_aliases
            or requested_aliases & container_aliases
            or any(container.lower().endswith(f"-{alias}") for alias in requested_aliases)
        ):
            matches.append(key)

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RuntimeError(
            f"node alias {requested!r} matches multiple runtime nodes: {', '.join(matches)}"
        )
    raise RuntimeError(f"node {requested!r} not found in runtime state")


def _jumphost_password(req: LabRequest) -> str:
    state = _lab_state(req)
    if not state.jumphost or not state.jumphost.password:
        raise RuntimeError(f"lab {_lab_name(req)} has no jumphost password in state")
    return state.jumphost.password


def _runtime_relay(req: NodeRequest) -> dict[str, Any]:
    state = _lab_state(req)
    runtime_key = _resolve_runtime_node_key(state, req.node)
    runtime = (state.node_runtime or {}).get(runtime_key)
    relay = (state.runtime_relays or {}).get(runtime.host)
    if relay is None:
        raise RuntimeError(f"runtime relay missing for host {runtime.host!r}")
    if runtime.container not in set(relay.allowed or []):
        raise RuntimeError(f"container {runtime.container!r} is not allowed on relay {runtime.host!r}")
    return {
        "container": runtime.container,
        "host": relay.bind_ip,
        "port": relay.port,
        "api_key": relay.api_key,
        "relay_host": runtime.host,
    }


def _clean_persist_dirs(req: LabRequest) -> dict[str, Any]:
    cfg = load_hosts_config(req.hosts_file)
    lab_name = _lab_name(req)
    persist_root = f"{cfg.persistence.root.rstrip('/')}/{lab_name}"
    results: dict[str, str] = {}
    all_hosts = {"master": cfg.master, **cfg.workers}
    for name, host in all_hosts.items():
        client = SSHClient(host=host.host, user=host.ssh_user, key_path=host.ssh_key, name=name)
        try:
            client.connect()
            client.run(f"rm -rf {shlex.quote(persist_root)}", timeout=15)
            results[name] = "ok"
        except Exception as exc:
            results[name] = f"error: {exc}"
        finally:
            client.close()
    try:
        placement_file_path(lab_name, Path(req.topology_file).parent).unlink(missing_ok=True)
    except Exception as exc:
        results["placement-history"] = f"error: {exc}"
    return results


def _wipe_node_persist_dir(req: NodeRequest) -> dict[str, Any]:
    cfg = load_hosts_config(req.hosts_file)
    topo = parse_topology(req.topology_file, hosts_file=req.hosts_file)
    lab_name = topo.name
    node = topo.nodes.get(req.node)
    if node is None:
        raise RuntimeError(f"node {req.node!r} not found in topology")
    persist_key = node.persist_id or req.node
    persist_dir = persist_dir_for_node(lab_name, req.node, node.persist_id, cfg.persistence.root)
    quoted = shlex.quote(persist_dir)
    results: dict[str, str] = {}
    all_hosts = {"master": cfg.master, **cfg.workers}
    for name, host in all_hosts.items():
        client = SSHClient(host=host.host, user=host.ssh_user, key_path=host.ssh_key, name=name)
        try:
            client.connect()
            rc, _out, err = client.run_no_check(
                f"if test -d {quoted}; then rm -rf -- {quoted}; else exit 3; fi",
                timeout=30,
            )
            if rc == 0:
                results[name] = "ok"
            elif rc == 3:
                results[name] = "missing"
            else:
                results[name] = f"error: {err or f'rc={rc}'}"
        except Exception as exc:
            results[name] = f"error: {exc}"
        finally:
            client.close()

    try:
        _drop_node_placement(
            placement_file_path(lab_name, Path(req.topology_file).parent),
            req.node,
            persist_key,
        )
    except Exception as exc:
        results["placement-history"] = f"error: {exc}"
    return {"path": persist_dir, "persist_id": persist_key, "results": results}


def _drop_node_placement(path: Path, node_name: str, persist_id: str | None = None) -> None:
    if not path.exists():
        return
    data = json.loads(path.read_text())
    keys = {node_name}
    if persist_id:
        keys.add(persist_id)
    if isinstance(data, dict) and isinstance(data.get("placements"), dict):
        for key in keys:
            data["placements"].pop(key, None)
        if isinstance(data.get("nodes"), dict):
            for key in keys:
                data["nodes"].pop(key, None)
        path.write_text(json.dumps(data, indent=2))
    elif isinstance(data, dict):
        for key in keys:
            data.pop(key, None)
        path.write_text(json.dumps(data, indent=2))


def _ensure_realnet_rr(hosts_file: str | None) -> dict[str, Any]:
    cfg = load_hosts_config(hosts_file)
    rn = cfg.realnet
    if not rn.rr_ip or not rn.host_net:
        return {
            "ok": False,
            "skipped": True,
            "reason": "RealNet BGP RR IP/Host network not configured",
        }
    infra = RealNetInfraCfg(
        network=rn.network,
        bridge=rn.bridge,
        ipv4_subnet=rn.ipv4_subnet,
        ipv4_gw=rn.ipv4_gw,
        image=rn.image,
        wan_iface=rn.wan_iface,
        rr_as=rn.rr_as,
        rr_ip=rn.rr_ip,
        host_net=rn.host_net,
        router_as_pool=rn.router_as_pool,
        router_ip_pool=rn.router_ip_pool,
        realnet_network_pool=rn.realnet_network_pool,
        rr_password=rn.rr_password,
    )
    topo = SimpleNamespace(realnet_infra=infra)
    client = SSHClient(
        host=cfg.master.host,
        user=cfg.master.ssh_user,
        key_path=cfg.master.ssh_key,
        name=cfg.master.name,
    )
    client.connect()
    try:
        realnet_svc.deploy_route_reflector(topo, client)
        return {"ok": True, "skipped": False, **_realnet_rr_status(client)}
    finally:
        client.close()


def _realnet_rr_status(client: SSHClient) -> dict[str, Any]:
    rc, out, _ = client.run_no_check(
        "docker inspect -f '{{.State.Running}} {{.Config.Image}}' dnlab-realnet-rr"
    )
    if rc != 0:
        return {"running": False, "container": "dnlab-realnet-rr", "image": ""}
    parts = (out or "").split(maxsplit=1)
    return {
        "running": bool(parts and parts[0] == "true"),
        "container": "dnlab-realnet-rr",
        "image": parts[1] if len(parts) > 1 else "",
    }


def _realnet_rr_status_from_hosts(hosts_file: str | None) -> dict[str, Any]:
    cfg = load_hosts_config(hosts_file)
    client = SSHClient(
        host=cfg.master.host,
        user=cfg.master.ssh_user,
        key_path=cfg.master.ssh_key,
        name=cfg.master.name,
    )
    client.connect()
    try:
        return _realnet_rr_status(client)
    finally:
        client.close()


def _topic(req: LabRequest) -> str:
    return req.lab_id or Path(req.topology_file).stem


def _queue_event(q: asyncio.Queue, event: dict[str, Any]) -> None:
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        pass


def _host(host, *, is_master: bool) -> dict[str, Any]:
    return {
        "name": host.name,
        "host": host.host,
        "ssh_user": host.ssh_user,
        "is_master": is_master,
    }


def main() -> None:
    import uvicorn

    setup_service_logging(
        service="multinode",
        filename="dnlab-multinode.log",
    )
    uvicorn.run(
        "dnlab_multinode.api:app",
        host=os.getenv("DNLAB_MULTINODE_API_HOST", "127.0.0.1"),
        port=int(os.getenv("DNLAB_MULTINODE_API_PORT", "8081")),
        reload=os.getenv("DNLAB_MULTINODE_API_RELOAD", "false").lower() == "true",
    )


if __name__ == "__main__":
    main()
