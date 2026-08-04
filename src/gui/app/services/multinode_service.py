"""Async façade over the dnlab-multinode orchestrator.

`dnlab-multinode` is a thread-safe but blocking Python library (paramiko
SSH + subprocess). Wrapping every call in :func:`asyncio.to_thread`
gives FastAPI route handlers a clean `await` surface without dragging
an async SSH stack into the orchestrator.

Concurrency rules:

* **deploy / destroy are serialised** by a single module-level
  :class:`asyncio.Lock`. Running two deploys at the same time would
  race on the master's mgmt bridge and the clab state file.
* **plan / status / sync** are read-mostly and run concurrently —
  they do not acquire the global lock.

Progress callback → event bus bridge:

Each long-running method builds a synchronous callback that enriches
the :class:`dnlab_multinode.ProgressEvent` with the current lab name and
hands the result to the in-process :class:`~app.services.events_bus.EventsBus`.
The callback runs on the controller thread (inside :func:`asyncio.to_thread`),
so it uses the bus's thread-safe :meth:`~app.services.events_bus.EventsBus.publish`
API.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import json
import logging
from pathlib import Path
import shlex
import threading
from types import SimpleNamespace
from typing import Any

import httpx
import websockets

from app.config import settings
from app.services.events_bus import BusEvent, bus
from app.services.lab_resolver import ResolvedLab

log = logging.getLogger(__name__)


# One lock for GUI process: serialises deploy / destroy. Plan / status
# / sync remain concurrent.
_deploy_lock = asyncio.Lock()


@dataclasses.dataclass
class _LocalNodeStart:
    cancel: threading.Event
    done: asyncio.Event
    phase: str = "queued"


_local_node_starts: dict[tuple[str, str], _LocalNodeStart] = {}


class MultinodeServiceError(Exception):
    """Raised when the orchestrator cannot be invoked (missing hosts.yml,
    topology not found, etc)."""


def _load_hosts_config_or_raise(hosts_file: str | None):
    from dnlab_multinode import load_hosts_config
    from dnlab_multinode.services.hosts_config import HostsConfigError

    try:
        return load_hosts_config(hosts_file)
    except HostsConfigError as exc:
        raise MultinodeServiceError(str(exc)) from exc


def _require_file(lab: ResolvedLab) -> Path:
    if not lab.yaml_path.exists():
        raise MultinodeServiceError(
            f"Topology file not found: {lab.yaml_path}",
        )
    return lab.yaml_path


def _bus_tag(lab: ResolvedLab) -> str:
    """Event-bus topic key. We use the UUID string so routes can
    subscribe via ``/ws/events/<uuid>`` without having to resolve the
    netname client-side."""
    return str(lab.id)


def _derive_mgmt_ipv6_defaults(v4_subnet: str, v4_gw: str) -> tuple[str, str]:
    """Build IPv4-mapped IPv6 defaults from the IPv4 mgmt config.

    e.g. ``192.0.2.0/24`` → ``::ffff:192.0.2.0/120``,
         ``192.0.2.1`` → ``::ffff:192.0.2.1``. The jumphost talks v4
    only, so the v6 block is purely a containerlab assignment hint.
    """
    if not v4_subnet:
        return "", ""
    try:
        net = ipaddress.IPv4Network(v4_subnet, strict=False)
    except (ValueError, ipaddress.AddressValueError):
        return "", ""
    v6_prefix = 96 + net.prefixlen
    v6_subnet = f"::ffff:{net.network_address}/{v6_prefix}"
    try:
        v4_gateway = str(net.broadcast_address - 1)
    except Exception:
        v4_gateway = v4_gw.strip() if v4_gw and v4_gw.strip() else ""
    v6_gw = f"::ffff:{v4_gateway}" if v4_gateway else ""
    return v6_subnet, v6_gw


def _runtime_aliases(value: str) -> set[str]:
    value = str(value or "").strip()
    aliases = {value} if value else set()
    upper = value.upper()
    if upper.startswith("NEW-") and len(value) > 4:
        aliases.add(value[4:])
    elif value:
        aliases.add(f"NEW-{value}")
    return {alias for alias in aliases if alias}


def _resolve_runtime_node_key(state: Any, requested: str) -> str:
    """Resolve a UI/runtime alias to the persisted node_runtime key.

    Some older GUI-created topologies used names such as ``NEW-SERVER`` while
    the visual/runtime object may later be addressed as ``SERVER``. Relay state
    remains keyed by the deployment-time node name, so console/log callers need
    one canonical lookup point instead of failing on that harmless alias drift.
    """
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
        raise MultinodeServiceError(
            f"node alias {requested!r} matches multiple runtime nodes: {', '.join(matches)}"
        )
    raise MultinodeServiceError(f"node {requested!r} not found in runtime state")


def _materialize_topology_metadata(topo_path: Path) -> None:
    """Refresh GUI-derived deployment metadata sidecars before planning.

    The multinode orchestrator intentionally stays catalog-agnostic; the GUI
    adapter writes data-driven sidecars (deploy-kind aliases, resource schema,
    Web UI wishlist, node overrides) into the topology file before invoking it.
    """
    from app.services.containerlab_service import ContainerLabService
    clab = ContainerLabService()
    topology = clab.load_topology_from_file(topo_path)
    clab.save_topology_to(topo_path, topology)


class MultinodeService:
    """Thin async adapter around the dnlab-multinode controllers."""

    def __init__(self) -> None:
        self._hosts_file = settings.DNLAB_MULTINODE_HOSTS
        self._api_url = settings.DNLAB_MULTINODE_API_URL
        self._remote_event_bridges: dict[str, asyncio.Task] = {}

    @property
    def _use_api(self) -> bool:
        return bool(self._api_url)

    # ── helpers ───────────────────────────────────────────────────

    def _make_progress_cb(self, lab_tag: str):
        """Build a sync callback that forwards controller events to the
        in-process event bus, tagging each event with the lab tag."""
        def _cb(evt) -> None:
            bus.publish(BusEvent(
                lab=lab_tag,
                phase=evt.phase,
                status=evt.status,
                host=evt.host,
                detail=evt.detail,
                elapsed_ms=evt.elapsed_ms,
                data=dict(evt.data or {}),
            ))
        return _cb

    # ── read-only operations ──────────────────────────────────────

    async def list_hosts(self) -> dict:
        """Return the parsed site-wide inventory as a JSON-safe dict.

        Used by ``GET /api/hosts/``.
        """
        if self._use_api:
            return await self._api_post("/hosts", {"hosts_file": self._hosts_file})

        def _load() -> dict:
            cfg = _load_hosts_config_or_raise(self._hosts_file)
            return {
                "source_path": str(cfg.source_path) if cfg.source_path else None,
                "underlay_iface": cfg.underlay_iface,
                "master": {
                    "name": cfg.master.name,
                    "host": cfg.master.host,
                    "ssh_user": cfg.master.ssh_user,
                    "is_master": True,
                },
                "workers": [
                    {
                        "name": w.name,
                        "host": w.host,
                        "ssh_user": w.ssh_user,
                        "is_master": False,
                    }
                    for w in cfg.workers.values()
                ],
                "mgmt_defaults": {
                    "ipv4_subnet": cfg.mgmt_defaults.ipv4_subnet,
                    "ipv4_gw": cfg.mgmt_defaults.ipv4_gw,
                    **dict(zip(
                        ("ipv6_subnet", "ipv6_gw"),
                        _derive_mgmt_ipv6_defaults(
                            cfg.mgmt_defaults.ipv4_subnet,
                            cfg.mgmt_defaults.ipv4_gw,
                        ),
                    )),
                },
                "image_sync": {
                    "enabled": cfg.image_sync.enabled,
                    "include": cfg.image_sync.include,
                    "exclude": cfg.image_sync.exclude,
                    "interval_seconds": cfg.image_sync.interval_seconds,
                },
            }
        return await asyncio.to_thread(_load)

    async def resolve_node_host(
        self, lab: ResolvedLab, node_name: str,
    ) -> Any | None:
        """Resolve the host where ``node_name``.

        Ritorna l'``InfraHost`` del worker che lo ospita, oppure
        ``None`` if the node is on the master (the caller will use local docker
        locale). For deployed labs, prefer the live status probe; the planner
        is only a fallback for non-deployed/pre-deploy contexts.
        """
        topo_path = _require_file(lab)
        if self._use_api:
            _materialize_topology_metadata(topo_path)
            result = await self._api_post(
                "/labs/nodes/resolve-host",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )
            host = result.get("host")
            return SimpleNamespace(**host) if isinstance(host, dict) else None

        def _resolve() -> Any | None:
            from dnlab_multinode import PlanController, StatusController

            cfg = _load_hosts_config_or_raise(self._hosts_file)

            try:
                status = StatusController(str(topo_path), hosts_file=self._hosts_file).run()
                if status.deployed:
                    node = status.nodes.get(node_name)
                    if node is None:
                        raise MultinodeServiceError(
                            f"node {node_name!r} not found in live status for {lab.netname}"
                        )
                    if node.duplicate_hosts:
                        raise MultinodeServiceError(
                            f"container {node.container} exists on multiple hosts "
                            f"({', '.join(node.duplicate_hosts)}); refusing to guess"
                        )
                    if node.placement_mismatch:
                        log.warning(
                            "resolve_node_host(%s/%s): live host %s differs from scheduled host %s",
                            lab.netname, node_name, node.host, node.scheduled_host,
                        )
                    host_name = node.host or node.scheduled_host
                    if not host_name or host_name == cfg.master.name:
                        return None
                    host = cfg.workers.get(host_name)
                    if host is None:
                        raise MultinodeServiceError(
                            f"node {node_name!r} resolved to unknown worker {host_name!r}"
                        )
                    return host
            except MultinodeServiceError:
                raise
            except Exception as exc:
                log.warning(
                    "resolve_node_host(%s/%s): live status failed, falling back to planner: %s",
                    lab.netname, node_name, exc,
                )

            try:
                _materialize_topology_metadata(topo_path)
                ctrl = PlanController(str(topo_path), hosts_file=self._hosts_file)
                plan = ctrl.run()
            except Exception as exc:
                # Il planner fallisce se le images non sono ancora
                # sincronizzate sui worker: in quel caso non possiamo
                # resolve the host, the caller will use the fallback
                # locale (master docker exec).
                log.warning("resolve_node_host(%s/%s): planner failed: %s",
                            lab.netname, node_name, exc)
                raise MultinodeServiceError(f"planner failed: {exc}") from exc
            host_name = plan.host_for_vd(node_name)
            if not host_name or host_name == cfg.master.name:
                return None
            return cfg.workers.get(host_name)
        return await asyncio.to_thread(_resolve)

    async def plan(self, lab: ResolvedLab) -> dict:
        """Run the planner and return the resulting schedule."""
        topo_path = _require_file(lab)
        _materialize_topology_metadata(topo_path)
        if self._use_api:
            return await self._api_post(
                "/labs/plan",
                self._lab_payload(lab, topology_file=topo_path),
            )

        def _plan() -> dict:
            from dnlab_multinode import PlanController

            ctrl = PlanController(str(topo_path), hosts_file=self._hosts_file)
            plan_result = ctrl.run()
            # SchedulePlan is a dataclass with no to_dict(); asdict()
            # handles it + all nested dataclasses in one shot.
            return dataclasses.asdict(plan_result)
        return await asyncio.to_thread(_plan)

    async def status(self, lab: ResolvedLab, *, emit_events: bool = True) -> dict:
        """Run the live status probe and return the JSON report.

        GUI polling calls this often; those probes should not be rendered
        as lab progress events.
        """
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/status",
                self._lab_payload(lab, topology_file=topo_path),
                bridge_events=emit_events,
                topic=_bus_tag(lab),
            )
        cb = self._make_progress_cb(_bus_tag(lab)) if emit_events else None

        def _status() -> dict:
            from dnlab_multinode import StatusController

            kwargs: dict[str, Any] = {"hosts_file": self._hosts_file}
            if cb is not None:
                kwargs["progress"] = cb
            ctrl = StatusController(str(topo_path), **kwargs)
            report = ctrl.run()
            return report.to_dict()
        report = await asyncio.to_thread(_status)
        for (netname, node), operation in list(_local_node_starts.items()):
            if netname != lab.netname or operation.done.is_set():
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

    async def image_sync_status(self) -> dict | None:
        """Return the daemon's published state (or None if unavailable)."""
        if self._use_api:
            result = await self._api_get("/image-sync/status")
            return result.get("state") if result.get("available") else None

        from dnlab_multinode.services.image_sync import read_state_file

        def _read() -> dict | None:
            return read_state_file(settings.IMAGE_SYNC_STATE_FILE)
        return await asyncio.to_thread(_read)

    async def trigger_image_sync_reconcile(self) -> dict:
        """Ask the image-sync systemd unit to reconcile now (SIGUSR1).

        The daemon's CLI entrypoint installs a SIGUSR1 handler that
        calls :meth:`ImageSyncDaemon.trigger_reconcile`. We deliver the
        signal via ``systemctl kill``, which is a no-op on systems
        where the unit isn't running — we report that case back so the
        UI can surface it instead of silently succeeding.
        """
        if self._use_api:
            return await self._api_post("/image-sync/reconcile", {})

        import subprocess

        unit = "dnlab-image-sync.service"

        def _kill() -> dict:
            # Is the unit active? If not, SIGUSR1 can't be delivered.
            rc = subprocess.run(
                ["systemctl", "is-active", "--quiet", unit],
                check=False,
            ).returncode
            if rc != 0:
                raise MultinodeServiceError(
                    f"{unit} is not active — start it with "
                    f"`systemctl start {unit}` before triggering a reconcile"
                )
            # --kill-whom=main targets only the main PID of the unit.
            # Without it systemctl signals every process in the cgroup,
            # which could hit transient docker subprocesses with SIGUSR1
            # (default action: terminate) and abort an in-flight pull.
            proc = subprocess.run(
                ["systemctl", "kill", "--kill-whom=main", "-s", "SIGUSR1", unit],
                capture_output=True, text=True, check=False,
            )
            if proc.returncode != 0:
                raise MultinodeServiceError(
                    f"failed to signal {unit}: {proc.stderr.strip() or proc.stdout.strip()}"
                )
            return {"triggered": True, "unit": unit}
        return await asyncio.to_thread(_kill)

    async def sync_images(self, lab: ResolvedLab) -> dict:
        """Sync the images referenced by the lab from the master
        to every worker that will schedule one of them.

        Returns ``{image: [hosts_synced]}`` as produced by
        :class:`dnlab_multinode.SyncController`.
        """
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/sync-images",
                self._lab_payload(lab, topology_file=topo_path),
                bridge_events=True,
                topic=_bus_tag(lab),
            )
        cb = self._make_progress_cb(_bus_tag(lab))

        def _sync() -> dict:
            from dnlab_multinode import SyncController

            ctrl = SyncController(
                str(topo_path),
                hosts_file=self._hosts_file,
                progress=cb,
            )
            return ctrl.run()
        return await asyncio.to_thread(_sync)

    async def jumphost_password(self, lab: ResolvedLab) -> str:
        """Return the per-lab jumphost password from the deployment state.

        Raises :class:`MultinodeServiceError` if the lab isn't deployed or
        the state file has no jumphost block. The password is never
        logged — callers audit the event separately.
        """
        topo_path = _require_file(lab)
        if self._use_api:
            result = await self._api_post(
                "/labs/jumphost/password",
                self._lab_payload(lab, topology_file=topo_path),
            )
            password = result.get("password")
            if not isinstance(password, str):
                raise MultinodeServiceError("multinode API returned invalid jumphost password response")
            return password

        def _read() -> str:
            from dnlab_multinode.services import state as state_svc
            state = state_svc.load_state(lab.netname, topo_path.parent)
            if state is None:
                raise MultinodeServiceError(f"lab {lab.netname} not deployed")
            if not state.jumphost or not state.jumphost.password:
                raise MultinodeServiceError(
                    f"lab {lab.netname} has no jumphost password in state",
                )
            return state.jumphost.password
        return await asyncio.to_thread(_read)

    async def resolve_runtime_relay(self, lab: ResolvedLab, node_name: str) -> dict:
        """Return runtime relay endpoint/auth for a deployed lab node."""
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/runtime-relay",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )

        def _read() -> dict:
            from dnlab_multinode.services import state as state_svc
            state = state_svc.load_state(lab.netname, topo_path.parent)
            if state is None:
                raise MultinodeServiceError(f"lab {lab.netname} not deployed")
            runtime_key = _resolve_runtime_node_key(state, node_name)
            runtime = (state.node_runtime or {}).get(runtime_key)
            relay = (state.runtime_relays or {}).get(runtime.host)
            if relay is None:
                raise MultinodeServiceError(
                    f"runtime relay missing for host {runtime.host!r}"
                )
            if runtime.container not in set(relay.allowed or []):
                raise MultinodeServiceError(
                    f"container {runtime.container!r} is not allowed on relay {runtime.host!r}"
                )
            return {
                "container": runtime.container,
                "host": relay.bind_ip,
                "port": relay.port,
                "api_key": relay.api_key,
                "relay_host": runtime.host,
            }
        return await asyncio.to_thread(_read)

    # ── deploy / destroy (serialised) ─────────────────────────────

    async def deploy(self, lab: ResolvedLab) -> dict:
        topo_path = _require_file(lab)
        _materialize_topology_metadata(topo_path)
        if self._use_api:
            return await self._api_post(
                "/labs/deploy",
                self._lab_payload(lab, topology_file=topo_path),
                bridge_events=True,
                topic=_bus_tag(lab),
            )
        cb = self._make_progress_cb(_bus_tag(lab))

        async with _deploy_lock:
            log.info("deploy %s (%s): acquired lock", lab.display_name, lab.netname)

            def _deploy() -> dict:
                from dnlab_multinode import DeployController

                ctrl = DeployController(
                    str(topo_path),
                    hosts_file=self._hosts_file,
                    progress=cb,
                )
                state = ctrl.run()
                return state.to_dict() if hasattr(state, "to_dict") else {}
            try:
                return await asyncio.to_thread(_deploy)
            finally:
                log.info("deploy %s: released lock", lab.netname)

    async def clean_persist_dirs(self, lab: ResolvedLab) -> dict:
        """Remove the lab's persist directory on every host.

        ``persist_root`` comes from ``hosts.yml`` persistence settings,
        falling back to ``paths.yml`` defaults. The orchestrator generator
        writes `/persist` binds at ``<persist_root>/<netname>/<vd>/`` — so
        we wipe by netname, not by display name. Best-effort: unreachable
        hosts or missing dirs are silently skipped. Returns
        ``{host: "ok"|"error: ..."}``.
        """
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/persistence/clean",
                self._lab_payload(lab, topology_file=topo_path),
            )

        def _clean() -> dict:
            cfg = _load_hosts_config_or_raise(self._hosts_file)

            from dnlab_multinode.services.ssh import SSHClient
            from dnlab_multinode.services.persistence import placement_file_path
            persist_root = f"{cfg.persistence.root.rstrip('/')}/{lab.netname}"
            results: dict[str, str] = {}
            all_hosts = {"master": cfg.master, **cfg.workers}
            for name, host in all_hosts.items():
                client = SSHClient(
                    host=host.host,
                    user=host.ssh_user,
                    key_path=host.ssh_key,
                    name=name,
                )
                try:
                    client.connect()
                    client.run(f"rm -rf '{persist_root}'", timeout=15)
                    results[name] = "ok"
                except Exception as exc:
                    results[name] = f"error: {exc}"
                    log.warning("[%s] clean_persist_dirs(%s): %s", name, lab.netname, exc)
                finally:
                    client.close()
            try:
                placement_file_path(lab.netname, lab.yaml_path.parent).unlink(missing_ok=True)
            except Exception as exc:
                results["placement-history"] = f"error: {exc}"
            return results
        return await asyncio.to_thread(_clean)

    async def wipe_node_persist_dir(self, lab: ResolvedLab, node_name: str) -> dict:
        """Remove one VD persistent directory on every host.

        Persistence lives at ``<persist_root>/<netname>/<vd>``. We wipe all
        hosts because placement may have changed across deploys, leaving a
        stale overlay away from the current scheduler choice.
        """
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/persistence/wipe-node",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )

        def _wipe() -> dict:
            cfg = _load_hosts_config_or_raise(self._hosts_file)

            from dnlab_multinode.services.ssh import SSHClient
            from dnlab_multinode.services.persistence import placement_file_path
            from dnlab_multinode.services.paths import persist_dir_for

            persist_dir = persist_dir_for(lab.netname, node_name, cfg.persistence.root)
            quoted = shlex.quote(persist_dir)
            results: dict[str, str] = {}
            all_hosts = {"master": cfg.master, **cfg.workers}
            for name, host in all_hosts.items():
                client = SSHClient(
                    host=host.host,
                    user=host.ssh_user,
                    key_path=host.ssh_key,
                    name=name,
                )
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
                    log.warning(
                        "[%s] wipe_node_persist_dir(%s/%s): %s",
                        name, lab.netname, node_name, exc,
                    )
                finally:
                    client.close()

            try:
                _drop_node_placement(
                    placement_file_path(lab.netname, lab.yaml_path.parent),
                    node_name,
                )
            except Exception as exc:
                results["placement-history"] = f"error: {exc}"
            return {"path": persist_dir, "results": results}
        return await asyncio.to_thread(_wipe)

    async def destroy(self, lab: ResolvedLab) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            result = await self._api_post(
                "/labs/destroy",
                self._lab_payload(lab, topology_file=topo_path),
                bridge_events=True,
                topic=_bus_tag(lab),
            )
            return {"destroyed": lab.netname, **result}
        cb = self._make_progress_cb(_bus_tag(lab))

        async with _deploy_lock:
            log.info("destroy %s (%s): acquired lock", lab.display_name, lab.netname)

            def _destroy() -> dict:
                from dnlab_multinode import DestroyController

                ctrl = DestroyController(
                    str(topo_path),
                    hosts_file=self._hosts_file,
                    progress=cb,
                )
                ctrl.run()
                return {"destroyed": lab.netname}
            try:
                return await asyncio.to_thread(_destroy)
            finally:
                log.info("destroy %s: released lock", lab.netname)

    # ── single VD lifecycle (serialised with deploy/destroy) ────────

    async def node_start(self, lab: ResolvedLab, node_name: str) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/nodes/start",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )
        key = (lab.netname, node_name)
        existing = _local_node_starts.get(key)
        if existing and not existing.done.is_set():
            raise MultinodeServiceError(f"Start already active for node {node_name!r}")
        operation = _LocalNodeStart(threading.Event(), asyncio.Event())
        _local_node_starts[key] = operation
        try:
            async with _deploy_lock:
                def _phase(value: str) -> None:
                    operation.phase = value

                def _start() -> dict:
                    from dnlab_multinode import NodeLifecycleController

                    state = NodeLifecycleController(
                        str(topo_path), hosts_file=self._hosts_file,
                        cancel_event=operation.cancel,
                        phase_callback=_phase,
                    ).start(node_name)
                    result = state.to_dict() if hasattr(state, "to_dict") else {}
                    result["_operation_outcome"] = (
                        "cancelled" if operation.cancel.is_set() else "completed"
                    )
                    return result
                return await asyncio.to_thread(_start)
        except Exception:
            if operation.cancel.is_set():
                return {"_operation_outcome": "cancelled", "cancelled": True}
            raise
        finally:
            operation.done.set()
            _local_node_starts.pop(key, None)

    async def node_stop(self, lab: ResolvedLab, node_name: str) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/nodes/stop",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )
        operation = _local_node_starts.get((lab.netname, node_name))
        cancelled_start = False
        if operation and not operation.done.is_set():
            cancelled_start = True
            operation.cancel.set()
            previous_phase = operation.phase
            if previous_phase == "queued":
                operation.phase = "stopped"
            else:
                operation.phase = "cancelling"
            return {"_operation_outcome": "cancelled", "cancelled": True}
        async with _deploy_lock:
            def _stop() -> dict:
                from dnlab_multinode import NodeLifecycleController

                state = NodeLifecycleController(
                    str(topo_path), hosts_file=self._hosts_file,
                ).stop(node_name, force=True)
                result = state.to_dict() if hasattr(state, "to_dict") else {}
                if cancelled_start:
                    result["cancelled"] = True
                return result
            return await asyncio.to_thread(_stop)

    async def node_restart(self, lab: ResolvedLab, node_name: str) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/nodes/restart",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )
        async with _deploy_lock:
            def _restart() -> dict:
                from dnlab_multinode import NodeLifecycleController

                state = NodeLifecycleController(
                    str(topo_path), hosts_file=self._hosts_file,
                ).restart(node_name)
                return state.to_dict() if hasattr(state, "to_dict") else {}
            return await asyncio.to_thread(_restart)

    async def node_remove(self, lab: ResolvedLab, node_name: str) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/nodes/remove",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )
        async with _deploy_lock:
            def _remove() -> dict:
                from dnlab_multinode import NodeLifecycleController

                state = NodeLifecycleController(
                    str(topo_path), hosts_file=self._hosts_file,
                ).remove(node_name)
                return state.to_dict() if hasattr(state, "to_dict") else {}
            return await asyncio.to_thread(_remove)

    async def node_reconcile(self, lab: ResolvedLab, node_name: str | None = None) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            if not node_name:
                raise MultinodeServiceError("remote node reconcile requires a node name")
            return await self._api_post(
                "/labs/nodes/reconcile",
                self._lab_payload(lab, topology_file=topo_path, node=node_name),
            )
        async with _deploy_lock:
            def _reconcile() -> dict:
                from dnlab_multinode import NodeLifecycleController

                state = NodeLifecycleController(
                    str(topo_path), hosts_file=self._hosts_file,
                ).reconcile(node_name)
                return state.to_dict() if hasattr(state, "to_dict") else {}
            return await asyncio.to_thread(_reconcile)

    async def link_reconcile(self, lab: ResolvedLab, link: dict) -> dict:
        topo_path = _require_file(lab)
        payload = self._lab_payload(lab, topology_file=topo_path, **link)
        if self._use_api:
            return await self._api_post("/labs/links/reconcile", payload)
        async with _deploy_lock:
            def _reconcile() -> dict:
                from dnlab_multinode import NodeLifecycleController

                ctrl = NodeLifecycleController(
                    str(topo_path), hosts_file=self._hosts_file,
                )
                source_is_node = link["source"] in ctrl.topo.nodes
                target_is_node = link["target"] in ctrl.topo.nodes
                if source_is_node and target_is_node:
                    state = ctrl.reconcile_link(
                        link["source"], link["source_iface"],
                        link["target"], link["target_iface"],
                    )
                elif source_is_node:
                    state = ctrl.reconcile_link(
                        link["source"], link["source_iface"], real_net=link["target"],
                    )
                elif target_is_node:
                    state = ctrl.reconcile_link(
                        link["target"], link["target_iface"], real_net=link["source"],
                    )
                else:
                    raise MultinodeServiceError("link must contain at least one VD endpoint")
                return dataclasses.asdict(state)
            return await asyncio.to_thread(_reconcile)

    async def realnet_reconcile(self, lab: ResolvedLab, realnet_name: str) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                "/labs/realnet/reconcile",
                self._lab_payload(lab, topology_file=topo_path, realnet=realnet_name),
            )
        async with _deploy_lock:
            def _reconcile() -> dict:
                from dnlab_multinode import RealNetLifecycleController

                state = RealNetLifecycleController(
                    str(topo_path), hosts_file=self._hosts_file,
                ).reconcile(realnet_name)
                return state.to_dict() if hasattr(state, "to_dict") else {}
            return await asyncio.to_thread(_reconcile)

    async def node_list(self, lab: ResolvedLab) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            result = await self._api_post(
                "/labs/nodes",
                self._lab_payload(lab, topology_file=topo_path),
            )
            return result.get("nodes") or {}

        def _list() -> dict:
            from dnlab_multinode import NodeLifecycleController

            ctrl = NodeLifecycleController(str(topo_path), hosts_file=self._hosts_file)
            return {
                name: dataclasses.asdict(runtime)
                for name, runtime in ctrl.list_nodes().items()
            }
        return await asyncio.to_thread(_list)

    async def follow_rabbit_start(self, lab: ResolvedLab, payload: dict) -> dict:
        topo_path = _require_file(lab)
        body = self._lab_payload(lab, topology_file=topo_path, **payload)
        if self._use_api:
            self._ensure_remote_event_bridge(_bus_tag(lab))
            return await self._api_post("/labs/follow-rabbit/sessions", body)

        def _emit(event: dict) -> None:
            bus.publish(BusEvent(
                lab=_bus_tag(lab),
                phase=event.get("phase", "follow-rabbit"),
                status=event.get("status", event.get("event", "")),
                detail=event.get("detail", ""),
                data={
                    **(event.get("data") or {}),
                    "session_id": event.get("session_id"),
                    "event": event.get("event"),
                },
            ))

        async def _start() -> dict:
            from dnlab_multinode.services.follow_rabbit import FlowFilter, follow_rabbit_manager

            flow = FlowFilter(
                src_ip=payload["src_ip"],
                dst_ip=payload["dst_ip"],
                protocol=payload.get("protocol") or "",
                src_port=int(payload.get("src_port") or 0),
                dst_port=int(payload.get("dst_port") or 0),
            )
            return await follow_rabbit_manager.start(
                topology_file=str(topo_path),
                hosts_file=self._hosts_file,
                source_node=payload["source_node"],
                flow=flow,
                timeout_seconds=int(payload.get("timeout_seconds") or 60),
                emit=_emit,
            )

        return await _start()

    async def follow_rabbit_sessions(self, lab: ResolvedLab) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            result = await self._api_post(
                "/labs/follow-rabbit/sessions/list",
                self._lab_payload(lab, topology_file=topo_path),
            )
            return {"sessions": result.get("sessions") or []}
        from dnlab_multinode.services.follow_rabbit import follow_rabbit_manager

        return {"sessions": await follow_rabbit_manager.list_sessions(lab.netname)}

    async def follow_rabbit_stop(self, lab: ResolvedLab, session_id: str) -> dict:
        topo_path = _require_file(lab)
        if self._use_api:
            return await self._api_post(
                f"/labs/follow-rabbit/sessions/stop?session_id={session_id}",
                self._lab_payload(lab, topology_file=topo_path),
            )

        def _emit(event: dict) -> None:
            bus.publish(BusEvent(
                lab=_bus_tag(lab),
                phase=event.get("phase", "follow-rabbit"),
                status=event.get("status", event.get("event", "")),
                detail=event.get("detail", ""),
                data={
                    **(event.get("data") or {}),
                    "session_id": event.get("session_id"),
                    "event": event.get("event"),
                },
            ))

        from dnlab_multinode.services.follow_rabbit import follow_rabbit_manager

        return await follow_rabbit_manager.stop(session_id, emit=_emit)

    def _lab_payload(self, lab: ResolvedLab, *, topology_file: Path, **extra) -> dict:
        payload = {
            "topology_file": str(topology_file),
            "hosts_file": self._hosts_file,
            "lab_id": str(lab.id),
            "lab_name": lab.netname,
        }
        payload.update(extra)
        return payload

    async def _api_get(self, path: str) -> dict:
        return await self._api_request("GET", path)

    async def _api_post(
        self,
        path: str,
        payload: dict,
        *,
        bridge_events: bool = False,
        topic: str | None = None,
    ) -> dict:
        bridge_task = None
        if bridge_events and topic:
            bridge_task = asyncio.create_task(self._bridge_remote_events(topic))
            await asyncio.sleep(0)
        try:
            return await self._api_request("POST", path, json=payload)
        finally:
            if bridge_task is not None:
                bridge_task.cancel()
                try:
                    await bridge_task
                except asyncio.CancelledError:
                    pass

    async def _api_request(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self._api_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                response = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise MultinodeServiceError(f"multinode API request failed: {exc}") from exc
        if response.status_code >= 400:
            detail = _api_error_detail(response)
            raise MultinodeServiceError(detail or f"multinode API returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise MultinodeServiceError("multinode API returned non-JSON response") from exc
        return data if isinstance(data, dict) else {"result": data}

    async def _bridge_remote_events(self, topic: str) -> None:
        ws_url = _ws_url(self._api_url, f"/ws/events/{topic}")
        try:
            async with websockets.connect(ws_url) as ws:
                async for raw in ws:
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    bus.publish(BusEvent(
                        lab=topic,
                        phase=str(data.get("phase") or ""),
                        status=str(data.get("status") or ""),
                        host=data.get("host"),
                        detail=str(data.get("detail") or ""),
                        elapsed_ms=int(data.get("elapsed_ms") or 0),
                        data=dict(data.get("data") or {}),
                    ))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("remote multinode event bridge stopped for %s: %s", topic, exc)
        finally:
            current = asyncio.current_task()
            if current is not None and self._remote_event_bridges.get(topic) is current:
                self._remote_event_bridges.pop(topic, None)

    def _ensure_remote_event_bridge(self, topic: str) -> None:
        task = self._remote_event_bridges.get(topic)
        if task is not None and not task.done():
            return
        self._remote_event_bridges[topic] = asyncio.create_task(self._bridge_remote_events(topic))


# Module-level singleton — routes and the LabController can share one.
multinode = MultinodeService()


def _drop_node_placement(path: Path, node_name: str) -> None:
    if not path.exists():
        return
    data = json.loads(path.read_text())
    if isinstance(data, dict) and isinstance(data.get("placements"), dict):
        data["placements"].pop(node_name, None)
        path.write_text(json.dumps(data, indent=2))
    elif isinstance(data, dict):
        data.pop(node_name, None)
        path.write_text(json.dumps(data, indent=2))


def _api_error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text
    detail = body.get("detail") if isinstance(body, dict) else None
    return str(detail or body)


def _ws_url(base_url: str, path: str) -> str:
    if base_url.startswith("https://"):
        return "wss://" + base_url[len("https://"):].rstrip("/") + path
    if base_url.startswith("http://"):
        return "ws://" + base_url[len("http://"):].rstrip("/") + path
    return base_url.rstrip("/") + path
