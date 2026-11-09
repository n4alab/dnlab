"""Conservative cleanup reconciler for stale dNLab lab artifacts."""

from __future__ import annotations

from contextlib import nullcontext

import json
import logging
import re
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.services import mgmt_network as mgmt_network_svc, state as state_svc, realnet as realnet_svc
from dnlab_multinode.services.hosts_config import HostsConfig
from dnlab_multinode.services.paths import PATHS
from dnlab_multinode.services.ssh import SSHClient, create_clients
from dnlab_multinode.utils import naming

log = logging.getLogger(__name__)

DEFAULT_STATE_FILE = Path(PATHS.lab_cleanup_state)
_DOCKER_STATES_RUNNING = {"running"}
_CLEANABLE_CONTAINER_STATES = {"created", "exited", "dead", "removing"}
_SHARED_NETWORKS = {"dnlab-jumphost", "dnlab-realnet"}
_MGMT_ANCHOR_RE = re.compile(r"^clab-dnlab-(?P<lab>.+?)-mgmt-.+-mgmt-anchor$")
_SERVICE_CONTAINER_RE = re.compile(
    r"^dnlab-(?P<lab>.+?)-(?:dns|jumphost|runtime-relay|syslog|log-shipper)$"
)
_REALNET_CONTAINER_RE = re.compile(r"^dnlab-(?P<lab>.+?)-[^-]+-realnet$")
_LEGACY_CLAB_CONTAINER_RE = re.compile(r"^clab-(?P<lab>.+?)-[^-]+$")


@dataclass
class CleanupArtifact:
    kind: str
    name: str
    host: str
    lab: str
    state: str = ""
    age_seconds: int | None = None
    shared: bool = False
    source: str = "live"
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "host": self.host,
            "lab": self.lab,
            "state": self.state,
            "age_seconds": self.age_seconds,
            "shared": self.shared,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class HostCleanupInventory:
    name: str
    host: str
    reachable: bool = False
    error: str = ""
    artifacts: list[CleanupArtifact] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "host": self.host,
            "reachable": self.reachable,
            "error": self.error,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


@dataclass
class CleanupAction:
    action: str
    artifact: CleanupArtifact
    command: str
    reason: str
    executed: bool = False
    ok: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "artifact": self.artifact.to_dict(),
            "command": self.command,
            "reason": self.reason,
            "executed": self.executed,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass
class LabCleanupPlan:
    lab: str
    protected: bool = False
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    actions: list[CleanupAction] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "lab": self.lab,
            "protected": self.protected,
            "reasons": self.reasons,
            "warnings": self.warnings,
            "actions": [a.to_dict() for a in self.actions],
        }


@dataclass
class CleanupReport:
    updated_at: str
    dry_run: bool
    grace_seconds: int
    scanned_hosts: dict[str, HostCleanupInventory] = field(default_factory=dict)
    labs: dict[str, LabCleanupPlan] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    reconcile_count: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "updated_at": self.updated_at,
            "dry_run": self.dry_run,
            "grace_seconds": self.grace_seconds,
            "reconcile_count": self.reconcile_count,
            "duration_ms": self.duration_ms,
            "hosts": {n: h.to_dict() for n, h in self.scanned_hosts.items()},
            "labs": {n: p.to_dict() for n, p in self.labs.items()},
            "errors": self.errors,
        }


def discover_state_files(topologies_dir: Path | str = PATHS.topologies_dir) -> dict[str, DeploymentState]:
    """Load all deployment state files from the configured topologies dir."""
    states: dict[str, DeploymentState] = {}
    root = Path(topologies_dir)
    if not root.exists():
        return states
    for path in sorted(root.glob(".*.multinode.json")):
        lab = path.name[1:-len(".multinode.json")]
        state = state_svc.load_state(lab, root)
        if state is not None:
            states[lab] = state
    return states


def parse_artifact_lab(kind: str, name: str, known_labs: set[str] | None = None) -> str:
    """Return the lab name encoded in a dNLab artifact name, or ``""``."""
    known_labs = known_labs or set()
    if name in _SHARED_NETWORKS:
        return ""
    for lab in sorted(known_labs, key=len, reverse=True):
        if kind == "network" and name in {lab, f"mgmt-{lab}", naming.mgmt_network_name(lab)}:
            return lab
        prefixes = (
            f"dnlab-{lab}-",
            f"clab-dnlab-{lab}-",
            f"clab-{lab}-",
        )
        if any(name.startswith(p) for p in prefixes):
            return lab

    if name.startswith("clab-dnlab-"):
        lab = _parse_micro_container_lab(name)
        if lab:
            return lab

    for pattern in (
        _MGMT_ANCHOR_RE,
        _SERVICE_CONTAINER_RE,
        _REALNET_CONTAINER_RE,
        _LEGACY_CLAB_CONTAINER_RE,
    ):
        match = pattern.match(name)
        if match:
            return match.group("lab")

    if kind == "interface":
        match = re.match(r"^(?:vx-|br-|vrf-)(?P<lab>[A-Za-z0-9_.-]+)", name)
        if match:
            return match.group("lab").removesuffix("-mgmt")
    return ""


def _parse_micro_container_lab(name: str) -> str:
    """Parse ``clab-dnlab-<lab>-<vd>-<vd>`` without state.

    Per-VD micro topologies repeat the VD name twice: once in the
    topology/project name and once as the node name. Use that repetition to
    avoid treating ``dnlab-<lab>-<vd>`` as the lab name.
    """
    body = name.removeprefix("clab-dnlab-")
    parts = body.split("-")
    for i in range(1, len(parts)):
        tail = parts[i:]
        if not tail:
            continue
        half = len(tail) // 2
        if len(tail) % 2 == 0 and tail[:half] == tail[half:]:
            return "-".join(parts[:i])
    return ""


def expected_artifacts_from_state(state: DeploymentState) -> list[CleanupArtifact]:
    """Build state-derived cleanup targets that are safe to name exactly."""
    lab = state.lab_name
    out: list[CleanupArtifact] = []
    for runtime in {**state.retired_native_nodes,**state.node_runtime}.values():
        if runtime.host and runtime.container:
            out.append(CleanupArtifact("container", runtime.container, runtime.host, lab, source="state"))
    if state.dns:
        out.append(CleanupArtifact("container", state.dns.container, state.dns.node, lab, source="state"))
    if state.jumphost:
        out.append(CleanupArtifact("container", state.jumphost.container, state.jumphost.node, lab, source="state"))
    for host, relay in state.runtime_relays.items():
        out.append(CleanupArtifact("container", relay.container, host, lab, source="state"))
    for anchor in state.mgmt_anchors.values():
        if anchor.host and anchor.container:
            out.append(CleanupArtifact(
                "container",
                anchor.container,
                anchor.host,
                lab,
                source="state",
                metadata={"role": "mgmt-anchor"},
            ))
    for rn in state.realnets:
        metadata={"role":"realnet","realnet":rn.name}
        for host in set(rn.hosts or ["master"]) | set(rn.vxlan_ifaces):
            if rn.bridge:
                out.append(CleanupArtifact("interface", rn.bridge, host, lab, source="state",metadata=dict(metadata)))
            for name in rn.vxlan_ifaces.get(host,[]):
                out.append(CleanupArtifact("interface",name,host,lab,source="state",metadata=dict(metadata)))
        if rn.router_veth:
            out.append(CleanupArtifact("interface",rn.router_veth,"master",lab,source="state",metadata=dict(metadata)))
        if rn.router_container:
            out.append(CleanupArtifact("container", rn.router_container, "master", lab, source="state",metadata=dict(metadata)))
    if state.mgmt:
        network = state.mgmt.network or naming.mgmt_network_name(lab)
        for host in state.scheduling or {}:
            out.extend([
                # Live inventory supplies the container count. A state-only
                # network stays a warning/no-op, preserving the conservative
                # cleanup policy when a host cannot confirm its current state.
                CleanupArtifact(
                    "network", network, host, lab, source="state",
                    metadata={"role": "mgmt-network"},
                ),
                CleanupArtifact(
                    "interface", state.mgmt.vxlan_iface, host, lab, source="state",
                    metadata={"role": "mgmt-infra"},
                ),
                CleanupArtifact(
                    "interface", state.mgmt.bridge, host, lab, source="state",
                    metadata={"role": "mgmt-infra"},
                ),
                CleanupArtifact(
                    "interface", state.mgmt.vrf, host, lab, source="state",
                    metadata={"role": "mgmt-infra"},
                ),
            ])
    for link in state.vxlan_dataplane:
        for side_name in ("side_a", "side_b"):
            side = getattr(link, side_name, {}) or {}
            host = side.get("node", "")
            iface = side.get("iface", "")
            if host and iface:
                out.append(CleanupArtifact("interface", f"vx-{iface}"[:15], host, lab, source="state"))
    return out


def collect_inventory(
    hosts: HostsConfig,
    states: dict[str, DeploymentState],
    *,
    clients: dict[str, SSHClient] | None = None,
) -> dict[str, HostCleanupInventory]:
    own_clients = clients is None
    if clients is None:
        clients = create_clients(hosts.all_hosts)
    known_labs = set(states)
    inventories: dict[str, HostCleanupInventory] = {}

    def _collect(name: str, client: SSHClient) -> HostCleanupInventory:
        inv = HostCleanupInventory(name=name, host=client.host)
        try:
            if own_clients:
                client.connect()
            inv.reachable = True
            inv.artifacts.extend(_list_containers(client, name, known_labs))
            inv.artifacts.extend(_list_networks(client, name, states))
            inv.artifacts.extend(_list_interfaces(client, name, known_labs))
        except Exception as exc:
            inv.reachable = False
            inv.error = str(exc)
            log.warning("[%s] cleanup inventory failed: %s", name, exc)
        finally:
            if own_clients:
                client.close()
        return inv

    with ThreadPoolExecutor(max_workers=max(1, len(clients))) as pool:
        futures = {pool.submit(_collect, name, client): name for name, client in clients.items()}
        for future in as_completed(futures):
            inv = future.result()
            inventories[inv.name] = inv
    return inventories


def build_cleanup_plan(
    inventories: dict[str, HostCleanupInventory],
    states: dict[str, DeploymentState],
    *,
    grace_seconds: int,
) -> dict[str, LabCleanupPlan]:
    by_lab: dict[str, list[CleanupArtifact]] = {}
    for inv in inventories.values():
        for artifact in inv.artifacts:
            if artifact.lab:
                by_lab.setdefault(artifact.lab, []).append(artifact)
    for lab, state in states.items():
        by_lab.setdefault(lab, []).extend(expected_artifacts_from_state(state))

    plans: dict[str, LabCleanupPlan] = {}
    for lab in sorted(by_lab):
        plan = LabCleanupPlan(lab=lab)
        artifacts = _dedupe_artifacts(by_lab[lab])
        state = states.get(lab)
        expected_hosts = set((state.scheduling or {}).keys()) if state else set()
        if state:
            expected_hosts.update(a.host for a in expected_artifacts_from_state(state) if a.host)

        expected_hosts.update(a.host for a in artifacts if a.host)
        if state is None:expected_hosts.update(inventories)
        reason=_vd_block_reason(artifacts,state)
        if reason:
            plan.protected=True;plan.reasons.append(reason)
        teardown_requested = bool(state and state.teardown_requested)
        if not teardown_requested and _lab_has_running_vd(lab, artifacts, state):
            plan.protected = True
            plan.reasons.append("lab-runtime-running")
        for host in sorted(expected_hosts):
            inv = inventories.get(host)
            if inv is None or not inv.reachable:
                plan.protected = True
                plan.reasons.append(f"host-unreachable:{host}")
        if not teardown_requested and any(
            a.age_seconds is not None and a.age_seconds < grace_seconds
            for a in artifacts
        ):
            plan.protected = True
            plan.reasons.append("artifact-inside-grace")

        if plan.protected:
            plans[lab] = plan
            continue

        for artifact in artifacts:
            action = _action_for_artifact(artifact, state)
            if action is None:
                if artifact.shared:
                    plan.warnings.append(f"shared artifact skipped: {artifact.name}")
                elif artifact.kind == "network":
                    plan.warnings.append(f"network skipped: {artifact.name}")
                elif artifact.kind == "interface" and artifact.source != "state":
                    plan.warnings.append(f"interface skipped without state: {artifact.name}")
                continue
            plan.actions.append(action)
        _guard_mgmt_infrastructure(plan, artifacts, state)
        plans[lab] = plan
    return plans


def reconcile_once(
    hosts: HostsConfig,
    *,
    state_file: Path = DEFAULT_STATE_FILE,
    topologies_dir: Path | str = PATHS.topologies_dir,
    clients: dict[str, SSHClient] | None = None,
    dry_run: bool | None = None,
    grace_seconds: int | None = None,
) -> CleanupReport:
    started = time.monotonic()
    effective_dry_run = hosts.lab_cleanup.dry_run if dry_run is None else dry_run
    effective_grace = hosts.lab_cleanup.grace_seconds if grace_seconds is None else grace_seconds
    states = discover_state_files(topologies_dir)
    inventories = collect_inventory(hosts, states, clients=clients)
    plans = build_cleanup_plan(inventories, states, grace_seconds=effective_grace)
    report = CleanupReport(
        updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        dry_run=effective_dry_run,
        grace_seconds=effective_grace,
        scanned_hosts=inventories,
        labs=plans,
    )
    if not effective_dry_run:
        _execute_plans(plans, clients or create_clients(hosts.all_hosts), own_clients=clients is None,
                       states=states,state_directory=Path(topologies_dir))
        teardown_status = _finalize_requested_teardowns(
            states,
            Path(topologies_dir),
            hosts,
            clients=clients,
        )
        for lab, status in teardown_status.items():
            if lab in plans:
                plans[lab].warnings.append(status)
    report.duration_ms = int((time.monotonic() - started) * 1000)
    write_state_file(state_file, report)
    return report


def write_state_file(path: Path, report: CleanupReport) -> None:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        tmp.replace(path)
    except OSError as exc:
        log.warning("Cannot write lab-cleanup state %s: %s", path, exc)


def read_state_file(path: Path = DEFAULT_STATE_FILE) -> dict | None:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


class LabCleanupDaemon:
    def __init__(self, hosts: HostsConfig, state_file: Path = DEFAULT_STATE_FILE):
        self.hosts = hosts
        self.state_file = Path(state_file)
        self._stop = threading.Event()
        self._trigger = threading.Event()
        self._reconcile_count = 0

    def stop(self) -> None:
        self._stop.set()
        self._trigger.set()

    def trigger_reconcile(self) -> None:
        self._trigger.set()

    def run(self) -> None:
        if not self.hosts.lab_cleanup.enabled:
            log.info("lab-cleanup disabled in hosts.yml")
            return
        self._do_reconcile()
        interval = max(30, self.hosts.lab_cleanup.interval_seconds)
        while not self._stop.is_set():
            self._trigger.wait(timeout=interval)
            if self._stop.is_set():
                break
            self._trigger.clear()
            self._do_reconcile()

    def _do_reconcile(self) -> None:
        try:
            report = reconcile_once(self.hosts, state_file=self.state_file)
            self._reconcile_count += 1
            report.reconcile_count = self._reconcile_count
            write_state_file(self.state_file, report)
            actions = sum(len(p.actions) for p in report.labs.values())
            log.info("lab-cleanup reconcile #%d done: labs=%d actions=%d dry_run=%s",
                     self._reconcile_count, len(report.labs), actions, report.dry_run)
        except Exception:
            log.exception("lab-cleanup reconcile failed")


def _list_containers(client: SSHClient, host: str, known_labs: set[str]) -> list[CleanupArtifact]:
    rc, out, _ = client.run_no_check(
        "docker ps -a --format '{{.Names}}\t{{.State}}\t{{.CreatedAt}}'",
        timeout=20,
    )
    if rc != 0:
        raise RuntimeError("cannot read VD container inventory")
    artifacts = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name = parts[0]
        lab = parse_artifact_lab("container", name, known_labs)
        if not lab:
            continue
        artifacts.append(CleanupArtifact(
            kind="container",
            name=name,
            host=host,
            lab=lab,
            state=parts[1],
            age_seconds=_age_from_created_at(parts[2] if len(parts) > 2 else ""),
            metadata={"live_observed":True},
        ))
    # Discover custom workloads independently of naming and without returning
    # their environment or birth nonce in the cleanup report.
    rc,ids,_=client.run_no_check("docker container ls -aq --no-trunc --filter label=org.dnlab.runtime",timeout=20)
    if rc!=0:raise RuntimeError("cannot read runtime-owned VD inventory")
    fields={'id':'.Id','name':'.Name','state':'.State.Status','created':'.Created',
            'backend':'index .Config.Labels "org.dnlab.runtime"',
            'lab':'index .Config.Labels "org.dnlab.runtime.lab"',
            'node':'index .Config.Labels "org.dnlab.runtime.node"',
            'creator':'index .Config.Labels "org.dnlab.runtime.creator"',
            'spec':'index .Config.Labels "org.dnlab.runtime.spec"'}
    template='{'+','.join(json.dumps(k)+':{{json ('+v+')}}' for k,v in fields.items())+'}'
    for cid in ids.splitlines():
        if not re.fullmatch(r'[0-9a-f]{64}',cid):raise RuntimeError("invalid runtime container identity")
        rc,raw,_=client.run_no_check(shlex.join(['docker','inspect','--format',template,cid]),timeout=20)
        if rc!=0:raise RuntimeError("runtime VD identity unavailable")
        try:value=json.loads(raw)
        except (ValueError,TypeError):raise RuntimeError("invalid runtime VD metadata") from None
        if (not isinstance(value,dict) or value.get('id')!=cid or not isinstance(value.get('name'),str)
                or not value['name'].startswith('/') or not isinstance(value.get('state'),str)):
            raise RuntimeError("runtime VD metadata identity differs")
        name=value['name'][1:];claimed=value.get('lab');inferred=parse_artifact_lab('container',name,known_labs)
        if not isinstance(claimed,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',claimed):
            raise RuntimeError("runtime VD lab ownership is unqualified")
        owner={k:value.get(k) for k in ('backend','lab','node','creator','spec')}
        for lab in {claimed,inferred}-{'',None}:
            artifacts.append(CleanupArtifact('container',name,host,lab,state=value['state'],
                age_seconds=_age_from_created_at(value.get('created','')),
                metadata={'live_observed':True,'container_id':cid,'runtime_owner':owner}))
    return artifacts


def _list_networks(
    client: SSHClient,
    host: str,
    states: dict[str, DeploymentState],
) -> list[CleanupArtifact]:
    known_labs = set(states)
    rc, out, _ = client.run_no_check("docker network ls --format '{{.Name}}'", timeout=20)
    if rc != 0:
        return []
    artifacts = []
    for name in out.splitlines():
        name = name.strip()
        if not name:
            continue
        shared = name in _SHARED_NETWORKS
        lab = parse_artifact_lab("network", name, known_labs)
        if not lab and not shared:
            continue
        state = states.get(lab)
        metadata = _network_inventory_metadata(client, name, lab, state)
        artifacts.append(CleanupArtifact(
            kind="network",
            name=name,
            host=host,
            lab=lab,
            shared=shared,
            metadata=metadata,
        ))
    return artifacts


def _list_interfaces(client: SSHClient, host: str, known_labs: set[str]) -> list[CleanupArtifact]:
    rc, out, _ = client.run_no_check("ip -o link show | awk -F': ' '{print $2}'", timeout=20)
    if rc != 0:
        return []
    artifacts = []
    for raw in out.splitlines():
        name = raw.split("@", 1)[0].strip()
        lab = parse_artifact_lab("interface", name, known_labs)
        if lab:
            artifacts.append(CleanupArtifact("interface", name, host, lab))
    return artifacts


def _network_inventory_metadata(
    client: SSHClient,
    name: str,
    lab: str,
    state: DeploymentState | None,
) -> dict:
    metadata: dict = {"live_observed": True, "containers": None}
    rc, out, _ = client.run_no_check(
        f"docker network inspect {shlex.quote(name)}",
        timeout=10,
    )
    if rc != 0:
        return metadata
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return metadata
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        return metadata
    network = payload[0]
    containers = network.get("Containers") or {}
    if not isinstance(containers, dict):
        return metadata
    metadata["containers"] = len(containers)
    if state and state.mgmt and name == (state.mgmt.network or naming.mgmt_network_name(lab)):
        metadata["role"] = "mgmt-network"
        metadata["mgmt_vrf_owned"] = _is_vrf_mgmt_network(network, lab, state)
    return metadata


def _is_vrf_mgmt_network(network: dict, lab: str, state: DeploymentState) -> bool:
    """Return true only for the Docker network owned by the current driver."""
    mgmt = state.mgmt
    if mgmt is None:
        return False
    if network.get("Driver") != mgmt_network_svc.NETWORK_DRIVER:
        return False
    ipam = network.get("IPAM") or {}
    if ipam.get("Driver") != mgmt_network_svc.IPAM_DRIVER:
        return False
    labels = network.get("Labels") or {}
    if (
        labels.get(mgmt_network_svc.MANAGED_LABEL) != "mgmt-vrf"
        or labels.get(mgmt_network_svc.LAB_LABEL) != lab
    ):
        return False
    options = network.get("Options") or {}
    if not isinstance(options, dict):
        return False
    generic = options.get(mgmt_network_svc.GENERIC_OPTIONS_KEY)
    if isinstance(generic, dict):
        options = generic
    return (
        options.get(mgmt_network_svc.BRIDGE_OPTION) == mgmt.bridge
        and options.get(mgmt_network_svc.VRF_OPTION) == mgmt.vrf
        and options.get(mgmt_network_svc.LAB_OPTION) == lab
    )


def _action_for_artifact(
    artifact: CleanupArtifact,
    state: DeploymentState | None,
) -> CleanupAction | None:
    if artifact.shared or _is_vd_container(artifact,artifact.lab,state):
        return None
    if (artifact.metadata.get("role")=="realnet"
            or artifact.kind=="container" and _REALNET_CONTAINER_RE.fullmatch(artifact.name)
            or state and any(item.metadata.get("role")=="realnet" and
                            (item.host,item.kind,item.name)==(artifact.host,artifact.kind,artifact.name)
                            for item in expected_artifacts_from_state(state))):
        # Inventory names authorize observation, never generic deletion.
        return None
    if artifact.kind == "container" and (
        artifact.name == naming.runtime_relay_container_name(artifact.lab)
        or state and any(artifact.name == relay.container for relay in state.runtime_relays.values())
    ):
        return CleanupAction(action="cleanup-relay", artifact=artifact, command="",
                             reason="journal-owned relay cleanup; never remove by name")
    if artifact.kind == "container" and (
        artifact.name == f"dnlab-{artifact.lab}-dns"
        or state and state.dns and artifact.name == state.dns.container
    ):
        return CleanupAction(action="cleanup-dns", artifact=artifact, command="",
                             reason="journal-owned DNS cleanup; never remove by name")
    if artifact.kind == "container" and (
        artifact.name == naming.jumphost_container_name(artifact.lab)
        or state and state.jumphost and artifact.name == state.jumphost.container
    ):
        return CleanupAction(action="cleanup-jumphost", artifact=artifact, command="",
                             reason="journal-owned jumphost cleanup; never remove by name")
    if artifact.kind == "container":
        if (
            artifact.state
            and artifact.state not in _CLEANABLE_CONTAINER_STATES
            and not _is_per_lab_container(artifact)
        ):
            return None
        return CleanupAction(
            action="remove-container",
            artifact=artifact,
            command=f"docker rm -f {shlex.quote(artifact.name)}",
            reason="stale dNLab lab container",
        )
    if artifact.kind == "network" and artifact.metadata.get('role') == 'mgmt-network':
        return None  # Docker birth journal, never generic network rm by name.
    if artifact.kind == "network":
        containers = artifact.metadata.get("containers")
        # A state-derived network must also be observed live and empty before
        # removal. Never infer that a network is empty from stale state.
        if containers != 0:
            return None
        if (
            artifact.metadata.get("role") == "mgmt-network"
            and artifact.metadata.get("live_observed") is True
            and artifact.metadata.get("mgmt_vrf_owned") is not True
        ):
            return None
        return CleanupAction(
            action="remove-network",
            artifact=artifact,
            command=f"docker network rm {shlex.quote(artifact.name)}",
            reason="empty per-lab docker network",
        )
    if artifact.kind == "interface" and artifact.metadata.get('role') == 'mgmt-infra':
        return None  # Host journal is the only authority for management teardown.
    if artifact.kind == "interface":
        if state is None and artifact.source != "state":
            return None
        return CleanupAction(
            action="delete-interface",
            artifact=artifact,
            command=f"ip link delete {shlex.quote(artifact.name)}",
            reason="state-derived stale lab interface",
        )
    return None


def _guard_mgmt_infrastructure(
    plan: LabCleanupPlan,
    artifacts: list[CleanupArtifact],
    state: DeploymentState | None,
) -> None:
    """Keep bridge/VRF intact while an observed Docker mgmt network remains."""
    if state is None or state.mgmt is None:
        return
    blocked_hosts: set[str] = set()
    for artifact in artifacts:
        if artifact.metadata.get("role") != "mgmt-network":
            continue
        if artifact.metadata.get("live_observed") is not True:
            continue
        if artifact.metadata.get("containers") != 0:
            blocked_hosts.add(artifact.host)
            plan.warnings.append(
                f"mgmt infrastructure skipped on {artifact.host}: network {artifact.name} is attached"
            )
        elif artifact.metadata.get("mgmt_vrf_owned") is not True:
            blocked_hosts.add(artifact.host)
            plan.warnings.append(
                f"mgmt infrastructure skipped on {artifact.host}: network {artifact.name} failed ownership check"
            )
    if not blocked_hosts:
        return
    plan.actions = [
        action
        for action in plan.actions
        if not (
            action.artifact.host in blocked_hosts
            and action.artifact.metadata.get("role") == "mgmt-infra"
        )
    ]


def _is_mgmt_anchor_container(artifact: CleanupArtifact) -> bool:
    if artifact.kind != "container":
        return False
    if artifact.metadata.get("role") == "mgmt-anchor":
        return True
    return bool(_MGMT_ANCHOR_RE.match(artifact.name))


def _is_service_container(artifact: CleanupArtifact) -> bool:
    return artifact.kind == "container" and bool(_SERVICE_CONTAINER_RE.match(artifact.name))


def _is_per_lab_container(artifact: CleanupArtifact) -> bool:
    return artifact.kind == "container" and bool(artifact.lab)


def _expected_vd_container_names(lab: str, state: DeploymentState | None) -> set[str]:
    names: set[str] = set()
    if not state:
        return names
    for runtime in {**state.retired_native_nodes,**state.node_runtime}.values():
        if runtime.container:
            names.add(runtime.container)
        if runtime.node:
            names.add(naming.vd_container_name(lab, runtime.node))
            names.add(naming.micro_vd_container_name(lab, runtime.node))
    for schedule in (state.scheduling or {}).values():
        for vd in schedule.vd:
            names.add(naming.vd_container_name(lab, vd))
            names.add(naming.micro_vd_container_name(lab, vd))
    return names


def _is_vd_container(artifact,lab,state,expected_names=None):
    if artifact.kind!='container':return False
    if artifact.metadata.get('runtime_owner'):return True
    expected_names=expected_names if expected_names is not None else _expected_vd_container_names(lab,state)
    if artifact.name in expected_names:return True
    if _is_mgmt_anchor_container(artifact) or _is_service_container(artifact):return False
    return artifact.name.startswith(f'clab-{lab}-') or artifact.name.startswith(f'clab-dnlab-{lab}-')


def _vd_block_reason(artifacts,state):
    if state:
        for runtime in {**state.retired_native_nodes,**state.node_runtime}.values():
            if not runtime.runtime_binding and runtime.state not in ('running','stopped'):
                return 'vd-lifecycle-unresolved'
        if any(r.runtime_binding for r in {**state.retired_native_nodes,**state.node_runtime}.values()) and not state.teardown_requested:
            return 'runtime-teardown-intent-required'
    for artifact in artifacts:
        if not _is_vd_container(artifact,artifact.lab,state):continue
        if not artifact.state and not artifact.metadata.get('live_observed'):continue
        runtime=next((r for r in {**state.retired_native_nodes,**state.node_runtime}.values() if r.host==artifact.host and r.container==artifact.name),None) if state else None
        if not runtime or not runtime.runtime_binding:return 'vd-ownership-unqualified'
        owner=artifact.metadata.get('runtime_owner')
        if owner and (owner.get('backend')!='v1' or owner.get('lab')!=artifact.lab or owner.get('node')!=runtime.node):
            return 'vd-ownership-conflict'
        if not state.teardown_requested:return 'runtime-teardown-intent-required'
    return ''


def _vd_preflight(plan,state,clients,state_directory,*,advance,management_guarded=False):
    from .runtime_cleanup import CleanupBlocked,Delegate,operation_directory,management_cleanup_guard
    if not management_guarded:
        with management_cleanup_guard(plan.lab,state,state_directory):
            return _vd_preflight(plan,state,clients,state_directory,advance=advance,management_guarded=True)
    required={a.artifact.host for a in plan.actions}
    if state:
        required.update(state.scheduling)
        required.update(a.host for a in expected_artifacts_from_state(state) if a.host)
    else:required.update(clients)
    if required-set(clients):raise CleanupBlocked('complete VD preflight: host unavailable')
    artifacts=[]
    for host in sorted(required):
        artifacts.extend(a for a in _list_containers(clients[host],host,{plan.lab}) if a.lab==plan.lab)
    reason=_vd_block_reason(artifacts,state)
    if reason:raise CleanupBlocked(reason)
    if any(a.action=='remove-container' and _is_vd_container(a.artifact,plan.lab,state) for a in plan.actions):
        raise CleanupBlocked('generic VD cleanup action rejected')
    bindings=bool(state and any(r.runtime_binding for r in {**state.retired_native_nodes,**state.node_runtime}.values()))
    ledger=state_directory is not None and (operation_directory(state_directory)/'operations.sqlite3').is_file()
    if bindings or ledger:
        if state_directory is None:raise CleanupBlocked('runtime intent directory missing')
        owner=state or DeploymentState(lab_name=plan.lab,topology_file='')
        delegate=Delegate(owner,clients,state_directory)
        try:
            delegate.preflight(artifacts)
            if bindings:
                if state.realnets:raise CleanupBlocked('VD cleanup with RealNet requires its distributed coordinator')
                if not state.teardown_requested:raise CleanupBlocked('runtime teardown intent required')
                delegate.fence()
                done=delegate.advance() if advance else delegate.verified()
                if not done:raise CleanupBlocked('runtime cleanup pending; dependent infrastructure retained')
                delegate.seal()
        finally:delegate.close()


def _lab_has_running_vd(
    lab: str,
    artifacts: list[CleanupArtifact],
    state: DeploymentState | None,
) -> bool:
    # Unqualified orphan workloads are protected by the ownership preflight.
    # This additional running-state rule only applies to known deployment state.
    if state is None:
        return False
    expected_names = _expected_vd_container_names(lab, state)
    return any(
        artifact.state in _DOCKER_STATES_RUNNING
        and _is_vd_container(artifact, lab, state, expected_names)
        for artifact in artifacts
    )


def _execute_plans(
    plans: dict[str, LabCleanupPlan],
    clients: dict[str, SSHClient],
    *,
    own_clients: bool,
    states: dict[str, DeploymentState] | None = None,
    state_directory: Path | None = None,
) -> None:
    connected: set[str] = set()
    try:
        if own_clients:
            for name, client in clients.items():
                try:
                    client.connect()
                    connected.add(name)
                except Exception:
                    log.exception("[%s] cannot connect for cleanup execution", name)
        else:
            connected = set(clients)
        for plan in plans.values():
            if plan.protected:
                continue
            state=(states or {}).get(plan.lab)
            from .native_public import state_guard
            try:
                guard=state_guard(state,state_directory) if state else nullcontext()
                from .runtime_cleanup import management_cleanup_guard
                with guard, management_cleanup_guard(plan.lab,state,state_directory):
                    available={name:clients[name] for name in connected}
                    from . import runtime_relay as relay_svc
                    try:
                        for action in plan.actions:
                            if action.action != 'cleanup-relay': continue
                            host=action.artifact.host
                            relay=state.runtime_relays.get(host) if state else None
                            if not relay or host not in available:raise RuntimeError('relay host or coordinator proof unavailable')
                            relay_svc.preflight_relay_cleanup(plan.lab,host,available[host],relay.generation)
                    except Exception as exc:
                        plan.protected=True;plan.reasons.append('relay-preflight-failed');plan.warnings.append(str(exc))
                        continue
                    from . import dns as dns_svc
                    try:
                        for action in plan.actions:
                            if action.action != 'cleanup-dns': continue
                            host = action.artifact.host
                            if host not in available: raise RuntimeError('DNS host unavailable')
                            if not state or not state.dns or not state.dns.generation:
                                raise RuntimeError('DNS cleanup requires qualified coordinator generation')
                            dns_svc.preflight_dns_cleanup(plan.lab, available[host], state.dns.generation)
                    except Exception as exc:
                        plan.protected=True;plan.reasons.append('dns-preflight-failed')
                        plan.warnings.append(str(exc));continue
                    from . import jumphost as jumphost_svc
                    try:
                        for action in plan.actions:
                            if action.action != 'cleanup-jumphost': continue
                            host = action.artifact.host
                            if host not in available: raise RuntimeError('jumphost host unavailable')
                            if not state or not state.jumphost or not state.jumphost.generation:
                                raise RuntimeError('jumphost cleanup requires qualified coordinator generation')
                            jumphost_svc.preflight_jumphost_cleanup(plan.lab, available[host], action.artifact.name, state.jumphost.generation)
                    except Exception as exc:
                        plan.protected=True;plan.reasons.append('jumphost-preflight-failed')
                        plan.warnings.append(str(exc));continue
                    if state and state.mgmt:
                        try:
                            from . import netsetup
                            if not state.teardown_requested: raise RuntimeError('management teardown intent required')
                            netsetup.preflight_management(state, available)
                        except Exception as exc:
                            plan.protected=True;plan.reasons.append('management-preflight-failed');plan.warnings.append(str(exc))
                            continue
                    try:_vd_preflight(plan,state,available,state_directory,advance=True,management_guarded=True)
                    except Exception as exc:
                        plan.protected=True;plan.reasons.append('vd-runtime-preflight-failed')
                        plan.warnings.append(str(exc));continue
                    if state and state.realnets:
                        try:
                            if not state.teardown_requested:
                                raise RuntimeError("RealNet infrastructure requires explicit teardown intent")
                            if state_directory is None:
                                raise RuntimeError("RealNet recovery requires a persistent state directory")
                            required=set(state.scheduling)
                            required.update(a.host for a in expected_artifacts_from_state(state) if a.host)
                            if required-set(available):raise RuntimeError("complete cleanup preflight: host unavailable")
                            realnet_svc.preflight_realnets(state.lab_name,available,state.realnets)
                            from .realnet_cleanup import detach_realnet_attachments
                            detach_realnet_attachments(state.lab_name,available,state.realnets,
                                checkpoint=lambda:state_svc.save_state(state,state_directory),runtime_links=state.runtime_links)
                        except Exception as exc:
                            plan.protected=True
                            plan.reasons.append("realnet-preflight-failed")
                            plan.warnings.append(str(exc))
                            continue
                    blocked_mgmt_hosts: set[str] = set()
                    for action in sorted(plan.actions, key=_cleanup_action_priority):
                        client = clients.get(action.artifact.host)
                        if (
                            action.artifact.host in blocked_mgmt_hosts
                            and action.artifact.metadata.get("role") == "mgmt-infra"
                        ):
                            action.error = "skipped: managed Docker network removal failed"
                            continue
                        if client is None or action.artifact.host not in connected:
                            action.executed = True
                            action.ok = False
                            action.error = "host unavailable"
                            continue
                        action.executed = True
                        if action.action == 'cleanup-relay':
                            try:
                                relay_svc.destroy_runtime_relays(plan.lab,{action.artifact.host:client},
                                                               {action.artifact.host:state.runtime_relays[action.artifact.host]})
                                action.ok=True
                            except Exception as exc:
                                action.ok=False;action.error=str(exc)
                                plan.protected=True;plan.reasons.append('relay-recovery-required')
                                break
                            continue
                        if action.action == 'cleanup-dns':
                            try:
                                dns_svc.destroy_dns(plan.lab, client, state.dns.generation)
                                action.ok=True
                            except Exception as exc:
                                action.ok=False;action.error=str(exc)
                                plan.protected=True;plan.reasons.append('dns-recovery-required')
                                break
                            continue
                        if action.action == 'cleanup-jumphost':
                            try:
                                jumphost_svc.destroy_jumphost(plan.lab, client, state.jumphost.generation)
                                action.ok=True
                            except Exception as exc:
                                action.ok=False;action.error=str(exc)
                                plan.protected=True;plan.reasons.append('jumphost-recovery-required')
                                break
                            continue
                        rc, _, err = client.run_no_check(action.command, timeout=30)
                        action.ok = rc == 0
                        action.error = "" if rc == 0 else err.strip()
                        if (
                            not action.ok
                            and action.action == "remove-network"
                            and action.artifact.metadata.get("role") == "mgmt-network"
                        ):
                            blocked_mgmt_hosts.add(action.artifact.host)
                    if plan.protected: continue
                    if state and state.mgmt:
                        if any(action.executed and not action.ok for action in plan.actions):
                            plan.warnings.append('management recovery deferred: earlier cleanup failed');continue
                        try:
                            netsetup.destroy_management(state, available,
                                checkpoint=lambda:state_svc.save_state(state,state_directory))
                        except Exception as exc:
                            plan.warnings.append('management recovery pending: '+str(exc));continue
                    if state and state.realnets:
                        if any(action.executed and not action.ok for action in plan.actions):
                            plan.warnings.append("RealNet recovery deferred: earlier cleanup failed")
                            continue
                        try:
                            realnet_svc.destroy_realnets(state.lab_name,available,state.realnets,
                                checkpoint=lambda:state_svc.save_state(state,state_directory))
                        except Exception as exc:
                            plan.warnings.append("RealNet recovery pending: "+str(exc))
            except Exception as exc:
                plan.protected=True;plan.reasons.append('native-state-guard-failed');plan.warnings.append(str(exc))

    finally:
        if own_clients:
            for name in connected:
                clients[name].close()


def _finalize_requested_teardowns(
    states: dict[str, DeploymentState],
    topologies_dir: Path,
    hosts: HostsConfig,
    *,
    clients: dict[str, SSHClient] | None = None,
) -> dict[str, str]:
    """Delete teardown-marked state only after exact artifact verification.

    Cleanup plans are based on a snapshot taken before actions run. Re-query
    the state-owned names here, so a successful finalization never depends on
    stale inventory or on a best-effort delete command returning success.
    """
    pending = {
        lab: state for lab, state in states.items()
        if state.teardown_requested
    }
    if not pending:
        return {}

    own_clients = clients is None
    active_clients = clients or create_clients(hosts.all_hosts)
    connected: set[str] = set()
    status: dict[str, str] = {}
    try:
        if own_clients:
            for name, client in active_clients.items():
                try:
                    client.connect()
                    connected.add(name)
                except Exception as exc:
                    log.warning("[%s] cannot verify pending teardown: %s", name, exc)
        else:
            connected = set(active_clients)

        for lab, state in pending.items():
            from .native_public import state_guard
            try:
                from .runtime_cleanup import management_cleanup_guard
                with state_guard(state,topologies_dir), management_cleanup_guard(lab,state,topologies_dir):
                    try:_vd_preflight(LabCleanupPlan(lab=lab),state,
                                      {name:active_clients[name] for name in connected},topologies_dir,advance=False,management_guarded=True)
                    except Exception as exc:
                        status[lab]='pending teardown state retained: VD runtime: '+str(exc)
                        continue
                    try:
                        from . import runtime_relay as relay_svc
                        for host,relay in state.runtime_relays.items():
                            if host not in connected:raise RuntimeError('relay host unavailable')
                            relay_svc.verify_relay_cleaned(lab,host,active_clients[host],relay.generation)
                    except Exception as exc:
                        status[lab]='pending teardown state retained: relay journal: '+str(exc)
                        continue
                    if state.dns:
                        try:
                            from . import dns as dns_svc
                            if state.dns.node not in connected or not state.dns.generation:
                                raise RuntimeError('DNS host or coordinator generation unavailable')
                            dns_svc.verify_dns_cleaned(lab, active_clients[state.dns.node], state.dns.generation)
                        except Exception as exc:
                            status[lab]='pending teardown state retained: DNS journal: '+str(exc)
                            continue
                    if state.jumphost:
                        try:
                            from . import jumphost as jumphost_svc
                            jh=state.jumphost
                            if jh.node not in connected: raise RuntimeError('jumphost host unavailable')
                            if not jh.generation: raise RuntimeError("unqualified jumphost coordinator generation")
                            jumphost_svc.verify_jumphost_cleaned(lab, active_clients[jh.node], jh.container, jh.generation)
                        except Exception as exc:
                            status[lab]='pending teardown state retained: jumphost journal: '+str(exc)
                            continue
                    remaining, reason = _teardown_remaining_artifacts(
                        state, active_clients, connected,
                    )
                    if remaining:
                        status[lab] = f"pending teardown state retained: {reason}"
                        continue
                    if state.realnets:
                        try:
                            from .realnet_cleanup import verify_realnets_cleaned
                            verify_realnets_cleaned(state.lab_name,
                                {name:active_clients[name] for name in connected},state.realnets)
                            from .realnet_vni import release_realnets
                            release_realnets(state.lab_name,
                                {name:active_clients[name] for name in connected},state.realnets)
                        except Exception as exc:
                            status[lab]="pending teardown state retained: RealNet journal/VNI recovery: "+str(exc)
                            continue
                    if state.mgmt:
                        try:
                            from .netsetup import release_management
                            release_management(state,{name:active_clients[name] for name in connected},
                                checkpoint=lambda:state_svc.save_state(state,topologies_dir))
                        except Exception as exc:
                            status[lab]='pending teardown state retained: management journal/VNI recovery: '+str(exc)
                            continue
                    state_svc.delete_state(lab, topologies_dir)
                    status[lab] = "pending teardown state finalized"
            except Exception as exc:
                status[lab]='pending teardown state retained: native state guard: '+str(exc)

    finally:
        if own_clients:
            for name in connected:
                active_clients[name].close()
    return status


def _teardown_remaining_artifacts(
    state: DeploymentState,
    clients: dict[str, SSHClient],
    connected: set[str],
) -> tuple[bool, str]:
    """Return whether state-owned teardown artifacts still exist or cannot be checked."""
    artifacts_by_host: dict[str, list[CleanupArtifact]] = {}
    for artifact in _dedupe_artifacts(expected_artifacts_from_state(state)):
        if artifact.host:
            artifacts_by_host.setdefault(artifact.host, []).append(artifact)
    for host in state.scheduling:
        artifacts_by_host.setdefault(host, [])

    for host, artifacts in sorted(artifacts_by_host.items()):
        client = clients.get(host)
        if client is None or host not in connected:
            return True, f"host unavailable: {host}"
        remaining, reason = _host_teardown_artifacts_remaining(client, artifacts)
        if remaining:
            return True, f"{host}: {reason}"
    return False, ""


def _host_teardown_artifacts_remaining(
    client: SSHClient,
    artifacts: list[CleanupArtifact],
) -> tuple[bool, str]:
    containers = {a.name for a in artifacts if a.kind == "container"}
    networks = {a.name for a in artifacts if a.kind == "network"}
    interfaces = {a.name for a in artifacts if a.kind == "interface"}

    if containers:
        rc, out, err = client.run_no_check(
            "docker ps -a --format '{{.Names}}'", timeout=20,
        )
        if rc != 0:
            return True, f"cannot verify containers: {(err or '').strip()}"
        present = containers.intersection(line.strip() for line in out.splitlines())
        if present:
            return True, f"containers still present: {', '.join(sorted(present))}"

    if networks:
        rc, out, err = client.run_no_check(
            "docker network ls --format '{{.Name}}'", timeout=20,
        )
        if rc != 0:
            return True, f"cannot verify networks: {(err or '').strip()}"
        present = networks.intersection(line.strip() for line in out.splitlines())
        if present:
            return True, f"networks still present: {', '.join(sorted(present))}"

    if interfaces:
        rc, out, err = client.run_no_check(
            "ip -o link show | awk -F': ' '{print $2}'", timeout=20,
        )
        if rc != 0:
            return True, f"cannot verify interfaces: {(err or '').strip()}"
        observed = {line.split("@", 1)[0].strip() for line in out.splitlines()}
        present = interfaces.intersection(observed)
        if present:
            return True, f"interfaces still present: {', '.join(sorted(present))}"

    return False, ""


def _cleanup_action_priority(action: CleanupAction) -> int:
    """Keep Docker endpoint teardown ahead of dependent mgmt infrastructure."""
    return {
        "cleanup-jumphost": 5,
        "cleanup-dns": 5,
        "cleanup-relay": 5,
        "remove-container": 10,
        "remove-network": 20,
        "delete-interface": 40,
    }.get(action.action, 50)


def _dedupe_artifacts(artifacts: list[CleanupArtifact]) -> list[CleanupArtifact]:
    merged: dict[tuple[str, str, str], CleanupArtifact] = {}
    for artifact in artifacts:
        key = (artifact.kind, artifact.host, artifact.name)
        prev = merged.get(key)
        if prev is None:
            merged[key] = artifact
            continue
        if artifact.state:
            prev.state = artifact.state
        if artifact.age_seconds is not None:
            prev.age_seconds = artifact.age_seconds
        if artifact.metadata:
            prev.metadata.update(artifact.metadata)
        if artifact.source == "state":
            prev.source = "state"
    return list(merged.values())


def _age_from_created_at(value: str) -> int | None:
    if not value:
        return None
    # Docker's CreatedAt includes a timezone abbreviation after a numeric
    # offset; the numeric offset is enough for fromisoformat.
    cleaned = re.sub(r"\s+[A-Z]{2,5}$", "", value.strip())
    try:
        created = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()))
