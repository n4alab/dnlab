"""Deployment state model — serialized to/from JSON."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class MgmtState:
    subnet: str
    gateway: str
    bridge: str
    vrf: str
    vxlan_id: int
    vxlan_iface: str
    network: str = ""
    network_driver: str = ""
    ipam_driver: str = ""


@dataclass
class JumphostState:
    node: str             # host name (always "master")
    container: str
    mgmt_ip: str
    host_ip: str          # IP on the dedicated ext network (master-local)
    ext_network: str      # dedicated docker network name (master-local)
    password: str = ""    # generated password
    resolver: str = ""    # DNS container mgmt IP used as --dns
    # Host-side SSH port-publish on master (from hosts.yml range).
    # ``ssh_port == 0`` means no port-forward was allocated — either an
    # old state file, or the feature disabled for the lab.
    ssh_port: int = 0
    ssh_bind_ip: str = ""


@dataclass
class DnsState:
    node: str             # host name (always "master")
    container: str
    mgmt_ip: str
    upstream: list[str] = field(default_factory=list)
    hosts_file: str = ""  # path on master of the merged hosts file
    entries: int = 0      # number of DNS records served


@dataclass
class RuntimeRelayState:
    host: str
    container: str
    bind_ip: str
    port: int
    api_key: str = ""
    allowed: list[str] = field(default_factory=list)


@dataclass
class HostScheduleState:
    host: str             # IP
    topology_file: str
    vd: list[str] = field(default_factory=list)
    resources_used: dict[str, int] = field(default_factory=dict)


@dataclass
class VxlanLinkState:
    id: int
    link: str
    side_a: dict[str, str] = field(default_factory=dict)
    side_b: dict[str, str] = field(default_factory=dict)
    status: str = "unknown"


@dataclass
class NodeRuntimeState:
    node: str
    state: str = "running"
    host: str = ""
    container: str = ""
    topology_file: str = ""
    kind: str = ""
    image: str = ""
    mgmt_ipv4: str = ""
    started_at: str = ""
    last_error: str = ""
    warm_ports: int = 0
    hot_links_status: str = "unsupported"


@dataclass
class MgmtAnchorState:
    host: str = ""
    container: str = ""
    topology_file: str = ""
    state: str = "running"


@dataclass
class RuntimeLinkState:
    id: str
    link_type: str
    endpoint_a: dict[str, str] = field(default_factory=dict)
    endpoint_b: dict[str, str] = field(default_factory=dict)
    host_a: str = ""
    host_b: str = ""
    host_endpoint_a: str = ""
    host_endpoint_b: str = ""
    container_a: str = ""
    container_b: str = ""
    warm_a: bool = False
    warm_b: bool = False
    vxlan_id: int = 0
    state: str = "down"
    last_error: str = ""
    validation_error: bool = False


@dataclass
class WebUIAllocation:
    """Una porta host-side allocata per esporre una Web UI di un VD.

    Il pool è in ``hosts.yml::infrastructure.webui_ports``. Le entry
    sono **sticky cross-deploy**: vengono ri-allocate alla stessa porta
    al prossimo deploy se lo state file è preservato (default).

    Campi:
      * ``container_port`` — porta dentro il VD (es. 443).
      * ``host_port``      — porta sul master (es. 8456).
      * ``bind_ip``        — IP sul master a cui il porto è pubblicato.
      * ``proto``          — sempre ``tcp`` per le UI HTTP/S; lasciato
        configurabile per il futuro (gRPC su tcp + reflection ecc.).
    """
    container_port: int
    host_port: int
    bind_ip: str = "127.0.0.1"
    proto: str = "tcp"


@dataclass
class RealNetState:
    name: str
    bridge: str
    vxlan_id: int
    hosts: list[str] = field(default_factory=list)
    router_container: str = ""
    router_wan_ip: str = ""
    lan_ipv4: str = ""
    nat: bool = True
    bgp: bool = False
    bgp_as: int = 0
    bgp_router_ip: str = ""


@dataclass
class DeploymentState:
    lab_name: str
    topology_file: str
    deployed_at: str = ""
    dnlab_deployed: bool = True
    # A destroy request is durable until every state-owned artifact has been
    # observed absent. This lets lab-cleanup finish a teardown after a host
    # was unavailable during the original destroy operation.
    teardown_requested: bool = False
    # ``per-vd`` deployments use one Containerlab micro-topology per node and
    # can therefore grow while the shared lab infrastructure stays online.
    # An empty/legacy value is deliberately conservative for old state files.
    runtime_mode: str = ""
    vrf_table_id: int = 0
    mgmt: MgmtState | None = None
    jumphost: JumphostState | None = None
    dns: DnsState | None = None
    runtime_relays: dict[str, RuntimeRelayState] = field(default_factory=dict)
    scheduling: dict[str, HostScheduleState] = field(default_factory=dict)
    vxlan_dataplane: list[VxlanLinkState] = field(default_factory=list)
    mgmt_anchors: dict[str, MgmtAnchorState] = field(default_factory=dict)
    node_runtime: dict[str, NodeRuntimeState] = field(default_factory=dict)
    runtime_links: list[RuntimeLinkState] = field(default_factory=list)
    # Mappa node_name → lista di allocazioni Web UI host-side (porte
    # esposte via clab `ports:`). Persistita per garantire stickiness
    # delle porte fra destroy/deploy successivi.
    webui_allocations: dict[str, list[WebUIAllocation]] = field(default_factory=dict)
    # Mappa node_name → mgmt-ipv4 assegnato. È un ledger sticky: conserva
    # anche nodi rimossi dalla topology corrente finché lo state file vive,
    # così gli IP non vengono riciclati accidentalmente su deploy successivi.
    mgmt_ip_reservations: dict[str, str] = field(default_factory=dict)
    # IPv6, L2 and DHCPv6 identities remain sticky for removed nodes too.
    mgmt_ipv6_reservations: dict[str, str] = field(default_factory=dict)
    mgmt_mac_reservations: dict[str, str] = field(default_factory=dict)
    mgmt_duid_reservations: dict[str, str] = field(default_factory=dict)
    mgmt_iaid_reservations: dict[str, str] = field(default_factory=dict)
    realnets: list[RealNetState] = field(default_factory=list)
    # Track completed phases for rollback
    phases_completed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        import dataclasses
        def _convert(obj):
            if dataclasses.is_dataclass(obj):
                return {k: _convert(v) for k, v in dataclasses.asdict(obj).items()}
            if isinstance(obj, list):
                return [_convert(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _convert(v) for k, v in obj.items()}
            return obj
        return _convert(self)

    @classmethod
    def from_dict(cls, d: dict) -> DeploymentState:
        state = cls(
            lab_name=d["lab_name"],
            topology_file=d["topology_file"],
            deployed_at=d.get("deployed_at", ""),
            dnlab_deployed=d.get("dnlab_deployed", True),
            teardown_requested=d.get("teardown_requested", False),
            runtime_mode=d.get("runtime_mode", ""),
            vrf_table_id=d.get("vrf_table_id", 0),
            phases_completed=d.get("phases_completed", []),
        )
        if d.get("mgmt"):
            m = d["mgmt"]
            state.mgmt = MgmtState(**m)
        if d.get("jumphost"):
            j = d["jumphost"]
            state.jumphost = JumphostState(**j)
        if d.get("dns"):
            state.dns = DnsState(**d["dns"])
        for name, rr in d.get("runtime_relays", {}).items():
            state.runtime_relays[name] = RuntimeRelayState(**rr)
        for name, s in d.get("scheduling", {}).items():
            state.scheduling[name] = HostScheduleState(**s)
        for v in d.get("vxlan_dataplane", []):
            state.vxlan_dataplane.append(VxlanLinkState(**v))
        for host, anchor in (d.get("mgmt_anchors") or {}).items():
            state.mgmt_anchors[host] = MgmtAnchorState(**anchor)
        for node, runtime in (d.get("node_runtime") or {}).items():
            state.node_runtime[node] = NodeRuntimeState(**runtime)
        for link in d.get("runtime_links", []):
            state.runtime_links.append(RuntimeLinkState(**link))
        for node, allocs in (d.get("webui_allocations") or {}).items():
            state.webui_allocations[node] = [WebUIAllocation(**a) for a in allocs]
        state.mgmt_ip_reservations = dict(d.get("mgmt_ip_reservations") or {})
        state.mgmt_ipv6_reservations = dict(d.get("mgmt_ipv6_reservations") or {})
        state.mgmt_mac_reservations = dict(d.get("mgmt_mac_reservations") or {})
        state.mgmt_duid_reservations = dict(d.get("mgmt_duid_reservations") or {})
        state.mgmt_iaid_reservations = dict(d.get("mgmt_iaid_reservations") or {})
        for rn in d.get("realnets", []):
            rn = dict(rn)
            if "ospf" in rn and "bgp" not in rn:
                rn["bgp"] = bool(rn.pop("ospf"))
            rn.pop("ospf_area", None)
            state.realnets.append(RealNetState(**rn))
        if not state.node_runtime:
            state._populate_legacy_node_runtime()
        if not state.runtime_mode and state.node_runtime:
            prefix = f"clab-dnlab-{state.lab_name}-"
            if all(runtime.container.startswith(prefix) for runtime in state.node_runtime.values()):
                state.runtime_mode = "per-vd"
            else:
                state.runtime_mode = "legacy"
        if not state.mgmt_ip_reservations:
            state.mgmt_ip_reservations = {
                node: runtime.mgmt_ipv4
                for node, runtime in state.node_runtime.items()
                if runtime.mgmt_ipv4
            }
        return state

    def _populate_legacy_node_runtime(self) -> None:
        from dnlab_multinode.utils.naming import vd_container_name

        for host_name, schedule in self.scheduling.items():
            for node in schedule.vd:
                self.node_runtime[node] = NodeRuntimeState(
                    node=node,
                    state="running",
                    host=host_name,
                    container=vd_container_name(self.lab_name, node),
                    topology_file=schedule.topology_file,
                )
