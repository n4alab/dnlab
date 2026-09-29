"""Distributed topology data model."""

from __future__ import annotations

from dataclasses import dataclass, field

from dnlab_multinode.services.images import image_for


@dataclass
class VDNode:
    """Virtual Device node from the topology."""
    name: str
    kind: str
    image: str
    mgmt_ipv4: str = ""
    mgmt_ipv4_explicit: bool = False
    mgmt_ipv6: str = ""
    mgmt_ipv6_explicit: bool = False
    mgmt_mac: str = ""
    mgmt_duid: str = ""
    mgmt_iaid: str = ""
    env: dict[str, str] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    persist_id: str = ""


@dataclass
class Link:
    """A point-to-point link between two VD interfaces."""
    source: str          # node name
    source_iface: str    # interface name (e.g. eth1)
    target: str
    target_iface: str

    def __str__(self) -> str:
        return f"{self.source}:{self.source_iface} <-> {self.target}:{self.target_iface}"


@dataclass
class RealNet:
    """GUI-defined L2 domain backed by dNLab infrastructure.

    ``name`` is the pseudo-node name used by the GUI. It is not deployed as a
    user VD. The orchestrator creates a per-host bridge/VXLAN fabric and an
    unmanaged router container on the master when links reference it.
    """
    name: str
    ipv4: str
    nat: bool = True
    bgp: bool = False
    bgp_as: int = 0
    bgp_router_ip: str = ""
    bgp_password: str = ""
    import_routers: list[dict] = field(default_factory=list)
    description: str = ""


@dataclass
class RealNetLink:
    """A VD interface attached to a RealNet pseudo-node."""
    real_net: str
    node: str
    iface: str
    host: str = ""
    bridge_iface: str = ""


@dataclass
class InfraHost:
    """An infrastructure host (master or worker)."""
    name: str
    host: str           # IP address
    ssh_user: str
    ssh_key: str
    is_master: bool = False


@dataclass
class MgmtConfig:
    """Management network configuration."""
    network: str         # docker network name
    bridge: str          # bridge name
    ipv4_subnet: str     # e.g. 192.168.200.0/24
    ipv4_gw: str         # jumphost/default gateway seen by VDs
    docker_ipv4_gw: str = ""  # technical Docker/bridge gateway
    ipv6_subnet: str = ""
    ipv6_gw: str = ""
    dhcp: bool = False


@dataclass
class JumphostConfig:
    """Per-lab jumphost configuration.

    The jumphost network (bridge, subnet, gateway) is shared infrastructure
    and lives in ``hosts.yml`` as ``infrastructure.jumphost_net``. Per-lab
    only the container image is configurable; the IP is auto-assigned
    from the shared pool at deploy time.
    """
    image: str = field(default_factory=lambda: image_for("jumphost"))


@dataclass
class JumphostNet:
    """Shared jumphost docker network (mirror of HostsConfig.jumphost_net).

    Threaded into the topology by :func:`parse_topology` so controllers can
    read the network config without needing a HostsConfig reference.
    """
    network: str
    bridge: str
    ipv4_subnet: str
    ipv4_gw: str
    ssh_port_range: str = "2200-2299"
    ssh_bind_ip: str = "0.0.0.0"


@dataclass
class WebUIPortsCfg:
    """Pool host-side per le Web UI dei VD (mirror di
    ``HostsConfig.webui_ports``). Threaded nella topology da
    :func:`parse_topology` come per :class:`JumphostNet`."""
    port_range: str = "8443-8999"
    bind_ip: str = "127.0.0.1"


@dataclass
class RealNetInfraCfg:
    """Shared infrastructure settings for per-lab real networks."""
    network: str = "dnlab-realnet"
    bridge: str = "br-dnlab-rn"
    ipv4_subnet: str = "192.168.101.0/24"
    ipv4_gw: str = "192.168.101.1"
    image: str = field(default_factory=lambda: image_for("realnet-router"))
    wan_iface: str = ""
    rr_as: int = 64512
    rr_ip: str = ""
    host_net: str = ""
    router_as_pool: str = "64513-65534"
    router_ip_pool: str = ""
    realnet_network_pool: str = "100.64.0.0/10"
    rr_password: str = ""


@dataclass
class CephFSConfig:
    """CephFS persistence backend settings.

    Ceph is treated as an optional plugin: the default deployment path stays
    local-sticky and this block is only used when the inventory explicitly
    selects the ``cephfs`` backend.
    """
    mountpoint: str = "/var/lib/docker/dnlab-backups"
    expected_fstype: str = "ceph"
    marker: str = ".dnlab-cephfs"
    require_shared_marker: bool = True


@dataclass
class PersistenceConfig:
    """VD overlay persistence strategy threaded from hosts.yml."""
    backend: str = "local-sticky"
    root: str = "/var/lib/docker/dnlab-backups"
    allow_migration_fallback: bool = True
    cephfs: CephFSConfig = field(default_factory=CephFSConfig)


@dataclass
class DistributedTopology:
    """Parsed distributed topology from YAML file."""
    name: str
    master: InfraHost
    workers: dict[str, InfraHost]   # name → InfraHost
    underlay_iface: str
    jumphost: JumphostConfig
    jumphost_net: JumphostNet
    nodes: dict[str, VDNode]        # name → VDNode
    links: list[Link]
    mgmt: MgmtConfig
    real_nets: dict[str, RealNet] = field(default_factory=dict)
    real_net_links: list[RealNetLink] = field(default_factory=list)
    realnet_infra: RealNetInfraCfg = field(default_factory=RealNetInfraCfg)
    raw: dict = field(default_factory=dict)  # original parsed YAML
    # Wishlist Web UI per nodo, popolata dal sidecar
    # ``# dnlab-gui-webui:`` lasciato dalla GUI nel topology YAML.
    # Schema entry: {container_port:int, scheme:str, path:str,
    # label:str, source:"catalog"|"user"}.
    # Consumata in generator._build_clab_dict per scrivere ``ports:``.
    webui_wishlist: dict[str, list[dict]] = field(default_factory=dict)
    # Override GUI per nodo. Consumati dal generator/deploy per
    # materializzare asset runtime come cat9kv /tmp/.../vswitch.xml.
    node_overrides: dict[str, dict] = field(default_factory=dict)
    # Feature GUI data-driven per nodo. Ogni entry contiene stato utente
    # e istruzioni generiche di materializzazione, senza vincolare
    # l'orchestrator a uno specifico vendor/kind.
    node_features: dict[str, dict] = field(default_factory=dict)
    # Resource schema per nodo, popolato dal sidecar GUI. The scheduler
    # uses it to resolve effective CPU/RAM dynamically from node data
    # without hardcoding env var names in the orchestrator.
    resource_specs: dict[str, dict] = field(default_factory=dict)
    # Pool delle porte host-side da cui la deploy controller alloca
    # quelle riservate ad ogni VD (mirror di HostsConfig.webui_ports).
    webui_ports: WebUIPortsCfg = field(default_factory=WebUIPortsCfg)
    # Strategia di persistenza degli overlay VD. Default locale sticky;
    # CephFS è un plugin esplicito configurato da hosts.yml.
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)

    @property
    def all_hosts(self) -> dict[str, InfraHost]:
        """All hosts including master."""
        return {"master": self.master, **self.workers}

    @property
    def all_host_ips(self) -> dict[str, str]:
        """name → IP for all hosts."""
        return {name: h.host for name, h in self.all_hosts.items()}
