"""Global host inventory loader.

The physical hosts (master + workers), their SSH credentials, the shared
mgmt defaults / image-sync filter, and the **shared jumphost network**
live in a single site-wide file — by default
``/etc/dnlab/hosts.yml`` — so that a topology file can be pure
ContainerLab YAML and stay portable across sites.

The jumphost network is shared infrastructure: one Docker network on the
master hosts all lab jumphosts. Per-lab the topology only specifies the
jumphost image (for per-lab image overrides); the IP is auto-assigned
from the pool at deploy time.

File schema::

    infrastructure:
      master:
        host: 10.0.0.1
        ssh_user: root
        ssh_key: ~/.ssh/id_ed25519
      workers:
        worker1:
          host: 10.0.0.2
          ssh_user: root
          ssh_key: ~/.ssh/id_ed25519
      underlay_iface: eth0
      jumphost_net:                     # shared across all labs
        network: dnlab-jumphost
        bridge: br-dnlab-jh
        ipv4_subnet: 192.168.100.0/24
        ipv4_gw: 192.168.100.1

    defaults:
      mgmt:
        ipv4_subnet: 172.20.0.0/24
        ipv4_gw: 172.20.0.1

    image_sync:          # optional, used by the image-sync daemon
      enabled: true
      include: ["vrnetlab/*", "dnlab-runtime-relay", "dnlab-mgmt-anchor"]
      exclude: ["dnlab-jumphost", "dnlab-dns",
                "dnlab-realnet-router", "dnlab-realnet-rr",
                "postgres", "<none>:<none>"]
      interval_seconds: 300

The location can be overridden via the ``DNLAB_MULTINODE_HOSTS``
environment variable, or by passing an explicit path to
:func:`load_hosts_config`.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dnlab_multinode.models.topology import (
    CephFSConfig, InfraHost, JumphostConfig, PersistenceConfig,
)
from dnlab_multinode.services.images import image_for
from dnlab_multinode.services.paths import PATHS

log = logging.getLogger(__name__)


DEFAULT_HOSTS_FILE = PATHS.hosts_file
ENV_VAR = "DNLAB_MULTINODE_HOSTS"


class HostsConfigError(Exception):
    pass


def _mapping(value: Any, path: str) -> dict[str, Any]:
    """Return a YAML mapping or raise a path-specific configuration error."""
    if not isinstance(value, dict):
        raise HostsConfigError(f"{path} must be a mapping")
    return value


def _reject_unknown(value: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if not unknown:
        return
    key = unknown[0]
    if path in {"infrastructure.master", "infrastructure.workers.*"} and key == "interface":
        raise HostsConfigError(
            f"{path}.interface is not supported; use the site-wide "
            "infrastructure.underlay_iface instead"
        )
    raise HostsConfigError(f"{path}: unknown key '{key}'")


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise HostsConfigError(f"{path} must be {qualifier}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise HostsConfigError(f"{path} must be a boolean")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HostsConfigError(f"{path} must be an integer")
    return value


@dataclass
class MgmtDefaults:
    ipv4_subnet: str = "172.20.0.0/24"
    ipv4_gw: str = "172.20.0.1"


@dataclass
class JumphostNetConfig:
    """Shared jumphost docker network (master-local)."""
    network: str = "dnlab-jumphost"
    bridge: str = "br-dnlab-jh"
    ipv4_subnet: str = "192.168.100.0/24"
    ipv4_gw: str = "192.168.100.1"
    # Host-side port publishing for per-lab SSH access.
    # `ssh_port_range` is an inclusive "<low>-<high>" range; one port is
    # allocated per lab at deploy time. `ssh_bind_ip` is the master-side
    # IP the port is published on ("0.0.0.0" = all interfaces).
    ssh_port_range: str = "2200-2299"
    ssh_bind_ip: str = "0.0.0.0"


@dataclass
class WebUIPortsConfig:
    """Pool host-side per le porte Web UI dei VD pubblicate via clab.

    Allocazione dinamica, sticky cross-deploy via ``LabState``. Pool
    disgiunto da ``JumphostNetConfig.ssh_port_range`` (validation a
    carico del loader).
    """
    port_range: str = "8443-8999"
    bind_ip: str = "127.0.0.1"


@dataclass
class RealNetConfig:
    """Shared WAN network for unmanaged per-lab real_net routers."""
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
class ImageSyncConfig:
    enabled: bool = True
    include: list[str] = field(default_factory=lambda: ["*"])
    exclude: list[str] = field(
        default_factory=lambda: [
            "dnlab-jumphost",
            "dnlab-dns",
            "dnlab-realnet-router",
            "dnlab-realnet-rr",
            "postgres",
            "<none>:<none>",
        ]
    )
    interval_seconds: int = 300


@dataclass
class LabCleanupConfig:
    enabled: bool = True
    interval_seconds: int = 300
    grace_seconds: int = 600
    dry_run: bool = False


@dataclass
class FollowRabbitConfig:
    max_sessions: int = 1


@dataclass
class HostsConfig:
    """Parsed contents of the global hosts file.

    ``jumphost`` is kept as an optional field **only** for the
    backward-compatibility path where a legacy topology still carries an
    in-topology ``infrastructure:`` block alongside a ``jumphost:`` block.
    In the supported layout the jumphost lives in the topology file and
    is threaded through :func:`~dnlab_multinode.services.config.parse_topology`.
    """
    master: InfraHost
    workers: dict[str, InfraHost]
    underlay_iface: str
    mgmt_defaults: MgmtDefaults
    image_sync: ImageSyncConfig
    lab_cleanup: LabCleanupConfig = field(default_factory=LabCleanupConfig)
    jumphost_net: JumphostNetConfig = field(default_factory=JumphostNetConfig)
    webui_ports: WebUIPortsConfig = field(default_factory=WebUIPortsConfig)
    realnet: RealNetConfig = field(default_factory=RealNetConfig)
    follow_the_rabbit: FollowRabbitConfig = field(default_factory=FollowRabbitConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    jumphost: JumphostConfig | None = None
    source_path: Path | None = None   # where this was loaded from (for errors)

    @property
    def all_hosts(self) -> dict[str, InfraHost]:
        return {"master": self.master, **self.workers}


def resolve_hosts_file(explicit: str | Path | None = None) -> Path:
    """Resolve the path of the hosts file.

    Precedence: explicit argument > ``DNLAB_MULTINODE_HOSTS`` env var >
    ``/etc/dnlab/hosts.yml``.
    """
    if explicit is not None:
        return Path(explicit).expanduser()
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env).expanduser()
    return Path(DEFAULT_HOSTS_FILE)


def load_hosts_config(path: str | Path | None = None) -> HostsConfig:
    """Load and validate the global hosts file.

    Raises :class:`HostsConfigError` if the file is missing or malformed.
    """
    resolved = resolve_hosts_file(path)
    if not resolved.exists():
        raise HostsConfigError(
            f"Global hosts file not found: {resolved}. "
            f"Create it or set {ENV_VAR} to a different location."
        )

    log.info("Loading hosts config: %s", resolved)
    try:
        with resolved.open() as fh:
            raw = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise HostsConfigError(f"Invalid YAML in {resolved}: {exc}") from exc

    if not isinstance(raw, dict):
        raise HostsConfigError(f"{resolved}: root must be a mapping")

    return _parse_hosts_dict(raw, source_path=resolved)


def _parse_hosts_dict(raw: dict, source_path: Path | None = None) -> HostsConfig:
    """Parse the canonical site inventory and reject ignored configuration."""
    _reject_unknown(raw, {
        "infrastructure", "defaults", "image_sync", "lab_cleanup",
        "follow_the_rabbit", "plus", "jumphost",
    }, "hosts")
    if "infrastructure" not in raw:
        raise HostsConfigError("Missing required section: 'infrastructure'")
    infra = _mapping(raw["infrastructure"], "infrastructure")
    _reject_unknown(infra, {
        "master", "workers", "underlay_iface", "jumphost_net", "webui_ports",
        "realnet", "persistence",
    }, "infrastructure")

    if "master" not in infra:
        raise HostsConfigError("Missing or incomplete 'infrastructure.master'")
    master_cfg = _mapping(infra["master"], "infrastructure.master")
    _reject_unknown(master_cfg, {"host", "ssh_user", "ssh_key"}, "infrastructure.master")
    if "host" not in master_cfg:
        raise HostsConfigError("Missing or incomplete 'infrastructure.master'")
    master = InfraHost(
        name="master",
        host=_string(master_cfg["host"], "infrastructure.master.host"),
        ssh_user=_string(master_cfg.get("ssh_user", "root"), "infrastructure.master.ssh_user"),
        ssh_key=os.path.expanduser(_string(
            master_cfg.get("ssh_key", "~/.ssh/id_ed25519"),
            "infrastructure.master.ssh_key",
        )),
        is_master=True,
    )

    workers_raw = _mapping(infra.get("workers", {}), "infrastructure.workers")
    workers: dict[str, InfraHost] = {}
    for wname, raw_worker in workers_raw.items():
        if not isinstance(wname, str) or not wname.strip():
            raise HostsConfigError("infrastructure.workers keys must be non-empty strings")
        wcfg = _mapping(raw_worker, f"infrastructure.workers.{wname}")
        _reject_unknown(wcfg, {"host", "ssh_user", "ssh_key"}, "infrastructure.workers.*")
        if "host" not in wcfg:
            raise HostsConfigError(f"Worker '{wname}' has no 'host' field")
        workers[wname] = InfraHost(
            name=wname,
            host=_string(wcfg["host"], f"infrastructure.workers.{wname}.host"),
            ssh_user=_string(wcfg.get("ssh_user", "root"), f"infrastructure.workers.{wname}.ssh_user"),
            ssh_key=os.path.expanduser(_string(
                wcfg.get("ssh_key", "~/.ssh/id_ed25519"),
                f"infrastructure.workers.{wname}.ssh_key",
            )),
        )

    underlay_iface = _string(
        infra.get("underlay_iface", "eth0"), "infrastructure.underlay_iface"
    )

    jh_net_cfg = _mapping(infra.get("jumphost_net", {}), "infrastructure.jumphost_net")
    _reject_unknown(jh_net_cfg, {
        "network", "bridge", "ipv4_subnet", "ipv4_gw", "ssh_port_range", "ssh_bind_ip",
    }, "infrastructure.jumphost_net")
    defaults = JumphostNetConfig()
    ssh_bind_ip = _string(
        jh_net_cfg.get("ssh_bind_ip", defaults.ssh_bind_ip),
        "infrastructure.jumphost_net.ssh_bind_ip",
    )
    try:
        ipaddress.ip_address(ssh_bind_ip)
    except ValueError as exc:
        raise HostsConfigError(
            "infrastructure.jumphost_net.ssh_bind_ip: invalid IPv4 "
            f"address '{ssh_bind_ip}'"
        ) from exc
    ssh_port_range = _string(
        jh_net_cfg.get("ssh_port_range", defaults.ssh_port_range),
        "infrastructure.jumphost_net.ssh_port_range",
    )
    if not re.fullmatch(r"\d+-\d+", ssh_port_range):
        raise HostsConfigError(
            "infrastructure.jumphost_net.ssh_port_range: expected '<low>-<high>', "
            f"got '{ssh_port_range}'"
        )
    low, high = (int(p) for p in ssh_port_range.split("-"))
    if not (1 <= low <= high <= 65535):
        raise HostsConfigError(
            "infrastructure.jumphost_net.ssh_port_range: invalid range "
            f"'{ssh_port_range}' (must satisfy 1 <= low <= high <= 65535)"
        )
    jumphost_net = JumphostNetConfig(
        network=_string(jh_net_cfg.get("network", defaults.network), "infrastructure.jumphost_net.network"),
        bridge=_string(jh_net_cfg.get("bridge", defaults.bridge), "infrastructure.jumphost_net.bridge"),
        ipv4_subnet=_string(jh_net_cfg.get("ipv4_subnet", defaults.ipv4_subnet), "infrastructure.jumphost_net.ipv4_subnet"),
        ipv4_gw=_string(jh_net_cfg.get("ipv4_gw", defaults.ipv4_gw), "infrastructure.jumphost_net.ipv4_gw"),
        ssh_port_range=ssh_port_range,
        ssh_bind_ip=ssh_bind_ip,
    )

    webui_cfg = _mapping(infra.get("webui_ports", {}), "infrastructure.webui_ports")
    _reject_unknown(webui_cfg, {"port_range", "bind_ip"}, "infrastructure.webui_ports")
    webui_defaults = WebUIPortsConfig()
    webui_bind_ip = _string(webui_cfg.get("bind_ip", webui_defaults.bind_ip), "infrastructure.webui_ports.bind_ip")
    try:
        ipaddress.ip_address(webui_bind_ip)
    except ValueError as exc:
        raise HostsConfigError(
            f"infrastructure.webui_ports.bind_ip: invalid IPv4 address '{webui_bind_ip}'"
        ) from exc
    webui_port_range = _string(webui_cfg.get("port_range", webui_defaults.port_range), "infrastructure.webui_ports.port_range")
    if not re.fullmatch(r"\d+-\d+", webui_port_range):
        raise HostsConfigError(
            "infrastructure.webui_ports.port_range: expected '<low>-<high>', "
            f"got '{webui_port_range}'"
        )
    wlow, whigh = (int(p) for p in webui_port_range.split("-"))
    if not (1 <= wlow <= whigh <= 65535):
        raise HostsConfigError(
            "infrastructure.webui_ports.port_range: invalid range "
            f"'{webui_port_range}' (require 1 <= low <= high <= 65535)"
        )
    if not (whigh < low or wlow > high):
        log.warning(
            "infrastructure.webui_ports.port_range %s overlaps "
            "infrastructure.jumphost_net.ssh_port_range %s — allocations may collide",
            webui_port_range, ssh_port_range,
        )
    webui_ports = WebUIPortsConfig(port_range=webui_port_range, bind_ip=webui_bind_ip)

    realnet_cfg = _mapping(infra.get("realnet", {}), "infrastructure.realnet")
    _reject_unknown(realnet_cfg, {
        "network", "bridge", "ipv4_subnet", "ipv4_gw", "image", "wan_iface", "rr_as",
        "bgp_as", "rr_ip", "host_net", "router_as_pool", "lab_as_pool", "router_ip_pool",
        "realnet_network_pool", "rr_password",
    }, "infrastructure.realnet")
    realnet_defaults = RealNetConfig()
    rr_as_value = realnet_cfg.get("rr_as", realnet_cfg.get("bgp_as", realnet_defaults.rr_as))
    router_as_pool = realnet_cfg.get(
        "router_as_pool", realnet_cfg.get("lab_as_pool", realnet_defaults.router_as_pool)
    )
    realnet = RealNetConfig(
        network=_string(realnet_cfg.get("network", realnet_defaults.network), "infrastructure.realnet.network"),
        bridge=_string(realnet_cfg.get("bridge", realnet_defaults.bridge), "infrastructure.realnet.bridge"),
        ipv4_subnet=_string(realnet_cfg.get("ipv4_subnet", realnet_defaults.ipv4_subnet), "infrastructure.realnet.ipv4_subnet"),
        ipv4_gw=_string(realnet_cfg.get("ipv4_gw", realnet_defaults.ipv4_gw), "infrastructure.realnet.ipv4_gw"),
        image=_string(realnet_cfg.get("image", realnet_defaults.image), "infrastructure.realnet.image"),
        wan_iface=_string(realnet_cfg.get("wan_iface", realnet_defaults.wan_iface), "infrastructure.realnet.wan_iface", allow_empty=True),
        rr_as=_integer(rr_as_value, "infrastructure.realnet.rr_as"),
        rr_ip=_string(realnet_cfg.get("rr_ip", realnet_defaults.rr_ip), "infrastructure.realnet.rr_ip", allow_empty=True),
        host_net=_string(realnet_cfg.get("host_net", realnet_defaults.host_net), "infrastructure.realnet.host_net", allow_empty=True),
        router_as_pool=_string(router_as_pool, "infrastructure.realnet.router_as_pool"),
        router_ip_pool=_string(realnet_cfg.get("router_ip_pool", realnet_defaults.router_ip_pool), "infrastructure.realnet.router_ip_pool", allow_empty=True),
        realnet_network_pool=_string(realnet_cfg.get("realnet_network_pool", realnet_defaults.realnet_network_pool), "infrastructure.realnet.realnet_network_pool"),
        rr_password=_string(realnet_cfg.get("rr_password", realnet_defaults.rr_password), "infrastructure.realnet.rr_password", allow_empty=True),
    )
    try:
        ipaddress.ip_network(realnet.ipv4_subnet, strict=False)
        ipaddress.ip_address(realnet.ipv4_gw)
    except ValueError as exc:
        raise HostsConfigError(f"infrastructure.realnet: invalid subnet/gateway: {exc}") from exc
    _validate_realnet_bgp(realnet)

    persistence = _parse_persistence_config(infra.get("persistence", {}))

    # Retained only for legacy topology files. Supported inventories never use it.
    jumphost: JumphostConfig | None = None
    if "jumphost" in raw:
        legacy_jumphost = _mapping(raw["jumphost"], "jumphost")
        # A legacy topology may carry historical jumphost-only fields. They
        # remain outside the supported site-inventory schema but must not make
        # an old topology undeployable while it is being migrated.
        jumphost = JumphostConfig(
            image=_string(legacy_jumphost.get("image", JumphostConfig().image), "jumphost.image")
        )

    defaults_raw = _mapping(raw.get("defaults", {}), "defaults")
    _reject_unknown(defaults_raw, {"mgmt"}, "defaults")
    mgmt_raw = _mapping(defaults_raw.get("mgmt", {}), "defaults.mgmt")
    _reject_unknown(mgmt_raw, {"ipv4_subnet", "ipv4_gw"}, "defaults.mgmt")
    mgmt_defaults = MgmtDefaults(
        ipv4_subnet=_string(mgmt_raw.get("ipv4_subnet", MgmtDefaults.ipv4_subnet), "defaults.mgmt.ipv4_subnet"),
        ipv4_gw=_string(mgmt_raw.get("ipv4_gw", MgmtDefaults.ipv4_gw), "defaults.mgmt.ipv4_gw"),
    )

    isync_cfg = _mapping(raw.get("image_sync", {}), "image_sync")
    _reject_unknown(isync_cfg, {"enabled", "include", "exclude", "interval_seconds"}, "image_sync")
    def string_list(value: Any, path: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise HostsConfigError(f"{path} must be a list of non-empty strings")
        return value
    image_defaults = ImageSyncConfig()
    image_sync = ImageSyncConfig(
        enabled=_boolean(isync_cfg.get("enabled", image_defaults.enabled), "image_sync.enabled"),
        include=string_list(isync_cfg.get("include", image_defaults.include), "image_sync.include"),
        exclude=string_list(isync_cfg.get("exclude", image_defaults.exclude), "image_sync.exclude"),
        interval_seconds=_integer(isync_cfg.get("interval_seconds", image_defaults.interval_seconds), "image_sync.interval_seconds"),
    )
    if image_sync.interval_seconds < 30:
        raise HostsConfigError("image_sync.interval_seconds must be >= 30")

    cleanup_cfg = _mapping(raw.get("lab_cleanup", {}), "lab_cleanup")
    _reject_unknown(cleanup_cfg, {"enabled", "interval_seconds", "grace_seconds", "dry_run"}, "lab_cleanup")
    cleanup_defaults = LabCleanupConfig()
    cleanup_interval = _integer(cleanup_cfg.get("interval_seconds", cleanup_defaults.interval_seconds), "lab_cleanup.interval_seconds")
    cleanup_grace = _integer(cleanup_cfg.get("grace_seconds", cleanup_defaults.grace_seconds), "lab_cleanup.grace_seconds")
    if cleanup_interval < 30:
        raise HostsConfigError("lab_cleanup.interval_seconds must be >= 30")
    if cleanup_grace < 0:
        raise HostsConfigError("lab_cleanup.grace_seconds must be >= 0")
    lab_cleanup = LabCleanupConfig(
        enabled=_boolean(cleanup_cfg.get("enabled", cleanup_defaults.enabled), "lab_cleanup.enabled"),
        interval_seconds=cleanup_interval,
        grace_seconds=cleanup_grace,
        dry_run=_boolean(cleanup_cfg.get("dry_run", cleanup_defaults.dry_run), "lab_cleanup.dry_run"),
    )

    rabbit_cfg = raw.get("follow_the_rabbit")
    if rabbit_cfg is None and "plus" in raw:
        plus = _mapping(raw["plus"], "plus")
        _reject_unknown(plus, {"follow_the_rabbit"}, "plus")
        rabbit_cfg = plus.get("follow_the_rabbit", {})
    rabbit_cfg = _mapping(rabbit_cfg or {}, "follow_the_rabbit")
    _reject_unknown(rabbit_cfg, {"max_sessions"}, "follow_the_rabbit")
    max_sessions = _integer(rabbit_cfg.get("max_sessions", FollowRabbitConfig.max_sessions), "follow_the_rabbit.max_sessions")
    if max_sessions < 0:
        raise HostsConfigError("follow_the_rabbit.max_sessions must be >= 0")
    follow_the_rabbit = FollowRabbitConfig(max_sessions=max_sessions)

    return HostsConfig(
        master=master, workers=workers, underlay_iface=underlay_iface,
        jumphost_net=jumphost_net, webui_ports=webui_ports, realnet=realnet,
        persistence=persistence, lab_cleanup=lab_cleanup,
        follow_the_rabbit=follow_the_rabbit, jumphost=jumphost, mgmt_defaults=mgmt_defaults,
        image_sync=image_sync, source_path=source_path,
    )


def _parse_persistence_config(raw: dict | None) -> PersistenceConfig:
    raw = _mapping(raw or {}, "infrastructure.persistence")
    _reject_unknown(raw, {"backend", "root", "allow_migration_fallback", "cephfs"}, "infrastructure.persistence")
    backend = _string(raw.get("backend", PersistenceConfig.backend), "infrastructure.persistence.backend")
    if backend not in {"local-sticky", "cephfs"}:
        raise HostsConfigError(
            "infrastructure.persistence.backend must be one of: local-sticky, cephfs"
        )
    root = _string(raw.get("root", PATHS.persist_root), "infrastructure.persistence.root").rstrip("/") or PATHS.persist_root
    allow_fallback = _boolean(
        raw.get("allow_migration_fallback", PersistenceConfig.allow_migration_fallback),
        "infrastructure.persistence.allow_migration_fallback",
    )
    ceph_raw = _mapping(raw.get("cephfs", {}), "infrastructure.persistence.cephfs")
    _reject_unknown(ceph_raw, {"mountpoint", "expected_fstype", "marker", "require_shared_marker"}, "infrastructure.persistence.cephfs")
    ceph = CephFSConfig(
        mountpoint=_string(
            ceph_raw.get("mountpoint", root), "infrastructure.persistence.cephfs.mountpoint"
        ).rstrip("/") or root,
        expected_fstype=_string(
            ceph_raw.get("expected_fstype", CephFSConfig.expected_fstype),
            "infrastructure.persistence.cephfs.expected_fstype",
        ),
        marker=_string(ceph_raw.get("marker", CephFSConfig.marker), "infrastructure.persistence.cephfs.marker"),
        require_shared_marker=_boolean(
            ceph_raw.get("require_shared_marker", CephFSConfig.require_shared_marker),
            "infrastructure.persistence.cephfs.require_shared_marker",
        ),
    )
    return PersistenceConfig(
        backend=backend, root=root, allow_migration_fallback=allow_fallback, cephfs=ceph,
    )


def _validate_realnet_bgp(realnet: RealNetConfig) -> None:
    def private_as(asn: int) -> bool:
        return 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294

    if not private_as(int(realnet.rr_as)):
        raise HostsConfigError("infrastructure.realnet.rr_as must be a private BGP AS")
    try:
        low_s, high_s = str(realnet.router_as_pool).split("-", 1)
        low, high = int(low_s), int(high_s)
    except Exception as exc:
        raise HostsConfigError("infrastructure.realnet.router_as_pool must be '<low>-<high>'") from exc
    if low > high or not private_as(low) or not private_as(high):
        raise HostsConfigError("infrastructure.realnet.router_as_pool must be inside private BGP AS ranges")
    if not ((64512 <= low <= high <= 65534) or (4200000000 <= low <= high <= 4294967294)):
        raise HostsConfigError("infrastructure.realnet.router_as_pool cannot span private AS ranges")
    if realnet.rr_ip or realnet.host_net:
        try:
            rr_ip = ipaddress.ip_address(realnet.rr_ip)
            host_net = ipaddress.ip_network(realnet.host_net, strict=False)
        except ValueError as exc:
            raise HostsConfigError(f"infrastructure.realnet: invalid rr_ip/host_net: {exc}") from exc
        if rr_ip not in host_net:
            raise HostsConfigError("infrastructure.realnet.rr_ip must belong to host_net")
    if realnet.router_ip_pool:
        raw = str(realnet.router_ip_pool)
        try:
            if "/" in raw:
                ipaddress.ip_network(raw, strict=False)
            else:
                low_ip, high_ip = [ipaddress.ip_address(p.strip()) for p in raw.split("-", 1)]
                if low_ip.version != high_ip.version or int(low_ip) > int(high_ip):
                    raise ValueError("invalid range")
        except ValueError as exc:
            raise HostsConfigError(f"infrastructure.realnet.router_ip_pool invalid: {exc}") from exc
    try:
        pool = ipaddress.ip_network(str(realnet.realnet_network_pool), strict=False)
        if pool.version != 4 or pool.prefixlen > 24:
            raise ValueError("must be an IPv4 CIDR containing at least one /24")
    except ValueError as exc:
        raise HostsConfigError(f"infrastructure.realnet.realnet_network_pool invalid: {exc}") from exc
    if realnet.rr_password:
        if len(str(realnet.rr_password)) > 80 or any(ch.isspace() for ch in str(realnet.rr_password)):
            raise HostsConfigError("infrastructure.realnet.rr_password must be 1-80 characters without whitespace")
def hosts_config_from_legacy_topology(raw: dict) -> HostsConfig:
    """Build a HostsConfig from the legacy in-topology ``infrastructure:`` /
    ``jumphost:`` blocks.

    Used for backward-compatibility: if a topology still carries those
    sections, we honour them and log a deprecation warning.
    """
    synthetic = {
        "infrastructure": raw.get("infrastructure") or {},
        "jumphost": raw.get("jumphost") or {},
    }
    return _parse_hosts_dict(synthetic, source_path=None)
