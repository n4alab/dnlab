"""YAML topology file parsing and validation.

The topology YAML is expected to be **pure ContainerLab** plus two
optional blocks: ``mgmt:`` (override of the inventory defaults) and
``jumphost:`` (per-lab jumphost image and external IP). Physical host
inventory and mgmt/image-sync defaults come from the global hosts file
(see :mod:`dnlab_multinode.services.hosts_config`).

For backward compatibility we still accept the legacy layout in which
``infrastructure:`` (and optionally ``jumphost:``) lives inside the
topology. When we detect the ``infrastructure:`` block, we log a
deprecation warning and honour it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from pathlib import Path

import yaml

from dnlab_multinode.models.topology import (
    DistributedTopology, VDNode, Link, MgmtConfig, JumphostConfig, JumphostNet,
    WebUIPortsCfg, RealNet, RealNetLink, RealNetInfraCfg,
)
from dnlab_multinode.services.hosts_config import (
    HostsConfig, load_hosts_config, hosts_config_from_legacy_topology,
)
from dnlab_multinode.services.mgmt_ips import (
    MgmtAddressError, derive_ipv6_subnet_from_ipv4, ipv4_reservations,
    ipv6_gateway,
)
from dnlab_multinode.utils.naming import mgmt_bridge_name, mgmt_network_name

log = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


def _resolve_mgmt_config(
    lab_name: str,
    mgmt_cfg: dict,
    hosts: HostsConfig,
) -> tuple[str, str, str, str, str]:
    default_subnet = hosts.mgmt_defaults.ipv4_subnet
    requested_subnet = mgmt_cfg.get("ipv4-subnet")

    if requested_subnet:
        try:
            subnet = ipaddress.IPv4Network(requested_subnet, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid mgmt.ipv4-subnet {requested_subnet!r}: {exc}") from exc
        try:
            reserved = ipv4_reservations(str(subnet))
        except MgmtAddressError as exc:
            raise ConfigError(str(exc)) from exc
        ipv6_subnet = _resolve_mgmt_ipv6_subnet(mgmt_cfg, str(subnet))
        return str(subnet), reserved.jumphost, reserved.docker_gw, ipv6_subnet, ipv6_gateway(ipv6_subnet)

    try:
        subnet = ipaddress.IPv4Network(default_subnet, strict=False)
    except ValueError as exc:
        raise ConfigError(f"Invalid default mgmt subnet {default_subnet!r}: {exc}") from exc
    try:
        reserved = ipv4_reservations(str(subnet))
    except MgmtAddressError as exc:
        raise ConfigError(str(exc)) from exc
    ipv6_subnet = _resolve_mgmt_ipv6_subnet(mgmt_cfg, str(subnet))
    return str(subnet), reserved.jumphost, reserved.docker_gw, ipv6_subnet, ipv6_gateway(ipv6_subnet)


def _resolve_mgmt_ipv6_subnet(mgmt_cfg: dict, ipv4_subnet: str) -> str:
    requested = (mgmt_cfg.get("ipv6-subnet") or "").strip()
    if requested:
        try:
            subnet = ipaddress.IPv6Network(requested, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid mgmt.ipv6-subnet {requested!r}: {exc}") from exc
        if subnet.network_address.ipv4_mapped is not None:
            derived = derive_ipv6_subnet_from_ipv4(ipv4_subnet)
            log.warning(
                "mgmt.ipv6-subnet %s is IPv4-mapped and not usable with Docker; "
                "using derived subnet %s instead",
                subnet,
                derived,
            )
            return derived
        return str(subnet)
    try:
        return derive_ipv6_subnet_from_ipv4(ipv4_subnet)
    except MgmtAddressError as exc:
        raise ConfigError(str(exc)) from exc


def _auto_assign_mgmt_ipv4(
    nodes: dict[str, "VDNode"],
    mgmt: "MgmtConfig",
) -> None:
    """Fill in ``mgmt_ipv4`` for every node that lacks one.

    IPs are drawn from ``mgmt.ipv4_subnet``, skipping the network address,
    the broadcast address, and the gateway. Already-static IPs (from nodes
    that have an explicit ``mgmt-ipv4``) are also excluded. Nodes are
    processed in sorted name order so the allocation is deterministic.

    Mutates ``nodes[*].mgmt_ipv4`` in place.
    """
    try:
        net = ipaddress.ip_network(mgmt.ipv4_subnet, strict=False)
    except ValueError as exc:
        log.warning("Cannot auto-assign mgmt IPs: invalid subnet %r (%s)",
                    mgmt.ipv4_subnet, exc)
        return

    reserved: set[ipaddress.IPv4Address] = set()
    try:
        r = ipv4_reservations(mgmt.ipv4_subnet)
        reserved.update(ipaddress.IPv4Address(v) for v in (r.docker_gw, r.anchor, r.dns, r.jumphost))
    except MgmtAddressError:
        pass

    used: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    used.update(reserved)
    for n in nodes.values():
        if n.mgmt_ipv4:
            try:
                ip = ipaddress.IPv4Address(n.mgmt_ipv4)
            except ValueError:
                pass
            else:
                if ip in reserved:
                    raise ConfigError(
                        f"node {n.name!r} mgmt-ipv4 {ip} is reserved "
                        "for mgmt infrastructure"
                    )
                used.add(ip)

    def _iter_pool():
        for ip in net.hosts():
            if ip not in used:
                yield ip

    pool = _iter_pool()
    for name in sorted(nodes):
        node = nodes[name]
        if node.mgmt_ipv4:
            continue
        try:
            ip = next(pool)
        except StopIteration:
            log.warning("mgmt pool %s exhausted; node %r has no auto IP",
                        mgmt.ipv4_subnet, name)
            return
        node.mgmt_ipv4 = str(ip)
        used.add(ip)
        log.debug("auto-assigned mgmt-ipv4 %s to node %s", ip, name)


def assign_sticky_mgmt_ipv4(
    nodes: dict[str, "VDNode"],
    mgmt: "MgmtConfig",
    reservations: dict[str, str] | None = None,
) -> dict[str, str]:
    """Assign stable management IPv4s and return the updated reservation map.

    Explicit ``mgmt-ipv4`` values in the topology always win. For nodes without
    an explicit IP, reuse the previous per-node reservation if valid; otherwise
    allocate the next free address. Existing reservations for removed nodes are
    preserved in the returned map so their addresses are not recycled while the
    lab state file exists.
    """
    try:
        net = ipaddress.ip_network(mgmt.ipv4_subnet, strict=False)
    except ValueError as exc:
        raise ConfigError(f"Invalid mgmt.ipv4-subnet {mgmt.ipv4_subnet!r}: {exc}") from exc

    sticky: dict[str, str] = {}
    reserved: set[ipaddress.IPv4Address] = set()
    try:
        r = ipv4_reservations(mgmt.ipv4_subnet)
        reserved.update(ipaddress.IPv4Address(v) for v in (r.docker_gw, r.anchor, r.dns, r.jumphost))
    except MgmtAddressError as exc:
        raise ConfigError(str(exc)) from exc

    ip_owner: dict[ipaddress.IPv4Address, str] = {}
    for owner, value in (reservations or {}).items():
        try:
            ip = ipaddress.IPv4Address(value)
        except ValueError:
            log.warning("Ignoring invalid sticky mgmt-ipv4 %r for node %s", value, owner)
            continue
        if ip not in net:
            log.warning("Ignoring sticky mgmt-ipv4 %s for node %s outside %s", ip, owner, net)
            continue
        if ip in reserved:
            log.warning("Ignoring sticky mgmt-ipv4 %s for node %s: reserved infrastructure IP", ip, owner)
            continue
        if ip in ip_owner:
            log.warning(
                "Ignoring duplicate sticky mgmt-ipv4 %s for node %s; already reserved by %s",
                ip, owner, ip_owner[ip],
            )
            continue
        sticky[owner] = str(ip)
        ip_owner[ip] = owner

    explicit_seen: dict[ipaddress.IPv4Address, str] = {}
    for name, node in nodes.items():
        if not node.mgmt_ipv4_explicit:
            continue
        try:
            ip = ipaddress.IPv4Address(node.mgmt_ipv4)
        except ValueError as exc:
            raise ConfigError(f"node {name!r} has invalid mgmt-ipv4 {node.mgmt_ipv4!r}: {exc}") from exc
        if ip not in net:
            raise ConfigError(f"node {name!r} mgmt-ipv4 {ip} is outside mgmt subnet {net}")
        if ip in reserved:
            raise ConfigError(
                f"node {name!r} mgmt-ipv4 {ip} is reserved for mgmt infrastructure"
            )
        if ip in explicit_seen:
            raise ConfigError(
                f"duplicate explicit mgmt-ipv4 {ip} on nodes {name!r} and {explicit_seen[ip]!r}"
            )
        explicit_seen[ip] = name
        previous_owner = ip_owner.get(ip)
        if previous_owner and previous_owner != name:
            sticky.pop(previous_owner, None)
        sticky[name] = str(ip)
        ip_owner[ip] = name

    for name in sorted(nodes):
        node = nodes[name]
        if node.mgmt_ipv4_explicit:
            continue
        previous = sticky.get(name)
        if previous:
            try:
                ip = ipaddress.IPv4Address(previous)
            except ValueError:
                ip = None
            if ip is not None and ip_owner.get(ip) == name:
                node.mgmt_ipv4 = str(ip)
                sticky[name] = str(ip)
                continue

        used: set[ipaddress.IPv4Address] = set(reserved) | set(ip_owner)
        for ip in net.hosts():
            if ip in used:
                continue
            node.mgmt_ipv4 = str(ip)
            sticky[name] = str(ip)
            ip_owner[ip] = name
            log.debug("reserved new sticky mgmt-ipv4 %s for node %s", ip, name)
            break
        else:
            raise ConfigError(f"mgmt pool {net} exhausted; cannot assign node {name!r}")

    return sticky


def _identity_digest(lab: str, node: VDNode, purpose: str) -> bytes:
    return hashlib.sha256(f"{lab}\0{node.persist_id or node.name}\0{purpose}".encode()).digest()


def _valid_ipv6(value: str, network: ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.IPv6Address(value) in network
    except ValueError:
        return False


def assign_sticky_mgmt_identities(
    nodes: dict[str, VDNode], mgmt: MgmtConfig, *, lab_name: str,
    ipv6_reservations: dict[str, str] | None = None,
    mac_reservations: dict[str, str] | None = None,
    duid_reservations: dict[str, str] | None = None,
    iaid_reservations: dict[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    """Assign stable IPv6, MAC and DHCPv6 identities for management."""
    try:
        network = ipaddress.IPv6Network(mgmt.ipv6_subnet, strict=False)
    except ValueError as exc:
        raise ConfigError(f"Invalid mgmt.ipv6-subnet {mgmt.ipv6_subnet!r}: {exc}") from exc
    v6, macs = dict(ipv6_reservations or {}), dict(mac_reservations or {})
    duids, iaids = dict(duid_reservations or {}), dict(iaid_reservations or {})
    used6 = {ipaddress.IPv6Address(value) for value in v6.values() if _valid_ipv6(value, network)}
    used6.add(ipaddress.IPv6Address(mgmt.ipv6_gw))
    used_macs = set(macs.values())
    for offset, name in enumerate(sorted(nodes), start=16):
        node = nodes[name]
        if node.mgmt_ipv6_explicit:
            address = ipaddress.IPv6Address(node.mgmt_ipv6)
            if address not in network or address == ipaddress.IPv6Address(mgmt.ipv6_gw):
                raise ConfigError(f"node {name!r} has invalid or reserved mgmt-ipv6 {address}")
            v6[name] = str(address)
        elif _valid_ipv6(v6.get(name, ""), network):
            node.mgmt_ipv6 = v6[name]
        else:
            address = ipaddress.IPv6Address(int(network.network_address) + offset)
            while address in used6:
                address = ipaddress.IPv6Address(int(address) + 1)
            node.mgmt_ipv6, v6[name] = str(address), str(address)
        used6.add(ipaddress.IPv6Address(v6[name]))
        if node.mgmt_mac:
            if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", node.mgmt_mac):
                raise ConfigError(f"node {name!r} has invalid mgmt-mac {node.mgmt_mac!r}")
            macs[name] = node.mgmt_mac
        elif name not in macs:
            digest = _identity_digest(lab_name, node, "mac")
            macs[name] = chr(58).join(["02"] + [f"{item:02x}" for item in digest[:5]])
        if macs[name] in used_macs and node.mgmt_mac:
            raise ConfigError(f"duplicate mgmt-mac {macs[name]} on node {name!r}")
        used_macs.add(macs[name])
        node.mgmt_mac = macs[name]
        if name not in duids:
            duids[name] = "00:04:" + chr(58).join(f"{item:02x}" for item in _identity_digest(lab_name, node, "duid")[:16])
        if name not in iaids:
            iaids[name] = _identity_digest(lab_name, node, "iaid")[:4].hex()
        node.mgmt_duid, node.mgmt_iaid = duids[name], iaids[name]
    return v6, macs, duids, iaids


def parse_topology(
    path: str | Path,
    *,
    hosts_file: str | Path | None = None,
    hosts_config: HostsConfig | None = None,
) -> DistributedTopology:
    """Parse a topology YAML file and merge it with the host inventory.

    Parameters
    ----------
    path:
        Path to the topology YAML.
    hosts_file:
        Optional override for the global hosts file path. Ignored if
        ``hosts_config`` is already provided.
    hosts_config:
        Optional pre-loaded inventory. When given, ``hosts_file`` is
        ignored. Used in tests and by programmatic callers that have
        already loaded the inventory (e.g. the GUI).
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Topology file not found: {path}")

    log.info("Parsing topology: %s", path)
    raw_text = path.read_text()
    raw = yaml.safe_load(raw_text)

    if not isinstance(raw, dict):
        raise ConfigError("Invalid topology file: root must be a mapping")

    # Sidecar GUI: ``# dnlab-gui-webui: {<json>}`` lasciato in coda al
    # YAML dal save della GUI. Contiene la wishlist di porte Web UI per
    # nodo: container_port + metadati (scheme/path/label/source).
    # È solo INPUT per il generator (che la traduce in ``ports:`` clab
    # native al deploy time); non torna mai indietro nel YAML.
    webui_wishlist = _parse_webui_sidecar(raw_text)
    node_ids = _parse_node_ids_sidecar(raw_text)
    node_overrides = _parse_node_overrides_sidecar(raw_text)
    node_features = _parse_node_features_sidecar(raw_text)
    resource_specs = _parse_resources_sidecar(raw_text)

    name = raw.get("name")
    if not name:
        raise ConfigError("Missing required field: 'name'")

    # ── Host inventory ────────────────────────────────────────────────
    # Precedence:
    #   1. Caller-provided HostsConfig
    #   2. Legacy in-topology 'infrastructure:' block (with warning)
    #   3. Global hosts file (default or env-overridden)
    if hosts_config is not None:
        hosts = hosts_config
    elif "infrastructure" in raw:
        log.warning(
            "Topology %s still carries an 'infrastructure:' block. "
            "This is deprecated: move host inventory to the global "
            "hosts file (default /etc/dnlab/hosts.yml).",
            path,
        )
        hosts = hosts_config_from_legacy_topology(raw)
    else:
        hosts = load_hosts_config(hosts_file)

    # ── Nodes ─────────────────────────────────────────────────────────
    topo = raw.get("topology", {})
    raw_nodes = topo.get("nodes", {})
    if not raw_nodes:
        raise ConfigError("No nodes defined in topology")

    nodes: dict[str, VDNode] = {}
    real_nets: dict[str, RealNet] = {}
    for nname, ncfg in raw_nodes.items():
        ncfg = ncfg or {}
        if ncfg.get("kind") == "_real_net":
            extra = ncfg.get("extra") or {}
            if not isinstance(extra, dict):
                extra = {}
            real_nets[nname] = RealNet(
                name=nname,
                ipv4=extra.get("ipv4") or extra.get("lan_ipv4") or "",
                nat=bool(extra.get("nat", not (extra.get("bgp") or extra.get("ospf")))),
                bgp=bool(extra.get("bgp", extra.get("ospf", False))),
                bgp_as=int(extra.get("bgp_as") or 0),
                bgp_router_ip=str(extra.get("bgp_router_ip") or ""),
                bgp_password=str(extra.get("bgp_password") or ""),
                import_routers=list(extra.get("import_routers") or []),
                description=extra.get("description", ""),
            )
            continue
        persist_id = _clean_persist_id(
            node_ids.get(nname)
            or ncfg.get("dnlab-persist-id")
            or ncfg.get("persist_id")
            or ""
        )
        if "mgmt-addressing" in ncfg:
            log.warning("Topology node %s: mgmt-addressing is ignored; DHCP is configured per management network", nname)
        nodes[nname] = VDNode(
            name=nname,
            kind=ncfg.get("kind", "linux"),
            image=ncfg.get("image", ""),
            persist_id=persist_id,
            mgmt_ipv4=ncfg.get("mgmt-ipv4", ""),
            mgmt_ipv4_explicit=bool(ncfg.get("mgmt-ipv4", "")),
            mgmt_ipv6=ncfg.get("mgmt-ipv6", ""),
            mgmt_ipv6_explicit=bool(ncfg.get("mgmt-ipv6", "")),
            mgmt_mac=str(ncfg.get("mgmt-mac", "") or "").lower(),
            env=ncfg.get("env", {}),
            extra={k: v for k, v in ncfg.items()
                   if k not in (
                       "kind", "image", "mgmt-ipv4", "mgmt-ipv6", "mgmt-addressing", "mgmt-mac", "env",
                       "dnlab-persist-id", "persist_id",
                   )},
        )

    # ── Links ─────────────────────────────────────────────────────────
    raw_links = topo.get("links", [])
    links: list[Link] = []
    real_net_links: list[RealNetLink] = []
    for lk in raw_links:
        endpoints = lk.get("endpoints", [])
        if len(endpoints) != 2:
            log.warning("Skipping invalid link (need 2 endpoints): %s", endpoints)
            continue
        a_node, a_iface = (endpoints[0].split(":", 1) + [""])[:2]
        b_node, b_iface = (endpoints[1].split(":", 1) + [""])[:2]
        if a_node in real_nets or b_node in real_nets:
            if a_node in real_nets and b_node in nodes:
                if b_iface == "eth0":
                    raise ConfigError("Interface eth0 is reserved for dNLab management")
                real_net_links.append(RealNetLink(
                    real_net=a_node, node=b_node, iface=b_iface,
                ))
                continue
            if b_node in real_nets and a_node in nodes:
                if a_iface == "eth0":
                    raise ConfigError("Interface eth0 is reserved for dNLab management")
                real_net_links.append(RealNetLink(
                    real_net=b_node, node=a_node, iface=a_iface,
                ))
                continue
            raise ConfigError(f"Invalid real_net link: {endpoints}")
        if a_node not in nodes or b_node not in nodes:
            raise ConfigError(
                f"Link references unknown node: {endpoints[0]} or {endpoints[1]}. "
                f"Known nodes: {list(nodes.keys())}"
            )
        if a_iface == "eth0" or b_iface == "eth0":
            raise ConfigError("Interface eth0 is reserved for dNLab management")
        links.append(Link(
            source=a_node, source_iface=a_iface,
            target=b_node, target_iface=b_iface,
        ))

    # ── Management ────────────────────────────────────────────────────
    # Network and bridge names are derived deterministically from the
    # lab name and bounded to fit the Linux 15-char interface limit;
    # any ``network``/``bridge`` in the topology YAML is ignored with a
    # deprecation warning. Subnet and gateway fall back to hosts.yml
    # defaults when not overridden per-topology.
    mgmt_cfg = raw.get("mgmt", {}) or {}
    for legacy_key in ("network", "bridge"):
        if legacy_key in mgmt_cfg:
            log.warning(
                "Topology '%s': 'mgmt.%s' is deprecated and ignored. "
                "Network and bridge names are auto-generated from the lab "
                "name (≤12 and ≤15 chars respectively).",
                name, legacy_key,
            )
    mgmt_subnet, mgmt_gw, docker_gw, mgmt_subnet_v6, mgmt_gw_v6 = _resolve_mgmt_config(name, mgmt_cfg, hosts)
    mgmt = MgmtConfig(
        network=mgmt_network_name(name),
        bridge=mgmt_bridge_name(name),
        ipv4_subnet=mgmt_subnet,
        ipv4_gw=mgmt_gw,
        docker_ipv4_gw=docker_gw,
        ipv6_subnet=mgmt_subnet_v6,
        ipv6_gw=mgmt_gw_v6,
        dhcp=bool(mgmt_cfg.get("dhcp", False)),
    )

    # ── Jumphost (per-lab image; network is shared infrastructure) ────
    # The jumphost network lives in ``hosts.yml`` as
    # ``infrastructure.jumphost_net``. Per-lab only the image is
    # customizable. Legacy ``host_ip`` in the topology is ignored with a
    # deprecation warning.
    jh_cfg = raw.get("jumphost") or {}
    if "host_ip" in jh_cfg:
        log.warning(
            "Topology '%s': 'jumphost.host_ip' is deprecated and ignored. "
            "The jumphost network is now shared infrastructure defined in "
            "hosts.yml (infrastructure.jumphost_net); the IP is auto-assigned.",
            name,
        )
    if jh_cfg:
        jumphost = JumphostConfig(
            image=jh_cfg.get("image", JumphostConfig().image),
        )
    elif hosts.jumphost is not None:
        jumphost = JumphostConfig(image=hosts.jumphost.image)
    else:
        jumphost = JumphostConfig()

    jumphost_net = JumphostNet(
        network=hosts.jumphost_net.network,
        bridge=hosts.jumphost_net.bridge,
        ipv4_subnet=hosts.jumphost_net.ipv4_subnet,
        ipv4_gw=hosts.jumphost_net.ipv4_gw,
        ssh_port_range=hosts.jumphost_net.ssh_port_range,
        ssh_bind_ip=hosts.jumphost_net.ssh_bind_ip,
    )

    webui_ports_cfg = WebUIPortsCfg(
        port_range=hosts.webui_ports.port_range,
        bind_ip=hosts.webui_ports.bind_ip,
    )

    realnet_infra = RealNetInfraCfg(
        network=hosts.realnet.network,
        bridge=hosts.realnet.bridge,
        ipv4_subnet=hosts.realnet.ipv4_subnet,
        ipv4_gw=hosts.realnet.ipv4_gw,
        image=hosts.realnet.image,
        wan_iface=hosts.realnet.wan_iface,
        rr_as=hosts.realnet.rr_as,
        rr_ip=hosts.realnet.rr_ip,
        host_net=hosts.realnet.host_net,
        router_as_pool=hosts.realnet.router_as_pool,
        router_ip_pool=hosts.realnet.router_ip_pool,
        realnet_network_pool=hosts.realnet.realnet_network_pool,
        rr_password=hosts.realnet.rr_password,
    )

    # ── Auto-assign mgmt-ipv4 for nodes without an explicit one ───────
    # Ephemeral: not written back to the YAML on disk. The pool is the
    # mgmt subnet minus the gateway and any already-static IP. Allocation
    # is stable (sorted node order) so repeated deploys are reproducible.
    _auto_assign_mgmt_ipv4(nodes, mgmt)

    log.info("Parsed topology '%s': %d nodes, %d links, %d real_net links, %d hosts",
             name, len(nodes), len(links), len(real_net_links), 1 + len(hosts.workers))

    return DistributedTopology(
        name=name,
        master=hosts.master,
        workers=hosts.workers,
        underlay_iface=hosts.underlay_iface,
        jumphost=jumphost,
        jumphost_net=jumphost_net,
        nodes=nodes,
        links=links,
        mgmt=mgmt,
        real_nets=real_nets,
        real_net_links=real_net_links,
        realnet_infra=realnet_infra,
        raw=raw,
        webui_wishlist=webui_wishlist,
        node_overrides=node_overrides,
        node_features=node_features,
        resource_specs=resource_specs,
        webui_ports=webui_ports_cfg,
        persistence=hosts.persistence,
    )


_WEBUI_SIDECAR_PREFIX = "# dnlab-gui-webui:"
_NODE_IDS_SIDECAR_PREFIX = "# dnlab-gui-node-ids:"
_NODE_OVERRIDES_SIDECAR_PREFIX = "# dnlab-gui-node-overrides:"
_NODE_FEATURES_SIDECAR_PREFIX = "# dnlab-gui-node-features:"
_RESOURCES_SIDECAR_PREFIX = "# dnlab-gui-resources:"


def _parse_webui_sidecar(raw_text: str) -> dict[str, list[dict]]:
    """Estrae la wishlist Web UI dal commento sidecar nel YAML.

    Formato atteso (singola riga, payload JSON):

    .. code-block:: text

        # dnlab-gui-webui: {"router1":[{"container_port":443,...}, ...], ...}

    Ritorna ``{}`` se il sidecar è assente o malformato (warn log).
    Tolleriamo input malformati per non bloccare il deploy: la
    wishlist è UX, il deploy può andare avanti senza.
    """
    for line in raw_text.splitlines():
        if not line.startswith(_WEBUI_SIDECAR_PREFIX):
            continue
        payload = line[len(_WEBUI_SIDECAR_PREFIX):].strip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            log.warning("Malformed webui sidecar: %s", exc)
            return {}
        if not isinstance(data, dict):
            log.warning("Webui sidecar is not a JSON object")
            return {}
        # Filtro entry malformate, salvaguardando il deploy.
        clean: dict[str, list[dict]] = {}
        for node, items in data.items():
            if not isinstance(items, list):
                continue
            valid = [
                e for e in items
                if isinstance(e, dict) and isinstance(e.get("container_port"), int)
            ]
            if valid:
                clean[node] = valid
        return clean
    return {}


def _parse_node_ids_sidecar(raw_text: str) -> dict[str, str]:
    """Extract GUI node stable IDs from the topology sidecar."""
    for line in raw_text.splitlines():
        if not line.startswith(_NODE_IDS_SIDECAR_PREFIX):
            continue
        payload = line[len(_NODE_IDS_SIDECAR_PREFIX):].strip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            log.warning("Malformed node-ids sidecar ignored")
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            str(node): clean
            for node, node_id in data.items()
            if node and (clean := _clean_persist_id(node_id))
        }
    return {}


def _clean_persist_id(value: object) -> str:
    persist_id = str(value or "").strip()
    if not persist_id:
        return ""
    if re.fullmatch(r"[A-Za-z0-9_.-]+", persist_id):
        return persist_id
    log.warning("Ignoring unsafe node persist id %r", persist_id)
    return ""


def _parse_node_overrides_sidecar(raw_text: str) -> dict[str, dict]:
    """Extract GUI node override state from the topology sidecar."""
    for line in raw_text.splitlines():
        if not line.startswith(_NODE_OVERRIDES_SIDECAR_PREFIX):
            continue
        payload = line[len(_NODE_OVERRIDES_SIDECAR_PREFIX):].strip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            log.warning("Malformed node-overrides sidecar: %s", exc)
            return {}
        if not isinstance(data, dict):
            log.warning("Node-overrides sidecar is not a JSON object")
            return {}
        return {
            str(node): state
            for node, state in data.items()
            if isinstance(state, dict)
        }
    return {}


def _parse_resources_sidecar(raw_text: str) -> dict[str, dict]:
    """Extract per-node resource schema from the topology sidecar."""
    return _parse_dict_sidecar(raw_text, _RESOURCES_SIDECAR_PREFIX, "resources")


def _parse_node_features_sidecar(raw_text: str) -> dict[str, dict]:
    """Extract data-driven node feature state/materializers."""
    return _parse_dict_sidecar(raw_text, _NODE_FEATURES_SIDECAR_PREFIX, "node-features")


def _parse_dict_sidecar(raw_text: str, prefix: str, label: str) -> dict[str, dict]:
    for line in raw_text.splitlines():
        if not line.startswith(prefix):
            continue
        payload = line[len(prefix):].strip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            log.warning("Malformed %s sidecar: %s", label, exc)
            return {}
        if not isinstance(data, dict):
            log.warning("%s sidecar is not a JSON object", label.capitalize())
            return {}
        return {
            str(node): spec
            for node, spec in data.items()
            if isinstance(spec, dict)
        }
    return {}
