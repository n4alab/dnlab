"""Per-VD runtime link reconciliation."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shlex
import time

from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.models.state import RuntimeLinkState
from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.utils import naming
from dnlab_multinode.services import warm_links

log = logging.getLogger(__name__)

_LINKCTL_READY_TIMEOUT = float(os.getenv("DNLAB_LINKCTL_READY_TIMEOUT", "900"))
_LINKCTL_RETRY_INTERVAL = 0.25
_LINK_LOCAL_PROTOCOLS = (
    ("0x88cc", "49140"),  # LLDP
    ("0x8809", "49141"),  # LACP / Slow Protocols
)


def build_runtime_links(topo: DistributedTopology, plan: SchedulePlan) -> list[RuntimeLinkState]:
    links: list[RuntimeLinkState] = []

    for idx, link in enumerate(plan.local_links):
        link_id = f"l{idx}"
        host = plan.host_for_vd(link.source) or ""
        links.append(RuntimeLinkState(
            id=link_id,
            link_type="same_host",
            endpoint_a={"node": link.source, "iface": link.source_iface},
            endpoint_b={"node": link.target, "iface": link.target_iface},
            host_a=host,
            host_b=host,
            host_endpoint_a=_endpoint_name(topo, link.source, link.source_iface, link_id),
            host_endpoint_b=_endpoint_name(topo, link.target, link.target_iface, link_id),
            container_a=naming.micro_vd_container_name(topo.name, link.source),
            container_b=naming.micro_vd_container_name(topo.name, link.target),
            warm_a=warm_links.is_enabled(topo.nodes[link.source]),
            warm_b=warm_links.is_enabled(topo.nodes[link.target]),
            state="down",
        ))

    for idx, link in enumerate(plan.cross_host_links):
        link_id = f"vx{idx}"
        links.append(RuntimeLinkState(
            id=link_id,
            link_type="cross_host",
            endpoint_a={"node": link.source_node, "iface": link.source_iface},
            endpoint_b={"node": link.target_node, "iface": link.target_iface},
            host_a=link.source_host,
            host_b=link.target_host,
            host_endpoint_a=_endpoint_name(
                topo, link.source_node, link.source_iface, link_id,
                fallback=link.source_host_iface,
            ),
            host_endpoint_b=_endpoint_name(
                topo, link.target_node, link.target_iface, link_id,
                fallback=link.target_host_iface,
            ),
            container_a=naming.micro_vd_container_name(topo.name, link.source_node),
            container_b=naming.micro_vd_container_name(topo.name, link.target_node),
            warm_a=warm_links.is_enabled(topo.nodes[link.source_node]),
            warm_b=warm_links.is_enabled(topo.nodes[link.target_node]),
            vxlan_id=link.vxlan_id,
            state="down",
        ))

    for idx, link in enumerate(topo.real_net_links):
        link_id = f"rn{idx}"
        bridge = naming.realnet_bridge_name(topo.name, link.real_net)
        links.append(RuntimeLinkState(
            id=link_id,
            link_type="real_net",
            endpoint_a={"node": link.node, "iface": link.iface},
            endpoint_b={"real_net": link.real_net},
            host_a=link.host,
            host_b=link.host,
            host_endpoint_a=_endpoint_name(
                topo, link.node, link.iface, link_id,
                fallback=link.bridge_iface or naming.realnet_bridge_iface(link.node, link.iface),
            ),
            host_endpoint_b=bridge,
            container_a=naming.micro_vd_container_name(topo.name, link.node),
            warm_a=warm_links.is_enabled(topo.nodes[link.node]),
            state="down",
        ))

    return links


def canonical_key(link: RuntimeLinkState) -> tuple:
    """Orientation-independent desired-link identity."""
    endpoints = tuple(sorted(
        tuple(sorted(endpoint.items()))
        for endpoint in (link.endpoint_a, link.endpoint_b)
    ))
    return endpoints


def merge_runtime_links(
    rebuilt: list[RuntimeLinkState],
    previous: list[RuntimeLinkState],
) -> list[RuntimeLinkState]:
    """Keep runtime identifiers stable while applying a new desired graph."""
    old = {canonical_key(link): link for link in previous}
    used_ids = {link.id for link in previous}
    used_vxlans = {link.vxlan_id for link in previous if link.vxlan_id}

    for link in rebuilt:
        prior = old.get(canonical_key(link))
        if prior and prior.link_type == link.link_type:
            link.id = prior.id
            link.vxlan_id = prior.vxlan_id
            if link.endpoint_a == prior.endpoint_a:
                link.host_endpoint_a = prior.host_endpoint_a
                link.host_endpoint_b = prior.host_endpoint_b
            else:
                link.host_endpoint_a = prior.host_endpoint_b
                link.host_endpoint_b = prior.host_endpoint_a
            link.state = prior.state
            link.last_error = prior.last_error
            link.validation_error = prior.validation_error
            continue

        prefix = {"same_host": "l", "cross_host": "vx", "real_net": "rn"}.get(
            link.link_type, "p",
        )
        index = 0
        while f"{prefix}{index}" in used_ids:
            index += 1
        link.id = f"{prefix}{index}"
        used_ids.add(link.id)
        if link.link_type == "cross_host":
            candidate = link.vxlan_id
            while candidate in used_vxlans:
                candidate += 1
            link.vxlan_id = candidate
            used_vxlans.add(candidate)
    return rebuilt


def pending_runtime_links(
    topo: DistributedTopology,
    scheduled_nodes: set[str],
) -> list[RuntimeLinkState]:
    """Represent desired links whose VD endpoint has no runtime yet."""
    pending: list[RuntimeLinkState] = []
    for link in topo.links:
        missing = {link.source, link.target} - scheduled_nodes
        if not missing:
            continue
        pending.append(RuntimeLinkState(
            id="",
            link_type="pending",
            endpoint_a={"node": link.source, "iface": link.source_iface},
            endpoint_b={"node": link.target, "iface": link.target_iface},
            state="partial",
            last_error=f"endpoint not started: {', '.join(sorted(missing))}",
        ))
    for link in topo.real_net_links:
        if link.node in scheduled_nodes:
            continue
        pending.append(RuntimeLinkState(
            id="",
            link_type="pending",
            endpoint_a={"node": link.node, "iface": link.iface},
            endpoint_b={"real_net": link.real_net},
            state="partial",
            last_error=f"endpoint not started: {link.node}",
        ))
    return pending


def create_link(
    link: RuntimeLinkState,
    clients: dict[str, SSHClient],
    underlay_ips: dict[str, str] | None = None,
    running_nodes: set[str] | None = None,
    *,
    defer_warm_carriers: bool = False,
) -> RuntimeLinkState:
    """Create one runtime link if both VD endpoints are running."""
    underlay_ips = underlay_ips or {}
    running_nodes = running_nodes or _nodes_in_link(link)
    missing = _stopped_endpoints(link, running_nodes)
    if missing:
        link.state = "partial"
        link.last_error = f"endpoint stopped: {', '.join(sorted(missing))}"
        return link

    try:
        if link.link_type == "same_host":
            _create_same_host(link, clients, defer_warm_carriers)
        elif link.link_type == "cross_host":
            _create_cross_host(link, clients, underlay_ips, defer_warm_carriers)
        elif link.link_type == "real_net":
            _create_realnet(link, clients, defer_warm_carriers)
        else:
            raise ValueError(f"unsupported link_type {link.link_type!r}")
        link.state = "up"
        link.last_error = ""
    except Exception as exc:
        link.state = "error"
        link.last_error = str(exc)
        raise
    return link


def delete_link(link: RuntimeLinkState, clients: dict[str, SSHClient]) -> RuntimeLinkState:
    try:
        if link.link_type == "same_host":
            _delete_same_host(link, clients)
        elif link.link_type == "cross_host":
            _delete_cross_host(link, clients)
        elif link.link_type == "real_net":
            _delete_realnet(link, clients)
        link.state = "down"
        link.last_error = ""
    except Exception as exc:
        link.state = "error"
        link.last_error = str(exc)
        raise
    return link


def delete_node_links(
    node: str,
    links: list[RuntimeLinkState],
    clients: dict[str, SSHClient],
) -> list[RuntimeLinkState]:
    touched = []
    for link in links:
        if node in _nodes_in_link(link):
            touched.append(delete_link(link, clients))
    return touched


def reconcile_all_links(
    links: list[RuntimeLinkState],
    clients: dict[str, SSHClient],
    underlay_ips: dict[str, str],
    running_nodes: set[str],
    *,
    defer_warm_carriers: bool = False,
) -> list[RuntimeLinkState]:
    reconciled = []
    for link in links:
        if link.validation_error or link.link_type == "pending":
            reconciled.append(link)
            continue
        reconciled.append(create_link(
            link, clients, underlay_ips, running_nodes,
            defer_warm_carriers=defer_warm_carriers,
        ))
    return reconciled


def reconcile_node_links(
    node: str,
    links: list[RuntimeLinkState],
    clients: dict[str, SSHClient],
    underlay_ips: dict[str, str],
    running_nodes: set[str],
) -> list[RuntimeLinkState]:
    reconciled = []
    for link in links:
        if node in _nodes_in_link(link):
            if link.validation_error:
                reconciled.append(link)
                continue
            reconciled.append(create_link(link, clients, underlay_ips, running_nodes))
    return reconciled


def _create_same_host(
    link: RuntimeLinkState,
    clients: dict[str, SSHClient],
    defer_warm_carriers: bool,
) -> None:
    client = clients[link.host_a]
    bridge = _runtime_bridge_name(link)
    client.run(f"ip link show {bridge} >/dev/null 2>&1 || ip link add {bridge} type bridge")
    client.run(f"ip link set {bridge} up")
    _ensure_bridge_forwarding(client, bridge)
    try:
        for iface in [link.host_endpoint_a, link.host_endpoint_b]:
            client.run(f"ip link set {iface} up")
            client.run(f"ip link set {iface} master {bridge}")
        _ensure_link_local_forwarding(
            client, link.host_endpoint_a, link.host_endpoint_b,
        )
        _set_link_carriers(
            link, clients, "up", check=True, defer=defer_warm_carriers,
        )
    except Exception:
        _set_link_carriers(link, clients, "down", check=False)
        _remove_link_local_forwarding(
            client, link.host_endpoint_a, link.host_endpoint_b,
        )
        _remove_bridge_forwarding(client, bridge)
        client.run(f"ip link delete {bridge} 2>/dev/null", check=False)
        raise


def _delete_same_host(link: RuntimeLinkState, clients: dict[str, SSHClient]) -> None:
    _set_link_carriers(link, clients, "down", check=False)
    client = clients.get(link.host_a)
    if client:
        bridge = _runtime_bridge_name(link)
        _remove_link_local_forwarding(
            client, link.host_endpoint_a, link.host_endpoint_b,
        )
        _remove_bridge_forwarding(client, bridge)
        client.run(f"ip link delete {bridge} 2>/dev/null", check=False)


def _create_cross_host(
    link: RuntimeLinkState,
    clients: dict[str, SSHClient],
    underlay_ips: dict[str, str],
    defer_warm_carriers: bool,
) -> None:
    src = clients[link.host_a]
    dst = clients[link.host_b]
    try:
        src.run(
            f"ip link show {_vxlan_altname(link.host_endpoint_a)} >/dev/null 2>&1 || "
            f"containerlab tools vxlan create --remote {underlay_ips[link.host_b]} "
            f"--id {link.vxlan_id} --link {link.host_endpoint_a}"
        )
        dst.run(
            f"ip link show {_vxlan_altname(link.host_endpoint_b)} >/dev/null 2>&1 || "
            f"containerlab tools vxlan create --remote {underlay_ips[link.host_a]} "
            f"--id {link.vxlan_id} --link {link.host_endpoint_b}"
        )
        _set_link_carriers(
            link, clients, "up", check=True, defer=defer_warm_carriers,
        )
    except Exception:
        _set_link_carriers(link, clients, "down", check=False)
        _delete_cross_host_network(link, clients)
        raise


def _delete_cross_host(link: RuntimeLinkState, clients: dict[str, SSHClient]) -> None:
    _set_link_carriers(link, clients, "down", check=False)
    _delete_cross_host_network(link, clients)


def _delete_cross_host_network(link: RuntimeLinkState, clients: dict[str, SSHClient]) -> None:
    for host, iface in [
        (link.host_a, link.host_endpoint_a),
        (link.host_b, link.host_endpoint_b),
    ]:
        client = clients.get(host)
        if client:
            client.run(f"ip link delete {_vxlan_altname(iface)} 2>/dev/null", check=False)


def _create_realnet(
    link: RuntimeLinkState,
    clients: dict[str, SSHClient],
    defer_warm_carriers: bool,
) -> None:
    client = clients[link.host_a]
    client.run(f"ip link set {link.host_endpoint_a} up")
    try:
        client.run(f"ip link set {link.host_endpoint_a} master {link.host_endpoint_b}")
        _set_link_carriers(
            link, clients, "up", check=True, defer=defer_warm_carriers,
        )
    except Exception:
        _set_link_carriers(link, clients, "down", check=False)
        client.run(f"ip link set {link.host_endpoint_a} nomaster 2>/dev/null", check=False)
        raise


def _delete_realnet(link: RuntimeLinkState, clients: dict[str, SSHClient]) -> None:
    _set_link_carriers(link, clients, "down", check=False)
    client = clients.get(link.host_a)
    if client:
        client.run(f"ip link set {link.host_endpoint_a} nomaster 2>/dev/null", check=False)


def _nodes_in_link(link: RuntimeLinkState) -> set[str]:
    nodes = set()
    for endpoint in [link.endpoint_a, link.endpoint_b]:
        node = endpoint.get("node")
        if node:
            nodes.add(node)
    return nodes


def _stopped_endpoints(link: RuntimeLinkState, running_nodes: set[str]) -> set[str]:
    return {node for node in _nodes_in_link(link) if node not in running_nodes}


def _runtime_bridge_name(link: RuntimeLinkState) -> str:
    digest = hashlib.sha1(link.id.encode()).hexdigest()[:8]
    return f"br-rt-{digest}"[:15]


def _vxlan_altname(host_endpoint: str) -> str:
    # The real kernel ifname remains containerlab's short unique clab-<hash>.
    # This requested name is stored as an altname, which ip-link can resolve for
    # idempotency checks and cleanup without violating the 15-char ifname limit.
    return f"vx-{host_endpoint}"


def _endpoint_name(
    topo: DistributedTopology,
    node: str,
    iface: str,
    link_id: str,
    *,
    fallback: str | None = None,
) -> str:
    if warm_links.is_enabled(topo.nodes[node]):
        return naming.runtime_port_endpoint(topo.name, node, iface)
    return fallback or naming.runtime_host_endpoint(topo.name, node, iface, link_id)


def _set_link_carriers(
    link: RuntimeLinkState,
    clients: dict[str, SSHClient],
    state: str,
    *,
    check: bool,
    defer: bool = False,
) -> None:
    targets = (
        (link.warm_a, link.host_a, link.container_a, link.endpoint_a.get("iface", "")),
        (link.warm_b, link.host_b, link.container_b, link.endpoint_b.get("iface", "")),
    )
    for enabled, host, container, iface in targets:
        if not enabled:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", container) or not re.fullmatch(r"eth[1-9][0-9]*", iface):
            raise ValueError(f"unsafe warm-link target {container}:{iface}")
        client = clients.get(host)
        if not client:
            if check:
                raise RuntimeError(f"host client unavailable for warm-link target {host}")
            continue
        command = f"docker exec {container} dnlab-linkctl {iface} {state}"
        if defer and state == "up":
            deferred = (
                "while [ ! -S /run/dnlab-link-control.sock ]; do "
                "sleep 0.25; done; "
                f"exec dnlab-linkctl {iface} up"
            )
            client.run(
                f"docker exec -d {container} sh -c {shlex.quote(deferred)}",
                check=check,
            )
            continue
        if not check or state != "up":
            client.run(command, check=check)
            continue
        _run_linkctl_when_ready(client, command)


def _run_linkctl_when_ready(client: SSHClient, command: str) -> None:
    """Wait out the short container-running/QEMU-controller readiness gap."""
    deadline = time.monotonic() + _LINKCTL_READY_TIMEOUT
    while True:
        try:
            client.run(command, check=True)
            return
        except Exception as exc:
            message = str(exc).lower()
            controller_not_ready = (
                "no such file or directory" in message
                or "connection refused" in message
            )
            if not controller_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(_LINKCTL_RETRY_INTERVAL)


def _ensure_bridge_forwarding(client: SSHClient, bridge: str) -> None:
    """Allow bridged IP traffic on runtime bridges when br_netfilter is on."""
    comment = f"dnlab runtime {bridge}"
    client.run(
        f"iptables -C FORWARD -i {bridge} -m comment --comment '{comment}' -j ACCEPT "
        f"2>/dev/null || iptables -I FORWARD 1 -i {bridge} "
        f"-m comment --comment '{comment}' -j ACCEPT; "
        f"iptables -C FORWARD -o {bridge} -m comment --comment '{comment}' -j ACCEPT "
        f"2>/dev/null || iptables -I FORWARD 1 -o {bridge} "
        f"-m comment --comment '{comment}' -j ACCEPT",
        check=False,
    )


def _ensure_link_local_forwarding(client: SSHClient, iface_a: str, iface_b: str) -> None:
    """Pass link-local L2 control protocols across same-host runtime links.

    Linux bridges intentionally consume reserved 01:80:c2 link-local groups by
    default. Runtime links should behave like a direct cable for LLDP and LACP,
    so mirror those ethertypes directly between the two host-side veths.
    """
    for iface in (iface_a, iface_b):
        client.run(f"tc qdisc add dev {iface} clsact 2>/dev/null", check=False)
    for src, dst in ((iface_a, iface_b), (iface_b, iface_a)):
        for protocol, pref in _LINK_LOCAL_PROTOCOLS:
            client.run(
                f"tc filter replace dev {src} ingress pref {pref} "
                f"protocol {protocol} flower "
                f"action mirred egress redirect dev {dst}"
            )


def _remove_link_local_forwarding(client: SSHClient, iface_a: str, iface_b: str) -> None:
    """Remove LLDP/LACP forwarding hooks installed for a runtime link."""
    for iface in (iface_a, iface_b):
        for protocol, pref in _LINK_LOCAL_PROTOCOLS:
            client.run(
                f"tc filter del dev {iface} ingress pref {pref} "
                f"protocol {protocol} 2>/dev/null",
                check=False,
            )
        client.run(f"tc qdisc del dev {iface} clsact 2>/dev/null", check=False)


def _remove_bridge_forwarding(client: SSHClient, bridge: str) -> None:
    comment = f"dnlab runtime {bridge}"
    client.run(
        f"while iptables -C FORWARD -i {bridge} -m comment --comment '{comment}' "
        f"-j ACCEPT 2>/dev/null; do "
        f"iptables -D FORWARD -i {bridge} -m comment --comment '{comment}' -j ACCEPT; "
        f"done; "
        f"while iptables -C FORWARD -o {bridge} -m comment --comment '{comment}' "
        f"-j ACCEPT 2>/dev/null; do "
        f"iptables -D FORWARD -o {bridge} -m comment --comment '{comment}' -j ACCEPT; "
        f"done",
        check=False,
    )
