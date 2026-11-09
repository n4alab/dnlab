"""Real network infrastructure for GUI pseudo-node ``_real_net``.

The GUI stores a cloud-like pseudo-node. At deploy time we translate it into:

* one Linux bridge per real_net on every participating host;
* a VXLAN port between each worker bridge and the master bridge;
* one unmanaged router container on the master, attached to the NAT Docker
  WAN network in NAT mode, or to the host-side BGP segment via ipvlan in
  BGP mode, plus the real_net bridge through a veth pair.
"""

from __future__ import annotations

import ipaddress
import copy
import hashlib
import logging
import shlex

from dnlab_multinode.models.state import RealNetState
from dnlab_multinode.models.topology import DistributedTopology, RealNet
from dnlab_multinode.services.images import image_for
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.utils import ids, naming

log = logging.getLogger(__name__)


def participating_hosts(topo: DistributedTopology, real_net: str) -> set[str]:
    return {l.host for l in topo.real_net_links if l.real_net == real_net and l.host}


def _ensure_bridge_forwarding(client: SSHClient, bridge: str) -> None:
    """Allow bridged IP traffic for a per-lab real_net bridge.

    Some hosts run with ``br_netfilter`` enabled and ``FORWARD`` policy DROP.
    ARP still passes in that mode, but IP traffic crossing the Linux bridge is
    evaluated by iptables and gets dropped unless the bridge is explicitly
    allowed. Keep this tied to the lab bridge lifecycle.
    """
    comment = f"dnlab real_net {bridge}"
    client.run(
        f"iptables -C FORWARD -i {bridge} -m comment --comment '{comment}' -j ACCEPT "
        f"2>/dev/null || iptables -I FORWARD 1 -i {bridge} "
        f"-m comment --comment '{comment}' -j ACCEPT; "
        f"iptables -C FORWARD -o {bridge} -m comment --comment '{comment}' -j ACCEPT "
        f"2>/dev/null || iptables -I FORWARD 1 -o {bridge} "
        f"-m comment --comment '{comment}' -j ACCEPT",
        check=False,
    )


def _remove_bridge_forwarding(client: SSHClient, bridge: str) -> None:
    comment = f"dnlab real_net {bridge}"
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
    # containerlab also adds FORWARD accepts for bridge nodes in generated
    # per-host topologies. They are tied to this per-lab bridge name and can
    # survive some destroy paths, so remove any remaining direct accepts too.
    client.run(
        f"while iptables -C FORWARD -i {bridge} -j ACCEPT 2>/dev/null; do "
        f"iptables -D FORWARD -i {bridge} -j ACCEPT; "
        f"done; "
        f"while iptables -C FORWARD -o {bridge} -j ACCEPT 2>/dev/null; do "
        f"iptables -D FORWARD -o {bridge} -j ACCEPT; "
        f"done",
        check=False,
    )
    client.run(
        f"while iptables -C FORWARD -i {bridge} -m comment --comment 'set by containerlab' "
        f"-j ACCEPT 2>/dev/null; do "
        f"iptables -D FORWARD -i {bridge} -m comment --comment 'set by containerlab' -j ACCEPT; "
        f"done; "
        f"while iptables -C FORWARD -o {bridge} -m comment --comment 'set by containerlab' "
        f"-j ACCEPT 2>/dev/null; do "
        f"iptables -D FORWARD -o {bridge} -m comment --comment 'set by containerlab' -j ACCEPT; "
        f"done",
        check=False,
    )


def ensure_realnet_wan_network(client: SSHClient, topo: DistributedTopology) -> None:
    from .realnet_wan import ensure_wan
    ensure_wan(client,topo.realnet_infra)


def ensure_realnet_bgp_network(client: SSHClient, topo: DistributedTopology) -> str:
    cfg = topo.realnet_infra
    if not cfg.host_net:
        raise ValueError("RealNet BGP requires infrastructure.realnet.host_net")
    network = _bgp_network_name(topo)
    host_net = ipaddress.ip_network(cfg.host_net, strict=False)
    parent = (cfg.wan_iface or "").strip() or _detect_host_iface(client, _host_net_probe_ip(host_net, cfg.rr_ip))
    if not parent:
        raise ValueError("RealNet BGP requires infrastructure.realnet.wan_iface or a routable host_net")
    rc, out, _ = client.run_no_check(
        f"docker network inspect -f '{{{{.Driver}}}} {{{{range .IPAM.Config}}}}{{{{.Subnet}}}}{{{{end}}}}' {network}"
    )
    if rc == 0:
        parts = (out or "").split()
        if len(parts) >= 2 and parts[0] == "macvlan" and parts[1] == str(host_net):
            return network
        raise ValueError(
            f"realnet BGP network {network} already exists with unexpected config: {out}. "
            "Remove/reconcile the RealNet BGP containers and network before redeploying."
        )
    client.run(
        f"docker network create {network} "
        f"--driver macvlan "
        f"-o parent={parent} -o macvlan_mode=bridge "
        f"--subnet {host_net}"
    )
    return network


def setup_bridges(
    topo: DistributedTopology,
    clients: dict[str, SSHClient],
    underlay_ips: dict[str, str],
    *, vni_directory=None, existing_states=(), checkpoint=None,
) -> list[RealNetState]:
    from .realnet_vni import reserve_realnets
    states: list[RealNetState] = []
    previous={state.name:state for state in existing_states}
    for rn_name, rn in topo.real_nets.items():
        hosts=participating_hosts(topo,rn_name)
        if not hosts:continue
        hosts.add('master')
        workers=sorted(host for host in hosts if host!='master')
        vx_iface=naming.realnet_vxlan_iface(topo.name,rn_name)
        state=RealNetState(
            name=rn_name,bridge=naming.realnet_bridge_name(topo.name,rn_name),vxlan_id=0,
            hosts=sorted(hosts),router_container=naming.realnet_router_container_name(topo.name,rn_name),
            lan_ipv4=rn.ipv4,nat=rn.nat and not rn.bgp,bgp=rn.bgp,bgp_as=rn.bgp_as,
            bgp_router_ip=rn.bgp_router_ip,
            vxlan_ifaces={**{host:[vx_iface] for host in workers},
                          'master':[naming.realnet_vxlan_peer_name(topo.name,rn_name,host) for host in workers]},
            router_veth=naming.realnet_router_veth_name(topo.name,rn_name))
        if rn_name in previous:state.resource_identities=copy.deepcopy(previous[rn_name].resource_identities)
        states.append(state)
    reserve_realnets(topo,clients,underlay_ips,states,directory=vni_directory)
    # Persist VNI intent and the complete named inventory before host mutations.
    if checkpoint:checkpoint(states)
    for state in states:
        bridge=state.bridge
        proofs=state.resource_identities.get('realnet_cleanup_v1',{})
        for host in state.hosts:
            client=clients[host]
            if bridge in proofs.get(host,{}).get('links',{}):continue
            client.run(f'ip link add {bridge} type bridge && ip link set {bridge} up')
            _ensure_bridge_forwarding(client,bridge)
        workers=sorted(host for host in state.hosts if host!='master')
        for worker,peer_iface in zip(workers,state.vxlan_ifaces['master']):
            for host,iface,remote in ((worker,state.vxlan_ifaces[worker][0],'master'),('master',peer_iface,worker)):
                if iface in proofs.get(host,{}).get('links',{}):continue
                clients[host].run(
                    f'ip link add {iface} type vxlan id {state.vxlan_ids[worker]} '
                    f'remote {underlay_ips[remote]} local {underlay_ips[host]} '
                    f'dstport 14789 dev {topo.underlay_iface} && '
                    f'ip link set {iface} master {bridge} && ip link set {iface} up')
        if checkpoint:checkpoint(states)
    return states


def deploy_route_reflector(topo: DistributedTopology, master: SSHClient) -> None:
    _ensure_route_reflector(topo,master)


def qualify_route_reflector(topo: DistributedTopology, master: SSHClient) -> dict:
    """Explicitly qualify an existing compatible legacy reflector, without restart."""
    return _ensure_route_reflector(topo,master,qualify_legacy=True)


def _ensure_route_reflector(topo: DistributedTopology, master: SSHClient, *, qualify_legacy=False) -> dict:
    from dnlab_multinode.services.realnet_reflector import ReflectorGuard,ReflectorError
    cfg = topo.realnet_infra
    if not cfg.rr_ip or not cfg.host_net:
        raise ValueError("RealNet BGP requires infrastructure.realnet.rr_ip and host_net")
    host_net = ipaddress.ip_network(cfg.host_net, strict=False)
    if ipaddress.ip_address(cfg.rr_ip) not in host_net:
        raise ValueError(f"RealNet RR IP {cfg.rr_ip} is outside host_net {host_net}")
    image = image_for("realnet-rr")
    rc, _, _ = master.run_no_check(f"docker image inspect {image} >/dev/null 2>&1")
    if rc != 0:
        raise RuntimeError(
            f"RealNet RR image '{image}' not found on master. "
            "Run: docker compose --profile release-images pull"
        )
    guard=ReflectorGuard(master)
    container=guard.inspect()
    if qualify_legacy and container is None:raise ReflectorError('no existing reflector to qualify')
    selected=guard.image(image)
    parent=(cfg.wan_iface or '').strip() or _detect_host_iface(master,_host_net_probe_ip(host_net,cfg.rr_ip))
    if not parent:raise ValueError('RealNet BGP requires a qualified WAN parent')
    network_name=_bgp_network_name(topo)
    if container is None:ensure_realnet_bgp_network(master,topo)
    network=guard.network(network_name,str(host_net),parent)
    configuration=_rr_frr_config(cfg)
    expected=guard.expected(selected,network,cfg.rr_ip,configuration)
    if container is not None:return guard.verify(container,selected,expected,qualify=qualify_legacy)
    identity=guard.create(selected,expected)
    guard.configure_new(identity,configuration)
    return guard.wait_ready(selected,expected)


def deploy_router(
    topo: DistributedTopology,
    rn: RealNet,
    state: RealNetState,
    master: SSHClient,
) -> RealNetState:
    if not rn.ipv4:
        raise ValueError(f"real_net {rn.name}: missing LAN IPv4 address")
    _ = ipaddress.ip_interface(rn.ipv4)
    image = image_for("realnet-router")
    container = state.router_container
    bridge = state.bridge
    veth_host = state.router_veth or naming.realnet_router_veth_name(topo.name, rn.name)
    state.router_veth = veth_host
    if rn.bgp:
        if not rn.bgp_as or not rn.bgp_router_ip:
            raise ValueError(f"real_net {rn.name}: missing BGP AS/router IP")
        host_net = ipaddress.ip_network(topo.realnet_infra.host_net, strict=False)
        if ipaddress.ip_address(rn.bgp_router_ip) not in host_net:
            raise ValueError(f"real_net {rn.name}: BGP router IP {rn.bgp_router_ip} is outside host_net {host_net}")
    from .realnet_bootstrap import bootstrap_router
    result=bootstrap_router(topo,rn,state,master,image,_bgp_network_name(topo) if rn.bgp else topo.realnet_infra.network)
    state.router_wan_ip=result['wan_ip']
    if rn.bgp:
        _write_frr_config(master,result['container_id'],_router_frr_config(topo,rn))
    return state


def _bgp_network_name(topo: DistributedTopology) -> str:
    return f"{topo.realnet_infra.network}-bgp"


def _detect_host_iface(client: SSHClient, target_ip: str) -> str:
    rc, out, _ = client.run_no_check(
        "sh -lc "
        + shlex.quote(
            f"ip -o route get {shlex.quote(str(target_ip))} 2>/dev/null "
            "| awk '{for (i=1; i<=NF; i++) if ($i==\"dev\") {print $(i+1); exit}}'"
        )
    )
    return (out or "").strip() if rc == 0 else ""


def _host_net_probe_ip(host_net: ipaddress.IPv4Network | ipaddress.IPv6Network, rr_ip: str) -> str:
    rr = ipaddress.ip_address(rr_ip) if rr_ip else None
    for ip in host_net.hosts():
        if rr is None or ip != rr:
            return str(ip)
    return str(host_net.network_address + 1)


def _rr_frr_config(cfg) -> str:
    return "\n".join([
        "frr defaults traditional",
        "hostname realnet-rr",
        "service integrated-vtysh-config",
        "!",
        "route-map PERMIT_REALNET_ROUTES permit 10",
        " match community HAS-COMMUNITY",
        "exit",
        "!",
        "route-map PERMIT_REALNET_ROUTES permit 20",
        f" set community {cfg.rr_as}:1",
        "exit",
        "!",
        f"router bgp {cfg.rr_as}",
        f" bgp router-id {cfg.rr_ip}",
        " neighbor REALNET_LAB peer-group",
        f" neighbor REALNET_LAB remote-as {cfg.rr_as}",
        *([f" neighbor REALNET_LAB password {cfg.rr_password}"] if getattr(cfg, "rr_password", "") else []),
        f" bgp listen range {cfg.host_net} peer-group REALNET_LAB",
        " !",
        " address-family ipv4 unicast",
        "  neighbor REALNET_LAB route-reflector-client",
        "  neighbor REALNET_LAB route-map PERMIT_REALNET_ROUTES in",
        " exit-address-family",
        "exit",
        "!",
        "bgp community-list expanded HAS-COMMUNITY seq 5 permit .*",
        "!",
        "end",
        "",
    ])


def _router_frr_config(topo: DistributedTopology, rn: RealNet) -> str:
    cfg = topo.realnet_infra
    lan_net = ipaddress.ip_interface(rn.ipv4).network
    lines = [
        "frr defaults traditional",
        f"hostname {rn.name}",
        "service integrated-vtysh-config",
        "!",
        "route-map PERMIT_IN_EBGP permit 10",
        f" set community {rn.bgp_as}:1",
        "exit",
        "!",
        "route-map PERMIT_IN_IBGP permit 10",
        " match community REALNET_PREFIX",
        "exit",
    ]
    for seq, imported in enumerate(rn.import_routers or [], start=20):
        name = _lab_community_name(imported.get("lab_id") or imported.get("id") or "")
        if name:
            lines.extend([
                "!",
                f"route-map PERMIT_IN_IBGP permit {seq}",
                f" match community {name}",
                "exit",
            ])
    lines.extend([
        "!",
        "route-map PERMIT_OUT_EBGP permit 10",
        " set community none",
        "exit",
        "!",
        f"router bgp {cfg.rr_as}",
        f" bgp router-id {rn.bgp_router_ip}",
        " neighbor VD peer-group",
        f" neighbor VD remote-as {rn.bgp_as}",
        f" neighbor {cfg.rr_ip} remote-as {cfg.rr_as}",
        *([f" neighbor VD password {rn.bgp_password}"] if rn.bgp_password else []),
        *([f" neighbor {cfg.rr_ip} password {cfg.rr_password}"] if getattr(cfg, "rr_password", "") else []),
        f" bgp listen range {lan_net} peer-group VD",
        " !",
        " address-family ipv4 unicast",
        "  neighbor VD route-map PERMIT_IN_EBGP in",
        "  neighbor VD route-map PERMIT_OUT_EBGP out",
        f"  neighbor {cfg.rr_ip} next-hop-self",
        f"  neighbor {cfg.rr_ip} route-map PERMIT_IN_IBGP in",
        " exit-address-family",
        "exit",
        "!",
        f"bgp community-list standard REALNET_PREFIX seq 5 permit {cfg.rr_as}:1",
    ])
    for imported in rn.import_routers or []:
        name = _lab_community_name(imported.get("lab_id") or imported.get("id") or "")
        asn = imported.get("bgp_as")
        if name and asn:
            lines.append(f"bgp community-list standard {name} seq 5 permit {int(asn)}:1")
    lines.extend(["!", "end", ""])
    return "\n".join(lines)


def _lab_community_name(lab_id: str) -> str:
    if not lab_id:
        return ""
    return "LAB_" + hashlib.sha1(str(lab_id).encode("utf-8")).hexdigest() + "_PREFIX"


def _write_frr_config(master: SSHClient, container: str, config: str) -> None:
    script = (
        "cat > /etc/frr/frr.conf <<'EOF'\n"
        + config
        + "EOF\n"
        "if [ -f /etc/frr/daemons ]; then sed -i 's/^bgpd=.*/bgpd=yes/' /etc/frr/daemons; fi\n"
        "chown frr:frr /etc/frr/frr.conf 2>/dev/null || true\n"
        "if [ -x /usr/lib/frr/frrinit.sh ]; then /usr/lib/frr/frrinit.sh restart || /usr/lib/frr/frrinit.sh start || true; fi\n"
        "if command -v vtysh >/dev/null 2>&1; then vtysh -b || true; fi\n"
    )
    master.run(
        f"docker exec {shlex.quote(container)} sh -lc {shlex.quote(script)}",
        check=False,
    )


def preflight_realnets(lab_name: str, clients: dict[str, SSHClient], states: list[RealNetState]) -> None:
    from .realnet_cleanup import preflight_realnets as preflight
    preflight(lab_name,clients,states)


def destroy_realnets(lab_name: str, clients: dict[str, SSHClient], states: list[RealNetState], *, checkpoint=None) -> None:
    from .realnet_cleanup import destroy_realnets as cleanup
    cleanup(lab_name,clients,states,checkpoint=checkpoint)
