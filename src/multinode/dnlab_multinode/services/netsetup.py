"""Management network infrastructure setup/teardown (VRF, bridge, VxLAN)."""

from __future__ import annotations

import logging

from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.utils import naming

log = logging.getLogger(__name__)


def _install_mgmt_bridge_firewall_rules(
    client: SSHClient,
    bridge: str,
    lab_name: str,
) -> None:
    """Allow bridged mgmt traffic through Docker's FORWARD policy.

    Docker enables bridge netfilter on many hosts and sends bridged IPv4/IPv6
    traffic through iptables. Containerlab adds equivalent rules for bridges it
    owns; DNLab-created mgmt bridges need the same treatment on every host.
    """
    comment = f"dnlab mgmt {lab_name}"
    for direction in ("i", "o"):
        cmd = (
            f"iptables -C DOCKER-USER -{direction} {bridge} "
            f"-m comment --comment '{comment}' -j ACCEPT 2>/dev/null || "
            f"iptables -I DOCKER-USER 1 -{direction} {bridge} "
            f"-m comment --comment '{comment}' -j ACCEPT"
        )
        client.run(cmd, check=False)


def _remove_mgmt_bridge_firewall_rules(
    client: SSHClient,
    bridge: str,
    lab_name: str,
) -> None:
    comment = f"dnlab mgmt {lab_name}"
    for direction in ("i", "o"):
        cmd = (
            f"while iptables -C DOCKER-USER -{direction} {bridge} "
            f"-m comment --comment '{comment}' -j ACCEPT 2>/dev/null; do "
            f"iptables -D DOCKER-USER -{direction} {bridge} "
            f"-m comment --comment '{comment}' -j ACCEPT; "
            f"done"
        )
        client.run(cmd, check=False)


def setup_mgmt_infra(
    topo: DistributedTopology,
    plan: SchedulePlan,
    client: SSHClient,
    host_name: str,
    all_host_ips: dict[str, str],
) -> None:
    """Set up VRF + bridge + VxLAN mgmt on a single host.

    Args:
        topo: topology config
        plan: scheduling plan
        client: connected SSH client for this host
        host_name: name of this host
        all_host_ips: {host_name: ip} for all hosts
    """
    lab = topo.name
    vrf = naming.vrf_name(lab)
    bridge = topo.mgmt.bridge
    vxlan_iface = naming.mgmt_vxlan_iface(lab)
    table_id = plan.vrf_table_id
    vxlan_id = plan.mgmt_vxlan_id
    gw = topo.mgmt.docker_ipv4_gw or topo.mgmt.ipv4_gw
    prefix = topo.mgmt.ipv4_subnet.split("/")[1]
    underlay = topo.underlay_iface
    my_ip = all_host_ips[host_name]

    log.info("[%s] Setting up mgmt infra: VRF=%s, bridge=%s, VxLAN=%s (id=%d)",
             host_name, vrf, bridge, vxlan_iface, vxlan_id)

    commands = [
        # VRF
        f"ip link add {vrf} type vrf table {table_id}",
        f"ip link set {vrf} up",

        # Bridge
        f"ip link add {bridge} type bridge",
        f"ip link set {bridge} up",
        f"ip link set {bridge} master {vrf}",
        f"ip addr add {gw}/{prefix} dev {bridge}",

        # VxLAN mgmt
        f"ip link add {vxlan_iface} type vxlan id {vxlan_id} dstport 4789 dev {underlay} nolearning",
        f"ip link set {vxlan_iface} master {bridge}",
        f"ip link set {vxlan_iface} up",
    ]

    for cmd in commands:
        client.run(cmd, check=False)  # Ignore errors for idempotency

    _install_mgmt_bridge_firewall_rules(client, bridge, lab)

    # FDB entries → ingress replication to all other hosts
    for other_name, other_ip in all_host_ips.items():
        if other_name == host_name:
            continue
        fdb_cmd = f"bridge fdb append 00:00:00:00:00:00 dev {vxlan_iface} dst {other_ip}"
        client.run(fdb_cmd, check=False)
        log.debug("[%s] FDB → %s (%s)", host_name, other_name, other_ip)

    log.info("[%s] Mgmt infra setup complete", host_name)


def teardown_mgmt_infra(
    lab_name: str,
    bridge: str,
    client: SSHClient,
    host_name: str,
) -> None:
    """Remove VRF + bridge + VxLAN mgmt from a host."""
    vrf = naming.vrf_name(lab_name)
    vxlan_iface = naming.mgmt_vxlan_iface(lab_name)

    log.info("[%s] Tearing down mgmt infra", host_name)


    _remove_mgmt_bridge_firewall_rules(client, bridge, lab_name)

    for iface in [vxlan_iface, bridge, vrf]:
        client.run(f"ip link delete {iface} 2>/dev/null", check=False)

    log.info("[%s] Mgmt infra teardown complete", host_name)
