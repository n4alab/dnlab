"""Dataplane VxLAN tunnel management."""

from __future__ import annotations

import hashlib
import json
import logging
import shlex

from dnlab_multinode.models.schedule import CrossHostLink
from dnlab_multinode.services.ssh import SSHClient

log = logging.getLogger(__name__)


def create_dataplane_tunnel(
    link: CrossHostLink,
    src_client: SSHClient,
    tgt_client: SSHClient,
    src_host_ip: str,
    tgt_host_ip: str,
) -> None:
    """Create VxLAN tunnel for a cross-host dataplane link.

    Uses `containerlab tools vxlan create` on both sides.
    """
    log.info("Creating VxLAN %d: %s (on %s ↔ %s)",
             link.vxlan_id, link, link.source_host, link.target_host)

    # Source side
    src_cmd = (
        f"containerlab tools vxlan create "
        f"--remote {tgt_host_ip} "
        f"--id {link.vxlan_id} "
        f"--link {link.source_host_iface}"
    )
    src_client.run(src_cmd)
    log.debug("[%s] VxLAN source side created: %s", link.source_host, src_cmd)

    # Target side
    tgt_cmd = (
        f"containerlab tools vxlan create "
        f"--remote {src_host_ip} "
        f"--id {link.vxlan_id} "
        f"--link {link.target_host_iface}"
    )
    tgt_client.run(tgt_cmd)
    log.debug("[%s] VxLAN target side created: %s", link.target_host, tgt_cmd)


def destroy_dataplane_tunnel(
    link: CrossHostLink,
    src_client: SSHClient,
    tgt_client: SSHClient,
) -> None:
    """Remove VxLAN tunnel interfaces on both sides.

    ``containerlab tools vxlan create --link <iface>`` creates a sibling
    interface addressed by ``vx-<iface>`` (an altname for long names).
    Resolve that full name and verify type/VNI before deleting one interface.
    """
    log.info("Removing VxLAN %d: %s", link.vxlan_id, link)

    for client, host_iface, host_name in [
        (src_client, link.source_host_iface, link.source_host),
        (tgt_client, link.target_host_iface, link.target_host),
    ]:
        _delete_vxlan_iface(client, host_iface, host_name, vxlan_id=link.vxlan_id)


def _resolve_vxlan(links: list[dict], name: str, vxlan_id: int | None) -> dict | None:
    matches = [link for link in links
               if link.get("ifname") == name or name in link.get("altnames", [])]
    if not matches:
        return None
    if len(matches) != 1:
        raise RuntimeError(f"ambiguous VxLAN identity: {name}")
    link = matches[0]
    info = link.get("linkinfo", {})
    if info.get("info_kind") != "vxlan":
        raise RuntimeError(f"refusing to delete non-VxLAN interface: {name}")
    if vxlan_id is not None and info.get("info_data", {}).get("id") != vxlan_id:
        raise RuntimeError(f"refusing to delete VxLAN with unexpected VNI: {name}")
    owners = {alt for alt in link.get("altnames", []) if alt.startswith("clab-o-")}
    expected_owner = "clab-o-" + hashlib.sha1(("host\0" + name).encode()).hexdigest()[:16]
    if owners and owners != {expected_owner}:
        raise RuntimeError(f"refusing to delete VxLAN with unexpected ownership: {name}")
    if type(link.get("ifindex")) is not int or not isinstance(link.get("ifname"), str):
        raise RuntimeError(f"missing kernel identity for VxLAN: {name}")
    return link


def _delete_vxlan_iface(
    client: SSHClient, host_iface: str, host_name: str, *, vxlan_id: int | None = None,
) -> None:
    """Delete only the full name/altname from persisted topology.

    Legacy state has no runtime ownership token: name, type and (when supplied)
    allocated VNI are its legacy identity contract. Validate Containerlab ownership
    altnames when present; older releases may not provide them. Never use a prefix or a
    truncated fallback. Inspection/deletion failures are reported to teardown.
    """
    name = f"vx-{host_iface}"

    def inspect():
        return _resolve_vxlan(json.loads(client.run("ip -j -d link show")), name, vxlan_id)

    before = inspect()
    if before is None:
        return
    current = inspect()
    if current is None:
        return
    if current != before:
        raise RuntimeError(f"VxLAN identity changed before deletion: {name}@{host_name}")
    rc, _, err = client.run_no_check(f"ip link delete dev {shlex.quote(name)}")
    remaining = inspect()
    if remaining is not None:
        raise RuntimeError(f"VxLAN deletion incomplete: {name}@{host_name} rc={rc}: {err.strip()}")
    log.debug("[%s] Deleted VxLAN %s (kernel name %s)", host_name, name, before["ifname"])


def verify_tunnels(
    links: list[CrossHostLink],
    ssh_clients: dict[str, SSHClient],
) -> list[dict]:
    """Verify that all VxLAN tunnel interfaces are UP.

    Returns: list of {link, status} dicts
    """
    results = []
    for link in links:
        status = "up"

        for host_name, iface in [
            (link.source_host, link.source_host_iface),
            (link.target_host, link.target_host_iface),
        ]:
            client = ssh_clients.get(host_name)
            if not client:
                status = "error"
                continue

            rc, out, _ = client.run_no_check(
                f"ip link show {iface} 2>/dev/null | head -1"
            )
            if rc != 0 or "UP" not in out.upper():
                status = "down"

        results.append({"link": str(link), "vxlan_id": link.vxlan_id, "status": status})

    return results
