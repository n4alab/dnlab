"""Warm-link capability profiles and per-node capacity calculation."""

from __future__ import annotations

import json
import re
import shlex

from dnlab_multinode.models.topology import DistributedTopology, VDNode
from dnlab_multinode.services import node_plugins


IMAGE_STATUS_ENV = "DNLAB_WARM_LINKS_IMAGE_STATUS"
BASE_DIGEST_ENV = "DNLAB_WARM_LINKS_BASE_DIGEST"


PROFILES: dict[str, dict[str, int]] = {
    "dnlab_frr": {"default_ports": 8, "max_ports": 8, "vm_index": 0},
    "openwrt": {"default_ports": 8, "max_ports": 64, "vm_index": 0},
    "dnlab_opnsense": {"default_ports": 8, "max_ports": 64, "vm_index": 0},
    "nvidia_cumulusvx": {"default_ports": 64, "max_ports": 64, "vm_index": 0},
    "mikrotik_ros": {"default_ports": 16, "max_ports": 31, "vm_index": 0},
    "cisco_vios": {"default_ports": 15, "max_ports": 15, "vm_index": 0},
    "juniper_vjunosrouter": {"default_ports": 16, "max_ports": 97, "vm_index": 0},
    "juniper_vjunosswitch": {"default_ports": 16, "max_ports": 57, "vm_index": 0},
    "juniper_vjunosevolved": {"default_ports": 16, "max_ports": 17, "vm_index": 0},
    "cisco_n9kv": {"default_ports": 16, "max_ports": 129, "vm_index": 0},
    "cisco_nxos": {"default_ports": 16, "max_ports": 32, "vm_index": 0},
    "cisco_cat9kv": {"default_ports": 9, "max_ports": 9, "vm_index": 0},
    "cisco_c9800cl": {"default_ports": 3, "max_ports": 3, "vm_index": 0},
    "cisco_xrv9k": {"default_ports": 16, "max_ports": 128, "vm_index": 0},
}

CLUSTER4_CANDIDATE_IMAGES = {
    "vrnetlab/juniper_vjunos-router_v2:25.2R1.9-dnlab",
    "vrnetlab/juniper_vjunos-router_v2:25.4R1.12-dnlab",
    "vrnetlab/juniper_vjunos-switch_v2:25.4R1.12-dnlab",
    "vrnetlab/juniper_vjunosevolved_v2:25.4R1.13-EVO-dnlab",
}

_IMAGE_PROFILE_PATTERNS = (
    ("dnlab_frr", "dnlab_frr"),
    ("dnlab_opnsense", "dnlab_opnsense"),
    ("nvidia_cumulusvx", "nvidia_cumulusvx"),
    ("mikrotik_ros", "mikrotik"),
    ("juniper_vjunosrouter", "vjunos-router"),
    ("juniper_vjunosrouter", "vjunosrouter"),
    ("juniper_vjunosswitch", "vjunos-switch"),
    ("juniper_vjunosswitch", "vjunosswitch"),
    ("juniper_vjunosevolved", "vjunosevolved"),
    ("cisco_c9800cl", "c9800"),
    ("cisco_cat9kv", "cat9kv"),
    ("cisco_n9kv", "n9kv"),
    ("cisco_nxos", "nxos"),
    ("cisco_xrv9k", "xrv9k"),
    ("cisco_vios", "vios"),
    ("openwrt", "openwrt"),
)


def profile_key(node: VDNode) -> str | None:
    image = node.image.lower()
    for key, fragment in _IMAGE_PROFILE_PATTERNS:
        if fragment in image:
            return key
    return node.kind if node.kind in PROFILES else None


def profile_for_node(node: VDNode) -> dict[str, int] | None:
    key = profile_key(node)
    return PROFILES.get(key) if key else None


def is_enabled(node: VDNode) -> bool:
    if not profile_for_node(node):
        return False
    image_status = str(node.env.get(IMAGE_STATUS_ENV, "")).lower()
    # Development images in qualification clusters 0..7 intentionally carry
    # ``experimental`` until certification is complete.  The capability label
    # and a known runtime profile are sufficient to enable them for testing;
    # missing/unlabelled/unsupported images remain blocked.
    return image_status in {"validated", "experimental"}


def status_for_node(node: VDNode) -> str:
    if not profile_for_node(node):
        return "unsupported"
    image_status = str(node.env.get(IMAGE_STATUS_ENV, "")).lower()
    if image_status == "validated":
        return "validated"
    if image_status in {"missing", "unsupported"}:
        return image_status
    return "experimental-enabled" if is_enabled(node) else "experimental"


def apply_image_labels(node: VDNode, labels: dict[str, str] | None) -> str:
    """Record verified image capability metadata on a topology node.

    Runtime code deliberately does not trust a repository tag.  The assigned
    host must inspect the exact local image and feed its OCI labels here before
    topology generation or node hot-add.
    """
    labels = labels or {}
    capabilities = {
        item.strip()
        for item in labels.get("org.dnlab.capabilities", "").split(",")
        if item.strip()
    }
    status = labels.get("org.dnlab.warm-links.status", "experimental").lower()
    if "warm-links-v1" not in capabilities or status not in {
        "validated", "experimental",
    }:
        status = "unsupported"
    node.env[IMAGE_STATUS_ENV] = status
    digest = labels.get("org.opencontainers.image.base.digest", "")
    if digest:
        node.env[BASE_DIGEST_ENV] = digest.rsplit("@", 1)[-1]
    else:
        node.env.pop(BASE_DIGEST_ENV, None)
    return status


def inspect_image_on_host(node: VDNode, client) -> str:
    """Inspect the exact image selected on one host and update ``node``."""
    rc, out, _ = client.run_no_check(
        "docker image inspect "
        f"{shlex.quote(node.image)} --format '{{{{json .Config.Labels}}}}'",
        timeout=30,
    )
    if rc != 0:
        node.env[IMAGE_STATUS_ENV] = "missing"
        node.env.pop(BASE_DIGEST_ENV, None)
        return "missing"
    try:
        labels = json.loads((out or "").strip() or "{}")
    except (TypeError, json.JSONDecodeError):
        labels = {}
    return apply_image_labels(node, labels)


def _iface_index(iface: str) -> int:
    match = re.fullmatch(r"eth([1-9][0-9]*)", iface)
    return int(match.group(1)) if match else 0


def highest_used_port(topo: DistributedTopology, node_name: str) -> int:
    indexes: list[int] = []
    for link in topo.links:
        if link.source == node_name:
            indexes.append(_iface_index(link.source_iface))
        if link.target == node_name:
            indexes.append(_iface_index(link.target_iface))
    for link in topo.real_net_links:
        if link.node == node_name:
            indexes.append(_iface_index(link.iface))
    return max(indexes, default=0)


def capacity_for_node(topo: DistributedTopology, node_name: str) -> int:
    node = topo.nodes[node_name]
    profile = profile_for_node(node)
    if not profile or not is_enabled(node):
        return 0
    try:
        requested = int(node.env.get("DNLAB_WARM_PORTS", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{node_name}: DNLAB_WARM_PORTS must be an integer") from exc
    highest = highest_used_port(topo, node_name)
    override = (topo.node_overrides or {}).get(node_name) or {}
    plugin = node_plugins.for_state(override)
    plugin_capacity = plugin.warm_capacity(override) if plugin else None
    if plugin_capacity is not None:
        if requested not in {0, plugin_capacity}:
            raise ValueError(
                f"{node_name}: DNLAB_WARM_PORTS cannot override plugin capacity "
                f"{plugin_capacity}"
            )
        if highest > plugin_capacity:
            raise ValueError(
                f"{node_name}: interface eth{highest} exceeds plugin capacity "
                f"{plugin_capacity}"
            )
        capacity = plugin_capacity
    else:
        capacity = max(profile["default_ports"], highest, requested)
    if capacity > profile["max_ports"]:
        raise ValueError(
            f"{node_name}: warm-port capacity {capacity} exceeds "
            f"{profile['max_ports']} for {profile_key(node)}"
        )
    return capacity
