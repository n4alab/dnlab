"""Generate per-node containerlab topology YAML files."""

from __future__ import annotations

import logging
import re

import yaml

from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.services.images import image_for
from dnlab_multinode.services.mgmt_ips import ipv4_reservations
from dnlab_multinode.services.paths import PATHS, persist_dir_for, persist_dir_for_node
from dnlab_multinode.utils import naming
from dnlab_multinode.services import node_plugins, warm_links

log = logging.getLogger(__name__)


# Re-exported for backward compatibility with callers that imported the
# old module-level constant. New code should read PATHS.persist_root.
PERSIST_DIR_ROOT = PATHS.persist_root

__all__ = [
    "PERSIST_DIR_ROOT", "persist_dir_for", "persist_dir_for_node", "generate_topology_files",
    "generate_micro_topology_files", "generate_mgmt_anchor_topology_files",
    "node_asset_path", "render_node_asset", "render_node_override_files",
    "render_node_feature_files",
]

MGMT_ANCHOR_NODE = "mgmt-anchor"


def _needs_persist_bind(image: str) -> bool:
    """Return True for images explicitly patched by dNLab.

    The primary contract is the ``-dnlab`` tag suffix. Older/local custom
    dNLab images can also use a ``dnlab_*`` repository name while already
    containing the persistence support in their launcher.
    """
    image = str(image or "").strip()
    if not image:
        return False
    tag = image.rsplit(":", 1)[-1]
    if tag.endswith("-dnlab"):
        return True
    repo = image.rsplit(":", 1)[0] if ":" in image else image
    return repo.rsplit("/", 1)[-1].startswith("dnlab_")


def node_asset_path(topo_name: str, node_name: str, filename: str) -> str:
    safe_topo = _safe_path_part(topo_name) or "lab"
    safe_node = _safe_path_part(node_name) or "node"
    safe_file = _safe_path_part(filename) or filename
    return f"{PATHS.tmp_dir}/dnlab-assets/{safe_topo}/{safe_node}/{safe_file}"


def render_node_asset(state: dict, filename: str) -> str | None:
    plugin = node_plugins.for_state(state)
    if not plugin:
        return None
    asset = plugin.render_assets(state).get(filename)
    return asset[1] if asset else None


def render_node_override_files(topo: DistributedTopology, node_name: str) -> dict[str, str]:
    state = (topo.node_overrides or {}).get(node_name) or {}
    plugin = node_plugins.for_state(state)
    if not plugin:
        return {}
    return {
        node_asset_path(topo.name, node_name, filename): content
        for filename, (_target, content, _read_only) in plugin.render_assets(state).items()
    }


def _node_override_binds(topo: DistributedTopology, node_name: str) -> list[str]:
    state = (topo.node_overrides or {}).get(node_name) or {}
    plugin = node_plugins.for_state(state)
    if not plugin:
        return []
    return [
        f"{node_asset_path(topo.name, node_name, filename)}:{target}"
        + (":ro" if read_only else "")
        for filename, (target, _content, read_only) in plugin.render_assets(state).items()
    ]


def render_node_feature_files(topo: DistributedTopology, node_name: str) -> dict[str, str]:
    """Render data-driven node feature files for a scheduled VD.

    Supported materializer:
    ``persist-key-value-bool-file`` writes one ``key=yes/no`` line per state
    entry under the node's host-side persist directory.
    """
    out: dict[str, str] = {}
    features = (topo.node_features or {}).get(node_name) or {}
    if not isinstance(features, dict):
        return out

    for payload in features.values():
        if not isinstance(payload, dict):
            continue
        state = payload.get("state")
        materialize = payload.get("materialize")
        if not isinstance(state, dict) or not isinstance(materialize, dict):
            continue
        if materialize.get("type") != "persist-key-value-bool-file":
            continue
        rel_path = _safe_rel_path(materialize.get("path"))
        if not rel_path:
            continue
        true_value = str(materialize.get("true", "yes"))
        false_value = str(materialize.get("false", "no"))
        lines = [
            f"{_safe_key(key)}={true_value if bool(value) else false_value}"
            for key, value in state.items()
            if _safe_key(key)
        ]
        if not lines:
            continue
        node = topo.nodes[node_name]
        remote_path = (
            f"{persist_dir_for_node(topo.name, node_name, node.persist_id, topo.persistence.root)}"
            f"/{rel_path}"
        )
        out[remote_path] = "\n".join(lines) + "\n"
    return out


def _safe_path_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._")


def _safe_key(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "", str(value or ""))


def _safe_rel_path(value: str) -> str:
    parts = [
        _safe_path_part(part)
        for part in str(value or "").split("/")
        if part not in {"", ".", ".."}
    ]
    return "/".join(part for part in parts if part)


def generate_topology_files(
    topo: DistributedTopology,
    plan: SchedulePlan,
    webui_allocations: dict[str, list[dict]] | None = None,
) -> dict[str, str]:
    """Generate a containerlab YAML string for each host.

    ``webui_allocations`` (opzionale): mappa
    ``node_name → [{container_port, host_port, bind_ip, proto}, ...]``
    già allocata dal deploy controller. Ogni voce viene tradotta in
    una entry ``ports:`` nel YAML del nodo.

    Returns: {host_name: yaml_content}
    """
    results: dict[str, str] = {}

    for host_name, assignment in plan.assignments.items():
        if not assignment.vd_names:
            continue

        clab_dict = _build_clab_dict(
            topo, plan, host_name, assignment.vd_names,
            webui_allocations=webui_allocations,
        )
        yaml_str = yaml.dump(clab_dict, default_flow_style=False, sort_keys=False)

        # Fix endpoints to use flow style
        # Re-dump with custom flow for endpoints
        yaml_str = _fix_endpoints_flow(clab_dict)

        results[host_name] = yaml_str
        log.info("Generated topology for %s: %d nodes", host_name, len(assignment.vd_names))

    return results


def generate_micro_topology_files(
    topo: DistributedTopology,
    plan: SchedulePlan,
    webui_allocations: dict[str, list[dict]] | None = None,
) -> dict[str, dict[str, str]]:
    """Generate one containerlab YAML string per VD, grouped by host.

    Returns: ``{host_name: {vd_name: yaml_content}}``.
    """
    endpoint_names = _micro_host_endpoints(topo, plan)
    results: dict[str, dict[str, str]] = {}

    for host_name, assignment in plan.assignments.items():
        if not assignment.vd_names:
            continue
        host_files: dict[str, str] = {}
        for vd_name in assignment.vd_names:
            clab_dict = _build_micro_clab_dict(
                topo, plan, host_name, vd_name, endpoint_names,
                webui_allocations=webui_allocations,
            )
            host_files[vd_name] = _fix_endpoints_flow(clab_dict)
        if host_files:
            results[host_name] = host_files
            log.info("Generated %d micro-topologies for %s", len(host_files), host_name)

    return results


def generate_mgmt_anchor_topology_files(
    topo: DistributedTopology,
    plan: SchedulePlan,
) -> dict[str, str]:
    """Generate one management-network anchor topology per active host."""
    results: dict[str, str] = {}
    for host_name, assignment in plan.assignments.items():
        if not assignment.vd_names:
            continue
        results[host_name] = _fix_endpoints_flow(
            _build_mgmt_anchor_clab_dict(topo, host_name)
        )
    return results


def _build_clab_dict(
    topo: DistributedTopology,
    plan: SchedulePlan,
    host_name: str,
    vd_names: list[str],
    webui_allocations: dict[str, list[dict]] | None = None,
) -> dict:
    """Build a containerlab-compatible dict for a single host."""
    vd_set = set(vd_names)

    # Nodes section
    nodes = {}
    for vd_name in vd_names:
        nodes[vd_name] = _build_node_dict(topo, vd_name, webui_allocations)

    # Links section
    links = []

    # GUI real_net pseudo-nodes are materialized as pre-created Linux
    # bridges on each host. Containerlab sees a regular bridge kind.
    realnet_bridges: dict[str, str] = {}
    for rn_link in topo.real_net_links:
        if rn_link.host != host_name or rn_link.node not in vd_set:
            continue
        bridge = naming.realnet_bridge_name(topo.name, rn_link.real_net)
        realnet_bridges[rn_link.real_net] = bridge
        nodes.setdefault(bridge, {"kind": "bridge"})
        links.append({
            "endpoints": [
                f"{rn_link.node}:{rn_link.iface}",
                f"{bridge}:{rn_link.bridge_iface}",
            ],
        })

    # Local links: both endpoints on this host → normal veth
    for link in plan.local_links:
        if link.source in vd_set and link.target in vd_set:
            links.append({
                "endpoints": [
                    f"{link.source}:{link.source_iface}",
                    f"{link.target}:{link.target_iface}",
                ],
            })

    # Cross-host links: this host's side terminates on host:<iface>
    for cl in plan.cross_host_links:
        if cl.source_host == host_name:
            links.append({
                "endpoints": [
                    f"{cl.source_node}:{cl.source_iface}",
                    f"host:{cl.source_host_iface}",
                ],
            })
        elif cl.target_host == host_name:
            links.append({
                "endpoints": [
                    f"{cl.target_node}:{cl.target_iface}",
                    f"host:{cl.target_host_iface}",
                ],
            })

    # Build final dict
    clab = {
        "name": topo.name,
        "mgmt": _mgmt_clab_config(topo),
        "topology": {
            "nodes": nodes,
        },
    }
    if links:
        clab["topology"]["links"] = links

    return clab


def _build_node_dict(
    topo: DistributedTopology,
    vd_name: str,
    webui_allocations: dict[str, list[dict]] | None = None,
) -> dict:
    vd = topo.nodes[vd_name]
    node_dict: dict = {
        "kind": vd.kind,
        "image": vd.image,
    }
    if vd.mgmt_ipv4:
        node_dict["mgmt-ipv4"] = vd.mgmt_ipv4
    if vd.mgmt_ipv6:
        node_dict["mgmt-ipv6"] = vd.mgmt_ipv6
    if vd.env:
        node_dict["env"] = {
            key: value for key, value in vd.env.items()
            if key not in {
                warm_links.IMAGE_STATUS_ENV,
                warm_links.BASE_DIGEST_ENV,
            }
        }
    # Enforce after catalog/user environment merge.
    if vd.image.startswith("vrnetlab/"):
        env = node_dict.setdefault("env", {})
        env["CLAB_MGMT_PASSTHROUGH"] = "true"
        env["CLAB_MGMT_MAC"] = vd.mgmt_mac
        env["CLAB_MGMT_DUID"] = vd.mgmt_duid
        env["CLAB_MGMT_IAID"] = vd.mgmt_iaid
    warm_capacity = warm_links.capacity_for_node(topo, vd_name)
    if warm_capacity:
        profile = warm_links.profile_for_node(vd)
        env = node_dict.setdefault("env", {})
        env["DNLAB_WARM_PORTS"] = str(warm_capacity)
        env.setdefault("DNLAB_NIC_POLL_INTERVAL", "0.05")
        env.setdefault("DNLAB_WARM_VM_INDEX", str(profile["vm_index"]))
    if vd.extra:
        extra_clean = {k: v for k, v in vd.extra.items() if k != "webui_ports"}
        if "webui_ports" in vd.extra:
            log.info(
                "Topology %s, node %s: dropping legacy 'webui_ports:' "
                "from generated YAML (sidecar webui_wishlist take precedence)",
                topo.name, vd_name,
            )
        node_dict.update(extra_clean)

    override_state = (topo.node_overrides or {}).get(vd_name) or {}
    plugin = node_plugins.for_state(override_state)
    if plugin:
        managed_targets = set(plugin.managed_targets)
        existing = [
            str(bind) for bind in list(node_dict.get("binds") or [])
            if not any(f":{target}" in str(bind) for target in managed_targets)
        ]
        existing.extend(_node_override_binds(topo, vd_name))
        node_dict["binds"] = existing

    node_allocs = (webui_allocations or {}).get(vd_name) or []
    if node_allocs:
        existing_ports = list(node_dict.get("ports") or [])
        for a in node_allocs:
            spec = f"{a['host_port']}:{a['container_port']}/{a.get('proto', 'tcp')}"
            if spec not in existing_ports:
                existing_ports.append(spec)
        node_dict["ports"] = existing_ports

    if _needs_persist_bind(vd.image):
        bind_spec = (
            f"{persist_dir_for_node(topo.name, vd_name, vd.persist_id, topo.persistence.root)}"
            ":/persist"
        )
        existing = list(node_dict.get("binds") or [])
        if not any(b.endswith(":/persist") for b in existing):
            existing.append(bind_spec)
        node_dict["binds"] = existing

    return node_dict


def _build_micro_clab_dict(
    topo: DistributedTopology,
    plan: SchedulePlan,
    host_name: str,
    vd_name: str,
    endpoint_names: dict[tuple[str, str, str], str],
    webui_allocations: dict[str, list[dict]] | None = None,
) -> dict:
    nodes = {vd_name: _build_node_dict(topo, vd_name, webui_allocations)}
    links = []

    for link_id, link in enumerate(plan.local_links):
        lid = f"l{link_id}"
        if link.source == vd_name:
            links.append({"endpoints": [
                f"{vd_name}:{link.source_iface}",
                f"host:{endpoint_names[(lid, link.source, link.source_iface)]}",
            ]})
        elif link.target == vd_name:
            links.append({"endpoints": [
                f"{vd_name}:{link.target_iface}",
                f"host:{endpoint_names[(lid, link.target, link.target_iface)]}",
            ]})

    for link_id, cl in enumerate(plan.cross_host_links):
        lid = f"vx{link_id}"
        if cl.source_node == vd_name and cl.source_host == host_name:
            links.append({"endpoints": [
                f"{vd_name}:{cl.source_iface}",
                f"host:{endpoint_names[(lid, cl.source_node, cl.source_iface)]}",
            ]})
        elif cl.target_node == vd_name and cl.target_host == host_name:
            links.append({"endpoints": [
                f"{vd_name}:{cl.target_iface}",
                f"host:{endpoint_names[(lid, cl.target_node, cl.target_iface)]}",
            ]})

    for link_id, rn_link in enumerate(topo.real_net_links):
        if rn_link.node == vd_name and rn_link.host == host_name:
            lid = f"rn{link_id}"
            links.append({"endpoints": [
                f"{vd_name}:{rn_link.iface}",
                f"host:{endpoint_names[(lid, rn_link.node, rn_link.iface)]}",
            ]})

    warm_capacity = warm_links.capacity_for_node(topo, vd_name)
    if warm_capacity:
        attached = {
            endpoint.split(":", 1)[1]
            for item in links
            for endpoint in item["endpoints"]
            if endpoint.startswith(f"{vd_name}:")
        }
        for index in range(1, warm_capacity + 1):
            iface = f"eth{index}"
            if iface in attached:
                continue
            links.append({"endpoints": [
                f"{vd_name}:{iface}",
                f"host:{naming.runtime_port_endpoint(topo.name, vd_name, iface)}",
            ]})

    clab = {
        "name": naming.micro_topology_name(topo.name, vd_name),
        "mgmt": _mgmt_clab_config(topo),
        "topology": {
            "nodes": nodes,
        },
    }
    if links:
        clab["topology"]["links"] = links

    return clab


def _build_mgmt_anchor_clab_dict(topo: DistributedTopology, host_name: str) -> dict:
    clab = {
        "name": naming.mgmt_anchor_topology_name(topo.name, host_name),
        "mgmt": _mgmt_clab_config(topo),
        "topology": {
            "nodes": {
                MGMT_ANCHOR_NODE: {
                    "kind": "linux",
                    "image": image_for("mgmt-anchor"),
                    "mgmt-ipv4": ipv4_reservations(topo.mgmt.ipv4_subnet).anchor,
                    "env": {
                        "CLAB_MGMT_PASSTHROUGH": "true",
                    },
                },
            },
        },
    }
    return clab


def _mgmt_clab_config(topo: DistributedTopology) -> dict:
    """Reference the pre-created dNLab remote-driver management network."""
    mgmt = {
        "network": topo.mgmt.network,
        # The network already exists, but retaining this metadata keeps
        # Containerlab's normal management-network view and bridge-aware
        # operations intact for per-VD and anchor topologies.
        "bridge": topo.mgmt.bridge,
        "ipv4-subnet": topo.mgmt.ipv4_subnet,
        "ipv4-gw": topo.mgmt.docker_ipv4_gw or topo.mgmt.ipv4_gw,
        "external-access": False,
    }
    if topo.mgmt.ipv6_subnet:
        mgmt["ipv6-subnet"] = topo.mgmt.ipv6_subnet
    if topo.mgmt.ipv6_gw:
        mgmt["ipv6-gw"] = topo.mgmt.ipv6_gw
    return mgmt


def _micro_host_endpoints(topo: DistributedTopology, plan: SchedulePlan) -> dict[tuple[str, str, str], str]:
    raw: dict[tuple[str, str, str], str] = {}
    per_host: dict[str, list[tuple[str, str, str]]] = {h: [] for h in plan.assignments}

    for link_id, link in enumerate(plan.local_links):
        lid = f"l{link_id}"
        host = plan.host_for_vd(link.source) or ""
        for node, iface in [(link.source, link.source_iface), (link.target, link.target_iface)]:
            key = (lid, node, iface)
            raw[key] = _runtime_endpoint_name(topo, node, iface, lid)
            per_host.setdefault(host, []).append(key)

    for link_id, cl in enumerate(plan.cross_host_links):
        lid = f"vx{link_id}"
        source_key = (lid, cl.source_node, cl.source_iface)
        target_key = (lid, cl.target_node, cl.target_iface)
        raw[source_key] = _runtime_endpoint_name(
            topo, cl.source_node, cl.source_iface, lid, fallback=cl.source_host_iface,
        )
        raw[target_key] = _runtime_endpoint_name(
            topo, cl.target_node, cl.target_iface, lid, fallback=cl.target_host_iface,
        )
        per_host.setdefault(cl.source_host, []).append(source_key)
        per_host.setdefault(cl.target_host, []).append(target_key)

    for link_id, rn_link in enumerate(topo.real_net_links):
        lid = f"rn{link_id}"
        key = (lid, rn_link.node, rn_link.iface)
        raw[key] = _runtime_endpoint_name(
            topo,
            rn_link.node,
            rn_link.iface,
            lid,
            fallback=rn_link.bridge_iface or naming.realnet_bridge_iface(rn_link.node, rn_link.iface),
        )
        per_host.setdefault(rn_link.host, []).append(key)

    out = dict(raw)
    for keys in per_host.values():
        names = [raw[k] for k in keys]
        for key, unique_name in zip(keys, naming.ensure_unique(names)):
            out[key] = unique_name
    return out


def _runtime_endpoint_name(
    topo: DistributedTopology,
    node_name: str,
    iface: str,
    link_id: str,
    *,
    fallback: str | None = None,
) -> str:
    if warm_links.is_enabled(topo.nodes[node_name]):
        return naming.runtime_port_endpoint(topo.name, node_name, iface)
    return fallback or naming.runtime_host_endpoint(topo.name, node_name, iface, link_id)


def _fix_endpoints_flow(clab_dict: dict) -> str:
    """Dump YAML with endpoints lists in flow style."""

    class _FlowList(list):
        pass

    def _flow_representer(dumper, data):
        return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True)

    yaml.add_representer(_FlowList, _flow_representer)

    # Convert endpoints to FlowList
    for link in clab_dict.get("topology", {}).get("links", []):
        if "endpoints" in link:
            link["endpoints"] = _FlowList(link["endpoints"])

    return yaml.dump(clab_dict, default_flow_style=False, sort_keys=False)
