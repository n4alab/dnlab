"""Interface naming utilities — Linux limit of 15 characters."""

import hashlib
import re

_MAX_IFACE_LEN = 15
_MAX_MGMT_NET_LEN = 12  # bridge = "br-" + network ⇒ 3 + 12 = 15


def shorten_iface(iface: str) -> str:
    """Shorten a vendor interface name to a compact form.

    eth1         → e1
    ge-0/0/0     → g000
    xe-0/0/1     → x001
    Ethernet1/10 → E110
    GigabitEthernet0/0/0/1 → G0001
    """
    # eth<N>
    m = re.match(r"eth(\d+)", iface)
    if m:
        return f"e{m.group(1)}"

    # ge-X/Y/Z or xe-X/Y/Z
    m = re.match(r"([gx])e-(\d+)/(\d+)/(\d+)", iface)
    if m:
        return f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(4)}"

    # Ethernet1/10
    m = re.match(r"[Ee]thernet(\d+)/(\d+)", iface)
    if m:
        return f"E{m.group(1)}{m.group(2)}"

    # GigabitEthernet0/0/0/1
    m = re.match(r"[Gg]igabit[Ee]thernet(\d+)/(\d+)/(\d+)/(\d+)", iface)
    if m:
        return f"G{m.group(1)}{m.group(2)}{m.group(3)}{m.group(4)}"

    # Fallback: strip non-alnum and truncate
    return re.sub(r"[^a-zA-Z0-9]", "", iface)[:6]


def _short_hash(value: str, length: int = 3) -> str:
    return hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:length]


def vxlan_host_iface(lab_name: str, node_name: str, iface: str) -> str:
    """Generate a host-side VxLAN interface name, max 15 chars.

    Include a lab-derived token so identical VD/interface names in different
    labs do not collide on the same Linux host.

    Format: vx<lab_hash>-<node_short>-<iface_short>
    """
    lab = _short_hash(lab_name, 3)
    node_short = re.sub(r"[^A-Za-z0-9]", "", str(node_name))[:4] or "n"
    iface_short = shorten_iface(iface)[:3] or "if"
    return f"vx{lab}-{node_short}-{iface_short}"[:_MAX_IFACE_LEN]


def mgmt_vxlan_iface(lab_name: str) -> str:
    """VxLAN mgmt interface name, max 15 chars.

    Format: vx-<lab>-mgmt
    """
    # "vx-" (3) + "-mgmt" (5) leaves 7 chars for the lab token.
    return f"vx-{_bounded_lab_token(lab_name, 7)}-mgmt"


def sanitize_lab_name(lab_name: str) -> str:
    """Return a lowercase, bridge-safe form of ``lab_name``.

    Replaces any character outside ``[a-z0-9-]`` with ``-``, collapses
    runs of ``-``, and strips leading/trailing ``-``. Empty result
    becomes ``"lab"`` so callers always get a usable identifier.
    """
    s = re.sub(r"[^a-z0-9-]+", "-", lab_name.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "lab"


def _bounded_lab_token(lab_name: str, max_length: int) -> str:
    """Return a short deterministic token without truncation collisions."""
    name = sanitize_lab_name(lab_name)
    if len(name) <= max_length:
        return name
    hash_length = min(6, max_length)
    prefix_length = max_length - hash_length - 1
    if prefix_length <= 0:
        return _short_hash(name, hash_length)
    return f"{name[:prefix_length]}-{_short_hash(name, hash_length)}"


def mgmt_network_name(lab_name: str) -> str:
    """Docker network name for the management plane (≤12 chars).

    Short lab names stay readable; longer names receive a deterministic hash
    suffix so ``"br-" + result`` fits the Linux interface-name limit without
    direct prefix-truncation collisions.
    """
    return _bounded_lab_token(lab_name, _MAX_MGMT_NET_LEN)


def mgmt_bridge_name(lab_name: str) -> str:
    """Management bridge name (≤15 chars): ``br-<mgmt_network_name>``."""
    return f"br-{mgmt_network_name(lab_name)}"


def vrf_name(lab_name: str) -> str:
    """VRF device name, collision-resistant within the Linux limit."""
    return f"vrf-{_bounded_lab_token(lab_name, _MAX_IFACE_LEN - 4)}"


def jumphost_container_name(lab_name: str) -> str:
    """Jump host Docker container name."""
    return f"dnlab-{lab_name}-jumphost"


def runtime_relay_container_name(lab_name: str) -> str:
    """Runtime relay sidecar Docker container name (one per host)."""
    return f"dnlab-{lab_name}-runtime-relay"


def vd_container_name(lab_name: str, vd_name: str) -> str:
    """Containerlab's convention for VD container names: ``clab-<lab>-<vd>``."""
    return f"clab-{lab_name}-{vd_name}"


def micro_topology_name(lab_name: str, vd_name: str) -> str:
    """Containerlab project name for a single-VD micro-topology."""
    return f"dnlab-{lab_name}-{vd_name}"


def micro_topology_file(lab_name: str, vd_name: str, host_name: str) -> str:
    """Remote path for a single-VD containerlab topology file."""
    return f"/tmp/{micro_topology_name(lab_name, vd_name)}-{host_name}.clab.yml"


def micro_vd_container_name(lab_name: str, vd_name: str) -> str:
    """Container name produced by the per-VD micro-topology convention."""
    return f"clab-{micro_topology_name(lab_name, vd_name)}-{vd_name}"


def mgmt_anchor_topology_name(lab_name: str, host_name: str) -> str:
    """Containerlab project name for the per-host management anchor."""
    return f"dnlab-{lab_name}-mgmt-{host_name}"


def mgmt_anchor_topology_file(lab_name: str, host_name: str) -> str:
    """Remote path for the per-host management anchor topology."""
    return f"/tmp/{mgmt_anchor_topology_name(lab_name, host_name)}.clab.yml"


def mgmt_anchor_container_name(lab_name: str, host_name: str) -> str:
    """Container name produced by the management anchor topology."""
    return f"clab-{mgmt_anchor_topology_name(lab_name, host_name)}-mgmt-anchor"


def runtime_host_endpoint(lab_name: str, node_name: str, iface: str, link_id: str | int) -> str:
    """Host-side endpoint name for per-VD runtime links, max 15 chars."""
    node = re.sub(r"[^A-Za-z0-9]", "", str(node_name))[:4] or "n"
    ifs = shorten_iface(iface)[:4] or "if"
    lid = re.sub(r"[^A-Za-z0-9]", "", str(link_id))[-3:] or "0"
    name = f"rt-{node}-{ifs}-{lid}"
    return name[:_MAX_IFACE_LEN]


def runtime_port_endpoint(lab_name: str, node_name: str, iface: str) -> str:
    """Stable host endpoint for a warm port, independent of link identity."""
    digest = hashlib.sha1(f"{lab_name}:{node_name}:{iface}".encode()).hexdigest()[:6]
    ifs = shorten_iface(iface)[:4] or "if"
    return f"wp-{ifs}-{digest}"[:_MAX_IFACE_LEN]


def realnet_bridge_name(lab_name: str, real_net: str) -> str:
    """Per-lab/per-real_net Linux bridge name, max 15 chars."""
    lab = sanitize_lab_name(lab_name)[:5]
    rn = sanitize_lab_name(real_net).replace("-", "")[:5]
    return f"br{lab}{rn}"[:_MAX_IFACE_LEN]


def realnet_vxlan_iface(lab_name: str, real_net: str) -> str:
    """Per-host VXLAN interface for a real_net fabric, max 15 chars."""
    lab = sanitize_lab_name(lab_name).replace("-", "")[:5]
    rn = sanitize_lab_name(real_net).replace("-", "")[:5]
    return f"vx{lab}{rn}"[:_MAX_IFACE_LEN]


def realnet_bridge_iface(node_name: str, iface: str) -> str:
    """Host-side veth name attached by clab to a real_net bridge."""
    return f"rn-{node_name[:4]}-{shorten_iface(iface)}"[:_MAX_IFACE_LEN]


def realnet_router_veth_name(lab_name: str, real_net: str) -> str:
    """Host-side veth for the unmanaged real_net router, unique per lab."""
    lab = sanitize_lab_name(lab_name).replace("-", "")[:5]
    rn = sanitize_lab_name(real_net).replace("-", "")[:5]
    return f"vh{lab}{rn}"[:_MAX_IFACE_LEN]


def realnet_router_container_name(lab_name: str, real_net: str) -> str:
    """Unmanaged infra router container for a real_net."""
    return f"dnlab-{lab_name}-{real_net}-realnet"


def ensure_unique(names: list[str]) -> list[str]:
    """Ensure all names are unique; append numeric suffix on collision."""
    seen: dict[str, int] = {}
    result = []
    for name in names:
        if name in seen:
            seen[name] += 1
            suffixed = f"{name[:_MAX_IFACE_LEN - 1]}{seen[name]}"
            result.append(suffixed[:_MAX_IFACE_LEN])
        else:
            seen[name] = 0
            result.append(name)
    return result
