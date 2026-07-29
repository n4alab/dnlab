"""Docker management-network lifecycle backed by the dNLab remote driver."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import shlex
from pathlib import Path

from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.services.mgmt_ips import ipv4_reservations
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.utils import naming
from dnlab_multinode import vrf_plugin


log = logging.getLogger(__name__)


NETWORK_DRIVER = vrf_plugin.PLUGIN_NAME
IPAM_DRIVER = vrf_plugin.PLUGIN_NAME
BRIDGE_OPTION = vrf_plugin.BRIDGE_OPTION
VRF_OPTION = vrf_plugin.VRF_OPTION
LAB_OPTION = vrf_plugin.LAB_OPTION
GENERIC_OPTIONS_KEY = vrf_plugin.GENERIC_OPTIONS_KEY
MANAGED_LABEL = "io.dnlab.managed"
LAB_LABEL = "io.dnlab.lab"
IPAM_TENANT_OPTION = vrf_plugin.TENANT_OPTION
IPAM_RESERVED_OPTION = vrf_plugin.RESERVED_OPTION
IPAM_HOST_INDEX_OPTION = vrf_plugin.HOST_INDEX_OPTION
IPAM_HOST_COUNT_OPTION = vrf_plugin.HOST_COUNT_OPTION

PLUGIN_INSTALL_DIR = "/opt/dnlab-vrf-plugin"
PLUGIN_SCRIPT = f"{PLUGIN_INSTALL_DIR}/dnlab_vrf_plugin.py"
PLUGIN_SERVICE = "dnlab-vrf-plugin.service"
PLUGIN_UNIT = f"/etc/systemd/system/{PLUGIN_SERVICE}"
PLUGIN_SPEC = f"/etc/docker/plugins/{NETWORK_DRIVER}.spec"
PLUGIN_SOCKET = "/run/dnlab-vrf-plugin/plugin.sock"
PLUGIN_STATE = "/var/lib/dnlab-vrf-plugin/state.json"

_LEGACY_IPAM_SERVICE = "dnlab-vrf-ipam.service"
_LEGACY_IPAM_SPEC = "/etc/docker/plugins/dnlab-vrf-ipam.spec"
_LEGACY_IPAM_UNIT = "/etc/systemd/system/dnlab-vrf-ipam.service"
_LEGACY_IPAM_DIR = "/opt/dnlab-vrf-ipam"


class MgmtNetworkError(RuntimeError):
    """A host cannot safely provide the requested Docker management network."""


def _quote(value: object) -> str:
    return shlex.quote(str(value))


def _plugin_script() -> str:
    return (Path(__file__).resolve().parents[1] / "vrf_plugin.py").read_text()


def _service_unit() -> str:
    return f"""[Unit]
Description=dNLab Docker VRF network and IPAM plugin
Documentation=https://docs.docker.com/engine/extend/plugins_network/
Wants=network-online.target
After=network-online.target
Before=docker.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {PLUGIN_SCRIPT} --socket {PLUGIN_SOCKET} --state {PLUGIN_STATE}
Restart=on-failure
RestartSec=1
StateDirectory=dnlab-vrf-plugin
RuntimeDirectory=dnlab-vrf-plugin
RuntimeDirectoryMode=0750
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
"""


def _write_if_changed(
    client: SSHClient,
    content: str,
    destination: str,
    *,
    mode: str,
) -> bool:
    """Atomically replace a remote text file only when its content changed."""
    digest = hashlib.sha256(content.encode()).hexdigest()[:16]
    temporary = f"/tmp/dnlab-{Path(destination).name}-{digest}.tmp"
    client.upload_text(content, temporary)
    rc, _, _ = client.run_no_check(
        f"cmp -s {_quote(temporary)} {_quote(destination)}",
        timeout=20,
    )
    if rc == 0:
        client.run(f"rm -f {_quote(temporary)}", check=False)
        return False
    client.run(
        f"install -D -m {mode} {_quote(temporary)} {_quote(destination)}; "
        f"rm -f {_quote(temporary)}"
    )
    return True


def _remove_legacy_ipam_plugin(client: SSHClient) -> None:
    """Remove the superseded IPAM-only service from a redeployed host."""
    client.run(f"systemctl disable --now {_LEGACY_IPAM_SERVICE}", check=False)
    client.run(
        f"rm -f {_quote(_LEGACY_IPAM_SPEC)} {_quote(_LEGACY_IPAM_UNIT)}",
        check=False,
    )
    client.run(f"rm -rf {_quote(_LEGACY_IPAM_DIR)}", check=False)


def ensure_vrf_plugin(client: SSHClient) -> None:
    """Install and start the single remote Docker network/IPAM plugin.

    This is an external Docker plugin discovered through a Unix ``.spec``
    file, not a Docker-managed plugin image and not a patched Docker daemon.
    It is intentionally installed before a management network is created.
    """
    _remove_legacy_ipam_plugin(client)
    client.run(
        f"install -d -m 0755 {_quote(PLUGIN_INSTALL_DIR)} /etc/docker/plugins"
    )
    changed = False
    changed |= _write_if_changed(client, _plugin_script(), PLUGIN_SCRIPT, mode="0755")
    changed |= _write_if_changed(client, _service_unit(), PLUGIN_UNIT, mode="0644")
    changed |= _write_if_changed(client, f"unix://{PLUGIN_SOCKET}\n", PLUGIN_SPEC, mode="0644")
    client.run("systemctl daemon-reload")
    client.run(f"systemctl enable --now {PLUGIN_SERVICE}")
    if changed:
        client.run(f"systemctl restart {PLUGIN_SERVICE}")
    rc, _, err = client.run_no_check(
        f"systemctl is-active --quiet {PLUGIN_SERVICE}",
        timeout=20,
    )
    if rc != 0:
        raise MgmtNetworkError(
            f"{PLUGIN_SERVICE} is not active on {client.name}: {(err or '').strip()}"
        )


def _expected_network(topo: DistributedTopology, host_name: str = "master") -> dict:
    hosts = sorted(topo.all_hosts)
    if host_name not in hosts:
        raise MgmtNetworkError(f"unknown management network host {host_name!r}")
    reservations = ipv4_reservations(topo.mgmt.ipv4_subnet)
    ipv4_subnet = str(ipaddress.ip_network(topo.mgmt.ipv4_subnet, strict=False))
    ipv4_gateway = topo.mgmt.docker_ipv4_gw or reservations.docker_gw
    expected = {
        "driver": NETWORK_DRIVER,
        "ipam_driver": IPAM_DRIVER,
        "network": topo.mgmt.network,
        "bridge": topo.mgmt.bridge,
        "vrf": naming.vrf_name(topo.name),
        "lab": topo.name,
        "ipv4_subnet": ipv4_subnet,
        "ipv4_gateway": str(ipaddress.ip_address(ipv4_gateway)),
        "host_index": hosts.index(host_name),
        "host_count": len(hosts),
        "reserved": sorted({
            reservations.docker_gw,
            reservations.anchor,
            reservations.dns,
            reservations.jumphost,
        }),
        "labels": {
            MANAGED_LABEL: "mgmt-vrf",
            LAB_LABEL: topo.name,
        },
    }
    if topo.mgmt.ipv6_subnet:
        expected["ipv6_subnet"] = str(ipaddress.ip_network(topo.mgmt.ipv6_subnet, strict=False))
    if topo.mgmt.ipv6_gw:
        expected["ipv6_gateway"] = str(ipaddress.ip_address(topo.mgmt.ipv6_gw))
    return expected


def _inspect_network(client: SSHClient, name: str) -> dict | None:
    rc, out, err = client.run_no_check(
        f"docker network inspect {_quote(name)}",
        timeout=30,
    )
    if rc != 0:
        if err:
            log.debug("[%s] network %s not inspectable: %s", client.name, name, err)
        return None
    try:
        payload = json.loads(out)
    except json.JSONDecodeError as exc:
        raise MgmtNetworkError(
            f"invalid docker network inspect output for {name} on {client.name}: {exc}"
        ) from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise MgmtNetworkError(f"unexpected docker network inspect output for {name} on {client.name}")
    return payload[0]


def _network_options(actual: dict) -> dict:
    options = actual.get("Options") or {}
    if not isinstance(options, dict):
        return {}
    generic = options.get(GENERIC_OPTIONS_KEY)
    return generic if isinstance(generic, dict) else options


def _normal_ip(value: object) -> str:
    text = str(value or "")
    try:
        return str(ipaddress.ip_interface(text).ip if "/" in text else ipaddress.ip_address(text))
    except ValueError:
        raise MgmtNetworkError(f"invalid Docker IPAM address {value!r}")


def _network_mismatches(actual: dict, expected: dict) -> list[str]:
    mismatches: list[str] = []
    if actual.get("Driver") != expected["driver"]:
        mismatches.append(f"driver={actual.get('Driver')!r}")
    ipam = actual.get("IPAM") or {}
    if ipam.get("Driver") != expected["ipam_driver"]:
        mismatches.append(f"ipam-driver={ipam.get('Driver')!r}")
    options = _network_options(actual)
    if options.get(BRIDGE_OPTION) != expected["bridge"]:
        mismatches.append("bridge option differs")
    if options.get(VRF_OPTION) != expected["vrf"]:
        mismatches.append("VRF option differs")
    if options.get(LAB_OPTION) != expected["lab"]:
        mismatches.append("lab option differs")
    labels = actual.get("Labels") or {}
    for key, value in expected["labels"].items():
        if labels.get(key) != value:
            mismatches.append(f"label {key!r} differs")
    ipam_options = ipam.get("Options") or {}
    if ipam_options.get(IPAM_TENANT_OPTION) != expected["network"]:
        mismatches.append("IPAM tenant differs")
    if ipam_options.get(IPAM_HOST_INDEX_OPTION) != str(expected["host_index"]):
        mismatches.append("IPAM host index differs")
    if ipam_options.get(IPAM_HOST_COUNT_OPTION) != str(expected["host_count"]):
        mismatches.append("IPAM host count differs")
    actual_reserved = sorted(
        item.strip()
        for item in str(ipam_options.get(IPAM_RESERVED_OPTION) or "").split(",")
        if item.strip()
    )
    if actual_reserved != expected["reserved"]:
        mismatches.append("IPAM reserved-address set differs")

    actual_pools: dict[str, str] = {}
    for config in ipam.get("Config") or []:
        subnet = config.get("Subnet")
        gateway = config.get("Gateway")
        if subnet and gateway:
            try:
                actual_pools[str(ipaddress.ip_network(subnet, strict=False))] = _normal_ip(gateway)
            except (ValueError, MgmtNetworkError):
                mismatches.append(f"invalid IPAM config {config!r}")
    if actual_pools.get(expected["ipv4_subnet"]) != expected["ipv4_gateway"]:
        mismatches.append("IPv4 subnet/gateway differs")
    if expected.get("ipv6_subnet") and actual_pools.get(expected["ipv6_subnet"]) != expected.get("ipv6_gateway"):
        mismatches.append("IPv6 subnet/gateway differs")
    return mismatches


def _create_network_command(expected: dict) -> str:
    parts = [
        "docker network create",
        "--driver", _quote(expected["driver"]),
        "--ipam-driver", _quote(expected["ipam_driver"]),
        "--ipam-opt", _quote(f"{IPAM_TENANT_OPTION}={expected['network']}"),
        "--ipam-opt", _quote(f"{IPAM_RESERVED_OPTION}={','.join(expected['reserved'])}"),
        "--ipam-opt", _quote(f"{IPAM_HOST_INDEX_OPTION}={expected['host_index']}"),
        "--ipam-opt", _quote(f"{IPAM_HOST_COUNT_OPTION}={expected['host_count']}"),
        "--opt", _quote(f"{BRIDGE_OPTION}={expected['bridge']}"),
        "--opt", _quote(f"{VRF_OPTION}={expected['vrf']}"),
        "--opt", _quote(f"{LAB_OPTION}={expected['lab']}"),
        "--label", _quote(f"{MANAGED_LABEL}={expected['labels'][MANAGED_LABEL]}"),
        "--label", _quote(f"{LAB_LABEL}={expected['labels'][LAB_LABEL]}"),
        "--subnet", _quote(expected["ipv4_subnet"]),
        "--gateway", _quote(expected["ipv4_gateway"]),
    ]
    if expected.get("ipv6_subnet"):
        parts.extend(["--ipv6", "--subnet", _quote(expected["ipv6_subnet"])])
        if expected.get("ipv6_gateway"):
            parts.extend(["--gateway", _quote(expected["ipv6_gateway"])])
    parts.append(_quote(expected["network"]))
    return " ".join(parts)


def ensure_mgmt_network(topo: DistributedTopology, client: SSHClient) -> None:
    """Ensure the exact per-lab Docker management network exists on a host."""
    ensure_vrf_plugin(client)
    expected = _expected_network(topo, client.name)
    actual = _inspect_network(client, expected["network"])
    if actual is not None:
        mismatches = _network_mismatches(actual, expected)
        if mismatches:
            raise MgmtNetworkError(
                f"management network {expected['network']!r} on {client.name} has unexpected "
                f"configuration: {', '.join(mismatches)}"
            )
        return
    client.run(_create_network_command(expected), timeout=60)
    actual = _inspect_network(client, expected["network"])
    if actual is None:
        raise MgmtNetworkError(
            f"management network {expected['network']!r} was not created on {client.name}"
        )
    mismatches = _network_mismatches(actual, expected)
    if mismatches:
        raise MgmtNetworkError(
            f"management network {expected['network']!r} on {client.name} was created with "
            f"unexpected configuration: {', '.join(mismatches)}"
        )


def destroy_mgmt_network(topo: DistributedTopology, client: SSHClient) -> None:
    """Remove only a dNLab-owned management Docker network, best effort."""
    expected = _expected_network(topo, client.name)
    actual = _inspect_network(client, expected["network"])
    if actual is None:
        return
    mismatches = _network_mismatches(actual, expected)
    if mismatches:
        log.warning(
            "[%s] refusing to remove unexpected management network %s: %s",
            client.name, expected["network"], ", ".join(mismatches),
        )
        return
    client.run(f"docker network rm {_quote(expected['network'])}", check=False, timeout=30)
