"""dNLab remote Docker network and IPAM driver for overlapping VRF networks.

The plugin intentionally uses only the Python standard library.  dNLab copies
this file verbatim to every Docker host and starts it as a small systemd
service.  Docker keeps ownership of the container network namespace and its
``eth0`` contract; the plugin only creates the host-side veth and attaches it
to the dNLab bridge that is already enslaved to the lab VRF.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any


PLUGIN_NAME = "dnlab-vrf"
STATE_VERSION = 2

TENANT_OPTION = "dnlab.tenant"
RESERVED_OPTION = "dnlab.reserved"
HOST_INDEX_OPTION = "dnlab.host-index"
HOST_COUNT_OPTION = "dnlab.host-count"

BRIDGE_OPTION = "dnlab.bridge"
VRF_OPTION = "dnlab.vrf"
LAB_OPTION = "dnlab.lab"
GENERIC_OPTIONS_KEY = "com.docker.network.generic"

_IFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\Z")


class PluginError(ValueError):
    """A request that the Docker remote-driver protocol must reject."""


class IPAMError(PluginError):
    """An invalid Docker remote-IPAM request."""


class NetworkDriverError(PluginError):
    """An invalid Docker remote-network request."""


def _pool_id(tenant: str, pool: str, address_space: str, v6: bool) -> str:
    payload = "\x00".join((tenant, pool, address_space, str(v6))).encode()
    return f"{PLUGIN_NAME}:{hashlib.sha256(payload).hexdigest()[:24]}"


def _canonical_network(value: str, *, v6: bool) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise IPAMError(f"invalid pool {value!r}: {exc}") from exc
    if network.version != (6 if v6 else 4):
        raise IPAMError(f"pool {network} does not match requested IP version")
    return network


def _canonical_address(
    value: str,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_interface(value).ip if "/" in value else ipaddress.ip_address(value)
    except ValueError as exc:
        raise IPAMError(f"invalid address {value!r}: {exc}") from exc
    if address.version != network.version or address not in network:
        raise IPAMError(f"address {address} is outside pool {network}")
    if address == network.network_address:
        raise IPAMError(f"address {address} is the network address of {network}")
    if network.version == 4 and address == network.broadcast_address:
        raise IPAMError(f"address {address} is the broadcast address of {network}")
    return address


def _network_driver_address(
    value: object,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    *,
    field: str,
) -> str:
    try:
        return str(_canonical_address(str(value or "").strip(), network))
    except IPAMError as exc:
        raise NetworkDriverError(f"invalid {field}: {exc}") from exc


def _required_iface(value: object, *, option: str) -> str:
    name = str(value or "").strip()
    if not _IFACE_RE.fullmatch(name):
        raise NetworkDriverError(
            f"network option {option} must be a Linux interface name of at most 15 characters"
        )
    return name


def _network_config(request: dict[str, Any]) -> dict[str, str]:
    options = request.get("Options") or {}
    if not isinstance(options, dict):
        raise NetworkDriverError("network options must be an object")
    generic = options.get(GENERIC_OPTIONS_KEY, options)
    if not isinstance(generic, dict):
        raise NetworkDriverError("Docker generic network options must be an object")

    bridge = _required_iface(generic.get(BRIDGE_OPTION), option=BRIDGE_OPTION)
    vrf = _required_iface(generic.get(VRF_OPTION), option=VRF_OPTION)
    lab = str(generic.get(LAB_OPTION) or "").strip()
    if not lab or len(lab) > 128:
        raise NetworkDriverError(f"network option {LAB_OPTION} must be a non-empty lab name")

    ipv4_subnet, ipv4_gateway = _family_network_config(
        request.get("IPv4Data"),
        version=4,
        required=True,
    )
    ipv6_subnet, ipv6_gateway = _family_network_config(
        request.get("IPv6Data"),
        version=6,
        required=False,
    )
    config = {
        "bridge": bridge,
        "vrf": vrf,
        "lab": lab,
        "ipv4_subnet": ipv4_subnet,
        "ipv4_gateway": ipv4_gateway,
    }
    if ipv6_subnet:
        config["ipv6_subnet"] = ipv6_subnet
        config["ipv6_gateway"] = ipv6_gateway
    return config


def _family_network_config(
    raw_data: object,
    *,
    version: int,
    required: bool,
) -> tuple[str, str]:
    if raw_data is None:
        raw_data = []
    if not isinstance(raw_data, list):
        raise NetworkDriverError("network IP data must be a list")
    entries = [entry for entry in raw_data if isinstance(entry, dict)]
    if len(entries) != len(raw_data) or len(entries) > 1:
        raise NetworkDriverError("dNLab management networks require at most one pool per IP family")
    if not entries:
        if required:
            raise NetworkDriverError("dNLab management networks require an explicit IPv4 subnet")
        return "", ""
    entry = entries[0]
    raw_pool = str(entry.get("Pool") or "").strip()
    if not raw_pool:
        raise NetworkDriverError("network IP data is missing Pool")
    try:
        network = ipaddress.ip_network(raw_pool, strict=False)
    except ValueError as exc:
        raise NetworkDriverError(f"invalid network pool {raw_pool!r}: {exc}") from exc
    if network.version != version:
        raise NetworkDriverError(f"network pool {network} does not match IPv{version}")
    gateway = _network_driver_address(entry.get("Gateway"), network, field="gateway")
    return str(network), gateway


def _endpoint_interface_names(network_id: str, endpoint_id: str) -> tuple[str, str]:
    """Generate collision-resistant host and sandbox veth names (<= 15 chars)."""
    digest = hashlib.sha256(f"{network_id}\x00{endpoint_id}".encode()).hexdigest()[:12]
    return f"dvh{digest}", f"dvp{digest}"


class NetworkOps:
    """Small, audited wrapper around the host ``ip`` utility."""

    def _run(self, args: list[str]) -> str:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "command failed").strip()
            raise NetworkDriverError(f"{' '.join(args)}: {detail}")
        return completed.stdout

    def _link_details(self, name: str) -> dict[str, Any]:
        output = self._run(["ip", "-j", "-d", "link", "show", "dev", name])
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise NetworkDriverError(f"cannot decode ip link data for {name}: {exc}") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise NetworkDriverError(f"unexpected ip link data for {name}")
        return payload[0]

    def validate_bridge_vrf(self, bridge: str, vrf: str) -> None:
        bridge_info = self._link_details(bridge)
        vrf_info = self._link_details(vrf)
        if ((bridge_info.get("linkinfo") or {}).get("info_kind")) != "bridge":
            raise NetworkDriverError(f"{bridge} is not a Linux bridge")
        if ((vrf_info.get("linkinfo") or {}).get("info_kind")) != "vrf":
            raise NetworkDriverError(f"{vrf} is not a Linux VRF device")
        if bridge_info.get("master") != vrf:
            raise NetworkDriverError(f"bridge {bridge} is not enslaved to VRF {vrf}")

    def link_exists(self, name: str) -> bool:
        completed = subprocess.run(
            ["ip", "link", "show", "dev", name],
            check=False,
            capture_output=True,
            text=True,
        )
        return completed.returncode == 0

    def create_veth(self, host_iface: str, sandbox_iface: str, bridge: str) -> None:
        self._run([
            "ip", "link", "add", host_iface,
            "type", "veth", "peer", "name", sandbox_iface,
        ])
        try:
            self._run(["ip", "link", "set", host_iface, "master", bridge])
            self._run(["ip", "link", "set", host_iface, "up"])
        except Exception:
            self.delete_link(host_iface)
            raise

    def delete_link(self, name: str) -> None:
        completed = subprocess.run(
            ["ip", "link", "delete", "dev", name],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0:
            return
        detail = (completed.stderr or completed.stdout or "").strip()
        if "Cannot find device" in detail or "does not exist" in detail:
            return
        raise NetworkDriverError(f"ip link delete {name}: {detail or 'command failed'}")


class PluginStore:
    """Durable IPAM and endpoint ledger with atomic JSON writes."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    # Docker IPAM API -----------------------------------------------------
    def request_pool(self, request: dict[str, Any]) -> dict[str, Any]:
        options = request.get("Options") or {}
        tenant = str(options.get(TENANT_OPTION) or "").strip()
        if not tenant:
            raise IPAMError(f"missing required IPAM option {TENANT_OPTION}")
        raw_pool = str(request.get("Pool") or "").strip()
        if not raw_pool:
            raise IPAMError("dNLab VRF IPAM requires an explicit --subnet")
        v6 = bool(request.get("V6"))
        network = _canonical_network(raw_pool, v6=v6)
        address_space = str(request.get("AddressSpace") or "dnlab-vrf-local")
        reserved = self._parse_reserved(options.get(RESERVED_OPTION), network)
        host_index, host_count = self._partition_options(options)
        pool_id = _pool_id(tenant, str(network), address_space, v6)

        with self._lock:
            state = self._load()
            pools = state["pools"]
            existing = pools.get(pool_id)
            if existing:
                if (
                    existing.get("tenant") != tenant
                    or existing.get("pool") != str(network)
                    or bool(existing.get("v6")) != v6
                    or existing.get("address_space") != address_space
                    or int(existing.get("host_index", 0)) != host_index
                    or int(existing.get("host_count", 1)) != host_count
                ):
                    raise IPAMError(f"pool identity mismatch for tenant {tenant!r}")
                if sorted(existing.get("reserved") or []) != reserved:
                    raise IPAMError(f"reserved-address set changed for tenant {tenant!r}")
            else:
                pools[pool_id] = {
                    "tenant": tenant,
                    "pool": str(network),
                    "address_space": address_space,
                    "v6": v6,
                    "reserved": reserved,
                    "host_index": host_index,
                    "host_count": host_count,
                    "allocated": [],
                }
                self._save(state)
        return {"PoolID": pool_id, "Pool": str(network), "Data": {}}

    def release_pool(self, request: dict[str, Any]) -> dict[str, Any]:
        pool_id = str(request.get("PoolID") or "")
        with self._lock:
            state = self._load()
            if state["pools"].pop(pool_id, None) is not None:
                self._save(state)
        return {}

    def request_address(self, request: dict[str, Any]) -> dict[str, Any]:
        pool_id = str(request.get("PoolID") or "")
        with self._lock:
            state = self._load()
            record = state["pools"].get(pool_id)
            if not record:
                raise IPAMError(f"unknown pool ID {pool_id!r}")
            network = _canonical_network(record["pool"], v6=bool(record.get("v6")))
            allocated = set(record.get("allocated") or [])
            requested = str(request.get("Address") or "").strip()
            if requested:
                address = _canonical_address(requested, network)
                if str(address) in allocated:
                    raise IPAMError(f"address {address} is already allocated in pool {network}")
            else:
                reserved = set(record.get("reserved") or [])
                address = self._next_available(
                    network,
                    allocated | reserved,
                    host_index=int(record.get("host_index", 0)),
                    host_count=int(record.get("host_count", 1)),
                )
            record["allocated"] = sorted(allocated | {str(address)})
            self._save(state)
        return {"Address": f"{address}/{network.prefixlen}", "Data": {}}

    def release_address(self, request: dict[str, Any]) -> dict[str, Any]:
        pool_id = str(request.get("PoolID") or "")
        raw_address = str(request.get("Address") or "").strip()
        with self._lock:
            state = self._load()
            record = state["pools"].get(pool_id)
            if not record:
                return {}
            network = _canonical_network(record["pool"], v6=bool(record.get("v6")))
            try:
                address = _canonical_address(raw_address, network)
            except IPAMError:
                return {}
            allocated = set(record.get("allocated") or [])
            if str(address) in allocated:
                record["allocated"] = sorted(allocated - {str(address)})
                self._save(state)
        return {}

    # Docker network-driver API -----------------------------------------
    def create_network(self, request: dict[str, Any], ops: NetworkOps) -> dict[str, Any]:
        network_id = str(request.get("NetworkID") or "").strip()
        if not network_id:
            raise NetworkDriverError("CreateNetwork is missing NetworkID")
        config = _network_config(request)
        ops.validate_bridge_vrf(config["bridge"], config["vrf"])
        with self._lock:
            state = self._load()
            existing = state["networks"].get(network_id)
            if existing:
                comparable = {key: existing.get(key, "") for key in config}
                if comparable != config:
                    raise NetworkDriverError(f"network {network_id} configuration changed")
                return {}
            state["networks"][network_id] = config
            self._save(state)
        return {}

    def delete_network(self, request: dict[str, Any], ops: NetworkOps) -> dict[str, Any]:
        network_id = str(request.get("NetworkID") or "").strip()
        if not network_id:
            raise NetworkDriverError("DeleteNetwork is missing NetworkID")
        with self._lock:
            state = self._load()
            endpoint_ids = [
                endpoint_id
                for endpoint_id, endpoint in state["endpoints"].items()
                if endpoint.get("network_id") == network_id
            ]
            host_ifaces = [
                str(state["endpoints"][endpoint_id].get("host_iface") or "")
                for endpoint_id in endpoint_ids
            ]
        for host_iface in host_ifaces:
            if host_iface:
                ops.delete_link(host_iface)
        with self._lock:
            state = self._load()
            state["networks"].pop(network_id, None)
            for endpoint_id in endpoint_ids:
                state["endpoints"].pop(endpoint_id, None)
            self._save(state)
        return {}

    def create_endpoint(self, request: dict[str, Any]) -> dict[str, Any]:
        network_id = str(request.get("NetworkID") or "").strip()
        endpoint_id = str(request.get("EndpointID") or "").strip()
        if not network_id or not endpoint_id:
            raise NetworkDriverError("CreateEndpoint is missing NetworkID or EndpointID")
        interface = request.get("Interface") or {}
        if not isinstance(interface, dict):
            raise NetworkDriverError("endpoint Interface must be an object")
        with self._lock:
            state = self._load()
            network = state["networks"].get(network_id)
            if not network:
                raise NetworkDriverError(f"unknown network {network_id}")
            ipv4_network = ipaddress.ip_network(network["ipv4_subnet"], strict=False)
            endpoint = {
                "network_id": network_id,
                "ipv4": _network_driver_address(
                    interface.get("Address"), ipv4_network, field="endpoint IPv4 address",
                ),
                "ipv6": "",
                "mac": str(interface.get("MacAddress") or "").strip(),
                "host_iface": "",
                "sandbox_iface": "",
            }
            if endpoint["mac"] and not _MAC_RE.fullmatch(endpoint["mac"]):
                raise NetworkDriverError("endpoint MAC address is invalid")
            if network.get("ipv6_subnet"):
                ipv6_network = ipaddress.ip_network(network["ipv6_subnet"], strict=False)
                endpoint["ipv6"] = _network_driver_address(
                    interface.get("AddressIPv6"), ipv6_network, field="endpoint IPv6 address",
                )
            existing = state["endpoints"].get(endpoint_id)
            if existing:
                comparable_keys = ("network_id", "ipv4", "ipv6", "mac")
                if any(existing.get(key, "") != endpoint[key] for key in comparable_keys):
                    raise NetworkDriverError(f"endpoint {endpoint_id} configuration changed")
                return {}
            state["endpoints"][endpoint_id] = endpoint
            self._save(state)
        return {}

    def delete_endpoint(self, request: dict[str, Any], ops: NetworkOps) -> dict[str, Any]:
        network_id = str(request.get("NetworkID") or "").strip()
        endpoint_id = str(request.get("EndpointID") or "").strip()
        if not network_id or not endpoint_id:
            raise NetworkDriverError("DeleteEndpoint is missing NetworkID or EndpointID")
        self.leave(request, ops)
        with self._lock:
            state = self._load()
            endpoint = state["endpoints"].get(endpoint_id)
            if endpoint and endpoint.get("network_id") == network_id:
                state["endpoints"].pop(endpoint_id, None)
                self._save(state)
        return {}

    def join(self, request: dict[str, Any], ops: NetworkOps) -> dict[str, Any]:
        network_id = str(request.get("NetworkID") or "").strip()
        endpoint_id = str(request.get("EndpointID") or "").strip()
        if not network_id or not endpoint_id:
            raise NetworkDriverError("Join is missing NetworkID or EndpointID")
        with self._lock:
            state = self._load()
            network = state["networks"].get(network_id)
            endpoint = state["endpoints"].get(endpoint_id)
            if not network or not endpoint or endpoint.get("network_id") != network_id:
                raise NetworkDriverError(f"unknown endpoint {endpoint_id} on network {network_id}")
            host_iface = str(endpoint.get("host_iface") or "")
            sandbox_iface = str(endpoint.get("sandbox_iface") or "")
            if host_iface or sandbox_iface:
                if host_iface and sandbox_iface and ops.link_exists(host_iface) and ops.link_exists(sandbox_iface):
                    return self._join_response(network, sandbox_iface)
                if host_iface:
                    ops.delete_link(host_iface)
                endpoint["host_iface"] = ""
                endpoint["sandbox_iface"] = ""
            host_iface, sandbox_iface = _endpoint_interface_names(network_id, endpoint_id)
            if ops.link_exists(host_iface) or ops.link_exists(sandbox_iface):
                raise NetworkDriverError(
                    f"refusing to reuse unexpected veth name for endpoint {endpoint_id}"
                )
            # Persist the intended interface before creating it.  A service
            # restart in the small gap is then recoverable by a later Join.
            endpoint["host_iface"] = host_iface
            endpoint["sandbox_iface"] = sandbox_iface
            self._save(state)

        try:
            ops.create_veth(host_iface, sandbox_iface, network["bridge"])
        except Exception:
            with self._lock:
                state = self._load()
                endpoint = state["endpoints"].get(endpoint_id)
                if endpoint and endpoint.get("host_iface") == host_iface:
                    endpoint["host_iface"] = ""
                    endpoint["sandbox_iface"] = ""
                    self._save(state)
            raise
        return self._join_response(network, sandbox_iface)

    def leave(self, request: dict[str, Any], ops: NetworkOps) -> dict[str, Any]:
        network_id = str(request.get("NetworkID") or "").strip()
        endpoint_id = str(request.get("EndpointID") or "").strip()
        if not network_id or not endpoint_id:
            raise NetworkDriverError("Leave is missing NetworkID or EndpointID")
        with self._lock:
            state = self._load()
            endpoint = state["endpoints"].get(endpoint_id)
            if not endpoint or endpoint.get("network_id") != network_id:
                return {}
            host_iface = str(endpoint.get("host_iface") or "")
        if host_iface:
            ops.delete_link(host_iface)
        with self._lock:
            state = self._load()
            endpoint = state["endpoints"].get(endpoint_id)
            if endpoint and endpoint.get("network_id") == network_id:
                endpoint["host_iface"] = ""
                endpoint["sandbox_iface"] = ""
                self._save(state)
        return {}

    @staticmethod
    def _join_response(network: dict[str, str], sandbox_iface: str) -> dict[str, Any]:
        response: dict[str, Any] = {
            "InterfaceName": {"SrcName": sandbox_iface, "DstPrefix": "eth"},
            "Gateway": network["ipv4_gateway"],
        }
        if network.get("ipv6_gateway"):
            response["GatewayIPv6"] = network["ipv6_gateway"]
        return response

    @staticmethod
    def _parse_reserved(
        raw: Any,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> list[str]:
        values = [item.strip() for item in str(raw or "").split(",") if item.strip()]
        reserved = set()
        for item in values:
            try:
                address = ipaddress.ip_interface(item).ip if "/" in item else ipaddress.ip_address(item)
            except ValueError as exc:
                raise IPAMError(f"invalid reserved address {item!r}: {exc}") from exc
            # Docker passes one IPAM option map to both pool families. The
            # dNLab infrastructure reservations are IPv4, so they are not
            # meaningful for an IPv6 RequestPool.
            if address.version != network.version:
                continue
            reserved.add(_canonical_address(item, network))
        return sorted(str(item) for item in reserved)

    @staticmethod
    def _partition_options(options: dict[str, Any]) -> tuple[int, int]:
        raw_index = options.get(HOST_INDEX_OPTION)
        raw_count = options.get(HOST_COUNT_OPTION)
        if raw_index is None and raw_count is None:
            return 0, 1
        try:
            index = int(raw_index)
            count = int(raw_count)
        except (TypeError, ValueError) as exc:
            raise IPAMError("invalid dNLab host partition options") from exc
        if count < 1 or index < 0 or index >= count:
            raise IPAMError(f"invalid dNLab host partition {index}/{count}")
        return index, count

    @staticmethod
    def _next_available(
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        unavailable: set[str],
        *,
        host_index: int,
        host_count: int,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        first = int(network.network_address) + 1
        # dNLab uses the final address as Docker's gateway. Reserving the
        # final address in both families keeps it out of dynamic allocation.
        last = int(network.broadcast_address) - 1
        total = last - first + 1
        if total < host_count:
            raise IPAMError(f"no dynamic host partition available in pool {network}")
        block, remainder = divmod(total, host_count)
        size = block + (1 if host_index < remainder else 0)
        start = first + host_index * block + min(host_index, remainder)
        for value in range(start, start + size):
            address = ipaddress.ip_address(value)
            if str(address) not in unavailable:
                return address
        raise IPAMError(f"no available addresses in pool {network}")

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": STATE_VERSION, "pools": {}, "networks": {}, "endpoints": {}}
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise PluginError(f"cannot load plugin state {self.path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("pools"), dict):
            raise PluginError(f"invalid plugin state format in {self.path}")
        if data.get("version", 1) not in {1, STATE_VERSION}:
            raise PluginError(f"unsupported plugin state version in {self.path}")
        data["version"] = STATE_VERSION
        data.setdefault("networks", {})
        data.setdefault("endpoints", {})
        if not isinstance(data["networks"], dict) or not isinstance(data["endpoints"], dict):
            raise PluginError(f"invalid plugin network state in {self.path}")
        return data

    def _save(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


class VRFRequestHandler(BaseHTTPRequestHandler):
    """HTTP-over-Unix-socket handler implementing Docker's remote APIs."""

    server_version = "dnlab-vrf/1"

    @property
    def store(self) -> PluginStore:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def ops(self) -> NetworkOps:
        return self.server.ops  # type: ignore[attr-defined]

    def do_POST(self) -> None:  # noqa: N802 - mandated by BaseHTTPRequestHandler
        endpoint = self.path.rstrip("/")
        try:
            payload = self._read_payload()
            response = self._dispatch(payload)
        except IPAMError as exc:
            response = {"Error": str(exc)}
        except NetworkDriverError as exc:
            response = {"Err": str(exc)}
        except PluginError as exc:
            response = {"Error" if endpoint.startswith("/IpamDriver") else "Err": str(exc)}
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            key = "Error" if endpoint.startswith("/IpamDriver") else "Err"
            response = {key: f"internal {PLUGIN_NAME} error: {exc}"}
        body = json.dumps(response, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.docker.plugins.v1.2+json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - mandated by BaseHTTPRequestHandler
        self.send_error(405, "POST required")

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _read_payload(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise PluginError("invalid Content-Length") from exc
        if length < 0 or length > 1024 * 1024:
            raise PluginError("invalid request size")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginError(f"invalid JSON request: {exc}") from exc
        if not isinstance(payload, dict):
            raise PluginError("request body must be a JSON object")
        return payload

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        endpoint = self.path.rstrip("/")
        if endpoint == "/Plugin.Activate":
            return {"Implements": ["NetworkDriver", "IpamDriver"]}

        if endpoint == "/IpamDriver.GetCapabilities":
            return {"RequiresMACAddress": False, "RequiresRequestReplay": False}
        if endpoint == "/IpamDriver.GetDefaultAddressSpaces":
            return {
                "LocalDefaultAddressSpace": "dnlab-vrf-local",
                "GlobalDefaultAddressSpace": "dnlab-vrf-global",
            }
        if endpoint == "/IpamDriver.RequestPool":
            return self.store.request_pool(request)
        if endpoint == "/IpamDriver.ReleasePool":
            return self.store.release_pool(request)
        if endpoint == "/IpamDriver.RequestAddress":
            return self.store.request_address(request)
        if endpoint == "/IpamDriver.ReleaseAddress":
            return self.store.release_address(request)

        if endpoint == "/NetworkDriver.GetCapabilities":
            return {"Scope": "local", "ConnectivityScope": "local"}
        if endpoint == "/NetworkDriver.CreateNetwork":
            return self.store.create_network(request, self.ops)
        if endpoint == "/NetworkDriver.DeleteNetwork":
            return self.store.delete_network(request, self.ops)
        if endpoint == "/NetworkDriver.CreateEndpoint":
            return self.store.create_endpoint(request)
        if endpoint == "/NetworkDriver.DeleteEndpoint":
            return self.store.delete_endpoint(request, self.ops)
        if endpoint == "/NetworkDriver.Join":
            return self.store.join(request, self.ops)
        if endpoint == "/NetworkDriver.Leave":
            return self.store.leave(request, self.ops)
        if endpoint == "/NetworkDriver.EndpointOperInfo":
            return {}
        if endpoint in {
            "/NetworkDriver.ProgramExternalConnectivity",
            "/NetworkDriver.RevokeExternalConnectivity",
            "/NetworkDriver.DiscoverNew",
            "/NetworkDriver.DiscoverDelete",
            "/NetworkDriver.AllocateNetwork",
            "/NetworkDriver.FreeNetwork",
        }:
            return {}
        raise PluginError(f"unsupported Docker plugin endpoint {endpoint!r}")


class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(
    socket_path: str | Path,
    state_path: str | Path,
    *,
    ops: NetworkOps | None = None,
) -> None:
    socket_file = Path(socket_path)
    socket_file.parent.mkdir(parents=True, exist_ok=True)
    if socket_file.exists() or socket_file.is_symlink():
        socket_file.unlink()
    server = ThreadingUnixHTTPServer(str(socket_file), VRFRequestHandler)
    server.store = PluginStore(state_path)  # type: ignore[attr-defined]
    server.ops = ops or NetworkOps()  # type: ignore[attr-defined]
    os.chmod(socket_file, 0o660)

    def _stop(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            socket_file.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="dNLab per-VRF Docker network and IPAM plugin"
    )
    parser.add_argument("--socket", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args(argv)
    serve(args.socket, args.state)


if __name__ == "__main__":
    main(sys.argv[1:])
