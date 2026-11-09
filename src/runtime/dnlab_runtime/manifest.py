"""Versioned local requests, with an intentionally small supported surface."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re


class RuntimeErrorBase(Exception):
    status = 422


class Conflict(RuntimeErrorBase):
    status = 409


class NotFound(RuntimeErrorBase):
    status = 404


class Busy(RuntimeErrorBase):
    status = 503


def canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value: dict) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value):
        raise RuntimeErrorBase(f"invalid {field}")
    return value


def validate_request(value: dict) -> dict:
    if not isinstance(value, dict):
        raise RuntimeErrorBase("request must be an object")
    allowed = {"schema_version", "request_id", "lab_id", "node_id", "expected_revision", "action", "spec", "force", "stop_mode", "lab_generation", "expected_stop_fingerprint", "management_preflight"}
    if set(value) - allowed:
        raise RuntimeErrorBase("unknown request fields")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise RuntimeErrorBase("schema_version must be 1")
    for field in ("request_id", "lab_id", "node_id"):
        identifier(value.get(field), field)
    epoch=value.get("lab_generation",1)
    if type(epoch) is not int or epoch<1:raise RuntimeErrorBase("lab_generation must be positive integer")
    revision = value.get("expected_revision")
    if type(revision) is not int or revision < 0:
        raise RuntimeErrorBase("expected_revision must be a nonnegative integer")
    if value.get("action") not in {"start", "stop"}:
        raise RuntimeErrorBase("supported actions: start, stop")
    if type(value.get("force", False)) is not bool:
        raise RuntimeErrorBase("force must be boolean")
    if 'stop_mode' in value and (value['action'] != 'stop' or value['stop_mode'] != 'coordinated'):
        raise RuntimeErrorBase('stop_mode must be coordinated on stop only')
    if 'expected_stop_fingerprint' in value and (value.get('stop_mode')!='coordinated' or not isinstance(value['expected_stop_fingerprint'],str) or not re.fullmatch(r'[0-9a-f]{64}',value['expected_stop_fingerprint'])):
        raise RuntimeErrorBase('invalid coordinated stop fingerprint')
    if value["action"] == "start":
        if value.get("force"):
            raise RuntimeErrorBase("force is only valid for stop")
        validate_spec(value.get("spec"))
    elif "spec" in value:
        raise RuntimeErrorBase("stop uses the committed node spec")
    if 'management_preflight' in value:
        proof=value['management_preflight']
        if (value['action']!='start' or not isinstance(proof,dict)
                or set(proof)!={'journal_id','request_fingerprint','management','network'}
                or not isinstance(proof['journal_id'],str) or not re.fullmatch(r'[0-9a-f]{32}',proof['journal_id'])
                or proof['request_fingerprint']!=fingerprint({k:v for k,v in value.items() if k!='management_preflight'})
                or not isinstance(proof['management'],dict) or not isinstance(proof['network'],dict)):
            raise RuntimeErrorBase('invalid management preflight context')
    return json.loads(canonical(value))


def validate_spec(spec: dict) -> None:
    if not isinstance(spec, dict):
        raise RuntimeErrorBase("start requires spec")
    allowed = {"kind", "image", "container_name", "command", "env", "management", "ports", "endpoints", "stop_timeout"}
    if set(spec) - allowed:
        raise RuntimeErrorBase("unknown spec fields")
    if spec.get("kind") != "linux":
        raise RuntimeErrorBase("only native linux is implemented; vrnetlab adapters are not qualified")
    identifier(spec.get("container_name"), "container_name")
    if not isinstance(spec.get("image"), str) or not re.fullmatch(r"(?:[^\s@]+@)?sha256:[0-9a-f]{64}", spec["image"]):
        raise RuntimeErrorBase("image must be pinned as repository@sha256:digest or immutable local sha256 ID")
    command = spec.get("command")
    if command is not None and (not isinstance(command, list) or not command or any(not isinstance(s, str) for s in command)):
        raise RuntimeErrorBase("command must be a nonempty array of strings")
    env = spec.get("env", {})
    if not isinstance(env, dict) or any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or not isinstance(v, str) for k, v in env.items()):
        raise RuntimeErrorBase("env must map variable names to strings")
    timeout = spec.get("stop_timeout", 30)
    if type(timeout) is not int or not 1 <= timeout <= 900:
        raise RuntimeErrorBase("stop_timeout must be 1..900 seconds")
    management = spec.get("management")
    if management is not None:
        if not isinstance(management, dict) or set(management) - {"network", "ipv4", "ipv6", "mac"}:
            raise RuntimeErrorBase("invalid management")
        identifier(management.get("network"), "management.network")
        if 'mac' in management:
            mac=management['mac']
            if (not isinstance(mac,str) or not re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}',mac)
                    or int(mac[:2],16)&1 or mac=='00:00:00:00:00:00'):
                raise RuntimeErrorBase('management.mac must be a canonical nonzero unicast MAC')
        for key, family in (("ipv4", 4), ("ipv6", 6)):
            if key in management:
                try:
                    address = ipaddress.ip_address(management[key])
                except (ValueError, TypeError):
                    raise RuntimeErrorBase(f"invalid management.{key}") from None
                if address.version != family:
                    raise RuntimeErrorBase(f"invalid management.{key} address family")
    ports = spec.get("ports", [])
    if not isinstance(ports, list) or (ports and management is None):
        raise RuntimeErrorBase("ports require a management network")
    allocations = set()
    for port in ports:
        if not isinstance(port, dict) or set(port) != {"container_port", "host_port", "host_ip", "protocol"}:
            raise RuntimeErrorBase("invalid port binding")
        for key in ("container_port", "host_port"):
            if type(port[key]) is not int or not 1 <= port[key] <= 65535:
                raise RuntimeErrorBase(f"invalid {key}")
        try:
            ipaddress.ip_address(port["host_ip"])
        except (ValueError, TypeError):
            raise RuntimeErrorBase("invalid port host_ip") from None
        if port["protocol"] not in {"tcp", "udp"}:
            raise RuntimeErrorBase("invalid port protocol")
        key = (port["host_ip"], port["host_port"], port["protocol"])
        if key in allocations:
            raise RuntimeErrorBase("duplicate host port")
        allocations.add(key)
    endpoints = spec.get("endpoints", [])
    if not isinstance(endpoints, list):
        raise RuntimeErrorBase("endpoints must be an array")
    host_names, node_names = set(), {"eth0"} if management else set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or set(endpoint) - {"host_interface", "node_interface", "mtu"}:
            raise RuntimeErrorBase("invalid endpoint")
        for key in ("host_interface", "node_interface"):
            name = endpoint.get(key)
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", name) or name == "lo":
                raise RuntimeErrorBase(f"invalid {key}")
        if endpoint["host_interface"] in host_names or endpoint["node_interface"] in node_names:
            raise RuntimeErrorBase("duplicate/reserved interface")
        host_names.add(endpoint["host_interface"])
        node_names.add(endpoint["node_interface"])
        mtu = endpoint.get("mtu", 1500)
        if type(mtu) is not int or not 576 <= mtu <= 9216:
            raise RuntimeErrorBase("invalid endpoint mtu")
    staging_names={'drp'+hashlib.sha256(name.encode()).hexdigest()[:12] for name in host_names}
    if len(staging_names)!=len(host_names) or staging_names & (host_names | node_names):
        raise RuntimeErrorBase('endpoint permanent and staging names overlap')


def capabilities() -> dict:
    return {
        "schema_version": 1,
        "experimental": True,
        "kinds": ["linux"],
        "actions": ["start", "stop"],
        "link_actions": ["create", "delete", "recover"],
        "link_kinds": ["vxlan", "bridge"],
        "link_endpoint_ownership": "committed native-linux node revision and kernel identity",
        "persistent_operations": True,
        "management_mac_identity": "optional native endpoint MAC; verified lifecycle; stable across restart",
        "initial_node_preflight": "read-only committed/workload/operation snapshot for initial starts",
        "resource_preflight": "read-only journal reservations; atomic admission before mutation",
        "management_barrier": "offline workload fence v2; read-only preflight; acquisition cancellation tombstones; provisioning seal",
        "lab_closure": "durable closing fence; qualified stop children only; explicit generation reopen",
        "runtime_cleanup": "verified exited local stop; durable coordinator intent; no generic removal",
        "node_inspection": "consistent committed node, qualified workload and pending operation",
        "workload_generation": "durable birth nonce and Docker ID; no implicit replacement adoption",
        "management_preflight": "read-only management proof; request-bound apply and recovery before allocation",
        "endpoint_preflight": "read-only data endpoint preflight; durable allocation evidence before create",
        "management_network_identity": "durable initial network ID/configuration; retained across stop; no implicit adoption",
        "node_ownership": "committed node revision, container labels and index-bound kernel endpoint identity",
        "request_controls": "lab/node request lookup and durable cancellation before submit",
        "request_content_check": True,
        "stop_plan_binding": "exact preflight footprint fingerprint before shutdown",
        "coordinated_stop": "verified exit, explicit local cleanup, explicit finalization",
        "cancellation": True,
        "safe_guest_shutdown": False,
        "linux_stop": "SIGTERM and observed process exit; timeout never escalates to SIGKILL",
        "live_management_move": False,
        "vrnetlab": False,
        "distributed_management_creation": False,
    }


def check_management_identity(request,current):
    if request['action']!='start' or not current:return
    previous=(current['spec'].get('management') or {}).get('mac')
    requested=(request['spec'].get('management') or {}).get('mac')
    if previous is not None and requested!=previous:
        raise Conflict('native management MAC identity cannot change across restart')
