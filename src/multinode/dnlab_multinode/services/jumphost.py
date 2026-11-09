"""Jump host container management.

The jumphost network is **shared infrastructure**: a single docker network
(default ``dnlab-jumphost``, configurable via
``infrastructure.jumphost_net`` in ``hosts.yml``) lives on the master and
hosts every lab's jumphost container. The image is derived from the active
dNLab product version; the IP is auto-assigned from the pool at deploy time by
inspecting the docker network for IPs already in use.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import shlex
import string
import time
import uuid

from pathlib import Path, PurePosixPath

from dnlab_multinode.models.topology import DistributedTopology, JumphostNet
from dnlab_multinode.services.images import image_for
from dnlab_multinode.services.mgmt_ips import ipv4_reservations
from dnlab_multinode.services.paths import PATHS
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.utils.naming import jumphost_container_name

log = logging.getLogger(__name__)


def _render_inventory_motd(lab_name: str, vd_names: list[str]) -> str:
    lines = [
        "",
        "======================================================",
        f"  Lab: {lab_name}",
        "  Virtual Devices in this lab:",
        *(f"    - {name}" for name in vd_names),
        "",
        "  Commands:",
        "    vd list             → list virtual devices",
        "    vd connect <name>   → open console",
        "    vd log <name>       → show container log history",
        "    vd log -f <name>    → follow container log in real time",
        "    vd help             → show command help",
        "======================================================",
        "",
    ]
    return "\n".join(lines) + "\n"


def refresh_jumphost_inventory(
    lab_name: str,
    client: SSHClient,
    vd_map: dict[str, str],
    relay_map: dict[str, dict],
    *, generation: str | None = None,
) -> None:
    """Refresh VD/relay maps and banner through the original tracked generation."""
    record = _guard(client, lab_name, "read")
    if record.get("phase") != "active":
        raise RuntimeError("Jumphost inventory requires an active qualified generation")
    if generation is not None and record["config"]["generation"] != generation:
        raise RuntimeError("Jumphost inventory coordinator generation differs")
    vd_content, relay_content = render_relay_inventory(vd_map, relay_map)
    _guard(client, lab_name, "inventory-refresh", {
        "lab": lab_name, "generation": record["config"]["generation"],
        "container_id": record["container_id"], "request_id": uuid.uuid4().hex,
        "vds": vd_content, "relays": relay_content,
        "motd": _render_inventory_motd(lab_name, sorted(vd_map)),
    })
    log.info("Jumphost inventory refreshed: %d VDs", len(vd_map))


def render_relay_inventory(vd_map, relay_map):
    """Validate complete relay coverage before publishing either inventory."""
    import re
    token = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
    if (not isinstance(vd_map, dict) or not isinstance(relay_map, dict)
            or any(not isinstance(v, str) or not token.fullmatch(v) for pair in vd_map.items() for v in pair)
            or len(set(vd_map.values())) != len(vd_map)):
        raise RuntimeError("Invalid VD inventory")
    if not set(vd_map.values()) <= set(relay_map):
        raise RuntimeError("Runtime relay missing for VD inventory")
    rows = []
    for runtime in sorted(vd_map.values()):
        meta = relay_map[runtime]
        native_fields={"host","port","api_key","runtime_backend","container_id"}
        if (not isinstance(meta, dict) or set(meta) not in ({"host", "port", "api_key"},native_fields)
                or not isinstance(meta["host"], str) or not token.fullmatch(meta["host"])
                or type(meta["port"]) is not int or not 1 <= meta["port"] <= 65535
                or not isinstance(meta["api_key"], str) or not token.fullmatch(meta["api_key"])):
            raise RuntimeError("Invalid runtime relay inventory")
        suffix=''
        if set(meta)==native_fields:
            if meta['runtime_backend']!='custom' or not isinstance(meta['container_id'],str) or not re.fullmatch('[0-9a-f]{64}',meta['container_id']):
                raise RuntimeError('Invalid native relay identity')
            suffix=':custom:'+meta['container_id']
        rows.append(f"{runtime}={meta['host']}:{meta['port']}:{meta['api_key']}{suffix}\n")
    return "".join(f"{name}={vd_map[name]}\n" for name in sorted(vd_map)), "".join(rows)


def relay_inventory_from_state(state, *, verified_bindings=None):
    """Bind allowlist entries to each VD's current placement; never guess."""
    from . import native_public
    mode=getattr(state,'runtime_mode','')
    if mode not in ('','legacy','per-vd','custom'):raise RuntimeError('Unknown persisted runtime backend')
    native=bool(mode=='custom' or any(getattr(r,'runtime_binding',{}) for r in
                [*state.node_runtime.values(),*getattr(state,'retired_native_nodes',{}).values()]))
    if native:
        native_public.backend(state)
        if verified_bindings!={k:r.runtime_binding for k,r in state.node_runtime.items()}:
            raise RuntimeError('Native relay inventory requires verified bindings')
    result = {}
    for runtime in state.node_runtime.values():
        relay = state.runtime_relays.get(runtime.host)
        if (relay is None or relay.host != runtime.host or runtime.container not in relay.allowed):
            raise RuntimeError("Runtime relay placement or allowlist differs")
        result[runtime.container] = {"host": relay.bind_ip, "port": relay.port, "api_key": relay.api_key}
        if native:
            result[runtime.container].update(runtime_backend='custom',container_id=runtime.runtime_binding['container_id'])
    render_relay_inventory({r.node: r.container for r in state.node_runtime.values()}, result)
    return result


def generate_password(length: int = 12) -> str:
    """Generate a random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_jumphost_network(client: SSHClient, net: JumphostNet, *, action: str = "ensure") -> dict:
    """Qualify persistent shared infrastructure; never delete it per lab.

    Unqualified existing networks and incomplete births require an explicit
    infrastructure decision/recovery. No shell error is interpreted as absence.
    """
    from .jumphost_network_host import config
    value = config(dict(network=net.network, bridge=net.bridge, subnet=net.ipv4_subnet, gateway=net.ipv4_gw))
    if action not in ("ensure", "preflight", "recover"):
        raise RuntimeError("Unsupported jumphost network action")
    socket_path = PATHS.docker_socket
    if not socket_path.startswith("unix://"):
        raise RuntimeError("Jumphost network requires a Docker Unix socket")
    request = dict(config=value, action=action, directory=PATHS.jumphost_network_journal_dir, socket=socket_path[7:])
    program = Path(__file__).with_name("jumphost_network_host.py").read_text()
    try:
        ack = json.loads(client.run_input(shlex.join(["python3", "-c", program]), json.dumps(request), timeout=120))
    except Exception as error:
        raise RuntimeError("Shared jumphost network rejected or requires explicit infrastructure recovery") from error
    expected = "verified" if action == "preflight" else "active"
    if (not isinstance(ack, dict) or ack.get("status") != expected
            or (action != "preflight" or ack.get("network_id") is not None)
               and (not isinstance(ack.get("network_id"), str) or len(ack["network_id"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in ack["network_id"]))):
        raise RuntimeError("Invalid shared jumphost network acknowledgement")
    return ack


_JUMPHOST_NAME_PREFIX = "dnlab-"
_JUMPHOST_NAME_SUFFIX = "-jumphost"


def parse_port_range(spec: str) -> tuple[int, int]:
    """Parse a ``"<low>-<high>"`` string into an inclusive port range.

    Raises ``ValueError`` if the format is wrong or the range invalid.
    """
    if "-" not in spec:
        raise ValueError(f"port range must be '<low>-<high>', got {spec!r}")
    low_s, high_s = spec.split("-", 1)
    low, high = int(low_s), int(high_s)
    if not (1 <= low <= high <= 65535):
        raise ValueError(
            f"port range {spec!r} invalid (require 1 <= low <= high <= 65535)"
        )
    return low, high


def _ports_in_use_on_master(client: SSHClient, bind_ip: str) -> set[int]:
    """Return the host-side TCP ports already published by other labs'
    jumphosts on ``bind_ip``.

    We only look at containers named ``dnlab-*-jumphost`` so that user
    topologies with overlapping bind ranges elsewhere don't poison the
    allocator. The bind IP is matched exactly (``0.0.0.0`` does NOT
    collide with a specific IP and vice-versa).
    """
    # `docker ps` format: <name>\t<ports>
    # Ports look like: "0.0.0.0:2201->22/tcp, :::2201->22/tcp"
    rc, out, _ = client.run_no_check(
        "docker ps --filter 'name=" + _JUMPHOST_NAME_PREFIX + "' "
        "--format '{{.Names}}\t{{.Ports}}'"
    )
    if rc != 0 or not out:
        return set()

    used: set[int] = set()
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        name, ports = parts[0].strip(), parts[1].strip()
        if not name.endswith(_JUMPHOST_NAME_SUFFIX):
            continue
        # Each mapping is "<host-ip>:<host-port>-><cont-port>/<proto>".
        for chunk in ports.split(","):
            chunk = chunk.strip()
            if "->" not in chunk:
                continue
            lhs = chunk.split("->", 1)[0]
            # "host-ip:port" or "[::]:port"
            if ":" not in lhs:
                continue
            ip_part, _, port_part = lhs.rpartition(":")
            if ip_part != bind_ip:
                continue
            try:
                used.add(int(port_part))
            except ValueError:
                continue
    return used


def allocate_jumphost_ssh_port(
    client: SSHClient, bind_ip: str, port_range: str,
) -> int:
    """Pick the first free TCP port in ``port_range`` on ``bind_ip``.

    Only looks at existing ``dnlab-*-jumphost`` containers on the master;
    non-jumphost services on the same port will cause the ``docker run``
    to fail later (fail-fast is fine — operator chose the range).
    """
    low, high = parse_port_range(port_range)
    used = _ports_in_use_on_master(client, bind_ip)
    for port in range(low, high + 1):
        if port not in used:
            return port
    raise RuntimeError(
        f"Jumphost SSH port range {port_range} on {bind_ip} exhausted "
        f"({len(used)} in use). Widen the range in hosts.yml or destroy "
        f"an idle lab."
    )


def allocate_jumphost_ip(client: SSHClient, net: JumphostNet) -> str:
    """Pick a free IP from the shared jumphost network.

    Returns the IP as a CIDR string (``<ip>/<prefix>``) so callers can
    pass it to ``docker network connect --ip`` and store it in state.

    The allocation algorithm:
      1. ``docker network inspect`` to enumerate IPs currently assigned.
      2. Walk the subnet hosts skipping the gateway and reserved addresses.
      3. Return the first unallocated IP.
    """
    rc, out, _ = client.run_no_check(
        "docker network inspect -f "
        "'{{range .Containers}}{{.IPv4Address}} {{end}}' "
        f"{net.network}"
    )
    if rc != 0:
        raise RuntimeError(
            f"Cannot inspect jumphost network '{net.network}'. "
            f"Ensure_jumphost_network() must run first."
        )

    # Output is space-separated list of "<ip>/<prefix>"; strip prefix.
    used: set[str] = set()
    for tok in (out or "").split():
        tok = tok.strip()
        if not tok:
            continue
        ip = tok.split("/")[0]
        if ip:
            used.add(ip)

    subnet = ipaddress.ip_network(net.ipv4_subnet)
    gateway = net.ipv4_gw
    prefix = subnet.prefixlen

    for candidate in subnet.hosts():
        ip_str = str(candidate)
        if ip_str == gateway:
            continue
        if ip_str in used:
            continue
        return f"{ip_str}/{prefix}"

    raise RuntimeError(
        f"Jumphost network '{net.network}' subnet {net.ipv4_subnet} exhausted "
        f"(no free IP). Free some lab jumphosts or enlarge the subnet."
    )


def render_dhcp_config(topo: DistributedTopology, resolver_ip: str | None = None) -> str:
    """Return dnsmasq configuration with reservation-only dual-stack DHCP."""
    if not topo.mgmt.dhcp:
        return ""
    network4 = ipaddress.IPv4Network(topo.mgmt.ipv4_subnet, strict=False)
    lines = [
        "interface=eth1", "bind-dynamic", "dhcp-authoritative",
        "pid-file=/run/dnlab-dnsmasq.pid",
        f"dhcp-range=set:mgmt,{network4.network_address},static,12h",
        f"dhcp-option=tag:mgmt,option:router,{topo.mgmt.ipv4_gw}",
    ]
    if resolver_ip:
        lines.append(f"dhcp-option=tag:mgmt,option:dns-server,{resolver_ip}")
    if topo.mgmt.ipv6_subnet:
        network6 = ipaddress.IPv6Network(topo.mgmt.ipv6_subnet, strict=False)
        lines.extend(["enable-ra",
            f"dhcp-range=set:mgmt,{network6.network_address},static,{network6.prefixlen},12h",
            "ra-param=eth1,60,1800"])
    for name in sorted(topo.nodes):
        node = topo.nodes[name]
        lines.append(f"dhcp-host={node.mgmt_mac},{node.mgmt_ipv4}")
        if node.mgmt_ipv6:
            lines.append(f"dhcp-host=id:{node.mgmt_duid},[{node.mgmt_ipv6}]")
    return "\n".join(lines) + "\n"


def refresh_dhcp_config(
    topo: DistributedTopology, client: SSHClient, container: str, resolver_ip: str | None = None,
    *, generation: str | None = None, request_id: str | None = None,
) -> None:
    """Update only generation-qualified dynamic DHCP assets; recover on error."""
    if not topo.mgmt.dhcp:
        return
    if not generation:
        raise RuntimeError('DHCP refresh requires the original coordinator generation')
    _guard(client, topo.name, 'dhcp-refresh', {'container': container, 'generation': generation,
        'content': render_dhcp_config(topo, resolver_ip), 'request_id': request_id or uuid.uuid4().hex})


# Keep argv independent of worker size. Both source and request travel through
# the existing stdin transport; no remote temporary file or shell expansion.
_WORKER_BOOTSTRAP = """import io,json,sys
message=json.load(sys.stdin)
source=message['source']
sys.stdin=io.StringIO(json.dumps(message['request']))
exec(compile(source,'<dnlab-jumphost-worker>','exec'),{'__name__':'__main__'})
"""


def _guard(client, lab_name, action, config=None):
    """Run the root-local journal worker over the existing SSH boundary."""
    program = "INVENTORY_PROGRAM = " + repr((Path(__file__).resolve().parents[2] / "jumphost/inventory.py").read_text()) + "\n" + Path(__file__).with_name("jumphost_host.py").read_text()
    request = {"lab": lab_name, "action": action, "config": config,
               "directory": PATHS.jumphost_journal_dir, "management_directory": PATHS.management_journal_dir}
    try:
        value = json.loads(client.run_input(shlex.join(["python3", "-c", _WORKER_BOOTSTRAP]),
            json.dumps({"source":program,"request":request}, sort_keys=True, separators=(",", ":")), timeout=60))
    except Exception as error:
        raise RuntimeError("Jumphost operation rejected or recovery required; root-local journal retained") from error
    if not isinstance(value, dict) or "phase" not in value:
        raise RuntimeError("Invalid jumphost worker acknowledgement")
    return value


def add_jumphost_management_segment(lab_name, client, *, container_id, generation,
                                    request_id, attachment, management_intent, recover=False):
    """Internal append-only attachment operation; caller owns the offline barrier.

    Persist request_id and original parent binding before invocation. This does
    not alter the container birth configuration, DHCP structure, or public API.
    """
    request = dict(request_id=request_id, container_id=container_id, generation=generation,
                   attachment=attachment, management_intent=management_intent)
    return _guard(client, lab_name, 'segment-recover' if recover else 'segment-add', request)


def recover_jumphost(lab_name, client):
    """Explicitly continue the recorded operation, never recreate a lost generation."""
    return _guard(client, lab_name, "recover")


def deploy_jumphost(
    topo: DistributedTopology,
    client: SSHClient,
    mgmt_ip: str,
    resolver_ip: str | None = None,
    dhcp_config: str = "",
    vd_names: list[str] | None = None,
    vd_map: dict[str, str] | None = None,
    authorized_keys: str | None = None,
    relay_map: dict[str, dict] | None = None,
    ssh_bind_ip: str = "0.0.0.0",
    ssh_port_range: str = "2200-2299",
    generation: str | None = None,
) -> tuple[str, str, str, str, int]:
    """Provision or verify one journal-owned jumphost without implicit replacement.

    Pending operations require recover_jumphost(). A new explicit deploy after
    verified cleanup archives the previous generation before allocating another.
    The external Docker bridge continues to publish SSH; management is a manual
    veth on the lab bridge and does not change Docker's default endpoint.
    """
    container = jumphost_container_name(topo.name)
    previous = _guard(client, topo.name, "read")
    if previous["phase"] not in ("absent", "active", "cleaned"):
        raise RuntimeError("Explicit jumphost recovery required before deploy")
    active = previous["phase"] == "active"
    jh_net = topo.jumphost_net
    ensure_jumphost_network(client, jh_net)
    if active:
        password = previous["config"]["env"]["JUMPHOST_PASSWORD"]
        ssh_port = previous["config"]["port"]
        jh_ip = previous["config"]["ip"]
        lo, hi = parse_port_range(ssh_port_range)
        if not lo <= ssh_port <= hi:
            raise RuntimeError("Existing jumphost SSH port outside requested range")
    else:
        password = generate_password()
        ssh_port = allocate_jumphost_ssh_port(client, ssh_bind_ip, ssh_port_range)
        jh_ip = allocate_jumphost_ip(client, jh_net).split("/")[0]
    env = {"JUMPHOST_PASSWORD": password, "JUMPHOST_LAB_NAME": topo.name}
    if vd_names: env["JUMPHOST_VD_LIST"] = " ".join(vd_names)
    if vd_map: env["JUMPHOST_VD_MAP"] = " ".join(f"{name}={runtime}" for name, runtime in vd_map.items())
    if relay_map:
        _,content=render_relay_inventory(vd_map or {name:name for name in relay_map},relay_map)
        env["JUMPHOST_RELAY_MAP"] = " ".join(content.splitlines())
    if authorized_keys: env["JUMPHOST_AUTHORIZED_KEYS"] = authorized_keys
    if active:
        # Docker env is an immutable birth proof. Live inventory has its own
        # journal and must never rewrite this proof to follow placement changes.
        for key in ("JUMPHOST_VD_LIST", "JUMPHOST_VD_MAP", "JUMPHOST_RELAY_MAP"):
            env.pop(key, None)
            if key in previous["config"]["env"]: env[key] = previous["config"]["env"][key]

    attachment = {
        "segment": "default", "network": topo.mgmt.network, "bridge": topo.mgmt.bridge, "interface": "eth1",
        "ipv4": str(ipaddress.ip_interface(f"{mgmt_ip}/{ipaddress.ip_network(topo.mgmt.ipv4_subnet, strict=False).prefixlen}")),
        "ipv6": str(ipaddress.ip_interface(f"{topo.mgmt.ipv6_gw}/{ipaddress.ip_network(topo.mgmt.ipv6_subnet, strict=False).prefixlen}"))
                  if topo.mgmt.ipv6_gw and topo.mgmt.ipv6_subnet else "",
    }
    generation = generation or (previous["config"]["generation"] if active else uuid.uuid4().hex)
    config = {"lab": topo.name, "generation": generation, "name": container, "image": image_for("jumphost"),
              "network": {"name": jh_net.network, "bridge": jh_net.bridge, "subnet": jh_net.ipv4_subnet, "gateway": jh_net.ipv4_gw},
              "ip": jh_ip, "bind_ip": ssh_bind_ip, "port": ssh_port, "env": env,
              "dns": [resolver_ip] if resolver_ip else [], "binds": [], "dhcp": dhcp_config, "attachment": attachment}
    if not active or "management_intent" in previous["config"]:
        from .mgmt_network import _expected_network
        config["management_intent"] = _expected_network(topo, "master")
    record = _guard(client, topo.name, "provision" if previous["phase"] == "cleaned" else "ensure", config)
    if record["phase"] != "active": raise RuntimeError("Jumphost operation is not active")
    # Read-only qualification of the original ID, followed by SSH publication.
    # A publication error retains the journal and resources for explicit recovery.
    _verify_jumphost_ssh_publish(client, container=record["container_id"], ssh_bind_ip=ssh_bind_ip, ssh_port=ssh_port)
    if vd_map is not None and relay_map is not None and set(vd_map.values()) <= set(relay_map):
        refresh_jumphost_inventory(topo.name, client, vd_map, relay_map, generation=generation)
    prefix = ipaddress.ip_network(jh_net.ipv4_subnet, strict=False).prefixlen
    return container, password, jh_net.network, f"{jh_ip}/{prefix}", ssh_port


def _verify_jumphost_ssh_publish(
    client: SSHClient,
    *,
    container: str,
    ssh_bind_ip: str,
    ssh_port: int,
) -> None:
    """Wait for Docker's SSH port view to settle after the manual veth attach.

    Docker can briefly report no published port while it reconciles container
    networking. A stopped container is never retried: that is a real startup
    failure and its logs are included in the error.
    """
    expected = f"{ssh_bind_ip}:{ssh_port}"
    detail = "no docker port output"
    for attempt in range(20):
        rc, out, err = client.run_no_check(
            f"docker port {shlex.quote(container)} 22", timeout=15,
        )
        published = {line.strip() for line in (out or "").splitlines() if line.strip()}
        if rc == 0 and expected in published:
            return
        detail = (err or out or detail).strip()

        state_rc, state, _ = client.run_no_check(
            f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(container)}", timeout=15,
        )
        if state_rc != 0 or state.strip() != "true":
            _, logs, _ = client.run_no_check(
                f"docker logs {shlex.quote(container)} 2>&1 | tail -40", timeout=15,
            )
            raise RuntimeError(
                f"Jumphost container '{container}' stopped while management network was attached; "
                f"SSH port {expected}->22/tcp was not published ({detail!r}).\n"
                f"--- docker logs (last 40 lines) ---\n{logs}\n-----------------------------------"
            )
        if attempt < 19:
            time.sleep(0.25)

    raise RuntimeError(
        f"Jumphost container '{container}' did not restore SSH port publishing after "
        f"management network attach: expected {expected}->22/tcp but docker reported "
        f"{detail!r}. Journal and resources retained for explicit recovery."
    )


def attach_jumphost_to_mgmt_bridge(
    client: SSHClient, *, container: str, lab_name: str, bridge: str,
    mgmt_ip: str, mgmt_subnet: str, mgmt_ipv6: str = "", mgmt_ipv6_subnet: str = "",
) -> None:
    """Verify an attachment already admitted by the container's birth intent.

    The old standalone name-based allocator is deliberately unavailable. Retry
    of an incomplete birth/attachment uses recover_jumphost(), not this method.
    """
    record = _guard(client, lab_name, "read")
    if record.get("config", {}).get("name") != container:
        raise RuntimeError("Jumphost birth record missing or container differs")
    attachment = dict(record["config"]["attachment"])
    attachment.update(bridge=bridge,
        ipv4=str(ipaddress.ip_interface(f"{mgmt_ip}/{ipaddress.ip_network(mgmt_subnet, strict=False).prefixlen}")),
        ipv6=str(ipaddress.ip_interface(f"{mgmt_ipv6}/{ipaddress.ip_network(mgmt_ipv6_subnet, strict=False).prefixlen}"))
              if mgmt_ipv6 and mgmt_ipv6_subnet else "")
    _guard(client, lab_name, "attach", attachment)


def preflight_jumphost_cleanup(lab_name, client, container, generation=None):
    proof = {"container": container}
    if generation is not None: proof["generation"] = generation
    return _guard(client, lab_name, "preflight-delete", proof)


def verify_jumphost_cleaned(lab_name, client, container, generation=None):
    proof = {"container": container}
    if generation is not None: proof["generation"] = generation
    return _guard(client, lab_name, "verify-cleaned", proof)


def destroy_jumphost(lab_name: str, client: SSHClient, generation: str | None = None) -> None:
    """Cleanup only the generation in the root-local journal, without force."""
    record = _guard(client, lab_name, "delete", {"generation": generation} if generation is not None else None)
    if record["phase"] != "cleaned":
        raise RuntimeError("Jumphost cleanup is incomplete; journal retained")


def ensure_master_pubkey(client: SSHClient) -> str:
    """Return the master's root SSH public key, generating one if missing."""
    primary = PATHS.ssh_key
    ssh_dir = str(PurePosixPath(primary).parent)
    # Try the configured primary first, then the well-known id_rsa
    # fallback in the same directory.
    key_paths = [primary, f"{ssh_dir}/id_rsa"]
    for key in key_paths:
        rc, _, _ = client.run_no_check(f"test -f {key}.pub")
        if rc == 0:
            _, pub, _ = client.run_no_check(f"cat {key}.pub")
            pub = (pub or "").strip()
            if pub:
                return pub

    log.info("Master has no SSH key; generating %s", primary)
    client.run(
        f"mkdir -p {ssh_dir} && chmod 700 {ssh_dir} && "
        f"ssh-keygen -t ed25519 -f {primary} -N '' -q"
    )
    _, pub, _ = client.run_no_check(f"cat {primary}.pub")
    return (pub or "").strip()


def read_gui_pubkey(client: SSHClient) -> str | None:
    """Return the dnlab-gui public key from the master, or None if absent.

    The GUI has its own SSH key (``PATHS.gui_ssh_key``) to keep audit
    trails on destination hosts distinct from orchestrator actions.
    If the operator has not run ``setup-gui-ssh-key.sh`` yet, the file
    simply doesn't exist — we return None and the caller falls back
    to master-key-only authorization.
    """
    gui_path = f"{PATHS.gui_ssh_key}.pub"
    rc, pub, _ = client.run_no_check(f"test -f {gui_path} && cat {gui_path}")
    if rc == 0 and pub and pub.strip():
        return pub.strip()
    return None


def collect_authorized_pubkeys(client: SSHClient) -> str:
    """Newline-joined authorized_keys content for labuser@jumphost.

    Always includes the master's orchestrator pubkey (required for
    deploy-time SSH probes). Adds the GUI pubkey if present so the
    dnlab-gui process can reach the jumphost with its own key.
    """
    keys = [ensure_master_pubkey(client)]
    gui_pub = read_gui_pubkey(client)
    if gui_pub and gui_pub not in keys:
        keys.append(gui_pub)
        log.info("Jumphost authorized_keys: +GUI pubkey (%s)", PATHS.gui_ssh_key)
    else:
        log.info(
            "Jumphost authorized_keys: master-only "
            "(run setup-gui-ssh-key.sh to add the GUI key)"
        )
    return "\n".join(keys)


def trust_jumphost_hostkey(
    client: SSHClient, jumphost_ip: str, jumphost_name: str,
) -> None:
    """Scan the jumphost's SSH host key and add it to known_hosts."""
    ssh_dir = str(PurePosixPath(PATHS.ssh_key).parent)
    known = f"{ssh_dir}/known_hosts"
    cmd = (
        f"mkdir -p {ssh_dir} && chmod 700 {ssh_dir} && "
        f"touch {known} && chmod 600 {known} && "
        f"ssh-keygen -R {jumphost_ip}   >/dev/null 2>&1 || true; "
        f"ssh-keygen -R {jumphost_name} >/dev/null 2>&1 || true; "
        "for i in 1 2 3 4 5; do "
        f"  out=$(ssh-keyscan -T 2 -H {jumphost_ip} {jumphost_name} 2>/dev/null); "
        f"  [ -n \"$out\" ] && {{ printf '%s\\n' \"$out\" >> {known}; break; }}; "
        "  sleep 2; "
        "done"
    )
    client.run(cmd, check=False)


_HOSTS_BEGIN = "# dnlab-multinode:{lab}:jumphost BEGIN"
_HOSTS_END = "# dnlab-multinode:{lab}:jumphost END"


def add_master_hosts_entry(
    client: SSHClient, lab_name: str, jumphost_name: str, jumphost_ip: str,
) -> None:
    """Append ``<ip>  <jumphost_name>`` to /etc/hosts between markers."""
    begin = _HOSTS_BEGIN.format(lab=lab_name)
    end = _HOSTS_END.format(lab=lab_name)
    client.run(
        f"sed -i '\\|{begin}|,\\|{end}|d' /etc/hosts && "
        f"printf '%s\\n%s  %s\\n%s\\n' "
        f"'{begin}' '{jumphost_ip}' '{jumphost_name}' '{end}' >> /etc/hosts"
    )
    log.info("Added /etc/hosts entry on master: %s → %s", jumphost_name, jumphost_ip)


def remove_master_hosts_entry(client: SSHClient, lab_name: str) -> None:
    """Strip the lab-scoped jumphost block from /etc/hosts."""
    begin = _HOSTS_BEGIN.format(lab=lab_name)
    end = _HOSTS_END.format(lab=lab_name)
    client.run(
        f"sed -i '\\|{begin}|,\\|{end}|d' /etc/hosts",
        check=False,
    )
    log.info("Removed /etc/hosts entry on master for lab '%s'", lab_name)


def _compute_jumphost_mgmt_ip(subnet: str) -> str:
    """Compute the jumphost/default-gateway IP in the mgmt subnet."""
    return ipv4_reservations(subnet).jumphost
