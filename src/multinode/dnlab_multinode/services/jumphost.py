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
import logging
import secrets
import shlex
import string

from pathlib import PurePosixPath

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
) -> None:
    """Atomically refresh the live jumphost VD/relay maps and login banner."""
    container = jumphost_container_name(lab_name)
    vd_content = "".join(f"{name}={runtime}\n" for name, runtime in vd_map.items())
    relay_content = "".join(
        f"{runtime}={meta['host']}:{int(meta['port'])}:{meta['api_key']}\n"
        for runtime, meta in relay_map.items()
    )
    motd = _render_inventory_motd(lab_name, list(vd_map))

    rc, out, _ = client.run_no_check(
        f"docker inspect -f '{{{{.State.Running}}}}' {container}"
    )
    if rc != 0 or out.strip() != "true":
        raise RuntimeError(f"Jumphost container '{container}' is not running")

    command = (
        "set -e; "
        f"printf %s {shlex.quote(vd_content)} > /etc/dnlab-vds.new; "
        f"printf %s {shlex.quote(relay_content)} > /etc/dnlab-relays.new; "
        f"printf %s {shlex.quote(motd)} > /etc/motd.new; "
        "chown root:labuser /etc/dnlab-vds.new /etc/dnlab-relays.new; "
        "chmod 644 /etc/dnlab-vds.new; chmod 640 /etc/dnlab-relays.new; "
        "mv /etc/dnlab-vds.new /etc/dnlab-vds; "
        "mv /etc/dnlab-relays.new /etc/dnlab-relays; "
        "mv /etc/motd.new /etc/motd"
    )
    client.run(
        f"docker exec {container} sh -c {shlex.quote(command)}"
    )
    log.info("Jumphost inventory refreshed: %d VDs", len(vd_map))


def generate_password(length: int = 12) -> str:
    """Generate a random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_jumphost_network(client: SSHClient, net: JumphostNet) -> None:
    """Create the shared jumphost docker network if missing (idempotent).

    If a network with the same name exists but with a different subnet we
    log a warning and do NOT recreate it — active lab jumphosts may be
    attached. The operator must tear down all labs and re-run.
    """
    rc, existing, _ = client.run_no_check(
        f"docker network inspect -f '{{{{range .IPAM.Config}}}}{{{{.Subnet}}}}{{{{end}}}}' {net.network}"
    )
    if rc == 0 and existing.strip():
        if existing.strip() != net.ipv4_subnet:
            log.warning(
                "Jumphost network '%s' exists with subnet %s, "
                "hosts.yml declares %s. Leaving the existing one; "
                "destroy all labs to reset.",
                net.network, existing.strip(), net.ipv4_subnet,
            )
        return

    log.info("Creating shared jumphost network: %s (subnet=%s, gw=%s, bridge=%s)",
             net.network, net.ipv4_subnet, net.ipv4_gw, net.bridge)
    client.run(
        f"docker network create {net.network} "
        f"  --driver bridge "
        f"  -o com.docker.network.bridge.name={net.bridge} "
        f"  --subnet {net.ipv4_subnet} "
        f"  --gateway {net.ipv4_gw}"
    )


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


def deploy_jumphost(
    topo: DistributedTopology,
    client: SSHClient,
    mgmt_ip: str,
    resolver_ip: str | None = None,
    vd_names: list[str] | None = None,
    vd_map: dict[str, str] | None = None,
    authorized_keys: str | None = None,
    relay_map: dict[str, dict] | None = None,
    ssh_bind_ip: str = "0.0.0.0",
    ssh_port_range: str = "2200-2299",
) -> tuple[str, str, str, str, int]:
    """Deploy the jump host container on the master.

    The jumphost starts on the shared jumphost network for SSH port publishing
    and external reachability, then it is also attached to the lab mgmt
    network as the default gateway seen by VDs. VD console/log access may go
    through runtime relays, but those relays do not replace mgmt reachability.

    It also publishes its SSH port on the master so users outside the
    shared jumphost network can reach it by ``ssh -p <port> labuser@<master>``.
    The host-side port is allocated from ``ssh_port_range`` bound to
    ``ssh_bind_ip``.

    Args:
        topo: topology config (provides ``jumphost_net``)
        client: SSH client for master
        mgmt_ip: IP for the jumphost on the lab's mgmt network
        resolver_ip: if set, passed as ``--dns`` to docker run so the jumphost
            uses the centralized DNS container as its resolver
        vd_names: if set, passed as ``JUMPHOST_VD_LIST`` so the jumphost
            login banner lists the lab's VDs
        vd_map: optional logical VD name → runtime container name map
        authorized_keys: if set, passed as ``JUMPHOST_AUTHORIZED_KEYS`` so
            the master can reach labuser@jumphost without a password
        relay_map: optional runtime container → relay endpoint/auth metadata
        ssh_bind_ip: master-side IP the SSH port is published on
            (``0.0.0.0`` = all interfaces)
        ssh_port_range: inclusive ``<low>-<high>`` range to pick the
            host-side SSH port from

    Returns: (container_name, password, ext_network_name, assigned_ip_cidr, ssh_port)
    """
    container = jumphost_container_name(topo.name)
    image = image_for("jumphost")
    jh_net = topo.jumphost_net
    password = generate_password()
    ssh_port = allocate_jumphost_ssh_port(client, ssh_bind_ip, ssh_port_range)

    log.info(
        "Deploying jump host: %s (image=%s, resolver=%s)",
        container, image, resolver_ip or "default",
    )

    # Pre-flight: image exists locally?
    rc, _, _ = client.run_no_check(f"docker image inspect {image} >/dev/null 2>&1")
    if rc != 0:
        raise RuntimeError(
            f"Jumphost image '{image}' not found on master. "
            "Run: docker compose --profile release-images pull"
        )

    # Remove any stale container
    client.run(f"docker rm -f {container} 2>/dev/null", check=False)

    # Ensure the shared jumphost network exists and pick a free IP.
    ensure_jumphost_network(client, jh_net)
    jh_ip_cidr = allocate_jumphost_ip(client, jh_net)
    jh_ip = jh_ip_cidr.split("/")[0]

    # Start container on the shared jumphost network so docker's -p
    # DNAT targets the externally-routable IP (see docstring).
    dns_flag = f"--dns {resolver_ip} " if resolver_ip else ""

    env_flags = [
        f"-e JUMPHOST_PASSWORD={shlex.quote(password)}",
        f"-e JUMPHOST_LAB_NAME={shlex.quote(topo.name)}",
    ]
    if vd_names:
        env_flags.append(
            f"-e JUMPHOST_VD_LIST={shlex.quote(' '.join(vd_names))}"
        )
    if vd_map:
        encoded = " ".join(f"{name}={container}" for name, container in vd_map.items())
        env_flags.append(
            f"-e JUMPHOST_VD_MAP={shlex.quote(encoded)}"
        )
    if relay_map:
        encoded = " ".join(
            f"{container}={meta['host']}:{int(meta['port'])}:{meta['api_key']}"
            for container, meta in relay_map.items()
        )
        env_flags.append(
            f"-e JUMPHOST_RELAY_MAP={shlex.quote(encoded)}"
        )
    if authorized_keys:
        env_flags.append(
            f"-e JUMPHOST_AUTHORIZED_KEYS={shlex.quote(authorized_keys)}"
        )
    env_block = " ".join(env_flags)

    port_flag = f"-p {ssh_bind_ip}:{ssh_port}:22 "
    run_cmd = (
        f"docker run -d "
        f"--name {container} "
        f"--network {jh_net.network} "
        f"--ip {jh_ip} "
        f"{dns_flag}"
        f"{port_flag}"
        f"--cap-add NET_ADMIN "
        f"--sysctl net.ipv4.ip_forward=1 "
        f"{env_block} "
        f"{image}"
    )
    client.run(run_cmd)

    rc, out, _ = client.run_no_check(
        f"docker inspect -f '{{{{.State.Running}}}}' {container}"
    )
    if rc != 0 or out.strip() != "true":
        _, logs, _ = client.run_no_check(f"docker logs {container} 2>&1 | tail -40")
        client.run(f"docker rm -f {container} 2>/dev/null", check=False)
        raise RuntimeError(
            f"Jumphost container '{container}' failed to start.\n"
            f"--- docker logs (last 40 lines) ---\n{logs}\n"
            f"-----------------------------------"
        )
    log.info("Jump host container started: %s", container)

    try:
        attach_jumphost_to_mgmt_bridge(
            client,
            container=container,
            lab_name=topo.name,
            bridge=topo.mgmt.bridge,
            mgmt_ip=mgmt_ip,
            mgmt_subnet=topo.mgmt.ipv4_subnet,
        )
        log.info(
            "Jumphost %s attached to mgmt bridge '%s' with IP %s",
            container, topo.mgmt.bridge, mgmt_ip,
        )
        _verify_jumphost_ssh_publish(
            client,
            container=container,
            ssh_bind_ip=ssh_bind_ip,
            ssh_port=ssh_port,
        )
    except Exception:
        client.run(f"docker rm -f {container} 2>/dev/null", check=False)
        raise

    log.info(
        "Jumphost %s SSH port published on master: %s:%d → :22",
        container, ssh_bind_ip, ssh_port,
    )
    return container, password, jh_net.network, jh_ip_cidr, ssh_port


def _verify_jumphost_ssh_publish(
    client: SSHClient,
    *,
    container: str,
    ssh_bind_ip: str,
    ssh_port: int,
) -> None:
    """Ensure Docker kept the jumphost's published SSH port after mgmt attach."""
    rc, out, err = client.run_no_check(
        f"docker port {shlex.quote(container)} 22",
        timeout=15,
    )
    expected = f"{ssh_bind_ip}:{ssh_port}"
    published = {line.strip() for line in (out or "").splitlines() if line.strip()}
    if rc == 0 and expected in published:
        return
    detail = (err or out or "no docker port output").strip()
    raise RuntimeError(
        f"Jumphost container '{container}' lost SSH port publishing after "
        f"management network attach: expected {expected}->22/tcp "
        f"but docker reported {detail!r}. The lab was not left with an "
        "unreachable jumphost."
    )


def attach_jumphost_to_mgmt_bridge(
    client: SSHClient,
    *,
    container: str,
    lab_name: str,
    bridge: str,
    mgmt_ip: str,
    mgmt_subnet: str,
) -> None:
    """Attach jumphost to the lab mgmt bridge without a Docker endpoint.

    Docker remote-driver endpoints can take over external connectivity and
    revoke the bridge-published SSH port, so the jumphost gets only a manual
    veth on the lab bridge. Inside the container this is ``eth1``, matching
    the jumphost image's forwarding rules.
    """
    prefix = ipaddress.ip_network(mgmt_subnet, strict=False).prefixlen
    suffix = "".join(ch for ch in lab_name if ch.isalnum())[:8] or "lab"
    host_if = f"jh-{suffix}"
    peer_if = f"jhc-{suffix}"

    client.run(
        "set -e; "
        f"pid=$(docker inspect -f '{{{{.State.Pid}}}}' {shlex.quote(container)}); "
        f"test -n \"$pid\"; "
        f"ip link show {shlex.quote(bridge)} >/dev/null; "
        f"ip link del {shlex.quote(host_if)} 2>/dev/null || true; "
        f"nsenter -t \"$pid\" -n ip link del eth1 2>/dev/null || true; "
        f"ip link add {shlex.quote(host_if)} type veth peer name {shlex.quote(peer_if)}; "
        f"ip link set {shlex.quote(host_if)} master {shlex.quote(bridge)}; "
        f"ip link set {shlex.quote(host_if)} up; "
        f"ip link set {shlex.quote(peer_if)} netns \"$pid\"; "
        f"nsenter -t \"$pid\" -n ip link set {shlex.quote(peer_if)} name eth1; "
        f"nsenter -t \"$pid\" -n ip addr add {shlex.quote(f'{mgmt_ip}/{prefix}')} dev eth1; "
        f"nsenter -t \"$pid\" -n ip link set eth1 up",
        timeout=30,
    )


def destroy_jumphost(
    lab_name: str,
    client: SSHClient,
) -> None:
    """Remove the jump host container.

    The shared jumphost network is **not** removed — other labs may have
    their jumphosts attached. Removal only happens if the site operator
    manually tears it down (e.g. ``docker network rm dnlab-jumphost``
    after destroying all labs).
    """
    container = jumphost_container_name(lab_name)
    log.info("Removing jump host: %s", container)
    client.run(f"docker rm -f {container} 2>/dev/null", check=False)
    log.info("Jump host removed")


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
