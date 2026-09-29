"""Shared text transforms applied by per-kind patcher modules.

The dnlab patcher rebuilds upstream vrnetlab images with a
``-dnlab`` suffix after applying one or more transforms to the
``launch.py`` and ``vrnetlab.py`` files that live at ``/`` inside the
container.

Transforms are intentionally surgical (single-anchor `str.replace`)
rather than full AST rewrites: upstream launch.py files evolve but the
anchor strings we target (the overlay computation and the hardcoded
defaults) are stable idioms across vendors.

Each transform returns ``(new_text, applied: bool)``. ``applied`` is
False when the anchor was not found — callers decide whether that is a
fatal error or a warning (e.g. patch_env_credentials is optional and
skipped silently when defaults are already removed).
"""

from __future__ import annotations


# ── anchors ────────────────────────────────────────────────────────────

# Both upstream vrnetlab.py and the per-kind launch.py compute the
# overlay disk path via this exact idiom. Redirecting it to /persist
# lets us bind-mount overlay persistence from the host without patching
# qemu-img invocations.
_OVERLAY_ANCHOR = 'overlay_disk_image = re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)'

_OVERLAY_REPLACEMENT = (
    'overlay_disk_image = ('
    '"/persist/overlay.qcow2" if os.path.isdir("/persist") '
    'else re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)'
    ')'
)

# Marker we inject alongside the patch so the image is self-identifying
# (useful for provenance checks at deploy time).
_PROVENANCE_MARKER = "# dnlab-patched: persist-overlay-v1"

_OPTIONAL_IPV6_MARKER = "# dnlab-patched: optional-mgmt-ipv6-v1"
_WARM_LINK_MARKER = "# dnlab-patched: warm-links-v1"


def patch_persist_overlay(text: str) -> tuple[str, bool]:
    """Redirect overlay qcow2 to ``/persist/overlay.qcow2`` when the bind
    mount exists.

    Falls back to upstream behaviour when ``/persist`` is absent, so the
    patched image still boots standalone (e.g. in CI without a host
    bind mount).

    Indent-aware: the anchor appears with different leading whitespace
    depending on the file (e.g. 8 spaces in cisco launch.py, 12 spaces
    inside the ``else:`` block of vrnetlab.py). We detect the anchor
    line's indent and reuse it for both the provenance marker and the
    replacement statement, so the patched block stays syntactically
    valid in either context.
    """
    if _PROVENANCE_MARKER in text:
        # Idempotent: already patched, skip.
        return text, True

    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith(_OVERLAY_ANCHOR):
            continue
        indent = line[: len(line) - len(stripped)]
        # Preserve the original line's trailing newline by reading it
        # from the matched line rather than assuming "\n".
        eol = "\n" if line.endswith("\n") else ""
        lines[i] = (
            f"{indent}{_PROVENANCE_MARKER}{eol}"
            f"{indent}{_OVERLAY_REPLACEMENT}{eol}"
        )
        return "".join(lines), True
    return text, False


def patch_env_credentials(text: str) -> tuple[str, bool]:
    """Replace hardcoded argparse defaults for username/password with
    environment-variable lookups.

    Upstream launch.py files ship with defaults like ``--username vrnetlab
    --password VR-netlab9``. The dnlab-gui deployment model forbids
    credential injection from the UI, so the image should instead read
    ``USERNAME`` / ``PASSWORD`` from the process environment (which the
    orchestrator populates from the topology ``env`` block).

    Returns applied=False if the anchor is not present (the file is
    already environment-driven or the vendor uses a different idiom).
    """
    before = text
    # Common upstream pattern — two separate argparse calls with string
    # literals. We do not force a specific default here; callers control
    # credentials via USERNAME/PASSWORD env vars.
    anchors = [
        ('parser.add_argument("--username", default="vrnetlab", help="Username")',
         'parser.add_argument("--username", default=os.environ.get("USERNAME", "vrnetlab"), help="Username")'),
        ('parser.add_argument("--password", default="VR-netlab9", help="Password")',
         'parser.add_argument("--password", default=os.environ.get("PASSWORD", "VR-netlab9"), help="Password")'),
    ]
    for old, new in anchors:
        if old in text:
            text = text.replace(old, new, 1)
    return text, text != before


def patch_optional_mgmt_ipv6(text: str) -> tuple[str, bool]:
    """Allow launch.py templates to render when vrnetlab has no IPv6
    management address configured.

    Some images unconditionally replace IPv6 placeholders with
    ``self.mgmt_address_ipv6`` / ``self.mgmt_gw_ipv6``. In IPv4-only
    containerlab deployments those attributes can be ``None``, which
    makes ``str.replace`` raise ``TypeError`` before QEMU starts.
    """
    if _OPTIONAL_IPV6_MARKER in text:
        return text, True

    before = text
    anchors = [
        (
            'cfg = cfg.replace("{MGMT_IP_IPV6}", self.mgmt_address_ipv6)',
            'cfg = cfg.replace("{MGMT_IP_IPV6}", self.mgmt_address_ipv6 or "")',
        ),
        (
            'cfg = cfg.replace("{MGMT_GW_IPV6}", self.mgmt_gw_ipv6)',
            'cfg = cfg.replace("{MGMT_GW_IPV6}", self.mgmt_gw_ipv6 or "")',
        ),
    ]
    for old, new in anchors:
        text = text.replace(old, new, 1)
    if text == before:
        return text, False

    first_anchor = anchors[0][1]
    text = text.replace(first_anchor, f"{_OPTIONAL_IPV6_MARKER}\n        {first_anchor}", 1)
    return text, True


def patch_warm_links(text: str) -> tuple[str, bool]:
    """Add fast NIC polling and a launcher-owned QEMU carrier controller."""
    if _WARM_LINK_MARKER in text:
        return text, True

    delay_anchor = "            time.sleep(5)\n\n        # check if we need to provision"
    delay_replacement = (
        "            try:\n"
        "                poll_interval = float(os.environ.get(\"DNLAB_NIC_POLL_INTERVAL\", \"5\"))\n"
        "            except (TypeError, ValueError):\n"
        "                poll_interval = 5.0\n"
        "            time.sleep(max(0.02, min(poll_interval, 5.0)))\n\n"
        "        # check if we need to provision"
    )
    if delay_anchor not in text or "class QemuBroken" not in text:
        return text, False
    text = text.replace(delay_anchor, delay_replacement, 1)

    qemu_anchor = '        self.logger.debug("qemu cmd: {}".format(" ".join(cmd)))\n'
    qemu_replacement = (
        '        # DNLAB warm ports: pause before the guest executes so the\n'
        '        # controller can force carrier down through the monitor.\n'
        '        if int(os.environ.get("DNLAB_WARM_PORTS", "0") or 0) > 0:\n'
        '            cmd.append("-S")\n\n'
        + qemu_anchor
    )
    if qemu_anchor not in text:
        return text, False
    text = text.replace(qemu_anchor, qemu_replacement, 1)

    health_anchor = '''            if all_running:
                self.update_health(0, "running")
                started = True
'''
    health_replacement = '''            if all_running:
                degraded = [
                    str(vm.degraded_reason)
                    for vm in self.vms
                    if getattr(vm, "degraded_reason", None)
                ]
                message = "running-degraded: " + "; ".join(degraded) if degraded else "running"
                self.update_health(0, message)
                started = True
'''
    if health_anchor not in text:
        return text, False
    text = text.replace(health_anchor, health_replacement, 1)

    controller = r'''

# dnlab-patched: warm-links-v1
def _dnlab_warm_link_controller(vr):
    import re as _re
    import socket as _socket
    import threading as _threading
    import time as _time

    try:
        warm_ports = int(os.environ.get("DNLAB_WARM_PORTS", "0"))
        vm_index = int(os.environ.get("DNLAB_WARM_VM_INDEX", "0"))
    except (TypeError, ValueError):
        vr.logger.error("invalid DNLAB warm-link configuration")
        return
    if warm_ports <= 0:
        return
    if vm_index < 0 or vm_index >= len(vr.vms):
        vr.logger.error("DNLAB_WARM_VM_INDEX %s is outside vr.vms", vm_index)
        return

    vm = vr.vms[vm_index]
    lock = _threading.Lock()

    # Publish the control socket before waiting for QEMU.  A client may queue
    # its request in the listen backlog while initial carrier state is being
    # applied; this closes the container-running/socket-ready race.
    path = "/run/dnlab-link-control.sock"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, 0o660)
    server.listen(8)

    def monitor_ready():
        # Modern vrnetlab always creates the Scrapli driver and the self.qm
        # facade during VM construction, before Driver.open().  Object
        # existence therefore does not mean that the QEMU monitor is usable.
        driver = getattr(vm, "scrapli_qm", None)
        if driver is not None:
            try:
                return bool(driver.isalive())
            except Exception:
                return False
        monitor = getattr(vm, "qm", None)
        if monitor is None:
            return False
        get_socket = getattr(monitor, "get_socket", None)
        if callable(get_socket):
            try:
                return get_socket() is not None
            except Exception:
                return False
        return getattr(monitor, "sock", None) is not None

    def wait_monitor(timeout=300.0, require_running=False):
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            if (not require_running or getattr(vm, "running", False)) and monitor_ready():
                return
            _time.sleep(0.05)
        raise TimeoutError("QEMU monitor did not become ready")

    def monitor_command(command, timeout=30.0):
        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"QEMU monitor command timed out: {command}")
            wait_monitor(timeout=remaining)
            try:
                return vm._qemu_monitor_cmd(command, wait=True)
            except Exception:
                if _time.monotonic() >= deadline:
                    raise
                _time.sleep(0.05)

    # QEMU was launched with -S.  Initialise carrier only after the monitor
    # transport is genuinely open, then always release the paused guest.
    wait_monitor()
    try:
        with lock:
            for index in range(1, warm_ports + 1):
                monitor_command(f"set_link p{index:02d} off")
    except Exception:
        vr.logger.exception("failed to initialise one or more DNLAB warm ports")
    finally:
        # Retrying cont protects against a monitor reconnect race and prevents
        # a blank serial console caused by QEMU remaining paused.
        with lock:
            monitor_command("cont")

    def set_link(iface, state):
        match = _re.fullmatch(r"eth([1-9][0-9]*)", iface)
        if not match:
            raise ValueError("interface must match ethN with N >= 1")
        index = int(match.group(1))
        if index > warm_ports:
            raise ValueError(f"{iface} exceeds configured warm-port count {warm_ports}")
        if state not in {"up", "down"}:
            raise ValueError("state must be up or down")
        wait_monitor(require_running=True)
        with lock:
            monitor_command(
                f"set_link p{index:02d} {'on' if state == 'up' else 'off'}",
            )

    with server:
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    request = conn.recv(4096).decode().strip().split()
                    if len(request) != 2:
                        raise ValueError("request must be: ethN up|down")
                    set_link(request[0], request[1])
                    response = f"OK {request[0]} {request[1]}\n"
                except Exception as exc:
                    response = f"ERROR {type(exc).__name__}: {exc}\n"
                try:
                    conn.sendall(response.encode())
                except BrokenPipeError:
                    pass


_dnlab_original_vr_start = VR.start


def _dnlab_vr_start(self):
    import threading as _threading
    try:
        warm_ports = int(os.environ.get("DNLAB_WARM_PORTS", "0") or 0)
    except (TypeError, ValueError):
        warm_ports = 0
        self.logger.error("DNLAB_WARM_PORTS must be an integer")
    if warm_ports > 0:
        _threading.Thread(
            target=_dnlab_warm_link_controller,
            args=(self,),
            name="dnlab-warm-links",
            daemon=True,
        ).start()
    return _dnlab_original_vr_start(self)


VR.start = _dnlab_vr_start
'''
    text = text.replace("\nclass QemuBroken", controller + "\n\nclass QemuBroken", 1)
    return text, True
