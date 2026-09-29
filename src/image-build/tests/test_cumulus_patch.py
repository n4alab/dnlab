from __future__ import annotations

import base64
import datetime
import hashlib
import os
from pathlib import Path
import re
import time

from patches import _cumulus_launcher, nvidia_cumulusvx


LEGACY_LAUNCHER = Path("/opt/vrnetlab/nvidia/cumulusvx/docker/launch.py")


def test_cumulus_legacy_launcher_patch_adds_breakout_and_real_readiness():
    source = LEGACY_LAUNCHER.read_text(encoding="utf-8")

    patched, notes = nvidia_cumulusvx.apply("/launch.py", source)

    assert notes == [
        "/launch.py: cumulus-vx hardware, persistence, breakout, and readiness applied"
    ]
    assert "# dnlab-patched: cumulus-vx-persist-dir-v1" in patched
    assert "# dnlab-patched: cumulus-breakout-readiness-v4" in patched
    assert "DEFAULT_RAM_MB = 4096" in patched
    assert 'cpu="host" if os.path.exists("/dev/kvm") else "max"' in patched
    assert "DEFAULT_SMP" not in patched
    assert "DNLAB_WARM_PORTS" not in patched
    assert "PREALLOCATED_DATA_NICS = 64" in patched
    assert "VIRTIO_NET_VECTORS = 2" in patched
    assert 'self.nic_type = f"virtio-net-pci,vectors={VIRTIO_NET_VECTORS}"' in patched
    assert "self.num_nics = PREALLOCATED_DATA_NICS" in patched
    assert "_compute_renames(*_parse_breakout())" in patched
    assert patched.index("if not self._write_udev_rules():") < patched.index(
        "if not self._platform_is_ready():"
    )
    assert "__DNLAB_switchd_active__ __DNLAB_nvued_active__" in patched
    assert "self._login_deadline = time.monotonic() + LOGIN_READY_TIMEOUT" in patched
    assert "select.select([raw_socket], [], [], timeout)" in patched
    assert "Shell prompt not returned after breakout result" in patched
    assert "self.tn.expect(" not in patched
    assert "self.tn.read_until(" not in patched
    assert 'DNLAB_CONTROL_USER = "dnlab"' in patched
    assert 'DNLAB_CONTROL_PASSWORD = "Dnlab123!"' in patched
    assert 'self._console_expect([rb"\\$ ", b"# "]' in patched
    assert "factory_password" not in patched
    assert "sudo -n" in patched
    assert "sudo -S" not in patched
    assert "running-degraded" not in patched
    assert "self.tn = None" in patched
    compile(patched, "/launch.py", "exec")


def test_cumulus_breakout_slots_are_allocated_after_all_flat_ports(tmp_path):
    ports_conf = tmp_path / "ports.conf"
    ports_conf.write_text("10=4x\n")
    helpers = _cumulus_launcher._HELPERS.replace(
        '"/config/ports.conf"', repr(str(ports_conf))
    )
    namespace = {"os": os, "re": re}
    exec(helpers, namespace)

    parsed = namespace["_parse_breakout"]()
    assert parsed == (10, [(10, 4)])
    assert namespace["_compute_renames"](*parsed) == [
        (33 + lane, f"swp{33 + lane}", f"swp10s{lane}") for lane in range(4)
    ]


def test_cumulus_breakout_script_uses_real_newlines():
    namespace = {
        "base64": base64,
        "FIRST_EXTRA_SLOT": 33,
        "PREALLOCATED_DATA_NICS": 64,
        "BREAKOUT_TIMEOUT": 120,
        "LOGIN_TIMEOUT": 15,
        "BREAKOUT_UPLOAD_FILE": "/tmp/dnlab-cumulus-breakout.b64",
        "BREAKOUT_RULES_FILE": "/etc/udev/rules.d/70-dnlab-cumulus-breakout.rules",
        "SERIAL_CHUNK_SIZE": 512,
        "re": re,
    }
    exec("class Harness:\n" + _cumulus_launcher._BOOTSTRAP, namespace)
    harness = namespace["Harness"]()
    harness.data_intf_prefix = "eth"
    harness._breakout_renames = [
        (33 + lane, f"swp{33 + lane}", f"swp10s{lane}")
        for lane in range(4)
    ]
    harness.get_intf_mac = lambda name: (
        f"02:00:00:00:00:{int(name.removeprefix('eth')):02x}"
    )
    commands = []
    harness.wait_write = lambda command, _wait: commands.append(command)
    class Marker:
        @staticmethod
        def group(_index=0):
            return b"__DNLAB_BREAKOUT_OK__ changed=1"

    def fake_console_expect(patterns, _timeout):
        if len(patterns) == 2:
            return 0, object(), b"$ "
        return 0, Marker(), b"__DNLAB_BREAKOUT_OK__ changed=1"

    harness._console_expect = fake_console_expect
    harness.logger = type(
        "Logger",
        (),
        {
            "error": lambda *_args, **_kwargs: None,
            "info": lambda *_args, **_kwargs: None,
        },
    )()

    assert harness._write_udev_rules() is True
    assert len(commands) > 2
    upload_commands = [
        command
        for command in commands
        if command.startswith("printf %s ")
    ]
    assert upload_commands
    assert max(map(len, upload_commands)) < 1024
    assert commands[-1] == (
        "sudo -n bash -c 'base64 -d /tmp/dnlab-cumulus-breakout.b64 | bash'"
    )
    encoded_script = "".join(
        re.search(r"printf %s ([A-Za-z0-9+/=]+) >>", command).group(1)
        for command in upload_commands
    )
    script = base64.b64decode(encoded_script)
    assert script.startswith(
        b"rm -f /tmp/dnlab-cumulus-breakout.b64\nset -u\n"
    )
    assert b"breakout.b64\\nset -u" not in script
    assert b"trap cleanup EXIT" in script
    assert b"systemctl stop switchd" in script
    assert b"systemctl start switchd" in script
    assert b"__DNLAB_BREAKOUT_OK__ changed=1" in script
    assert b"__DNLAB_BREAKOUT_ERROR__" in script
    assert b"/sys/class/net/*/address" in script
    encoded_rules = re.search(
        rb"echo ([A-Za-z0-9+/=]+) \| base64 -d > ", script
    ).group(1)
    rules = base64.b64decode(encoded_rules)

    assert rules.count(b"\n") == 6
    for lane in range(4):
        assert f'NAME="swp10s{lane}"'.encode() in rules
    assert b'NAME="swp37"' not in rules


def test_cumulus_console_expect_preserves_fragments_and_has_finite_timeout():
    namespace = {
        "CONSOLE_POLL_TIMEOUT": 0.01,
        "re": re,
        "time": time,
    }
    exec("class Harness:\n" + _cumulus_launcher._BOOTSTRAP, namespace)
    harness = namespace["Harness"]()
    harness._console_buffer = b"cumulus lo"
    harness._console_read = lambda _timeout: b""

    index, match, response = harness._console_expect([b"cumulus login: "], 0.01)

    assert (index, match, response) == (-1, None, b"")
    assert harness._console_buffer == b"cumulus lo"

    chunks = iter([b"gin: "])
    harness._console_read = lambda _timeout: next(chunks, b"")

    index, match, response = harness._console_expect([b"cumulus login: "], 0.1)

    assert index == 0
    assert match is not None
    assert response == b"cumulus login: "
    assert harness._console_buffer == b""

    harness._console_read = lambda _timeout: b""
    started = time.monotonic()
    index, match, response = harness._console_expect([b"never"], 0.02)
    assert time.monotonic() - started < 0.2
    assert (index, match, response) == (-1, None, b"")


def test_cumulus_degraded_startup_closes_and_releases_serial_console():
    namespace = {
        "datetime": datetime,
        "re": re,
        "time": time,
    }
    exec("class Harness:\n" + _cumulus_launcher._BOOTSTRAP, namespace)
    harness = namespace["Harness"]()
    harness._bootstrap_done = True
    harness._logout_console = lambda: False
    harness.degraded_reason = None
    harness.start_time = datetime.datetime.now()
    harness.running = False

    class Console:
        closed = False

        def close(self):
            self.closed = True

    console = Console()
    harness.tn = console
    harness.logger = type(
        "Logger",
        (),
        {
            "warning": lambda *_args, **_kwargs: None,
            "info": lambda *_args, **_kwargs: None,
        },
    )()

    harness._finish_startup("breakout interface reconciliation failed")

    assert harness.running is True
    assert harness.tn is None
    assert console.closed is True
    assert harness.degraded_reason == "breakout interface reconciliation failed"


def test_cumulus_legacy_launcher_patch_is_idempotent():
    source = LEGACY_LAUNCHER.read_text(encoding="utf-8")
    patched, _ = nvidia_cumulusvx.apply("/launch.py", source)

    again, notes = nvidia_cumulusvx.apply("/launch.py", patched)

    assert again == patched
    assert notes == ["/launch.py: already patched"]


def test_cumulus_qcow_preparation_uses_copy_and_control_account(tmp_path):
    source = tmp_path / "vendor.qcow2"
    source.write_bytes(b"vendor-image")
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    destination = tmp_path / "prepared" / "vendor.qcow2"
    commands = []

    nvidia_cumulusvx.prepare_qcow(
        source,
        destination,
        run=lambda cmd: commands.append(cmd),
    )

    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert destination.read_bytes() == source.read_bytes()
    assert len(commands) == 1
    command = commands[0]
    assert command[:4] == ["virt-customize", "--no-network", "-a", str(destination)]
    guest_script = command[-1]
    assert "useradd -m -s /bin/bash" in guest_script
    assert "chage -m 0 -M -1 -I -1 -E -1 dnlab" in guest_script
    assert "dnlab ALL=(ALL) NOPASSWD: ALL" in guest_script
    assert "visudo -cf /etc/sudoers.d/90-dnlab" in guest_script
    assert (
        "console=tty0 console=ttyS0,115200n8" in guest_script
    )
    assert "update-grub" in guest_script
    assert "systemctl enable serial-getty@ttyS0.service" in guest_script
    assert nvidia_cumulusvx.DNLAB_CONTROL_PASSWORD not in guest_script


def test_cumulus_qcow_preparation_rejects_in_place_mutation(tmp_path):
    source = tmp_path / "vendor.qcow2"
    source.write_bytes(b"vendor-image")

    import pytest

    with pytest.raises(RuntimeError, match="distinct destination"):
        nvidia_cumulusvx.prepare_qcow(source, source, run=lambda _cmd: None)
