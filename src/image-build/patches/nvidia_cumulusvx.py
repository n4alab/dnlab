"""Per-kind patch plan for NVIDIA Cumulus VX.

Cumulus VX boots factory and manages its writable qcow2 overlay in
``/launch.py``. DnLab mounts persistent VM state at ``/persist``; this
patch makes the launcher prefer that path while keeping ``/config`` as a
compatibility fallback for plain containerlab/vrnetlab runs.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable

from patches import _cumulus_launcher


KIND = "nvidia_cumulusvx"
EXTRA_CAPABILITIES = (
    "cumulus-control-account-v1",
    "cumulus-serial-console-v1",
)

DNLAB_CONTROL_USER = "dnlab"
DNLAB_CONTROL_PASSWORD = "Dnlab123!"
# SHA-512 crypt hash for the documented lab-only password above.
DNLAB_CONTROL_PASSWORD_HASH = (
    "$6$dnlabvx$jhqOMBPQA24m9xyOzqPCgu97cOtv4dZ6.z21JPK9TOZPAz4WvvbxC7LO/"
    "ul4EOhDpNv29o7c0rLX0qQmRZQ6T."
)

FILES = [
    "/launch.py",
]

_MARKER = "# dnlab-patched: cumulus-vx-persist-dir-v1"

_CONST_ANCHOR = '''BOOT_SPIN_LIMIT = 6000
'''

_CONST_REPLACEMENT = '''BOOT_SPIN_LIMIT = 6000
PERSIST_DIRS = ("/persist", "/config")
'''

_METHOD_ANCHOR = '''    def _enable_persistent_overlay(self, disk_image):
        if not os.path.isdir("/config"):
            self.logger.warning(
                "/config not mounted; Cumulus VX disk changes are ephemeral"
            )
            return

        persistent_overlay = "/config/cumulusvx_overlay.qcow2"
'''

_METHOD_REPLACEMENT = f'''    def _enable_persistent_overlay(self, disk_image):
        {_MARKER}
        persist_dir = next((path for path in PERSIST_DIRS if os.path.isdir(path)), None)
        if not persist_dir:
            self.logger.warning(
                "No persistence mount found; Cumulus VX disk changes are ephemeral"
            )
            return

        persistent_overlay = os.path.join(persist_dir, "cumulusvx_overlay.qcow2")
'''


def prepare_qcow(
    source: Path,
    destination: Path,
    *,
    run: Callable[[list[str]], object],
    dry: bool = False,
) -> None:
    """Install the lab-only control account in a disposable QCOW copy."""
    if source.resolve() == destination.resolve():
        raise RuntimeError("Cumulus QCOW preprocessing requires a distinct destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not dry:
        shutil.copy2(source, destination)

    guest_script = "\n".join(
        [
            "set -eu",
            f"if id -u {DNLAB_CONTROL_USER} >/dev/null 2>&1; then",
            f"  usermod -s /bin/bash -p '{DNLAB_CONTROL_PASSWORD_HASH}' {DNLAB_CONTROL_USER}",
            "else",
            f"  useradd -m -s /bin/bash -p '{DNLAB_CONTROL_PASSWORD_HASH}' {DNLAB_CONTROL_USER}",
            "fi",
            f"chage -m 0 -M -1 -I -1 -E -1 {DNLAB_CONTROL_USER}",
            "install -d -m 0755 /etc/sudoers.d",
            f"printf '%s\\n' '{DNLAB_CONTROL_USER} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-dnlab",
            "chmod 0440 /etc/sudoers.d/90-dnlab",
            "visudo -cf /etc/sudoers.d/90-dnlab",
            "sed -i 's/console=ttyS0,115200n8 console=tty0/console=tty0 console=ttyS0,115200n8/' /etc/default/grub",
            "update-grub",
            "systemctl enable serial-getty@ttyS0.service",
        ]
    )
    run(
        [
            "virt-customize",
            "--no-network",
            "-a",
            str(destination),
            "--run-command",
            guest_script,
        ]
    )


def _patch_once(text: str, old: str, new: str) -> tuple[str, bool]:
    if old not in text:
        return text, False
    return text.replace(old, new, 1), True


def _patch_cumulus_launch(text: str) -> tuple[str, bool]:
    new_text = text
    if _MARKER not in new_text:
        new_text, ok = _patch_once(new_text, _CONST_ANCHOR, _CONST_REPLACEMENT)
        if not ok:
            return text, False

        new_text, ok = _patch_once(new_text, _METHOD_ANCHOR, _METHOD_REPLACEMENT)
        if not ok:
            return text, False

    new_text, ok = _cumulus_launcher.patch(new_text)
    if not ok:
        return text, False

    return new_text, True


def apply(path: str, text: str) -> tuple[str, list[str]]:
    new_text, ok = _patch_cumulus_launch(text)
    if not ok:
        raise RuntimeError(
            f"{path}: Cumulus VX hardware, persistence, breakout, or readiness "
            "anchors not found. Upstream launch.py likely changed; update the "
            "Cumulus patch anchors."
        )
    if new_text != text:
        return new_text, [
            f"{path}: cumulus-vx hardware, persistence, breakout, "
            "and readiness applied"
        ]
    return new_text, [f"{path}: already patched"]
