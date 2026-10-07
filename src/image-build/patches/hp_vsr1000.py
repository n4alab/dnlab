"""Persistence patch for the upstream HP/HPE VSR1000 launcher.

The vendor launcher performs an interactive first-boot setup every time the
guest reports its automatic configuration phase.  That is correct for an
ephemeral vrnetlab overlay, but duplicates users and management configuration
when dNLab reuses a disk.  A marker adjacent to the persistent overlay makes
the first boot explicit and keeps later starts non-destructive.
"""

from __future__ import annotations

from . import _common


KIND = "hp_vsr1000"
FILES = ["/vrnetlab.py", "/launch.py"]

_MARKER = "# dnlab-patched: hp-vsr1000-persist-v1"
_PERSIST_MARKER = 'PERSIST_MARKER = "/persist/overlay.qcow2.dnlab-initialized"'

_INIT_ANCHOR = '''    def __init__(self, username, password):
        for e in os.listdir("/"):
'''
_INIT_REPLACEMENT = f'''    def __init__(self, username, password):
        {_MARKER}
        # The marker is created only after the initial guest bootstrap
        # completed, so an interrupted first boot remains retryable.
        self._dnlab_persistent_overlay_reused = os.path.isfile(PERSIST_MARKER)
        for e in os.listdir("/"):
'''

_V2_INIT_ANCHOR = '''    def __init__(self, username, password, conn_mode):
        for e in os.listdir("/"):
'''
_V2_INIT_REPLACEMENT = f'''    def __init__(self, username, password, conn_mode):
        {_MARKER}
        # The marker is created only after the initial guest bootstrap
        # completed, so an interrupted first boot remains retryable.
        self._dnlab_persistent_overlay_reused = os.path.isfile(PERSIST_MARKER)
        for e in os.listdir("/"):
'''

_BOOTSTRAP_ANCHOR = '''                # run main config!
                self.bootstrap_config()
                # close telnet connection
'''
_BOOTSTRAP_REPLACEMENT = '''                # A reused overlay already contains the initial account and
                # management configuration. Reapplying it can block on
                # duplicate resources and would overwrite user changes.
                if self._dnlab_persistent_overlay_reused:
                    self.logger.info(
                        "persistent HPE VSR1000 overlay reused; skipping bootstrap configuration"
                    )
                else:
                    self.bootstrap_config()
                # close telnet connection
'''

# hp/vsr1000_V2 retains console fragments for modern vrnetlab and therefore
# removes the legacy ``if ridx`` nesting level before this call.
_V2_BOOTSTRAP_ANCHOR = '''            # run main config!
            self.bootstrap_config()
            # close telnet connection
'''
_V2_BOOTSTRAP_REPLACEMENT = '''            # A reused overlay already contains the initial account and
            # management configuration. Reapplying it can block on
            # duplicate resources and would overwrite user changes.
            if self._dnlab_persistent_overlay_reused:
                self.logger.info(
                    "persistent HPE VSR1000 overlay reused; skipping bootstrap configuration"
                )
            else:
                self.bootstrap_config()
            # close telnet connection
'''

_DONE_ANCHOR = '''        self.logger.info("completed bootstrap configuration")
'''
_DONE_REPLACEMENT = f'''        self.logger.info("completed bootstrap configuration")
        if os.path.isdir("/persist"):
            with open(PERSIST_MARKER, "a", encoding="utf-8"):
                pass
'''


def _patch_launch(text: str) -> tuple[str, bool]:
    if _MARKER in text:
        return text, True
    if _PERSIST_MARKER not in text:
        text = text.replace(
            "import vrnetlab\n",
            f"import vrnetlab\n\n{_PERSIST_MARKER}\n",
            1,
        )
    if _DONE_ANCHOR not in text:
        return text, False
    if _INIT_ANCHOR in text:
        text = text.replace(_INIT_ANCHOR, _INIT_REPLACEMENT, 1)
    elif _V2_INIT_ANCHOR in text:
        text = text.replace(_V2_INIT_ANCHOR, _V2_INIT_REPLACEMENT, 1)
    else:
        return text, False
    if _BOOTSTRAP_ANCHOR in text:
        text = text.replace(_BOOTSTRAP_ANCHOR, _BOOTSTRAP_REPLACEMENT, 1)
    elif _V2_BOOTSTRAP_ANCHOR in text:
        text = text.replace(_V2_BOOTSTRAP_ANCHOR, _V2_BOOTSTRAP_REPLACEMENT, 1)
    else:
        return text, False
    text = text.replace(_DONE_ANCHOR, _DONE_REPLACEMENT, 1)
    return text, True


def apply(path: str, text: str) -> tuple[str, list[str]]:
    """Apply the dNLab overlay and first-boot guards."""
    if path == "/vrnetlab.py":
        new_text, ok = _common.patch_persist_overlay(text)
        if not ok:
            raise RuntimeError(
                f"{path}: persist-overlay anchor not found; update patches/_common.py"
            )
        return new_text, [
            f"{path}: persist-overlay applied"
            if new_text != text else f"{path}: already patched"
        ]
    if path == "/launch.py":
        new_text, ok = _patch_launch(text)
        if not ok:
            raise RuntimeError(
                f"{path}: HPE VSR1000 bootstrap anchors not found; update patches/hp_vsr1000.py"
            )
        return new_text, [
            f"{path}: HPE VSR1000 persistence applied"
            if new_text != text else f"{path}: already patched"
        ]
    raise RuntimeError(f"{path}: no patch plan for this file")
