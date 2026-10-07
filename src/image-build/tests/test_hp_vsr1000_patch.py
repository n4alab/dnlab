from __future__ import annotations

from patches import hp_vsr1000 as PATCH


LAUNCH = '''import os
import vrnetlab

class VSR_vm(vrnetlab.VM):
    def __init__(self, username, password):
        for e in os.listdir("/"):
            pass

    def bootstrap_spin(self):
        (ridx, match, res) = self.tn.expect([b"Performing automatic"], 1)
        if match:
            if ridx == 0:
                # run main config!
                self.bootstrap_config()
                # close telnet connection
                self.tn.close()

    def bootstrap_config(self):
        self.logger.info("completed bootstrap configuration")
'''

VRNETLAB = '''import os
import re

def prepare(disk_image):
    overlay_disk_image = re.sub(r"(\\.[^.]+$)", r"-overlay\\1", disk_image)
    return overlay_disk_image
'''


def test_hp_vsr1000_patch_uses_persist_overlay_and_skips_reused_bootstrap():
    patched, notes = PATCH.apply("/launch.py", LAUNCH)

    assert notes == ["/launch.py: HPE VSR1000 persistence applied"]
    assert 'PERSIST_MARKER = "/persist/overlay.qcow2.dnlab-initialized"' in patched
    assert "self._dnlab_persistent_overlay_reused = os.path.isfile(PERSIST_MARKER)" in patched
    assert "skipping bootstrap configuration" in patched
    assert 'with open(PERSIST_MARKER, "a", encoding="utf-8"):' in patched
    compile(patched, "/launch.py", "exec")

    again, notes = PATCH.apply("/launch.py", patched)
    assert again == patched
    assert notes == ["/launch.py: already patched"]


def test_hp_vsr1000_patch_redirects_base_overlay_to_persist():
    patched, notes = PATCH.apply("/vrnetlab.py", VRNETLAB)

    assert notes == ["/vrnetlab.py: persist-overlay applied"]
    assert '"/persist/overlay.qcow2" if os.path.isdir("/persist")' in patched


def test_hp_vsr1000_patch_supports_v2_console_buffer_launcher():
    v2_launch = LAUNCH.replace(
        "def __init__(self, username, password):",
        "def __init__(self, username, password, conn_mode):",
        1,
    ).replace(
        '''        (ridx, match, res) = self.tn.expect([b"Performing automatic"], 1)
        if match:
            if ridx == 0:
                # run main config!
                self.bootstrap_config()
                # close telnet connection
''',
        '''        res = self.tn.read_very_eager()
        if b"Performing automatic" in res:
            # run main config!
            self.bootstrap_config()
            # close telnet connection
''',
    )

    patched, notes = PATCH.apply("/launch.py", v2_launch)

    assert notes == ["/launch.py: HPE VSR1000 persistence applied"]
    assert "skipping bootstrap configuration" in patched
    compile(patched, "/launch.py", "exec")
