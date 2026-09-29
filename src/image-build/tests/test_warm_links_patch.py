from __future__ import annotations

from pathlib import Path

from patches import _common
import warm_links


VRNETLAB_SAMPLE = '''import os
import time

class VR:
    def start(self):
        started = False
        while True:
            all_running = all(vm.running for vm in self.vms)
            if all_running:
                self.update_health(0, "running")
                started = True
            else:
                self.update_health(1, "starting")

class VM:
    def start(self):
        cmd = []
        self.logger.debug("qemu cmd: {}".format(" ".join(cmd)))

    def nic_provision_delay(self):
        while True:
            time.sleep(5)

        # check if we need to provision any more nics

    def gen_nics(self, i, mac):
        res = []
        res.append(
            f"{self.nic_type},netdev=p{i:02d},mac={mac}"
            + (
                f",bus=pci.{self.pci_bus},addr=0x{self.addr:x}"
                if self.provision_pci_bus
                else ""
            ),
        )
        return res

class QemuBroken(Exception):
    pass
'''


def test_warm_link_patch_is_compilable_and_idempotent():
    patched, ok = _common.patch_warm_links(VRNETLAB_SAMPLE)
    assert ok
    assert "DNLAB_NIC_POLL_INTERVAL" in patched
    assert "set_link p{index:02d}" in patched
    assert 'cmd.append("-S")' in patched
    assert 'monitor_command("cont")' in patched
    assert 'driver = getattr(vm, "scrapli_qm", None)' in patched
    assert "return bool(driver.isalive())" in patched
    assert "wait_monitor(require_running=True)" in patched
    assert "/run/dnlab-link-control.sock" in patched
    assert '"running-degraded: " + "; ".join(degraded)' in patched
    assert patched.index("server.bind(path)") < patched.index("wait_monitor()")
    assert patched.index("wait_monitor()") < patched.index('monitor_command("cont")')
    compile(patched, "/vrnetlab.py", "exec")

    again, ok = _common.patch_warm_links(patched)
    assert ok
    assert again == patched


def test_only_exact_validated_base_digest_is_certified():
    image, digest = next(iter(warm_links.VALIDATED_BASE_IMAGES.items()))
    assert warm_links.validation_status(image, digest) == "validated"
    assert warm_links.validation_status(image, f"repository@{digest}") == "validated"
    assert warm_links.validation_status(image, "sha256:different") == "experimental"
    assert warm_links.validation_status("other:tag", digest) == "experimental"


def test_cluster4_exact_digests_passed_technical_gate_but_are_not_certified():
    entries = [
        item for item in warm_links.REGISTRY["images"]
        if item["cluster"] == 4
    ]
    assert len(entries) == 4
    assert all(item["technical"] == "passed" for item in entries)
    for image, digest in warm_links.CLUSTER4_CANDIDATE_BASE_IMAGES.items():
        assert warm_links.validation_status(image, digest) == "experimental"


def test_linkctl_asset_is_executable():
    asset = Path(__file__).parents[1] / "assets" / "dnlab-linkctl"
    assert asset.stat().st_mode & 0o111
    assert "uv run --no-project" in asset.read_text()
    assert (asset.parent / "dnlab_linkctl.py").is_file()
