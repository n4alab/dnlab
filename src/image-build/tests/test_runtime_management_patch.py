import ast
import builtins
import io
import os
import re
from types import SimpleNamespace

import pytest

from patches import _common

SOURCE = '''
class VM:
    def __init__(self, mgmt_intf="eth0"):
        self.mgmt_intf = os.environ.get("CLAB_MGMT_INTF", mgmt_intf)
    def get_mgmt_address(self):
        stdout, _ = run_command(["ip", "--json", "address", "show", "dev", "eth0"])
        return stdout
'''


def vm(monkeypatch, *, ready=True, marker="123", start="123"):
    patched, ok = _common.patch_runtime_management(SOURCE)
    assert ok
    calls = []
    clock = [0.0]
    def sleep(duration):
        clock[0] += duration
    original_open = builtins.open
    def open_fixture(path, *args, **kwargs):
        if path == "/proc/1/stat":
            return io.StringIO("1 (launcher) " + " ".join(["S"] + ["0"] * 18 + [start]))
        if path == "/run/dnlab-runtime/management-ready":
            if not ready:
                raise FileNotFoundError(path)
            return io.StringIO(marker)
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", open_fixture)
    namespace = {"os": os, "re": re, "time": SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep), "run_command": lambda args: (calls.append(args) or b"[]", b"")}
    exec(compile(patched, "runtime-management-candidate.py", "exec"), namespace)
    return namespace["VM"], calls


def test_legacy_clab_override_keeps_original_address_discovery(monkeypatch):
    monkeypatch.delenv("DNLAB_RUNTIME_MGMT_INTF", raising=False)
    monkeypatch.delenv("DNLAB_RUNTIME_BOOT_WAIT", raising=False)
    monkeypatch.setenv("CLAB_MGMT_INTF", "eth2")
    cls, calls = vm(monkeypatch)
    device = cls()
    assert device.mgmt_intf == "eth2"
    device.get_mgmt_address()
    assert calls[0][-1] == "eth0"


def test_runtime_uses_stable_interface_for_both_datapath_and_address(monkeypatch):
    monkeypatch.setenv("DNLAB_RUNTIME_MGMT_INTF", "mgmt0")
    monkeypatch.setenv("DNLAB_RUNTIME_BOOT_WAIT", "true")
    cls, calls = vm(monkeypatch)
    device = cls()
    assert device.mgmt_intf == "mgmt0"
    device.get_mgmt_address()
    assert calls[0][-1] == "mgmt0"


def test_boot_wait_failure_prevents_guest_initialization(monkeypatch):
    monkeypatch.setenv("DNLAB_RUNTIME_MGMT_INTF", "mgmt0")
    monkeypatch.setenv("DNLAB_RUNTIME_BOOT_WAIT", "true")
    monkeypatch.setenv("DNLAB_RUNTIME_BOOT_TIMEOUT", "0.2")
    cls, calls = vm(monkeypatch, ready=False)
    with pytest.raises(RuntimeError, match="before guest boot"):
        cls()
    assert calls == []


@pytest.mark.parametrize("value", ["mgmt0;echo", "lo/../../", "x" * 16])
def test_invalid_interface_rejected(monkeypatch, value):
    monkeypatch.setenv("DNLAB_RUNTIME_MGMT_INTF", value)
    cls, _ = vm(monkeypatch)
    with pytest.raises(ValueError, match="Invalid"):
        cls()


def test_missing_anchor_returns_unmodified_source():
    source = SOURCE.replace('"CLAB_MGMT_INTF"', '"DIFFERENT"')
    assert _common.patch_runtime_management(source) == (source, False)


def test_transform_is_compilable_and_idempotent():
    patched, ok = _common.patch_runtime_management(SOURCE)
    assert ok
    ast.parse(patched)
    assert _common.patch_runtime_management(patched) == (patched, True)


def test_stale_marker_from_previous_container_boot_does_not_release(monkeypatch):
    monkeypatch.setenv("DNLAB_RUNTIME_MGMT_INTF", "mgmt0")
    monkeypatch.setenv("DNLAB_RUNTIME_BOOT_WAIT", "true")
    monkeypatch.setenv("DNLAB_RUNTIME_BOOT_TIMEOUT", "0.2")
    cls, calls = vm(monkeypatch, marker="122", start="123")
    with pytest.raises(RuntimeError, match="before guest boot"):
        cls()
    assert calls == []


LAUNCHER_ABI = '''
class Device(VM):
    def __init__(self):
        super(Device, self).__init__(
            use_scrapli=True,
        )
'''


def test_retired_scrapli_keyword_is_removed_and_constructor_runs():
    common = 'class VM:\n    def __init__(self): pass\n'
    patched, ok = _common.patch_launcher_constructor(LAUNCHER_ABI, common)
    assert ok
    namespace = {}
    exec(common + patched, namespace)
    namespace['Device']()
    assert _common.patch_launcher_constructor(patched, common) == (patched, True)


def test_existing_scrapli_constructor_keeps_keyword():
    common = 'class VM:\n    def __init__(self, use_scrapli): pass\n'
    assert _common.patch_launcher_constructor(LAUNCHER_ABI, common) == (LAUNCHER_ABI, True)


def test_retired_false_scrapli_setting_cannot_be_silently_changed():
    common = 'class VM:\n    def __init__(self): pass\n'
    source = LAUNCHER_ABI.replace('use_scrapli=True', 'use_scrapli=False')
    assert _common.patch_launcher_constructor(source, common) == (source, False)
