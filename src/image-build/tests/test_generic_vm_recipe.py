import argparse
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("build_image", ROOT / "build_image.py")
assert SPEC and SPEC.loader
build_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_image)


def _spec(**changes):
    value = {
        "id": "edge_router", "version": "1.0.0", "label": "Edge Router",
        "vendor": "generic", "type": "server", "firmware": "uefi",
        "nic_model": "virtio", "vcpu": 2, "ram_mb": 4096, "data_ports": 2,
        "mgmt_name": "mgmt0", "port_template": "ge-{n}",
        "port_names": {"1": "mgmt0", "2": "ge-1", "3": "ge-2"},
    }
    value.update(changes)
    return value


def test_generic_vm_spec_and_tag_are_deterministic():
    spec = build_image.validate_generic_vm_spec(_spec())
    assert build_image.generic_vm_tag(spec) == "vrnetlab/dnlab_edge_router:1.0.0-dnlab"
    assert spec["port_names"]["1"] == "mgmt0"


@pytest.mark.parametrize("change", [
    {"id": "UPPER"}, {"firmware": "coreboot"}, {"nic_model": "rtl8139"},
    {"data_ports": 33}, {"port_names": {"1": "same", "2": "same"}},
])
def test_generic_vm_spec_rejects_invalid_profiles(change):
    with pytest.raises(ValueError):
        build_image.validate_generic_vm_spec(_spec(**change))


def test_generic_vm_recipe_builds_qcow2_with_profile(tmp_path, monkeypatch):
    source = tmp_path / "router.qcow2"
    source.write_bytes(b"qcow2")
    calls = []
    monkeypatch.setattr(build_image, "_run", lambda command, **kwargs: calls.append((command, kwargs)))
    monkeypatch.setattr(build_image, "_require_built_image", lambda *_args, **_kwargs: None)
    assert build_image.cmd_build(argparse.Namespace(kind="generic_vm", source=str(source), generic_spec=_spec(), plain=False, with_persistence=False, dry_run=False, vrnetlab_root=str(tmp_path))) == 0
    assert calls[0][0] == ["docker", "build", "--tag", "vrnetlab/dnlab_edge_router:1.0.0-dnlab", "."]


def test_generic_recipe_declares_persistence_and_uefi_runtime():
    recipe = ROOT / "recipes" / "generic_vm"
    assert "/persist/overlay.qcow2" in (recipe / "patch_vrnetlab.py").read_text(encoding="utf-8")
    assert "/persist/OVMF_VARS.fd" in (recipe / "entrypoint.sh").read_text(encoding="utf-8")
    assert 'OVMF_CODE${suffix}.fd' in (recipe / "Dockerfile").read_text(encoding="utf-8")
    assert "SPEC[\"data_ports\"]" in (recipe / "launch.py").read_text(encoding="utf-8")
