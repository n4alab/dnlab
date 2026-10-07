import argparse
import importlib.util
import sys
import types
from types import SimpleNamespace
from pathlib import Path

import pytest
import flinos_bundle


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("build_image", ROOT / "build_image.py")
assert SPEC and SPEC.loader
build_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_image)


def _load_flinos_launcher(monkeypatch):
    class FakeVM:
        def __init__(self, **_kwargs):
            self.tn = None

        def create_tc_tap_ifup(self):
            return None

        def nic_provision_delay(self):
            return None

    fake_vrnetlab = types.SimpleNamespace(
        VM=FakeVM,
        VR=object,
        gen_mac=lambda index: f"0c:00:00:00:00:{index:02x}",
    )
    monkeypatch.setitem(sys.modules, "vrnetlab", fake_vrnetlab)
    spec = importlib.util.spec_from_file_location(
        "flinos_launcher_test", ROOT / "recipes" / "flinos" / "launch.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_flinos_recipe_is_listed_and_derives_a_stable_tag(tmp_path):
    release = "0.1.0-dev1"

    assert "flinos" in build_image.QCOW_RECIPE_KINDS
    assert build_image.is_persistent_kind("flinos")
    assert build_image._flinos_tag(release) == "vrnetlab/n4alab_flinos:0.1.0-dev1-dnlab"


def test_flinos_recipe_builds_from_verified_bundle_without_vrnetlab_directory(tmp_path, monkeypatch):
    bundle = tmp_path / "flinos-1.2.3.zip"
    bundle.write_bytes(b"zip")
    calls = []
    def verified(_bundle, directory):
        directory.mkdir()
        for name in build_image.REQUIRED_FILES:
            (directory / name).write_bytes(b"artifact")
        return SimpleNamespace(release="1.2.3", directory=directory, development=False, files=build_image.REQUIRED_FILES)
    monkeypatch.setattr(build_image, "validate_and_extract", verified)
    monkeypatch.setattr(build_image, "_run", lambda command, **kwargs: calls.append((command, kwargs)))
    monkeypatch.setattr(build_image, "_require_built_image", lambda *_args, **_kwargs: None)

    result = build_image.cmd_build(argparse.Namespace(kind="flinos", source=str(bundle), plain=False, with_persistence=False, dry_run=False, vrnetlab_root=str(tmp_path / "vrnetlab")))

    assert result == 0
    assert calls == [(["docker", "build", "--tag", "vrnetlab/n4alab_flinos:1.2.3-dnlab", "."], {"cwd": calls[0][1]["cwd"], "dry": False})]
    assert calls[0][1]["cwd"].name == "context"


def test_flinos_development_recipe_uses_an_isolated_tag_and_bundle_files(tmp_path, monkeypatch):
    bundle = tmp_path / "flinos-dev.zip"
    bundle.write_bytes(b"zip")
    calls = []

    def verified(_bundle, directory):
        directory.mkdir()
        for name in flinos_bundle.DEVELOPMENT_FILES:
            (directory / name).write_bytes(b"artifact")
        return SimpleNamespace(
            release="1.2.3-alpha-1", directory=directory, development=True,
            files=flinos_bundle.DEVELOPMENT_FILES,
        )

    monkeypatch.setattr(build_image, "validate_and_extract", verified)
    monkeypatch.setattr(build_image, "_run", lambda command, **kwargs: calls.append((command, kwargs)))
    monkeypatch.setattr(build_image, "_require_built_image", lambda *_args, **_kwargs: None)

    assert build_image._flinos_development_tag("1.2.3-alpha-1") == "vrnetlab/n4alab_flinos-dev:1.2.3-alpha-1-dnlab"
    assert build_image.cmd_build(argparse.Namespace(kind="flinos", source=str(bundle), plain=False, with_persistence=False, dry_run=False, vrnetlab_root=str(tmp_path / "vrnetlab"))) == 0
    assert calls[0][0] == ["docker", "build", "--tag", "vrnetlab/n4alab_flinos-dev:1.2.3-alpha-1-dnlab", "."]
    context = calls[0][1]["cwd"]
    assert context.name == "context"
    assert not context.exists()


def test_flinos_development_recipe_has_no_secure_boot_artifacts():
    dockerfile = (ROOT / "recipes" / "flinos-dev" / "Dockerfile").read_text(encoding="utf-8")

    assert "OVMF" not in dockerfile
    assert "pflash" not in dockerfile
    assert "entrypoint.sh" not in dockerfile
    assert 'ENTRYPOINT ["/opt/flinos/launch.sh"]' in dockerfile


def test_flinos_launcher_allocates_all_data_slots():
    launcher = (ROOT / "recipes" / "flinos" / "launch.py").read_text(encoding="utf-8")

    assert "for index in range(1, 9)" in launcher
    assert "socket,id={netdev},listen=:{10000 + index}" in launcher
    assert "def gen_dummy_nics" in launcher
    assert "tap0 <-> eth0" in launcher
    assert "tap1..tap8 <-> eth1..eth8" in launcher


def test_flinos_recipe_patches_vrnetlab_overlay_to_the_persist_bind(tmp_path):
    dockerfile = (ROOT / "recipes" / "flinos" / "Dockerfile").read_text(encoding="utf-8")
    patcher_path = ROOT / "recipes" / "flinos" / "patch_vrnetlab.py"
    patcher_spec = importlib.util.spec_from_file_location("flinos_patcher", patcher_path)
    assert patcher_spec and patcher_spec.loader
    patcher = importlib.util.module_from_spec(patcher_spec)
    patcher_spec.loader.exec_module(patcher)

    assert "patch-vrnetlab.py" in dockerfile
    assert "ARG VRNETLAB" not in dockerfile
    assert "3e8578d2e946d38a3176480e80f8510bdb2ee53a" in dockerfile
    assert "entrypoint.sh" in dockerfile
    source = "def build():\n        " + patcher.ANCHOR + "\n"
    target = tmp_path / "vrnetlab.py"
    target.write_text(source, encoding="utf-8")
    patcher.patch(target)

    assert "/persist/overlay.qcow2" in target.read_text(encoding="utf-8")
    compile(target.read_text(encoding="utf-8"), str(target), "exec")


def test_flinos_recipe_keeps_vrnetlab_telnetlib_available_on_python_313():
    dockerfile = (ROOT / "recipes" / "flinos" / "Dockerfile").read_text(encoding="utf-8")

    assert "python3-zombie-telnetlib" in dockerfile


def test_flinos_recipe_installs_the_console_telnet_client():
    dockerfile = (ROOT / "recipes" / "flinos" / "Dockerfile").read_text(encoding="utf-8")

    assert "inetutils-telnet" in dockerfile


def test_flinos_launcher_releases_vrnetlab_bootstrap_serial_connection():
    launcher = (ROOT / "recipes" / "flinos" / "launch.py").read_text(encoding="utf-8")

    assert "if self.tn is not None:" in launcher
    assert "self.tn.close()" in launcher
    assert "self.tn = None" in launcher


def test_flinos_containerlab_mac_reads_and_validates_runtime_address(monkeypatch):
    launcher = _load_flinos_launcher(monkeypatch)

    class FakePath:
        def __init__(self, path):
            self.path = path

        def read_text(self, *, encoding):
            assert encoding == "utf-8"
            return "06:26:8E:73:32:7A\n"

    monkeypatch.setattr(launcher, "Path", FakePath)

    assert launcher.containerlab_mac(0) == "06:26:8e:73:32:7a"


def test_flinos_containerlab_mac_handles_missing_and_invalid_addresses(monkeypatch):
    launcher = _load_flinos_launcher(monkeypatch)

    class MissingPath:
        def __init__(self, _path):
            pass

        def read_text(self, *, encoding):
            raise FileNotFoundError

    monkeypatch.setattr(launcher, "Path", MissingPath)
    assert launcher.containerlab_mac(4) is None

    class InvalidPath:
        def __init__(self, _path):
            pass

        def read_text(self, *, encoding):
            return "not-a-mac\n"

    monkeypatch.setattr(launcher, "Path", InvalidPath)
    with pytest.raises(RuntimeError, match="invalid Containerlab MAC for eth4"):
        launcher.containerlab_mac(4)


def test_flinos_launcher_uses_reserved_management_mac_and_runtime_data_macs(monkeypatch):
    launcher = _load_flinos_launcher(monkeypatch)
    addresses = {
        "/sys/class/net/eth0/address": "06:26:8e:73:32:7a\n",
        "/sys/class/net/eth1/address": "02:00:00:00:00:01\n",
        "/sys/class/net/eth2/address": "02:00:00:00:00:02\n",
    }

    class FakePath:
        def __init__(self, path):
            self.path = path

        def read_text(self, *, encoding):
            if self.path not in addresses:
                raise FileNotFoundError
            return addresses[self.path]

    monkeypatch.setattr(launcher, "Path", FakePath)
    monkeypatch.setenv("CLAB_MGMT_MAC", "02:c5:da:29:43:0d")
    vm = launcher.FlinosVM()

    mgmt = vm.gen_mgmt()
    data = vm.gen_nics()

    assert "mac=02:c5:da:29:43:0d" in mgmt[1]
    assert "mac=02:00:00:00:00:01" in data[1]
    assert "tap,id=p01,ifname=tap1" in data[3]
    assert "mac=0c:00:00:00:00:03" in data[9]
    assert "socket,id=p03,listen=:10003" in data[11]


def test_flinos_launcher_requires_containerlab_management_interface(monkeypatch):
    launcher = _load_flinos_launcher(monkeypatch)
    monkeypatch.delenv("CLAB_MGMT_MAC", raising=False)
    monkeypatch.setattr(launcher, "containerlab_mac", lambda _index: None)

    with pytest.raises(RuntimeError, match="management interface eth0 is required"):
        launcher.FlinosVM().gen_mgmt()

def test_flinos_management_mac_falls_back_to_containerlab(monkeypatch):
    launcher = _load_flinos_launcher(monkeypatch)
    monkeypatch.delenv("CLAB_MGMT_MAC", raising=False)
    monkeypatch.setattr(launcher, "containerlab_mac", lambda index: "06:26:8e:73:32:7a" if index == 0 else None)

    assert "mac=06:26:8e:73:32:7a" in launcher.FlinosVM().gen_mgmt()[1]


def test_flinos_management_mac_rejects_invalid_reservation(monkeypatch):
    launcher = _load_flinos_launcher(monkeypatch)
    monkeypatch.setenv("CLAB_MGMT_MAC", "not-a-mac")

    with pytest.raises(RuntimeError, match="invalid CLAB_MGMT_MAC"):
        launcher.FlinosVM().gen_mgmt()
