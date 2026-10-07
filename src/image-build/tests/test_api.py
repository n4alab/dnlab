import asyncio
from pathlib import Path

import pytest
from fastapi import HTTPException

import api
import build_image
import vrnetlab_binding


def _set_store(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api, "WORKSPACE", tmp_path)
    monkeypatch.setattr(api, "JOBS_DIR", tmp_path / "jobs")
    monkeypatch.setattr(api, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(api, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(
        api,
        "_binding_status",
        vrnetlab_binding.BindingStatus("aligned", "repo", "dnlab", "a" * 40, "a" * 40),
    )
    api._jobs.clear()


def test_vrnetlab_binding_status_and_degraded_job_rejection(monkeypatch, tmp_path):
    status = vrnetlab_binding.BindingStatus("degraded", "repo", "dnlab", "a" * 40, None, "network unavailable")
    monkeypatch.setattr(api, "_binding_status", status)
    assert asyncio.run(api.vrnetlab_binding_status()) == status.payload()
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    with pytest.raises(HTTPException, match="binding is degraded"):
        asyncio.run(api.create_job(api.ImageBuildRequest(kind="cisco_xrv")))


class _FakeUpload:
    def __init__(self, content: bytes, filename: str):
        self._content = content
        self._read = False
        self.filename = filename

    async def read(self, _size: int | None = None):
        if self._read:
            return b""
        self._read = True
        return self._content

    async def close(self):
        return None


def test_kinds_include_patchable_and_vrnetlab_builders(monkeypatch, tmp_path):
    patches = tmp_path / "patches"
    patches.mkdir()
    (patches / "openwrt.py").write_text("# patch\n", encoding="utf-8")
    monkeypatch.setattr(build_image, "PATCHES_DIR", patches)

    vrnetlab = tmp_path / "vrnetlab"
    (vrnetlab / "openwrt_V2").mkdir(parents=True)
    (vrnetlab / "openwrt_V2" / "Makefile").write_text("IMAGE_GLOB=*.qcow2\ndocker-image:\n\ttrue\n", encoding="utf-8")
    (vrnetlab / "openwrt_V2" / "README.md").write_text("Example filename: `openwrt-23.05.qcow2`\n", encoding="utf-8")
    (vrnetlab / "f5_bigip").mkdir(parents=True)
    (vrnetlab / "f5_bigip" / "Makefile").write_text("docker-image:\n\ttrue\n", encoding="utf-8")
    monkeypatch.setattr(api, "VRNETLAB_ROOT", vrnetlab)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    data = api._kinds_payload()
    by_kind = {item["kind"]: item for item in data["kinds"]}

    assert "openwrt" in data["patchable"]
    assert "openwrt" in data["vrnetlab"]
    assert by_kind["openwrt"]["builder"] == "dnlab-image-build"
    assert by_kind["openwrt"]["patchable"] is True
    assert by_kind["openwrt"]["image_globs"] == ["*.qcow2"]
    assert by_kind["openwrt"]["image_examples"] == ["openwrt-23.05.qcow2"]
    assert by_kind["f5_bigip"]["builder"] == "vrnetlab-make"
    assert by_kind["f5_bigip"]["patchable"] is False


def test_frr_is_source_free_but_other_kinds_require_upload(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    patches = tmp_path / "patches"
    patches.mkdir()
    (patches / "dnlab_frr.py").write_text("# patch\n", encoding="utf-8")
    monkeypatch.setattr(build_image, "PATCHES_DIR", patches)
    vrnetlab = tmp_path / "vrnetlab"
    frr = vrnetlab / "dnlab" / "frr"
    frr.mkdir(parents=True)
    (frr / "Makefile").write_text("docker-image:\n\ttrue\n", encoding="utf-8")
    monkeypatch.setattr(api, "VRNETLAB_ROOT", vrnetlab)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    data = api._kinds_payload()
    by_kind = {item["kind"]: item for item in data["kinds"]}
    assert by_kind["dnlab_frr"]["source_required"] is False

    def fake_create_task(coro):
        coro.close()
        return None

    monkeypatch.setattr(api.asyncio, "create_task", fake_create_task)
    result = asyncio.run(api.create_job(api.ImageBuildRequest(kind="dnlab_frr")))
    assert result["source_path"] is None
    assert result["with_persistence"] is True

    with pytest.raises(HTTPException, match="requires an uploaded source"):
        asyncio.run(api.create_job(api.ImageBuildRequest(kind="openwrt")))


def test_flinos_recipe_is_persistent_and_requires_bundle(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    data = api._kinds_payload()
    flinos = next(item for item in data["kinds"] if item["kind"] == "flinos")
    assert flinos["patchable"] is False
    assert flinos["persistent"] is True
    assert flinos["image_globs"] == ["*.zip"]
    assert flinos["development_warning"] == "Unsigned FLINOS development bundle — not for production"

    def fake_create_task(coro):
        coro.close()
        return None

    monkeypatch.setattr(api.asyncio, "create_task", fake_create_task)
    source = api.UPLOADS_DIR / "flinos" / "flinos-1.2.zip"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"")
    result = asyncio.run(api.create_job(api.ImageBuildRequest(kind="flinos", source_path=str(source))))
    assert result["with_persistence"] is True

    with pytest.raises(HTTPException, match="requires a .zip"):
        api._validate_image_filename("flinos", "flinos.iso")

    api._validate_image_filename("flinos", "flinos-1.2.zip")

    with pytest.raises(HTTPException, match="requires a .zip"):
        api._validate_image_filename("flinos", "flinos-1.2.qcow2")


def test_generic_vm_requires_qcow2_and_valid_profile(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")
    source = api.UPLOADS_DIR / "generic" / "router.qcow2"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"qcow2")
    spec = {
        "id": "router", "version": "1.0", "label": "Router", "vendor": "generic",
        "type": "server", "firmware": "bios", "nic_model": "virtio", "vcpu": 1,
        "ram_mb": 2048, "data_ports": 1, "mgmt_name": "mgmt0", "port_template": "eth{i}",
        "port_names": {"1": "mgmt0", "2": "eth0"},
    }
    api._validate_image_format("generic_vm", str(source))
    with pytest.raises(HTTPException, match="requires a .qcow2"):
        api._validate_image_filename("generic_vm", "router.img")
    assert build_image.validate_generic_vm_spec(spec)["id"] == "router"


def test_upload_sanitizes_filename_and_returns_source_path(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)

    upload = _FakeUpload(b"image-bytes", "../../bad name.qcow2")
    data = asyncio.run(api.upload_image(upload))

    assert data["filename"] == "bad_name.qcow2"
    source = Path(data["source_path"])
    assert source.read_bytes() == b"image-bytes"
    assert source.parent.parent == tmp_path / "uploads"


def test_create_job_forces_persistence_for_patchable_kind(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    patches = tmp_path / "patches"
    patches.mkdir()
    (patches / "openwrt.py").write_text("# patch\n", encoding="utf-8")
    monkeypatch.setattr(build_image, "PATCHES_DIR", patches)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    def fake_create_task(coro):
        coro.close()
        return None

    monkeypatch.setattr(api.asyncio, "create_task", fake_create_task)

    vrnetlab = tmp_path / "vrnetlab" / "openwrt_V2"
    vrnetlab.mkdir(parents=True)
    (vrnetlab / "Makefile").write_text("IMAGE_GLOB=*.qcow2\n", encoding="utf-8")
    monkeypatch.setattr(api, "VRNETLAB_ROOT", tmp_path / "vrnetlab")

    source = api.UPLOADS_DIR / "abc123" / "openwrt.qcow2"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"")

    data = asyncio.run(
        api.create_job(
            api.ImageBuildRequest(
                kind="openwrt",
                source_path=str(source),
                with_persistence=False,
            )
        )
    )

    assert data["with_persistence"] is True


def test_create_job_disables_persistence_for_plain_vrnetlab_kind(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    patches = tmp_path / "patches"
    patches.mkdir()
    monkeypatch.setattr(build_image, "PATCHES_DIR", patches)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    def fake_create_task(coro):
        coro.close()
        return None

    monkeypatch.setattr(api.asyncio, "create_task", fake_create_task)

    vrnetlab = tmp_path / "vrnetlab" / "f5_bigip"
    vrnetlab.mkdir(parents=True)
    (vrnetlab / "Makefile").write_text("IMAGE_GLOB=*.qcow2\n", encoding="utf-8")
    monkeypatch.setattr(api, "VRNETLAB_ROOT", tmp_path / "vrnetlab")

    source = api.UPLOADS_DIR / "def456" / "bigip.qcow2"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"")

    data = asyncio.run(
        api.create_job(
            api.ImageBuildRequest(
                kind="f5_bigip",
                source_path=str(source),
                with_persistence=True,
            )
        )
    )

    assert data["with_persistence"] is False


def test_create_job_rejects_wrong_image_format(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    vrnetlab = tmp_path / "vrnetlab" / "n9kv_V2"
    vrnetlab.mkdir(parents=True)
    (vrnetlab / "Makefile").write_text("IMAGE_GLOB=*.qcow2\n", encoding="utf-8")
    monkeypatch.setattr(api, "VRNETLAB_ROOT", tmp_path / "vrnetlab")
    monkeypatch.setitem(build_image.KIND_VRNETLAB_DIR, "cisco_n9kv", ["n9kv_V2"])

    source = api.UPLOADS_DIR / "ff00" / "n9kv-9300-10.5.4.M.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            api.create_job(
                api.ImageBuildRequest(kind="cisco_n9kv", source_path=str(source))
            )
        )
    assert exc.value.status_code == 400
    assert "*.qcow2" in exc.value.detail


def test_validate_filename_rejects_name_that_makefile_cannot_parse(monkeypatch, tmp_path):
    vrnetlab = tmp_path / "vrnetlab" / "n9kv_V2"
    vrnetlab.mkdir(parents=True)
    (vrnetlab / "Makefile").write_text(
        "\n".join([
            "IMAGE_FORMAT=qcow2",
            "IMAGE_GLOB=*.qcow2",
            "VERSION=$(shell echo $(IMAGE) | sed -e 's/n9kv-\\(.*\\)\\.qcow2/\\1/')",
            "version-test:",
            "\t@echo Version: $(VERSION)",
            "",
        ]),
        encoding="utf-8",
    )
    (vrnetlab / "README.md").write_text(
        "The filename must follow the format:\n\n```\nn9kv-<version>.qcow2\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(api, "VRNETLAB_ROOT", tmp_path / "vrnetlab")
    monkeypatch.setitem(build_image.KIND_VRNETLAB_DIR, "cisco_n9kv", ["n9kv_V2"])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            api.validate_filename(
                api.ImageFilenameValidationRequest(
                    kind="cisco_n9kv",
                    filename="cat9kv-prd-17.12.01.qcow2",
                )
            )
        )

    assert exc.value.status_code == 400
    assert "cisco_n9kv" in exc.value.detail
    assert "n9kv-<version>.qcow2" in exc.value.detail


def test_create_job_rejects_path_outside_uploads(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)
    monkeypatch.setattr(api, "SCRIPT", tmp_path / "build_image.py")
    api.SCRIPT.write_text("# script\n", encoding="utf-8")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            api.create_job(
                api.ImageBuildRequest(kind="cisco_n9kv", source_path="/etc/passwd")
            )
        )
    assert exc.value.status_code == 400
    assert "uploaded image" in exc.value.detail


def test_clear_jobs_removes_finished_keeps_active(monkeypatch, tmp_path):
    _set_store(monkeypatch, tmp_path)

    done = api.Job(id="done1", kind="k", source_path="s", with_persistence=False,
                   status="success")
    failed = api.Job(id="fail1", kind="k", source_path="s", with_persistence=False,
                     status="failed")
    running = api.Job(id="run1", kind="k", source_path="s", with_persistence=False,
                      status="running")
    for job in (done, failed, running):
        api._jobs[job.id] = job
        api._save_job(job)
        api._append_log(job, "line")

    result = asyncio.run(api.clear_jobs())

    assert result == {"removed": 2}
    assert set(api._jobs) == {"run1"}
    assert not api._job_state_path("done1").exists()
    assert not api._job_log_path("fail1").exists()
    assert api._job_state_path("run1").exists()
