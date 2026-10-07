import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.views.api import admin_routes


def _fake_build_module(work_dir: Path):
    return SimpleNamespace(
        CONTAINER_NATIVE_KINDS=set(),
        resolve_vrnetlab_dir=lambda _kind, _root: work_dir,
        image_globs_for=lambda _work_dir: ["*.qcow2"],
        list_patchable_kinds=lambda: [],
        list_vrnetlab_kinds=lambda _root: [{"kind": "cisco_n9kv", "vrnetlab_dir": str(work_dir)}],
    )


def _write_n9kv_makefile(work_dir: Path) -> None:
    work_dir.mkdir(parents=True)
    (work_dir / "Makefile").write_text(
        "\n".join(
            [
                "IMAGE_FORMAT=qcow2",
                "IMAGE_GLOB=*.qcow2",
                "VERSION=$(shell echo $(IMAGE) | sed -e 's/n9kv-\\(.*\\)\\.qcow2/\\1/')",
                "version-test:",
                "\t@echo Extracting version from filename $(IMAGE)",
                "\t@echo Version: $(VERSION)",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_image_build_rejects_n9kv_filename_that_makefile_cannot_parse(monkeypatch, tmp_path):
    work_dir = tmp_path / "vrnetlab" / "cisco" / "n9kv"
    _write_n9kv_makefile(work_dir)
    (work_dir / "README.md").write_text(
        "The filename must follow the format:\n\n"
        "```\n"
        "n9kv-<version>.qcow2\n"
        "```\n\n"
        "For example: `n9kv-9300-10.5.2.qcow2`\n",
        encoding="utf-8",
    )
    source = tmp_path / "cat9kv-prd-17.12.01.qcow2"
    source.write_bytes(b"image")

    monkeypatch.setattr(admin_routes, "_load_image_build_module", lambda _root: _fake_build_module(work_dir))
    monkeypatch.setattr(admin_routes, "_vrnetlab_dir", lambda: tmp_path / "vrnetlab")

    with pytest.raises(HTTPException) as exc:
        admin_routes._validate_local_image_build_source("cisco_n9kv", source)

    assert exc.value.status_code == 400
    assert "cisco_n9kv" in exc.value.detail
    assert "*.qcow2" in exc.value.detail
    assert "n9kv-<version>.qcow2" in exc.value.detail


def test_image_build_rejects_wrong_extension_before_makefile_preflight(monkeypatch, tmp_path):
    work_dir = tmp_path / "vrnetlab" / "cisco" / "n9kv"
    _write_n9kv_makefile(work_dir)
    source = tmp_path / "n9kv-9300-10.5.2.bin"
    source.write_bytes(b"image")

    monkeypatch.setattr(admin_routes, "_load_image_build_module", lambda _root: _fake_build_module(work_dir))
    monkeypatch.setattr(admin_routes, "_vrnetlab_dir", lambda: tmp_path / "vrnetlab")

    with pytest.raises(HTTPException) as exc:
        admin_routes._validate_local_image_build_source("cisco_n9kv", source)

    assert exc.value.status_code == 400
    assert "n9kv-9300-10.5.2.bin" in exc.value.detail
    assert "*.qcow2" in exc.value.detail


def test_image_build_kinds_include_globs_and_readme_examples(monkeypatch, tmp_path):
    image_build = tmp_path / "image-build"
    image_build.mkdir()
    (image_build / "build_image.py").write_text("# fake\n", encoding="utf-8")
    work_dir = tmp_path / "vrnetlab" / "cisco" / "n9kv"
    _write_n9kv_makefile(work_dir)
    (work_dir / "README.md").write_text("Example filename: `n9kv-9300-10.5.2.qcow2`\n", encoding="utf-8")

    monkeypatch.setattr(admin_routes, "_image_build_dir", lambda: image_build)
    monkeypatch.setattr(admin_routes, "_vrnetlab_dir", lambda: tmp_path / "vrnetlab")
    monkeypatch.setattr(admin_routes, "_load_image_build_module", lambda _root: _fake_build_module(work_dir))

    payload = admin_routes._local_image_build_kinds()
    by_kind = {item["kind"]: item for item in payload["kinds"]}

    assert by_kind["cisco_n9kv"]["image_globs"] == ["*.qcow2"]
    assert by_kind["cisco_n9kv"]["image_examples"] == ["n9kv-9300-10.5.2.qcow2"]


def test_vrnetlab_binding_is_proxied_to_image_build_for_admins(monkeypatch):
    monkeypatch.setattr(admin_routes.settings, "DNLAB_IMAGE_BUILD_API_URL", "http://image-build:8082")

    async def fake_get(path):
        assert path == "/vrnetlab/binding"
        return {"state": "aligned", "current_commit": "a" * 40}

    monkeypatch.setattr(admin_routes, "_image_build_api_get", fake_get)
    result = asyncio.run(admin_routes.image_build_vrnetlab_binding(None))

    assert result["state"] == "aligned"
