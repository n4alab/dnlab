import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest

import flinos_bundle


def _manifest(files: dict[str, bytes]) -> bytes:
    artifacts = []
    for path, role in flinos_bundle.REQUIRED_ARTIFACTS.items():
        content = files[path]
        artifacts.append({
            "path": path, "role": role, "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    return json.dumps({
        "format": flinos_bundle.FORMAT,
        "product": "flinos",
        "release": "0.2.0-alpha-1",
        "boot_mode": "uefi-secure-boot",
        "vrnetlab": {"ref": "v0.20.1"},
        "signature": {"algorithm": "openssl-sha256", "file": "manifest.sig"},
        "artifacts": artifacts,
    }).encode()


def _write_bundle(path: Path, *, duplicate: bool = False, bad_digest: bool = False) -> None:
    files = {name: name.encode() for name in flinos_bundle.REQUIRED_ARTIFACTS}
    manifest = _manifest(files)
    if bad_digest:
        manifest = manifest.replace(b'"sha256": "', b'"sha256": "0', 1)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", manifest)
        archive.writestr("manifest.sig", b"signature")
        for name, content in files.items():
            archive.writestr(name, content)
        if duplicate:
            archive.writestr("launch.py", b"duplicate")


def _write_development_bundle(
    path: Path, *, metadata_mode=True, version_suffix=b"", signature=False,
    manifest_signature=False, extra: str | None = None, bad_digest: bool = False,
    symlink=False,
) -> None:
    release = "0.2.0-alpha-1"
    files = {
        "flinos.qcow2": b"qcow2",
        "flinos.json": json.dumps({
            "release": release, "development_mode": metadata_mode,
            "boot_mode": "bios-dev", "image": "flinos.qcow2",
        }).encode(),
        "flinos.version": release.encode() + version_suffix,
        "launch.py": b"launcher",
        "launch.sh": b"entrypoint",
    }
    artifacts = [{
        "path": name, "role": role, "size": len(files[name]),
        "sha256": hashlib.sha256(files[name]).hexdigest(),
    } for name, role in flinos_bundle.DEVELOPMENT_ARTIFACTS.items()]
    if bad_digest:
        artifacts[0]["sha256"] = "0" * 64
    manifest = {
        "format": flinos_bundle.DEVELOPMENT_FORMAT,
        "product": "flinos",
        "release": release,
        "development_mode": True,
        "boot_mode": "bios-dev",
        "vrnetlab": {"ref": flinos_bundle.VRNETLAB_REF},
        "artifacts": artifacts,
    }
    if manifest_signature:
        manifest["signature"] = {"algorithm": "openssl-sha256", "file": "manifest.sig"}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, content in files.items():
            if symlink and name == "launch.py":
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b"flinos.qcow2")
            else:
                archive.writestr(name, content)
        if signature:
            archive.writestr("manifest.sig", b"forbidden")
        if extra:
            archive.writestr(extra, b"forbidden")


def test_valid_bundle_is_extracted_after_signature_check(tmp_path, monkeypatch):
    bundle = tmp_path / "flinos.zip"
    _write_bundle(bundle)
    monkeypatch.setattr(flinos_bundle, "_verify_signature", lambda _directory: None)

    result = flinos_bundle.validate_and_extract(bundle, tmp_path / "output")

    assert result.release == "0.2.0-alpha-1"
    assert (result.directory / "OVMF_CODE.fd").is_file()
    assert result.development is False


def test_valid_development_bundle_is_extracted_without_signature(tmp_path):
    bundle = tmp_path / "flinos-dev.zip"
    _write_development_bundle(bundle)

    result = flinos_bundle.validate_and_extract(bundle, tmp_path / "output")

    assert result.release == "0.2.0-alpha-1"
    assert result.development is True
    assert result.files == flinos_bundle.DEVELOPMENT_FILES


def test_development_bundle_accepts_the_flinos_producer_metadata_format(tmp_path):
    bundle = tmp_path / "flinos-dev.zip"
    _write_development_bundle(bundle, metadata_mode=1, version_suffix=b"\n")

    result = flinos_bundle.validate_and_extract(bundle, tmp_path / "output")

    assert result.release == "0.2.0-alpha-1"


@pytest.mark.parametrize("kwargs, match", [
    ({"duplicate": True}, "supported FLINOS file layout"),
    ({"bad_digest": True}, "digest is invalid|integrity mismatch"),
])
def test_invalid_bundle_is_rejected(tmp_path, monkeypatch, kwargs, match):
    bundle = tmp_path / "flinos.zip"
    _write_bundle(bundle, **kwargs)
    monkeypatch.setattr(flinos_bundle, "_verify_signature", lambda _directory: None)

    with pytest.raises(flinos_bundle.FlinosBundleError, match=match):
        flinos_bundle.validate_and_extract(bundle, tmp_path / "output")


def test_bundle_requires_zip_suffix(tmp_path):
    with pytest.raises(flinos_bundle.FlinosBundleError, match=".zip"):
        flinos_bundle.validate_and_extract(tmp_path / "flinos.qcow2", tmp_path / "output")


@pytest.mark.parametrize(("kwargs", "match"), [
    ({"metadata_mode": False}, "development metadata"),
    ({"version_suffix": b"\n\n"}, "version is inconsistent"),
    ({"signature": True}, "supported FLINOS file layout"),
    ({"manifest_signature": True}, "must not declare a signature"),
    ({"extra": "unexpected"}, "supported FLINOS file layout"),
    ({"extra": "../escape"}, "invalid bundle path"),
    ({"symlink": True}, "symbolic links are not permitted"),
    ({"bad_digest": True}, "integrity mismatch"),
])
def test_invalid_development_bundle_is_rejected(tmp_path, kwargs, match):
    bundle = tmp_path / "flinos-dev.zip"
    _write_development_bundle(bundle, **kwargs)

    with pytest.raises(flinos_bundle.FlinosBundleError, match=match):
        flinos_bundle.validate_and_extract(bundle, tmp_path / "output")
