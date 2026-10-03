import hashlib
import json
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


def test_valid_bundle_is_extracted_after_signature_check(tmp_path, monkeypatch):
    bundle = tmp_path / "flinos.zip"
    _write_bundle(bundle)
    monkeypatch.setattr(flinos_bundle, "_verify_signature", lambda _directory: None)

    result = flinos_bundle.validate_and_extract(bundle, tmp_path / "output")

    assert result.release == "0.2.0-alpha-1"
    assert (result.directory / "OVMF_CODE.fd").is_file()


@pytest.mark.parametrize("kwargs, match", [
    ({"duplicate": True}, "eight FLINOS v1 files"),
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
