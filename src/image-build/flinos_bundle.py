"""Safe validation for signed production and unsigned development FLINOS bundles."""
from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

FORMAT = "flinos-release-bundle/v1"
DEVELOPMENT_FORMAT = "flinos-development-bundle/v1"
VRNETLAB_REF = "v0.20.1"
MAX_ENTRY_BYTES = 6 * 1024**3
MAX_EXTRACTED_BYTES = 8 * 1024**3
REQUIRED_ARTIFACTS = {
    "flinos.qcow2": "qcow2", "OVMF_CODE.fd": "ovmf-code",
    "OVMF_VARS.fd": "ovmf-vars-template", "launch.py": "vrnetlab-launcher",
    "launch.sh": "vrnetlab-entrypoint", "flinos-release-ca.pem": "release-signing-certificate",
}
REQUIRED_FILES = frozenset({"manifest.json", "manifest.sig", *REQUIRED_ARTIFACTS})
DEVELOPMENT_ARTIFACTS = {
    "flinos.qcow2": "qcow2",
    "flinos.json": "development-metadata",
    "flinos.version": "release-version",
    "launch.py": "vrnetlab-launcher",
    "launch.sh": "vrnetlab-entrypoint",
}
DEVELOPMENT_FILES = frozenset({"manifest.json", *DEVELOPMENT_ARTIFACTS})


class FlinosBundleError(ValueError):
    pass


@dataclass(frozen=True)
class FlinosBundle:
    release: str
    directory: Path
    development: bool
    files: frozenset[str]


def validate_and_extract(bundle: Path, destination: Path) -> FlinosBundle:
    if bundle.suffix.lower() != ".zip" or not bundle.is_file():
        raise FlinosBundleError("FLINOS requires a .zip release bundle")
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(bundle) as archive:
            infos = archive.infolist()
            _check_safe_entries(infos)
            _check_layout_candidate(infos)
            for info in infos:
                target = destination / info.filename
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                if target.stat().st_size != info.file_size:
                    raise FlinosBundleError(f"archive entry size changed: {info.filename}")
        manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise FlinosBundleError("manifest must be a JSON object")
        if manifest.get("format") == FORMAT:
            _check_entries(infos, REQUIRED_FILES, "eight FLINOS v1 files")
            _verify_signature(destination)
            release = _check_release_manifest(manifest, destination)
            return FlinosBundle(release, destination, False, REQUIRED_FILES)
        if manifest.get("format") == DEVELOPMENT_FORMAT:
            _check_entries(infos, DEVELOPMENT_FILES, "six FLINOS development files")
            release = _check_development_manifest(manifest, destination)
            return FlinosBundle(release, destination, True, DEVELOPMENT_FILES)
        raise FlinosBundleError("unsupported FLINOS bundle manifest")
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise FlinosBundleError(f"invalid FLINOS release bundle: {exc}") from exc


def _check_entries(infos: list[zipfile.ZipInfo], required_files: frozenset[str], layout_name: str) -> None:
    names = [item.filename for item in infos]
    if len(infos) != len(required_files) or len(names) != len(set(names)) or set(names) != required_files:
        raise FlinosBundleError(f"bundle must contain exactly the {layout_name}")
    _check_safe_entries(infos)


def _check_safe_entries(infos: list[zipfile.ZipInfo]) -> None:
    total = 0
    for item in infos:
        if item.is_dir() or "/" in item.filename or "\\" in item.filename:
            raise FlinosBundleError(f"invalid bundle path: {item.filename!r}")
        if stat.S_ISLNK(item.external_attr >> 16):
            raise FlinosBundleError(f"symbolic links are not permitted: {item.filename}")
        mode = item.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            raise FlinosBundleError(f"bundle entries must be regular files: {item.filename}")
        if item.file_size < 0 or item.file_size > MAX_ENTRY_BYTES:
            raise FlinosBundleError(f"bundle entry is too large: {item.filename}")
        total += item.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise FlinosBundleError("bundle extracted size exceeds the limit")


def _check_layout_candidate(infos: list[zipfile.ZipInfo]) -> None:
    names = {item.filename for item in infos}
    if names not in {REQUIRED_FILES, DEVELOPMENT_FILES} or len(names) != len(infos):
        raise FlinosBundleError("bundle must contain exactly a supported FLINOS file layout")


def _verify_signature(directory: Path) -> None:
    key = directory / ".manifest-public-key.pem"
    try:
        _openssl(["x509", "-in", str(directory / "flinos-release-ca.pem"), "-pubkey", "-noout"], key)
        _openssl(["dgst", "-sha256", "-verify", str(key), "-signature", str(directory / "manifest.sig"), str(directory / "manifest.json")])
    finally:
        key.unlink(missing_ok=True)


def _openssl(args: list[str], output: Path | None = None) -> None:
    try:
        if output:
            with output.open("wb") as stream:
                result = subprocess.run(["openssl", *args], stdout=stream, stderr=subprocess.PIPE, text=True, check=False)
        else:
            result = subprocess.run(["openssl", *args], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
    except FileNotFoundError as exc:
        raise FlinosBundleError("openssl is required to verify FLINOS bundles") from exc
    if result.returncode:
        raise FlinosBundleError(f"FLINOS manifest signature is invalid: {result.stderr.strip() or 'verification failed'}")


def _check_release_manifest(manifest: dict, directory: Path) -> str:
    if manifest.get("format") != FORMAT or manifest.get("product") != "flinos" or manifest.get("boot_mode") != "uefi-secure-boot":
        raise FlinosBundleError("unsupported FLINOS bundle manifest")
    if manifest.get("signature") != {"algorithm": "openssl-sha256", "file": "manifest.sig"}:
        raise FlinosBundleError("unsupported FLINOS manifest signature declaration")
    return _check_common_manifest(manifest, directory, REQUIRED_ARTIFACTS)


def _check_development_manifest(manifest: dict, directory: Path) -> str:
    if (
        manifest.get("format") != DEVELOPMENT_FORMAT
        or manifest.get("product") != "flinos"
        or manifest.get("development_mode") is not True
        or manifest.get("boot_mode") != "bios-dev"
    ):
        raise FlinosBundleError("unsupported FLINOS development bundle manifest")
    if "signature" in manifest:
        raise FlinosBundleError("FLINOS development bundles must not declare a signature")
    release = _check_common_manifest(manifest, directory, DEVELOPMENT_ARTIFACTS)
    try:
        metadata = json.loads((directory / "flinos.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FlinosBundleError(f"invalid FLINOS development metadata: {exc}") from exc
    if not isinstance(metadata, dict) or (
        metadata.get("release") != release
        or not _is_development_mode(metadata.get("development_mode"))
        or metadata.get("boot_mode") != "bios-dev"
        or metadata.get("image") != "flinos.qcow2"
    ):
        raise FlinosBundleError("FLINOS development metadata is inconsistent")
    version = (directory / "flinos.version").read_bytes()
    if version not in {release.encode("utf-8"), f"{release}\n".encode("utf-8")}:
        raise FlinosBundleError("FLINOS development version is inconsistent")
    return release


def _is_development_mode(value: object) -> bool:
    """Accept the boolean and legacy numeric forms emitted by FLINOS dev builds."""
    return value is True or (type(value) is int and value == 1)


def _check_common_manifest(manifest: dict, directory: Path, artifacts: dict[str, str]) -> str:
    release = manifest.get("release")
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
    if not isinstance(release, str) or not release or any(char not in allowed for char in release):
        raise FlinosBundleError("manifest release is invalid")
    if manifest.get("vrnetlab") != {"ref": VRNETLAB_REF}:
        raise FlinosBundleError(f"FLINOS bundle must require vrnetlab {VRNETLAB_REF}")
    declared = manifest.get("artifacts")
    if not isinstance(declared, list) or len(declared) != len(artifacts):
        raise FlinosBundleError("manifest artifact list is invalid")
    by_path = {item.get("path"): item for item in declared if isinstance(item, dict)}
    if len(by_path) != len(declared) or set(by_path) != set(artifacts):
        raise FlinosBundleError("manifest artifacts do not match bundle files")
    for name, role in artifacts.items():
        item = by_path[name]
        digest = item.get("sha256")
        if item.get("role") != role or not isinstance(item.get("size"), int):
            raise FlinosBundleError(f"manifest metadata is invalid for {name}")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise FlinosBundleError(f"manifest digest is invalid for {name}")
        target = directory / name
        if target.stat().st_size != item["size"] or _sha256(target) != digest:
            raise FlinosBundleError(f"manifest integrity mismatch for {name}")
    return release


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
