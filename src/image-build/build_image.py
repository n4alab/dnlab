#!/usr/bin/env python3
"""build_image.py — unified wrapper for building/persisting dnlab images
with (or without) the dnlab persistence layer.

Base flow (without persistence):

    1. Copy the qcow2 selected by the user into the kind-specific vrnetlab
       kind (es. cisco_n9kv → /opt/vrnetlab/cisco/n9kv_V2/).
    2. Run ``make enable-amd-svm-on-images docker-image`` when that
       Makefile target exists, otherwise run ``make docker-image``.
    3. Delete the qcow2 copied into vrnetlab (the user's original file is
       NOT touched).

With ``--with-persistence`` it adds two final steps:

    4. Invoke ``apply.py <kind> <upstream_tag>`` to produce
       ``<upstream_tag>-dnlab``.
    5. Remove the upstream tag (without -dnlab). Use ``--keep-upstream``
       to skip this step.

Container-native flow:

    For kinds that do not use vrnetlab, the second positional argument is a
    remote Docker image ref to pull first (for example
    ``quay.io/frrouting/frr:10.2.6``). No qcow2 is copied and no ``make`` is
    run; with ``--with-persistence`` the wrapper patches the pulled tag when
    a matching ``patches/<kind>.py`` exists.

Introspection flags (without build):

    --list-patchable    print kinds with an available patch + exit 0
    --check-patch KIND  exit 0 if patches/<kind>.py exists, 1 otherwise

Usage:
    build_image.py cisco_n9kv ~/iso/n9kv-9300-10.5.5.M.qcow2
    build_image.py cisco_n9kv ~/iso/n9kv-9300-10.5.5.M.qcow2 --with-persistence
    build_image.py linux quay.io/frrouting/frr:10.2.6
    build_image.py linux quay.io/frrouting/frr:10.2.6 --with-persistence
    build_image.py --list-patchable
    build_image.py --check-patch cisco_n9kv
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ── Constants ────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PATCHES_DIR = SCRIPT_DIR / "patches"
APPLY_SCRIPT = SCRIPT_DIR / "apply.py"
DEFAULT_VRNETLAB_ROOT = Path(os.getenv("DNLAB_VRNETLAB_DIR", "/opt/vrnetlab"))
PERSIST_SUFFIX = "-dnlab"

# kind → relative path inside the vrnetlab root. A kind backed by a _V2
# directory must list only that directory: legacy builders are deliberately
# excluded and are never fallback candidates.
KIND_VRNETLAB_DIR: dict[str, list[str]] = {
    # Cisco
    "cisco_xrv":          ["cisco/xrv"],
    "cisco_xrv9k":        ["cisco/xrv9k_V2"],
    "cisco_n9kv":         ["cisco/n9kv_V2"],
    "cisco_csr1000v":     ["cisco/csr1000v"],
    "cisco_cat9kv":       ["cisco/cat9kv_V2"],
    "cisco_c9800cl":      ["cisco/cat9kv_V2"],
    "cisco_iol":          ["cisco/iol"],
    "cisco_vios":         ["cisco/vios_V2"],
    "cisco_c8000v":       ["cisco/c8000v"],
    "cisco_ftdv":         ["cisco/ftdv"],
    "cisco_asav":         ["cisco/asav"],
    "cisco_nxos":         ["cisco/nxos"],
    "cisco_sdwan":        ["cisco/sdwan-components"],
    # Juniper
    "juniper_vmx":            ["juniper/vmx"],
    "juniper_vqfx":           ["juniper/vqfx"],
    "juniper_vsrx":           ["juniper/vsrx"],
    "juniper_vjunosrouter":   ["juniper/vjunosrouter_V2"],
    "juniper_vjunosswitch":   ["juniper/vjunosswitch_V2"],
    "juniper_vjunosevolved":  ["juniper/vjunosevolved_V2"],
    "juniper_apstra":         ["juniper/apstra"],
    # Arista / Nokia / others
    "arista_veos":        ["arista/veos"],
    "nokia_sros":         ["nokia/sros"],
    "huawei_vrp":         ["huawei/huawei_vrp"],
    "mikrotik_ros":       ["mikrotik/routeros"],
    "paloalto_panos":     ["paloalto/pan"],
    "fortinet_fortigate": ["fortinet/fortigate"],
    "aruba_aoscx":        ["aruba/aoscx"],
    "dell_ftosv":         ["dell/ftosv"],
    "dell_sonic":         ["dell/dell_sonic"],
    "ipinfusion_ocnos":   ["ipinfusion/ocnos"],
    "sonic-vs":           ["sonic"],
    "sonic-vm":           ["sonic"],
    "openwrt":            ["openwrt_V2"],
    "nvidia_cumulusvx":   ["nvidia/cumulusvx"],
    "hp_vsr1000":         ["hp/vsr1000"],
    "f5_bigip":           ["f5_bigip"],
    "freebsd":            ["freebsd"],
    "ubuntu":             ["ubuntu"],
    "openbsd":            ["openbsd"],
    "nokia_cmglinux":     ["nokia/cmglinux"],
    "spirent_vstc":       ["spirent/vstc"],
    "extreme_exos":       ["extreme/exos"],
    "dnlab_frr":          ["dnlab/frr"],
    "dnlab_opnsense":     ["dnlab/opnsense"],
}

# Known container-native kinds (they do not go through vrnetlab). If one of
# these lands here, print an explicit message instead of trying a non-existent
# make target.
CONTAINER_NATIVE_KINDS = {
    "nokia_srlinux", "arista_ceos", "cisco_xrd", "juniper_crpd",
    "cisco_c8000", "juniper_cjunosevolved", "cumulus_cvx",
    "6wind_vsr", "keysight_ixia-c-one", "spirent_stc",
    "fdio_vpp", "rare", "vyosnetworks_vyos",
    "veesix_osvbng", "arrcus_arcos", "checkpoint_cloudguard",
    "nokia_srsim", "generic_vm", "linux",
}

# These kinds build all required artifacts from their checked-in vrnetlab
# directory and therefore intentionally have no uploaded source image.
SELF_BUILDING_KINDS = {"dnlab_frr"}

# Images built from an uploaded qcow2 by a recipe shipped with dNLab, rather
# than by one of the vendor directories in /opt/vrnetlab.  These recipes own
# their persistence implementation and always emit a ``-dnlab`` image tag.
QCOW_RECIPE_KINDS = {"flinos"}
RECIPES_DIR = SCRIPT_DIR / "recipes"


# ── Utilities ────────────────────────────────────────────────────────

def _run(cmd: list[str], *, cwd: Path | None = None, check: bool = True,
         dry: bool = False) -> subprocess.CompletedProcess | None:
    """Run a command (or only print it when dry=True)."""
    shown = " ".join(cmd)
    if cwd:
        shown = f"(cd {cwd}) {shown}"
    print(f"+ {shown}", file=sys.stderr)
    if dry:
        return None
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check)


def _list_patchable() -> list[str]:
    if not PATCHES_DIR.is_dir():
        return []
    return sorted(
        p.stem
        for p in PATCHES_DIR.glob("*.py")
        if not p.stem.startswith("_")
    )


def list_patchable_kinds() -> list[str]:
    return _list_patchable()


def _has_patch(kind: str) -> bool:
    return (PATCHES_DIR / f"{kind}.py").is_file()


def _prepare_qcow_source(
    kind: str,
    source: Path,
    destination: Path,
    *,
    dry: bool = False,
) -> bool:
    """Run an optional kind-owned QCOW preprocessing hook."""
    try:
        mod = importlib.import_module(f"patches.{kind}")
    except ModuleNotFoundError:
        return False
    prepare = getattr(mod, "prepare_qcow", None)
    if not callable(prepare):
        return False

    print(
        f"[{kind}] preparing guest image copy: {source} -> {destination}",
        file=sys.stderr,
    )
    prepare(
        source,
        destination,
        run=lambda cmd: _run(cmd, dry=dry),
        dry=dry,
    )
    return True


def has_patch(kind: str) -> bool:
    return _has_patch(kind)


def is_persistent_kind(kind: str) -> bool:
    """Return whether a builder produces an image with dNLab persistence."""
    return kind in QCOW_RECIPE_KINDS or _has_patch(kind)


def resolve_vrnetlab_dir(kind: str, root: Path | None = None) -> Path:
    return _resolve_vrnetlab_dir(kind, root or DEFAULT_VRNETLAB_ROOT)


def list_vrnetlab_kinds(root: Path | None = None) -> list[dict[str, str]]:
    vrnetlab_root = root or DEFAULT_VRNETLAB_ROOT
    items: list[dict[str, str]] = []
    for kind in sorted(KIND_VRNETLAB_DIR):
        try:
            path = _resolve_vrnetlab_dir(kind, vrnetlab_root)
        except SystemExit:
            continue
        if (path / "Makefile").is_file():
            items.append({"kind": kind, "vrnetlab_dir": str(path)})
    return items


def _resolve_vrnetlab_dir(kind: str, root: Path) -> Path:
    candidates = KIND_VRNETLAB_DIR.get(kind, [])
    if not candidates:
        raise SystemExit(
            f"error: no vrnetlab directory mapped for kind '{kind}'.\n"
            f"        add it to KIND_VRNETLAB_DIR in {__file__}"
        )
    for rel in candidates:
        p = root / rel
        if p.is_dir():
            return p
    raise SystemExit(
        f"error: vrnetlab directory not found for kind '{kind}'. "
        f"Tried: {', '.join(candidates)}"
    )


def _makefile_var(dir_: Path, name: str) -> str | None:
    """Read a simple ``NAME=value`` assignment from the kind Makefile."""
    makefile = dir_ / "Makefile"
    if not makefile.is_file():
        return None
    pat = re.compile(rf"^\s*{re.escape(name)}\s*[:?]?=\s*(.+?)\s*$")
    for line in makefile.read_text(errors="ignore").splitlines():
        m = pat.match(line)
        if m:
            return m.group(1)
    return None


def image_globs_for(dir_: Path) -> list[str]:
    """Return the shell glob patterns the kind's vrnetlab build accepts.

    Parsed from ``IMAGE_GLOB`` in the kind Makefile (e.g. ``*.qcow2``,
    ``*.vmdk *.vdi``), expanding a ``$(IMAGE_FORMAT)`` reference when present.
    Falls back to ``*.qcow2`` (by far the most common) if not declared.
    """
    raw = _makefile_var(dir_, "IMAGE_GLOB")
    if not raw:
        return ["*.qcow2"]
    fmt = _makefile_var(dir_, "IMAGE_FORMAT") or "qcow2"
    raw = raw.replace("$(IMAGE_FORMAT)", fmt).replace("${IMAGE_FORMAT}", fmt)
    return [p for p in raw.split() if p]


def _matches_image_glob(filename: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(filename, pat) for pat in patterns)


def _has_make_target(dir_: Path, target: str) -> bool:
    makefile = dir_ / "Makefile"
    if not makefile.is_file():
        return False
    for line in makefile.read_text(errors="ignore").splitlines():
        if line.startswith("\t") or not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.split(":", 1)[0].strip() == target:
            return True
    return False


def _make_build_cmd(dir_: Path) -> list[str]:
    if _has_make_target(dir_, "enable-amd-svm-on-images"):
        return ["make", "enable-amd-svm-on-images", "docker-image"]
    return ["make", "docker-image"]


def _docker_tag_for(dir_: Path, qcow2_name: str) -> str | None:
    """Infer the tag that the vrnetlab Docker build will produce from the qcow2 name.

    Do this without depending on variable expansion from ``make -pn`` (some
    Makefiles use ``$(shell …)`` for the version, and ``-pn`` output stays
    unexpanded). Instead use:

    * ``make version-test IMAGE=<qcow2>`` → prints the "Version" derived from
      the filename (the Makefile uses sed on IMAGE).
    * Directly read ``NAME`` / ``VENDOR`` from the kind Makefile (they are
      static, not ``$(shell …)``).
    """
    # 1. Version via make version-test.
    try:
        res = subprocess.run(
            ["make", "version-test", f"IMAGE={qcow2_name}"],
            cwd=dir_, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None
    if res.returncode != 0:
        return None
    version = None
    declared_image = None
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("Image:"):
            declared_image = line.split(":", 1)[1].strip()
    if declared_image and ":" in declared_image:
        return declared_image
    if not version or version == qcow2_name:
        # The Makefile exits early if the regex does not match and the
        # "version" equals the filename: the qcow2 does not follow the
        # naming expected by the kind.
        return None

    # 2. NAME / VENDOR direttamente dalla Makefile.
    makefile = dir_ / "Makefile"
    if not makefile.is_file():
        return None
    name = vendor = None
    for line in makefile.read_text().splitlines():
        line = line.strip()
        if line.startswith("NAME") and "=" in line and name is None:
            val = line.split("=", 1)[1].strip()
            if "$" not in val:
                name = val
        elif line.startswith("VENDOR") and "=" in line and vendor is None:
            val = line.split("=", 1)[1].strip()
            if "$" not in val:
                vendor = val
    if not vendor:
        return None
    if not name and dir_.name == "cat9kv_V2":
        name = "c9800cl_V2" if "c9800" in qcow2_name.lower() else "cat9kv_V2"
    if not name:
        return None
    repo = f"vrnetlab/{vendor.lower()}_{name.lower()}"
    return f"{repo}:{version}"


def _same_platform_default_tag(image: str) -> str | None:
    if ":" not in image:
        return None
    repo, tag = image.rsplit(":", 1)
    if "/" in tag:
        return None
    for arch in ("amd64", "arm64"):
        suffix = f"-{arch}{PERSIST_SUFFIX}"
        if tag.endswith(suffix):
            return f"{repo}:{tag[:-len(suffix)]}{PERSIST_SUFFIX}"
    return None


def _require_built_image(image: str, *, dry: bool = False) -> None:
    if dry:
        return
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"error: vrnetlab build completed without producing expected image '{image}'. "
            "Inspect the preceding make output; a pre-build command may have failed."
        )


def _patch_source_tag(kind: str, upstream_tag: str) -> str:
    """Return the canonical raw tag to feed to the patcher.

    The shared vIOS_V2 Makefile always emits the cisco_vios_v2 repository,
    including L2 versions. dNLab keeps vIOSL2 in its established distinct
    repository, so create an alias before patching instead of publishing an
    incorrectly named final image.
    """
    if kind == "cisco_vios" and upstream_tag.startswith("vrnetlab/cisco_vios_v2:L2-"):
        return upstream_tag.replace("vrnetlab/cisco_vios_v2:", "vrnetlab/cisco_vios_l2_v2:", 1)
    return upstream_tag


def _flinos_tag(qcow2: Path) -> str:
    """Build the persistent dNLab tag from an uploaded FLINOS qcow2."""
    version = qcow2.stem
    if version.startswith("flinos-"):
        version = version.removeprefix("flinos-")
    version = re.sub(r"[^A-Za-z0-9_.-]+", "-", version).strip(".-")
    if not version:
        raise SystemExit(f"error: cannot derive FLINOS image tag from '{qcow2.name}'")
    return f"vrnetlab/n4alab_flinos:{version}{PERSIST_SUFFIX}"


def _build_qcow_recipe(kind: str, source: str | None, *, dry: bool = False) -> str:
    if not source:
        raise SystemExit(f"error: kind '{kind}' requires a qcow2 source image")
    qcow2 = Path(source).expanduser().resolve()
    if not qcow2.is_file() or qcow2.suffix.lower() != ".qcow2":
        raise SystemExit(f"error: kind '{kind}' requires a .qcow2 source image")

    recipe = RECIPES_DIR / kind
    if not (recipe / "Dockerfile").is_file():
        raise SystemExit(f"error: recipe for kind '{kind}' is missing: {recipe}")
    image = _flinos_tag(qcow2)
    with tempfile.TemporaryDirectory(prefix=f"dnlab-{kind}-") as temporary:
        context = Path(temporary) / "context"
        shutil.copytree(recipe, context)
        shutil.copy2(qcow2, context / "flinos.qcow2")
        _run(
            ["docker", "build", "--tag", image, "--build-arg", "FLINOS_QCOW=flinos.qcow2", "."],
            cwd=context,
            dry=dry,
        )
    _require_built_image(image, dry=dry)
    return image


# ── Subcommands ──────────────────────────────────────────────────────

def cmd_list_patchable(_args: argparse.Namespace) -> int:
    kinds = _list_patchable()
    if not kinds:
        print("(no patch available)")
        return 0
    print("Kinds with an available patch:")
    for k in kinds:
        print(f"  - {k}")
    return 0


def cmd_check_patch(args: argparse.Namespace) -> int:
    if _has_patch(args.kind):
        print(f"{args.kind}: patch available (patches/{args.kind}.py)")
        return 0
    print(f"{args.kind}: no patch available", file=sys.stderr)
    return 1


def cmd_build(args: argparse.Namespace) -> int:
    kind: str = args.kind
    source: str | None = args.source
    vrnetlab_root = Path(args.vrnetlab_root).expanduser().resolve()
    plain = bool(getattr(args, "plain", False))
    patch_requested = (_has_patch(kind) and not plain) or args.with_persistence

    if plain and args.with_persistence:
        raise SystemExit("error: --plain and --with-persistence are mutually exclusive")

    if kind not in QCOW_RECIPE_KINDS and patch_requested and not _has_patch(kind):
        raise SystemExit(
            f"error: persistence requested but no patch is available for kind "
            f"'{kind}' (missing {PATCHES_DIR}/{kind}.py).\n"
            f"        currently patchable kinds: {', '.join(_list_patchable()) or '(none)'}"
        )

    if kind in QCOW_RECIPE_KINDS:
        if plain:
            raise SystemExit(
                f"error: kind '{kind}' only has the persistent dNLab recipe; "
                "--plain is not supported"
            )
        image = _build_qcow_recipe(kind, source, dry=args.dry_run)
        print(f"done: {image}")
        return 0

    if kind in SELF_BUILDING_KINDS:
        if source:
            raise SystemExit(f"error: self-building kind '{kind}' does not accept a source image")
        work_dir = _resolve_vrnetlab_dir(kind, vrnetlab_root)
        upstream_tag = _docker_tag_for(work_dir, "")
        if not upstream_tag:
            raise SystemExit(
                f"error: could not infer the image tag for self-building kind '{kind}'"
            )
        print(f"[{kind}] self-building vrnetlab dir: {work_dir}", file=sys.stderr)
        print(f"[{kind}] expected tag: {upstream_tag}", file=sys.stderr)
        _run(_make_build_cmd(work_dir), cwd=work_dir, dry=args.dry_run)
        _require_built_image(upstream_tag, dry=args.dry_run)
        if not patch_requested:
            print(f"done: {upstream_tag}")
            return 0
        patch_source = _patch_source_tag(kind, upstream_tag)
        if patch_source != upstream_tag:
            _run(["docker", "tag", upstream_tag, patch_source], dry=args.dry_run)
        tag_suffix = "" if patch_source.endswith(PERSIST_SUFFIX) else PERSIST_SUFFIX
        cmd = [sys.executable, str(APPLY_SCRIPT), kind, patch_source]
        if tag_suffix != PERSIST_SUFFIX:
            cmd.append(f"--tag-suffix={tag_suffix}")
        _run(cmd, dry=args.dry_run)
        patched_tag = f"{patch_source}{tag_suffix}"
        if not args.keep_upstream and tag_suffix:
            _run(["docker", "rmi", upstream_tag], check=False, dry=args.dry_run)
        print(f"done: {patched_tag}")
        return 0

    if kind in CONTAINER_NATIVE_KINDS:
        if not source:
            raise SystemExit(f"error: kind '{kind}' requires a source image reference")
        image = source
        print(f"[{kind}] container-native remote image: {image}", file=sys.stderr)
        _run(["docker", "pull", image], dry=args.dry_run)
        if not patch_requested:
            print(f"[{kind}] no vrnetlab build needed; pulled image is ready",
                  file=sys.stderr)
            print(f"done: {image}")
            return 0
        tag_suffix = "" if image.endswith(PERSIST_SUFFIX) else PERSIST_SUFFIX
        cmd = [sys.executable, str(APPLY_SCRIPT), kind, image]
        if tag_suffix != PERSIST_SUFFIX:
            cmd.append(f"--tag-suffix={tag_suffix}")
        _run(cmd, dry=args.dry_run)
        patched_tag = f"{image}{tag_suffix}"
        if args.keep_upstream or not tag_suffix:
            reason = "--keep-upstream" if args.keep_upstream else "same-tag rebuild"
            print(f"[{kind}] keeping source tag {image} ({reason})",
                  file=sys.stderr)
        else:
            _run(["docker", "rmi", image], check=False, dry=args.dry_run)
        print(f"done: {patched_tag}")
        return 0

    if not source:
        raise SystemExit(f"error: kind '{kind}' requires a source image")
    qcow2 = Path(source).expanduser().resolve()
    if not qcow2.is_file():
        raise SystemExit(f"error: qcow2 not found: {qcow2}")

    # Patch pre-check: with --with-persistence we want it BEFORE a long
    # vrnetlab build, so we fail fast.
    work_dir = _resolve_vrnetlab_dir(kind, vrnetlab_root)

    # Fail fast on a wrong file format: the vrnetlab Makefile globs for a
    # specific extension (e.g. *.qcow2). A mismatched file (a .bin uploaded
    # for a qcow2 kind) would otherwise silently produce an empty build and
    # an opaque "could not infer the upstream tag" error later on.
    globs = image_globs_for(work_dir)
    if not _matches_image_glob(qcow2.name, globs):
        raise SystemExit(
            f"error: kind '{kind}' expects an image matching {' '.join(globs)}, "
            f"but got '{qcow2.name}'. Upload the correct image format for this kind."
        )

    dest = work_dir / qcow2.name
    prepared_dir: tempfile.TemporaryDirectory[str] | None = None
    source_for_build = qcow2
    if patch_requested:
        prepared_dir = tempfile.TemporaryDirectory(prefix=f"dnlab-{kind}-qcow-")
        prepared_path = Path(prepared_dir.name) / qcow2.name
        if _prepare_qcow_source(
            kind,
            qcow2,
            prepared_path,
            dry=args.dry_run,
        ):
            source_for_build = prepared_path
        else:
            prepared_dir.cleanup()
            prepared_dir = None

    print(f"[{kind}] vrnetlab dir: {work_dir}", file=sys.stderr)
    print(f"[{kind}] qcow2 source: {qcow2}", file=sys.stderr)

    # 1. Copy the qcow2 into the vrnetlab path.
    if dest.exists():
        # Do not overwrite an existing file with the same name: if the user
        # placed it there manually, they may rely on it. Allow --force for
        # repeated reuse.
        if args.force:
            _run(["rm", "-f", str(dest)], dry=args.dry_run)
        else:
            raise SystemExit(
                f"error: {dest} already exists. Use --force to overwrite it "
                f"(warning: the file will still be removed at the end of the build)."
            )
    print(f"[{kind}] copying qcow2 to {dest}", file=sys.stderr)
    if not args.dry_run:
        shutil.copy2(source_for_build, dest)

    # 2. Build.
    upstream_tag = _docker_tag_for(work_dir, qcow2.name)
    if upstream_tag:
        print(f"[{kind}] expected tag: {upstream_tag}", file=sys.stderr)

    try:
        _run(_make_build_cmd(work_dir), cwd=work_dir, dry=args.dry_run)
    finally:
        # 3. Clean up the copied qcow2 every time, even on failure (B2: the
        # vrnetlab directory must not stay dirty).
        if dest.exists() and not args.dry_run:
            try:
                dest.unlink()
                print(f"[{kind}] removed {dest}", file=sys.stderr)
            except OSError as e:
                print(f"warning: could not remove {dest}: {e}", file=sys.stderr)
        if prepared_dir is not None:
            prepared_dir.cleanup()

    # If we could not infer the tag before the build, we do not know what
    # `make` produced; require the user to pass it via flag when they want
    # persistence.
    if patch_requested:
        if not upstream_tag:
            raise SystemExit(
                "error: could not infer the upstream tag; "
                "cannot continue with --with-persistence. "
                "Recheck the kind Makefile."
            )
        _require_built_image(upstream_tag, dry=args.dry_run)
        # 4. Apply. Some vrnetlab recipes already produce a -dnlab tag; in
        # that case apply.py rebuilds the same tag from the freshly built raw
        # image and the kind-specific patch module still owns all mutations.
        patch_source = _patch_source_tag(kind, upstream_tag)
        if patch_source != upstream_tag:
            _run(["docker", "tag", upstream_tag, patch_source], dry=args.dry_run)
        tag_suffix = "" if patch_source.endswith(PERSIST_SUFFIX) else PERSIST_SUFFIX
        cmd = [sys.executable, str(APPLY_SCRIPT), kind, patch_source]
        if tag_suffix != PERSIST_SUFFIX:
            cmd.append(f"--tag-suffix={tag_suffix}")
        _run(cmd, dry=args.dry_run)
        patched_tag = f"{patch_source}{tag_suffix}"
        same_platform_default = (
            _same_platform_default_tag(patched_tag) if not tag_suffix else None
        )
        if same_platform_default:
            _run(["docker", "tag", patched_tag, same_platform_default],
                 dry=args.dry_run)
        # 5. Remove the upstream tag (B3), skipped with --keep-upstream.
        if args.keep_upstream or not tag_suffix:
            reason = "--keep-upstream" if args.keep_upstream else "same-tag rebuild"
            print(f"[{kind}] keeping source tag {patch_source} ({reason})",
                  file=sys.stderr)
        else:
            _run(["docker", "rmi", patch_source],
                 check=False, dry=args.dry_run)
        if patch_source != upstream_tag and not args.keep_upstream:
            _run(["docker", "rmi", upstream_tag], check=False, dry=args.dry_run)
        print(f"done: {patched_tag}")
    else:
        if upstream_tag:
            print(f"done: {upstream_tag}")
        else:
            print("done")
    return 0


# ── Arg parsing ──────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Mutually exclusive: either build, or query patch status.
    ap.add_argument("--list-patchable", action="store_true",
                    help="print kinds with an available patch and exit")
    ap.add_argument("--check-patch", metavar="KIND",
                    help="exit 0 if the patch for KIND exists, 1 otherwise")

    # Build arguments.
    ap.add_argument("kind",  nargs="?", help="kind containerlab (es. cisco_n9kv)")
    ap.add_argument(
        "source",
        nargs="?",
        help=("source qcow2 path for vrnetlab kinds, or remote Docker image "
              "ref to pull for container-native kinds"),
    )
    ap.add_argument("--with-persistence", action="store_true",
                    help=("compatibility alias: require the dnlab patch (patches are "
                          "already the default for every patchable kind)"))
    ap.add_argument("--plain", action="store_true",
                    help="diagnostic build without the dnlab patch")
    ap.add_argument("--keep-upstream", action="store_true",
                    help="do not delete the upstream tag after --with-persistence")
    ap.add_argument("--vrnetlab-root", default=str(DEFAULT_VRNETLAB_ROOT),
                    help=f"vrnetlab root (default: {DEFAULT_VRNETLAB_ROOT})")
    ap.add_argument("--force", action="store_true",
                    help="overwrite a qcow2 already copied into the vrnetlab dir")
    ap.add_argument("--dry-run", action="store_true",
                    help="do not run commands, only print them")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _build_parser()
    args = ap.parse_args(argv)

    if args.list_patchable:
        return cmd_list_patchable(args)
    if args.check_patch:
        args.kind = args.check_patch
        return cmd_check_patch(args)

    if not args.kind:
        ap.error("need <kind> [source] or --list-patchable / --check-patch KIND")
    if not args.source and args.kind not in SELF_BUILDING_KINDS:
        ap.error(f"kind '{args.kind}' requires <source>")
    return cmd_build(args)


if __name__ == "__main__":
    sys.exit(main())
