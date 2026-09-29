#!/usr/bin/env python3
"""Apply dnlab patches to an upstream vrnetlab image.

Usage:
    apply.py <kind> <upstream_image> [--tag-suffix=-dnlab] [--dry-run]

Example:
    apply.py cisco_n9kv vrnetlab/cisco_n9kv_v2:9300-10.5.5.M

Produces ``vrnetlab/cisco_n9kv_v2:9300-10.5.5.M-dnlab``.

Strategy (Level 1 — convention-based wrapper):
  1. Spawn a throwaway container from the upstream image
  2. Extract the target files (launch.py, vrnetlab.py) into a build dir
  3. Apply kind-specific text transforms from ``patches/<kind>.py``
  4. Build a new image ``FROM <upstream>`` that ``COPY``s the patched
     files back to ``/``

Idempotent: re-running on an already-patched upstream is detected via
the provenance marker injected by ``patches/_common.py`` and silently
succeeds without modifying the file.
"""

from __future__ import annotations

import argparse
import json
import importlib
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import warm_links


TAG_SUFFIX_DEFAULT = "-dnlab"
DERIVED_NOTICE_PATH = "/usr/share/doc/dnlab/DERIVED_IMAGE_NOTICE.md"
LINKCTL_SOURCE = Path(__file__).parent / "assets" / "dnlab-linkctl"
LINKCTL_TARGET = "/usr/local/bin/dnlab-linkctl"
LINKCTL_PY_SOURCE = Path(__file__).parent / "assets" / "dnlab_linkctl.py"
LINKCTL_PY_TARGET = "/usr/local/lib/dnlab/dnlab_linkctl.py"


def _run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def _image_exists_locally(image: str) -> bool:
    res = _run(["docker", "image", "inspect", image], check=False, capture=True)
    return res.returncode == 0


def _image_identity(image: str) -> str:
    res = _run(["docker", "image", "inspect", image], capture=True)
    data = json.loads(res.stdout)
    if not data:
        return "unknown"
    repo_digests = data[0].get("RepoDigests") or []
    if repo_digests:
        return repo_digests[0]
    return data[0].get("Id", "unknown")


def _extract_files(image: str, files: list[str], dest: Path) -> None:
    """Copy ``files`` from a throwaway container of ``image`` into ``dest``."""
    res = _run(["docker", "create", image], capture=True)
    container_id = res.stdout.strip()
    try:
        for src in files:
            out = dest / Path(src).name
            _run(["docker", "cp", f"{container_id}:{src}", str(out)])
    finally:
        _run(["docker", "rm", "-f", container_id], check=False, capture=True)


def _build_patched(
    upstream: str,
    tag: str,
    build_dir: Path,
    patched_files: dict[str, Path],
    *,
    kind: str,
    upstream_identity: str,
    dnlab_version: str,
    generated_at: str,
    warm_profile: dict[str, int | bool] | None,
    warm_status: str,
) -> None:
    dockerfile = build_dir / "Dockerfile"
    notice = build_dir / "DERIVED_IMAGE_NOTICE.md"
    notice.write_text(
        "\n".join(
            [
                "# dNLab Derived Image Notice",
                "",
                f"- Upstream image: `{upstream}`",
                f"- Upstream identity: `{upstream_identity}`",
                f"- dNLab patch kind: `{kind}`",
                f"- dNLab version: `{dnlab_version}`",
                f"- Generated at: `{generated_at}`",
                "",
                "This image was rebuilt by dNLab from the upstream image listed",
                "above after applying dNLab runtime or persistence patches.",
                "Redistribution must preserve the upstream image notices and",
                "comply with the upstream image and vendor software licenses.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    labels = {
        "org.opencontainers.image.base.name": upstream,
        "org.opencontainers.image.base.digest": upstream_identity,
        "org.opencontainers.image.created": generated_at,
        "org.opencontainers.image.version": dnlab_version,
        "org.opencontainers.image.vendor": "dNLab",
        "org.dnlab.patch.kind": kind,
        "org.dnlab.patch.notice": DERIVED_NOTICE_PATH,
    }
    capabilities: list[str] = []
    if warm_profile:
        capabilities.append("warm-links-v1")
        labels.update({
            "org.dnlab.warm-links.status": warm_status,
            "org.dnlab.warm-links.default-ports": str(warm_profile["default_ports"]),
            "org.dnlab.warm-links.max-ports": str(warm_profile["max_ports"]),
            "org.dnlab.warm-links.vm-index": str(warm_profile["vm_index"]),
        })
    patch_module = sys.modules.get(f"patches.{kind}")
    capabilities.extend(getattr(patch_module, "EXTRA_CAPABILITIES", ()))
    if capabilities:
        labels["org.dnlab.capabilities"] = ",".join(dict.fromkeys(capabilities))
    lines = [f"FROM {upstream}", ""]
    for key, value in labels.items():
        lines.append(f"LABEL {key}={json.dumps(value)}")
    lines.append("")
    for target_path, local_file in patched_files.items():
        lines.append(f"COPY {local_file.name} {target_path}")
    if warm_profile:
        shutil.copy2(LINKCTL_SOURCE, build_dir / LINKCTL_SOURCE.name)
        shutil.copy2(LINKCTL_PY_SOURCE, build_dir / LINKCTL_PY_SOURCE.name)
        lines.append(f"COPY {LINKCTL_SOURCE.name} {LINKCTL_TARGET}")
        lines.append(f"COPY {LINKCTL_PY_SOURCE.name} {LINKCTL_PY_TARGET}")
        lines.append(f"RUN chmod 0755 {LINKCTL_TARGET} {LINKCTL_PY_TARGET}")
    lines.extend(
        [
            "RUN mkdir -p /usr/share/doc/dnlab",
            f"COPY {notice.name} {DERIVED_NOTICE_PATH}",
        ]
    )
    dockerfile.write_text("\n".join(lines) + "\n")
    _run(["docker", "build", "-t", tag, str(build_dir)])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kind", help="vrnetlab kind, e.g. cisco_n9kv")
    ap.add_argument("image", help="upstream image ref, e.g. vrnetlab/cisco_n9kv_v2:9300-10.5.5.M")
    ap.add_argument("--tag-suffix", default=TAG_SUFFIX_DEFAULT)
    ap.add_argument("--dry-run", action="store_true",
                    help="Extract + patch files and print the resulting diff; do not build.")
    args = ap.parse_args()

    sys.path.insert(0, str(Path(__file__).parent))
    try:
        mod = importlib.import_module(f"patches.{args.kind}")
    except ModuleNotFoundError:
        print(f"error: no patcher module for kind '{args.kind}' "
              f"(expected patches/{args.kind}.py)", file=sys.stderr)
        return 2

    if not _image_exists_locally(args.image):
        print(f"error: image {args.image!r} not present locally — pull it first.",
              file=sys.stderr)
        return 2

    out_tag = f"{args.image}{args.tag_suffix}"
    upstream_identity = _image_identity(args.image)
    dnlab_version = os.getenv("DNLAB_VERSION", "unknown")
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    print(f"[{mod.KIND}] upstream={args.image} -> {out_tag}", file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix="dnlab-image-build-") as td:
        build_dir = Path(td)
        warm_profile = warm_links.profile_for(args.kind, args.image)
        targets = list(mod.FILES)
        if warm_profile and "/vrnetlab.py" not in targets:
            targets.append("/vrnetlab.py")
        _extract_files(args.image, targets, build_dir)

        patched: dict[str, Path] = {}
        for target in targets:
            local = build_dir / Path(target).name
            original = local.read_text()
            if target in mod.FILES:
                new_text, notes = mod.apply(target, original)
            else:
                new_text, notes = original, []
            if target == "/vrnetlab.py" and warm_profile:
                from patches import _common
                new_text, ok = _common.patch_warm_links(new_text)
                if not ok:
                    raise RuntimeError(
                        f"{target}: warm-link anchors not found; update patches/_common.py"
                    )
                notes.append(f"{target}: warm-links-v1 applied")
            for n in notes:
                print(f"  {n}", file=sys.stderr)
            if new_text != original:
                local.write_text(new_text)
            patched[target] = local

        if args.dry_run:
            print("--- dry run: skipping docker build ---", file=sys.stderr)
            for target, local in patched.items():
                print(f"# {target}\n{local.read_text()}\n")
            return 0

        _build_patched(
            args.image,
            out_tag,
            build_dir,
            patched,
            kind=mod.KIND,
            upstream_identity=upstream_identity,
            dnlab_version=dnlab_version,
            generated_at=generated_at,
            warm_profile=warm_profile,
            warm_status=warm_links.validation_status(args.image, upstream_identity),
        )

    print(f"built {out_tag}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
