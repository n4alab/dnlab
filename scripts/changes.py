#!/usr/bin/env python3
"""Create, validate and release dNLab structured change fragments."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Iterable

import yaml


ROOT = Path(__file__).resolve().parents[1]
PENDING = ROOT / "changes" / "pending"
ARCHIVE = ROOT / "changes" / "archive"
RELEASES = ROOT / "docs" / "releases"
CHANGELOG = ROOT / "CHANGELOG.md"
DIST_RELEASES = ROOT / "dist" / "release"

CHANGE_TYPES = (
    "bugfix",
    "feature",
    "new-vd",
    "change",
    "deprecation",
    "removal",
    "security",
    "internal",
    "none",
)
VISIBILITIES = ("public", "internal")
AUDIENCES = ("user", "admin", "operator", "developer")
TYPE_CATEGORIES = {
    "feature": "Added",
    "new-vd": "New Virtual Devices",
    "change": "Changed",
    "deprecation": "Deprecated",
    "removal": "Removed",
    "bugfix": "Fixed",
    "security": "Security",
}
CATEGORY_ORDER = (
    "Added",
    "New Virtual Devices",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Breaking",
)
FRAGMENT_FIELDS = {
    "id",
    "type",
    "title",
    "description",
    "components",
    "audience",
    "visibility",
    "breaking",
    "upgrade_notes",
    "references",
    "vd",
    "reason",
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{5,79}$")
COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")
VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class ChangeError(Exception):
    """A user-actionable validation or release error."""


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ChangeError(f"{path.relative_to(ROOT)}: cannot read YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise ChangeError(f"{path.relative_to(ROOT)}: document must be a mapping")
    return value


def dump_yaml(value: dict[str, Any]) -> str:
    return yaml.safe_dump(
        value,
        sort_keys=False,
        allow_unicode=True,
        width=80,
        default_flow_style=False,
    )


def fragment_paths(include_archive: bool = True) -> list[Path]:
    paths = list(PENDING.glob("*.yml"))
    if include_archive and ARCHIVE.exists():
        paths.extend(ARCHIVE.glob("*/*.yml"))
    return sorted(paths)


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (bool(value) or not nonempty)
        and all(_nonempty_string(item) for item in value)
    )


def validate_fragment(data: dict[str, Any], path: Path | None = None) -> list[str]:
    name = str(path.relative_to(ROOT)) if path else str(data.get("id", "<fragment>"))
    errors: list[str] = []
    unknown = sorted(set(data) - FRAGMENT_FIELDS)
    if unknown:
        errors.append(f"{name}: unknown fields: {', '.join(unknown)}")

    fragment_id = data.get("id")
    if not _nonempty_string(fragment_id) or not ID_RE.fullmatch(fragment_id):
        errors.append(f"{name}: id must match {ID_RE.pattern}")
    elif path is not None and path.stem != fragment_id:
        errors.append(f"{name}: filename must be {fragment_id}.yml")

    change_type = data.get("type")
    if change_type not in CHANGE_TYPES:
        errors.append(f"{name}: type must be one of {', '.join(CHANGE_TYPES)}")
    for field in ("title", "description"):
        if not _nonempty_string(data.get(field)):
            errors.append(f"{name}: {field} must be a non-empty string")
    if not _string_list(data.get("components"), nonempty=True):
        errors.append(f"{name}: components must be a non-empty string list")
    else:
        if len(data["components"]) != len(set(data["components"])):
            errors.append(f"{name}: components must not contain duplicates")
        for component in data["components"]:
            if not COMPONENT_RE.fullmatch(component):
                errors.append(f"{name}: invalid component {component!r}")
    if not _string_list(data.get("audience"), nonempty=True):
        errors.append(f"{name}: audience must be a non-empty string list")
    else:
        if len(data["audience"]) != len(set(data["audience"])):
            errors.append(f"{name}: audience must not contain duplicates")
        invalid = sorted(set(data["audience"]) - set(AUDIENCES))
        if invalid:
            errors.append(f"{name}: invalid audience: {', '.join(invalid)}")
    if data.get("visibility") not in VISIBILITIES:
        errors.append(f"{name}: visibility must be public or internal")
    if not isinstance(data.get("breaking"), bool):
        errors.append(f"{name}: breaking must be true or false")
    if not _string_list(data.get("upgrade_notes")):
        errors.append(f"{name}: upgrade_notes must be a string list")
    elif len(data["upgrade_notes"]) != len(set(data["upgrade_notes"])):
        errors.append(f"{name}: upgrade_notes must not contain duplicates")
    if not _string_list(data.get("references")):
        errors.append(f"{name}: references must be a string list")
    elif len(data["references"]) != len(set(data["references"])):
        errors.append(f"{name}: references must not contain duplicates")

    if data.get("breaking") and not data.get("upgrade_notes"):
        errors.append(f"{name}: breaking changes require at least one upgrade note")
    if change_type in {"internal", "none"} and data.get("visibility") != "internal":
        errors.append(f"{name}: {change_type} fragments must use internal visibility")
    if change_type == "none":
        if not _nonempty_string(data.get("reason")):
            errors.append(f"{name}: none fragments require a reason")
        if data.get("breaking"):
            errors.append(f"{name}: none fragments cannot be breaking")
    elif "reason" in data:
        errors.append(f"{name}: reason is only allowed for type none")

    vd = data.get("vd")
    if change_type == "new-vd":
        if not isinstance(vd, dict):
            errors.append(f"{name}: new-vd fragments require vd.vendor and vd.platform")
        else:
            unknown_vd = sorted(set(vd) - {"vendor", "platform"})
            if unknown_vd:
                errors.append(f"{name}: unknown vd fields: {', '.join(unknown_vd)}")
            for field in ("vendor", "platform"):
                if not _nonempty_string(vd.get(field)):
                    errors.append(f"{name}: vd.{field} must be a non-empty string")
    elif vd is not None:
        errors.append(f"{name}: vd is only allowed for type new-vd")
    return errors


def load_fragments(paths: Iterable[Path]) -> list[tuple[Path, dict[str, Any]]]:
    loaded: list[tuple[Path, dict[str, Any]]] = []
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for path in paths:
        try:
            data = load_yaml(path)
        except ChangeError as exc:
            errors.append(str(exc))
            continue
        errors.extend(validate_fragment(data, path))
        fragment_id = data.get("id")
        if isinstance(fragment_id, str):
            if fragment_id in seen:
                errors.append(
                    f"duplicate id {fragment_id!r}: "
                    f"{seen[fragment_id].relative_to(ROOT)} and {path.relative_to(ROOT)}"
                )
            else:
                seen[fragment_id] = path
        loaded.append((path, data))
    if errors:
        raise ChangeError("\n".join(errors))
    return loaded


def version_key(version: str) -> tuple[int, int, int]:
    if not VERSION_RE.fullmatch(version):
        raise ChangeError(f"invalid semantic version: {version!r}")
    return tuple(int(part) for part in version.split("."))  # type: ignore[return-value]


def release_paths() -> list[Path]:
    paths: list[tuple[tuple[int, int, int], Path]] = []
    for path in RELEASES.glob("*.yml"):
        try:
            key = version_key(path.stem)
        except ChangeError:
            continue
        paths.append((key, path))
    return [path for _, path in sorted(paths, reverse=True)]


def _wrap(text: str, initial: str = "", subsequent: str = "") -> str:
    return textwrap.fill(
        " ".join(str(text).split()),
        width=80,
        initial_indent=initial,
        subsequent_indent=subsequent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def public_fragments(fragments: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (
            item
            for item in fragments
            if item["visibility"] == "public" and item["type"] not in {"internal", "none"}
        ),
        key=lambda item: (
            CATEGORY_ORDER.index(TYPE_CATEGORIES[item["type"]]),
            item["title"].casefold(),
            item["id"],
        ),
    )


def fragment_entry(fragment: dict[str, Any]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "category": TYPE_CATEGORIES[fragment["type"]],
        "title": fragment["title"],
        "body": fragment["description"],
        "change_id": fragment["id"],
        "components": fragment["components"],
        "audience": fragment["audience"],
    }
    if fragment.get("references"):
        entry["references"] = fragment["references"]
    if fragment.get("vd"):
        entry["vd"] = fragment["vd"]
    return entry


def artifacts_for(version: str, with_lxc: bool) -> list[dict[str, str]]:
    artifacts = [
        {
            "name": "Source archives",
            "type": "github-release",
            "path": f"*-{version}-source.tar.gz",
            "channel": "GitHub Release",
            "notes": "Corresponding source archives for the published GHCR images.",
        },
        {
            "name": "Source checksums",
            "type": "github-release",
            "path": "SHA256SUMS",
            "channel": "GitHub Release",
            "notes": "Checksums for downloadable release assets.",
        },
    ]
    if with_lxc:
        artifacts.extend(
            [
                {
                    "name": "Proxmox LXC template",
                    "type": "lxc-proxmox",
                    "path": f"dnlab-lxc-proxmox-{version}-amd64.tar.zst",
                    "channel": "GHCR and GitHub Release mirror",
                    "notes": f"Canonical OCI artifact ghcr.io/n4alab/dnlab-lxc-proxmox:{version}.",
                },
                {
                    "name": "Proxmox LXC release notes",
                    "type": "lxc-proxmox",
                    "path": f"LXC-RELEASE-NOTES-{version}.md",
                    "channel": "GHCR and GitHub Release mirror",
                    "notes": "Browser-friendly release note mirror for the LXC artifact.",
                },
            ]
        )
    return artifacts


def build_manifest(
    version: str,
    date: str,
    summary: str,
    fragments: list[dict[str, Any]],
    with_lxc: bool,
) -> dict[str, Any]:
    public = public_fragments(fragments)
    breaking_changes = [
        {"title": item["title"], "body": item["description"]}
        for item in public
        if item["breaking"]
    ]
    upgrade_notes: list[str] = []
    for item in public:
        for note in item["upgrade_notes"]:
            if note not in upgrade_notes:
                upgrade_notes.append(note)
    return {
        "version": version,
        "date": date,
        "tag": f"v{version}",
        "summary": summary,
        "entries": [fragment_entry(item) for item in public],
        "breaking_changes": breaking_changes,
        "upgrade_notes": upgrade_notes,
        "artifacts": artifacts_for(version, with_lxc),
        "source_notes": ["CHANGELOG.md", f"changes/archive/{version}/"],
        "internal_refs": [],
    }


def render_release_sections(manifest: dict[str, Any], *, include_artifacts: bool = True) -> str:
    lines: list[str] = []
    entries = manifest.get("entries", []) or []
    categories = {str(entry.get("category")) for entry in entries}
    ordered_categories = [category for category in CATEGORY_ORDER if category in categories]
    ordered_categories.extend(sorted(categories - set(ordered_categories)))
    for category in ordered_categories:
        lines.extend([f"### {category}", ""])
        # Preserve the source-manifest order. Newly generated manifests are
        # already sorted from fragment metadata; legacy manifests retain their
        # published order and therefore regenerate without gratuitous churn.
        category_entries = (entry for entry in entries if entry.get("category") == category)
        for entry in category_entries:
            title = str(entry.get("title", "")).strip()
            body = str(entry.get("body", "")).strip()
            lines.append(_wrap(f"{title}: {body}", initial="- ", subsequent="  "))
        lines.append("")
    breaking = manifest.get("breaking_changes", []) or []
    # Older manifests may already carry a dedicated public Breaking entry in
    # addition to machine-readable breaking_changes metadata. Do not render
    # both representations and duplicate the same release warning.
    if breaking and "Breaking" not in categories:
        lines.extend(["### Breaking Changes", ""])
        for item in breaking:
            lines.append(
                _wrap(
                    f"{item.get('title', '')}: {item.get('body', '')}",
                    initial="- ",
                    subsequent="  ",
                )
            )
        lines.append("")
    notes = manifest.get("upgrade_notes", []) or []
    if notes:
        lines.extend(["### Upgrade Notes", ""])
        lines.extend(_wrap(str(note), initial="- ", subsequent="  ") for note in notes)
        lines.append("")
    artifacts = manifest.get("artifacts", []) or []
    if include_artifacts and artifacts:
        lines.extend(["### Artifacts", ""])
        for artifact in artifacts:
            label = f"{artifact.get('name', '')}: {artifact.get('path', '')}"
            channel = artifact.get("channel")
            if channel:
                label += f" ({channel})"
            lines.append(_wrap(label, initial="- ", subsequent="  "))
        lines.append("")
    return "\n".join(lines).rstrip()


def render_changelog(manifests: Iterable[dict[str, Any]]) -> str:
    lines = [
        "# Changelog",
        "",
        "All notable public changes to dNLab are recorded in this file.",
        "",
        "This changelog is generated from the structured release sources in",
        "`docs/releases/`. Internal bug-tracking references stay in the private",
        "operational repository and are not published here.",
        "",
    ]
    for manifest in manifests:
        date = manifest.get("date", "")
        lines.extend([f"## {manifest['version']} - {date}", ""])
        lines.extend([_wrap(str(manifest.get("summary", ""))), ""])
        sections = render_release_sections(manifest)
        if sections:
            lines.extend([sections, ""])
    return "\n".join(lines).rstrip() + "\n"


def render_preview(fragments: list[dict[str, Any]]) -> str:
    manifest = build_manifest("0.0.0", "unreleased", "Unreleased changes.", fragments, False)
    sections = render_release_sections(manifest, include_artifacts=False)
    return "# Unreleased\n\n" + (sections or "No public changes.") + "\n"


def render_release_notes(manifest: dict[str, Any]) -> str:
    lines = [
        f"# dNLab {manifest['version']}",
        "",
        _wrap(str(manifest.get("summary", ""))),
        "",
        render_release_sections(manifest),
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def load_manifests(extra: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    manifests: dict[str, dict[str, Any]] = {}
    for path in release_paths():
        manifest = load_yaml(path)
        version = str(manifest.get("version", path.stem))
        version_key(version)
        manifests[version] = manifest
    if extra:
        manifests[str(extra["version"])] = extra
    return [manifests[key] for key in sorted(manifests, key=version_key, reverse=True)]


def validate_release_manifest(manifest: dict[str, Any], path: Path) -> list[str]:
    name = str(path.relative_to(ROOT))
    errors: list[str] = []
    required = {
        "version",
        "date",
        "tag",
        "summary",
        "entries",
        "breaking_changes",
        "upgrade_notes",
        "artifacts",
        "source_notes",
        "internal_refs",
    }
    missing = sorted(required - set(manifest))
    if missing:
        errors.append(f"{name}: missing fields: {', '.join(missing)}")
    version = str(manifest.get("version", ""))
    try:
        version_key(version)
    except ChangeError as exc:
        errors.append(f"{name}: {exc}")
    if path.stem != version:
        errors.append(f"{name}: filename/version mismatch")
    if manifest.get("tag") != f"v{version}":
        errors.append(f"{name}: tag must be v{version}")
    try:
        dt.date.fromisoformat(str(manifest.get("date", "")))
    except ValueError:
        errors.append(f"{name}: date must use YYYY-MM-DD")
    if not _nonempty_string(manifest.get("summary")):
        errors.append(f"{name}: summary must be a non-empty string")
    for field in ("entries", "breaking_changes", "artifacts"):
        if not isinstance(manifest.get(field), list):
            errors.append(f"{name}: {field} must be a list")
    for field in ("upgrade_notes", "source_notes", "internal_refs"):
        if not _string_list(manifest.get(field)):
            errors.append(f"{name}: {field} must be a string list")
    for index, entry in enumerate(manifest.get("entries", []) or []):
        if not isinstance(entry, dict) or not all(
            _nonempty_string(entry.get(field)) for field in ("category", "title", "body")
        ):
            errors.append(f"{name}: entries[{index}] requires category, title and body")
    for index, item in enumerate(manifest.get("breaking_changes", []) or []):
        if not isinstance(item, dict) or not all(
            _nonempty_string(item.get(field)) for field in ("title", "body")
        ):
            errors.append(f"{name}: breaking_changes[{index}] requires title and body")
    for index, artifact in enumerate(manifest.get("artifacts", []) or []):
        if not isinstance(artifact, dict) or not all(
            _nonempty_string(artifact.get(field))
            for field in ("name", "type", "path", "channel", "notes")
        ):
            errors.append(
                f"{name}: artifacts[{index}] requires name, type, path, channel and notes"
            )
    return errors


def validate_all(base: str | None = None, tag: str | None = None) -> None:
    partial_transactions = sorted(ARCHIVE.glob("*/.release-transaction.json"))
    if partial_transactions:
        paths = ", ".join(str(path.relative_to(ROOT)) for path in partial_transactions)
        raise ChangeError(
            f"incomplete release transaction found: {paths}; rerun the matching release command"
        )
    load_fragments(fragment_paths())
    errors: list[str] = []
    for path in release_paths():
        manifest = load_yaml(path)
        errors.extend(validate_release_manifest(manifest, path))
    if errors:
        raise ChangeError("\n".join(errors))
    expected_changelog = render_changelog(load_manifests())
    if not CHANGELOG.exists():
        raise ChangeError("missing generated CHANGELOG.md")
    if CHANGELOG.read_text(encoding="utf-8") != expected_changelog:
        raise ChangeError(
            "CHANGELOG.md differs from the deterministic release-manifest rendering; "
            "do not edit it manually"
        )
    if base:
        validate_coverage(base)
    if tag:
        validate_tag(tag)


def _git_lines(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ChangeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return [line for line in result.stdout.splitlines() if line]


def ensure_clean_release_worktree() -> None:
    """Reject a first release run that could capture unreviewed local state."""
    if not (ROOT / ".git").exists():
        return
    dirty = _git_lines("status", "--porcelain", "--untracked-files=all")
    if dirty:
        sample = ", ".join(line[3:] if len(line) > 3 else line for line in dirty[:5])
        suffix = " ..." if len(dirty) > 5 else ""
        raise ChangeError(
            f"new releases require a clean git worktree; outstanding paths: {sample}{suffix}"
        )


def validate_coverage(base: str) -> None:
    changed = _git_lines("diff", "--name-only", f"{base}...HEAD")
    product_changes = [
        path
        for path in changed
        if not path.startswith("changes/") and path not in {"CHANGELOG.md"}
    ]
    if not product_changes:
        return
    # A normal PR adds a pending fragment; a release PR usually moves it to
    # the version archive and Git may report that operation as a rename.
    introduced = _git_lines(
        "diff",
        "--diff-filter=ACR",
        "--find-renames",
        "--name-only",
        f"{base}...HEAD",
    )
    fragments = [
        path
        for path in introduced
        if re.fullmatch(
            r"changes/(?:pending|archive/\d+\.\d+\.\d+)/[a-z0-9][a-z0-9-]*\.yml",
            path,
        )
    ]
    if not fragments:
        raise ChangeError(
            "change coverage failed: add at least one pending change fragment "
            "(or a motivated type:none exemption); release PRs may add archived fragments"
        )
    load_fragments(ROOT / path for path in fragments)


def validate_tag(tag: str) -> None:
    version = tag[1:] if tag.startswith("v") else tag
    version_key(version)
    manifest_path = RELEASES / f"{version}.yml"
    if not manifest_path.exists():
        raise ChangeError(f"missing release manifest {manifest_path.relative_to(ROOT)}")
    manifest = load_yaml(manifest_path)
    if manifest.get("tag") != f"v{version}":
        raise ChangeError(f"release manifest tag does not match v{version}")
    pending = list(PENDING.glob("*.yml"))
    if pending:
        raise ChangeError("tag validation failed: pending change fragments remain")
    if (ARCHIVE / version / ".release-transaction.json").exists():
        raise ChangeError("tag validation failed: release transaction is incomplete")
    archive_paths = sorted((ARCHIVE / version).glob("*.yml"))
    if not archive_paths:
        raise ChangeError(f"tag validation failed: missing changes/archive/{version}/")
    fragments = [data for _, data in load_fragments(archive_paths)]
    with_lxc = any(item.get("type") == "lxc-proxmox" for item in manifest["artifacts"])
    rebuilt = build_manifest(
        version,
        str(manifest["date"]),
        str(manifest["summary"]),
        fragments,
        with_lxc,
    )
    generated_fields = (
        "version",
        "date",
        "tag",
        "summary",
        "entries",
        "breaking_changes",
        "upgrade_notes",
        "artifacts",
        "source_notes",
    )
    if any(manifest.get(field) != rebuilt.get(field) for field in generated_fields):
        raise ChangeError("release manifest does not match its archived change fragments")
    expected = render_changelog(load_manifests())
    actual = CHANGELOG.read_text(encoding="utf-8")
    if actual != expected:
        raise ChangeError("CHANGELOG.md is not the deterministic manifest rendering")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug[:40].rstrip("-") or "change"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _release_transaction_payload(
    args: argparse.Namespace, paths: Iterable[Path]
) -> dict[str, Any]:
    return {
        "version": args.version,
        "date": args.date,
        "summary": " ".join(args.summary.split()),
        "with_lxc": args.with_lxc,
        "fragments": {path.name: _file_sha256(path) for path in sorted(paths)},
    }


def _load_release_transaction(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ChangeError(f"cannot read partial release transaction {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("fragments"), dict):
        raise ChangeError(f"invalid partial release transaction {path}")
    return value


def _resume_release_paths(
    transaction: dict[str, Any],
    args: argparse.Namespace,
    pending_paths: list[Path],
    archived_paths: list[Path],
) -> list[Path]:
    metadata_matches = (
        transaction.get("version") == args.version
        and transaction.get("date") == args.date
        and transaction.get("summary") == " ".join(args.summary.split())
        and transaction.get("with_lxc") == args.with_lxc
    )
    if not metadata_matches:
        raise ChangeError("cannot resume release with different version, date, summary, or LXC profile")
    expected = transaction["fragments"]
    if not expected or not all(
        isinstance(name, str) and isinstance(digest, str) for name, digest in expected.items()
    ):
        raise ChangeError("partial release transaction has an invalid fragment inventory")
    pending = {path.name: path for path in pending_paths}
    archived = {path.name: path for path in archived_paths}
    unexpected = sorted((set(pending) | set(archived)) - set(expected))
    if unexpected:
        raise ChangeError(
            "cannot resume release with unexpected fragments: " + ", ".join(unexpected)
        )
    selected: list[Path] = []
    for name, digest in sorted(expected.items()):
        candidates = [path for path in (archived.get(name), pending.get(name)) if path is not None]
        if not candidates:
            raise ChangeError(f"cannot resume release: missing fragment {name}")
        for path in candidates:
            if _file_sha256(path) != digest:
                raise ChangeError(f"cannot resume release: fragment content changed for {name}")
        selected.append(archived.get(name) or pending[name])
    return selected


def command_new(args: argparse.Namespace) -> None:
    if args.type != "new-vd" and (args.vendor or args.platform):
        raise ChangeError("--vendor and --platform are only valid with --type new-vd")
    if args.type != "none" and args.reason:
        raise ChangeError("--reason is only valid with --type none")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    base_id = f"{timestamp}-{slugify(args.title)}"
    fragment_id = base_id
    counter = 2
    existing_ids = {path.stem for path in fragment_paths()}
    while fragment_id in existing_ids:
        fragment_id = f"{base_id}-{counter}"
        counter += 1
    visibility = "internal" if args.type in {"internal", "none"} else args.visibility
    fragment: dict[str, Any] = {
        "id": fragment_id,
        "type": args.type,
        "title": args.title.strip(),
        "description": args.description.strip(),
        "components": sorted(set(args.component)),
        "audience": sorted(set(args.audience)),
        "visibility": visibility,
        "breaking": args.breaking,
        "upgrade_notes": args.upgrade_note or [],
        "references": args.reference or [],
    }
    if args.type == "new-vd":
        fragment["vd"] = {"vendor": args.vendor or "", "platform": args.platform or ""}
    if args.type == "none":
        fragment["reason"] = args.reason or ""
    errors = validate_fragment(fragment)
    if errors:
        raise ChangeError("\n".join(errors))
    PENDING.mkdir(parents=True, exist_ok=True)
    path = PENDING / f"{fragment_id}.yml"
    path.write_text(dump_yaml(fragment), encoding="utf-8")
    print(path.relative_to(ROOT))


def command_validate(args: argparse.Namespace) -> None:
    validate_all(args.base, args.tag)
    print("change metadata is valid")


def command_preview(_: argparse.Namespace) -> None:
    fragments = [data for _, data in load_fragments(sorted(PENDING.glob("*.yml")))]
    print(render_preview(fragments), end="")


def command_release(args: argparse.Namespace) -> None:
    version_key(args.version)
    try:
        release_date = dt.date.fromisoformat(args.date)
    except ValueError as exc:
        raise ChangeError("release date must use YYYY-MM-DD") from exc
    canonical_summary = " ".join(args.summary.split())
    manifest_path = RELEASES / f"{args.version}.yml"
    archive_dir = ARCHIVE / args.version
    transaction_marker = archive_dir / ".release-transaction.json"
    pending_paths = sorted(PENDING.glob("*.yml"))
    archived_paths = sorted(archive_dir.glob("*.yml")) if archive_dir.exists() else []
    transaction: dict[str, Any] | None = None
    if transaction_marker.exists():
        transaction = _load_release_transaction(transaction_marker)
        selected_paths = _resume_release_paths(transaction, args, pending_paths, archived_paths)
    elif manifest_path.exists() and not archived_paths:
        raise ChangeError(
            f"{manifest_path.relative_to(ROOT)} already exists without a matching fragment archive"
        )
    elif archived_paths:
        if pending_paths:
            pending_by_name = {path.name: path.read_bytes() for path in pending_paths}
            archived_by_name = {path.name: path.read_bytes() for path in archived_paths}
            if pending_by_name != archived_by_name:
                raise ChangeError(
                    "cannot resume release: pending fragments differ from the partial archive"
                )
        selected_paths = archived_paths
    else:
        if not pending_paths:
            raise ChangeError("no pending fragments to release")
        ensure_clean_release_worktree()
        existing_versions = [version_key(path.stem) for path in release_paths()]
        if existing_versions and version_key(args.version) <= max(existing_versions):
            raise ChangeError("new release version must be greater than every existing release")
        existing_dates = [
            dt.date.fromisoformat(str(load_yaml(path)["date"])) for path in release_paths()
        ]
        if existing_dates and release_date < max(existing_dates):
            raise ChangeError("new release date must not precede an existing release date")
        selected_paths = pending_paths
    if manifest_path.exists():
        existing = load_yaml(manifest_path)
        existing_has_lxc = any(
            item.get("type") == "lxc-proxmox" for item in existing.get("artifacts", [])
        )
        immutable_values_match = (
            str(existing.get("version")) == args.version
            and str(existing.get("date")) == args.date
            and " ".join(str(existing.get("summary", "")).split())
            == " ".join(args.summary.split())
            and existing_has_lxc == args.with_lxc
        )
        if not immutable_values_match:
            raise ChangeError(
                "release metadata is immutable; repeat with the original date, summary, "
                "and LXC profile"
            )
    selected = load_fragments(selected_paths)
    fragments = [data for _, data in selected]
    manifest = build_manifest(args.version, args.date, canonical_summary, fragments, args.with_lxc)
    manifest_errors = validate_release_manifest(manifest, manifest_path)
    if manifest_errors:
        raise ChangeError("\n".join(manifest_errors))
    manifests = load_manifests(manifest)
    changelog = render_changelog(manifests)
    release_notes = render_release_notes(manifest)
    snapshot = render_changelog([manifest])

    asset_dir = DIST_RELEASES / args.version
    release_manifest = {
        "version": args.version,
        "tag": f"v{args.version}",
        "date": args.date,
        "changes": [item["id"] for item in fragments],
        "artifacts": manifest["artifacts"],
    }
    outputs = {
        manifest_path: dump_yaml(manifest),
        CHANGELOG: changelog,
        asset_dir / f"CHANGELOG-{args.version}.md": snapshot,
        asset_dir / f"RELEASE_NOTES-{args.version}.md": release_notes,
        asset_dir / f"RELEASE-MANIFEST-{args.version}.json": (
            json.dumps(release_manifest, indent=2, sort_keys=True) + "\n"
        ),
    }

    # Stage every generated file before changing source state. Archive copies
    # are written before output replacement, while pending files are removed
    # only after every output is durable. If the process is interrupted, the
    # next identical invocation recognizes the duplicate pending/archive set
    # and safely completes the transaction.
    RELEASES.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    asset_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".changes-release-", dir=ROOT) as temporary:
        staging = Path(temporary)
        staged: dict[Path, Path] = {}
        for index, (target, content) in enumerate(outputs.items()):
            staged_path = staging / f"output-{index}"
            staged_path.write_text(content, encoding="utf-8")
            staged[target] = staged_path
        if pending_paths:
            if transaction is None:
                transaction = _release_transaction_payload(args, pending_paths)
                staged_marker = staging / "release-transaction.json"
                staged_marker.write_text(
                    json.dumps(transaction, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                os.replace(staged_marker, transaction_marker)
            expected = transaction["fragments"]
            sources = {path.name: path for path in pending_paths}
            sources.update({path.name: path for path in archived_paths})
            for name, digest in expected.items():
                target = archive_dir / name
                if target.exists():
                    if _file_sha256(target) != digest:
                        raise ChangeError(f"archived fragment content changed for {name}")
                    continue
                source = sources.get(name)
                if source is None or _file_sha256(source) != digest:
                    raise ChangeError(f"cannot archive expected fragment {name}")
                shutil.copy2(source, target)
        for target, staged_path in staged.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged_path, target)
        for path in pending_paths:
            path.unlink()
        transaction_marker.unlink(missing_ok=True)
    print(f"prepared release {args.version} from {len(fragments)} fragments")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    new = subparsers.add_parser("new", help="create and validate a pending fragment")
    new.add_argument("--type", choices=CHANGE_TYPES, required=True)
    new.add_argument("--title", required=True)
    new.add_argument("--description", required=True)
    new.add_argument("--component", action="append", required=True)
    new.add_argument("--audience", action="append", choices=AUDIENCES, required=True)
    new.add_argument("--visibility", choices=VISIBILITIES, default="public")
    new.add_argument("--breaking", action="store_true")
    new.add_argument("--upgrade-note", action="append")
    new.add_argument("--reference", action="append")
    new.add_argument("--vendor")
    new.add_argument("--platform")
    new.add_argument("--reason")
    new.set_defaults(handler=command_new)

    validate = subparsers.add_parser("validate", help="validate fragments and release metadata")
    validate.add_argument("--base", help="git base revision used to enforce PR coverage")
    validate.add_argument("--tag", help="release tag to verify")
    validate.set_defaults(handler=command_validate)

    preview = subparsers.add_parser("preview", help="render pending public changes")
    preview.set_defaults(handler=command_preview)

    release = subparsers.add_parser("release", help="consume pending fragments into a release")
    release.add_argument("--version", required=True)
    release.add_argument("--date", required=True)
    release.add_argument("--summary", required=True)
    release.add_argument("--with-lxc", action="store_true")
    release.set_defaults(handler=command_release)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        args.handler(args)
    except ChangeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
