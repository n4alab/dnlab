"""Bind the host-mounted vrnetlab checkout to the dNLab release lock."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class BindingStatus:
    state: str
    repository: str | None
    branch: str | None
    requested_commit: str | None
    current_commit: str | None
    detail: str | None = None

    def payload(self) -> dict[str, str | None]:
        return asdict(self)


def _run(argv: list[str], *, cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(
        argv, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stdout.strip() or f"command failed: {' '.join(argv)}")
    return result.stdout.strip()


def load_lock(path: Path) -> dict[str, str]:
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read vrnetlab lock {path}: {exc}") from exc
    required = {"schema_version", "repository", "branch", "commit"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1:
        raise RuntimeError(f"invalid vrnetlab lock {path}")
    if not all(isinstance(value.get(key), str) and value[key] for key in ("repository", "branch", "commit")):
        raise RuntimeError(f"invalid vrnetlab lock {path}")
    if not SHA_RE.fullmatch(value["commit"]):
        raise RuntimeError(f"invalid vrnetlab lock commit in {path}")
    return {key: value[key] for key in ("repository", "branch", "commit")}


def _head(root: Path) -> str | None:
    try:
        value = _run(["git", "rev-parse", "HEAD"], cwd=root)
    except (OSError, RuntimeError):
        return None
    return value if SHA_RE.fullmatch(value) else None


def ensure_binding(lock_path: Path, root: Path) -> BindingStatus:
    """Safely align ``root`` with the immutable release lock.

    Failures deliberately return a degraded status rather than changing a dirty
    checkout or preventing the rest of dNLab from starting.
    """
    try:
        lock = load_lock(lock_path)
    except RuntimeError as exc:
        return BindingStatus("degraded", None, None, None, _head(root), str(exc))

    requested = lock["commit"]
    current = _head(root)
    if current == requested:
        return BindingStatus("aligned", lock["repository"], lock["branch"], requested, current)

    try:
        if (root / ".git").exists():
            if _run(["git", "status", "--short"], cwd=root):
                raise RuntimeError("vrnetlab checkout is dirty; refusing automatic checkout")
        else:
            root.parent.mkdir(parents=True, exist_ok=True)
            _run(["git", "clone", "--branch", lock["branch"], lock["repository"], str(root)])

        _run(["git", "fetch", "--quiet", lock["repository"], lock["branch"]], cwd=root)
        _run(["git", "cat-file", "-e", f"{requested}^{{commit}}"], cwd=root)
        _run(["git", "checkout", "--detach", "--quiet", requested], cwd=root)
        current = _head(root)
        if current != requested:
            raise RuntimeError(f"checkout resolved to {current or 'unknown'}, expected {requested}")
        return BindingStatus("aligned", lock["repository"], lock["branch"], requested, current)
    except (OSError, RuntimeError) as exc:
        return BindingStatus("degraded", lock["repository"], lock["branch"], requested, _head(root), str(exc))
