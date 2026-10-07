#!/usr/bin/env python3
"""Maintain the vrnetlab commit paired with a dNLab release.

The lock belongs to the dNLab source tree. A release maintainer updates it to
the current head of the declared branch before tagging dNLab. The packaged
image-build service applies the immutable commit automatically at runtime.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK_FILE = ROOT / "vrnetlab.lock.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class LockError(Exception):
    """A malformed lock or an unsafe Git state."""


def run(argv: list[str], *, cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and result.returncode:
        raise LockError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{result.stdout.strip()}"
        )
    return result.stdout.strip()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LockError(f"cannot read lock file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LockError(f"{path}: lock must be a JSON object")
    expected = {"schema_version", "repository", "branch", "commit"}
    if set(data) != expected:
        raise LockError(f"{path}: expected exactly {', '.join(sorted(expected))}")
    if data["schema_version"] != 1:
        raise LockError(f"{path}: unsupported schema_version {data['schema_version']!r}")
    for key in ("repository", "branch", "commit"):
        if not isinstance(data[key], str) or not data[key]:
            raise LockError(f"{path}: {key} must be a non-empty string")
    if not SHA_RE.fullmatch(data["commit"]):
        raise LockError(f"{path}: commit must be a lowercase 40-character Git SHA")
    return data


def write_lock(path: Path, lock: dict[str, Any]) -> None:
    path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def branch_head(lock: dict[str, Any]) -> str:
    output = run(["git", "ls-remote", lock["repository"], f"refs/heads/{lock['branch']}"])
    fields = output.split()
    if len(fields) < 2 or fields[1] != f"refs/heads/{lock['branch']}" or not SHA_RE.fullmatch(fields[0]):
        raise LockError(
            f"branch {lock['branch']!r} was not found at declared repository {lock['repository']}"
        )
    return fields[0]


def cmd_update(args: argparse.Namespace) -> int:
    lock = load_lock(args.lock_file)
    head = branch_head(lock)
    if lock["commit"] == head:
        print(f"vrnetlab lock already records {head}")
        return 0
    lock["commit"] = head
    write_lock(args.lock_file, lock)
    print(f"updated {args.lock_file} to {lock['branch']}@{head}")
    return 0


def cmd_check_latest(args: argparse.Namespace) -> int:
    lock = load_lock(args.lock_file)
    head = branch_head(lock)
    if lock["commit"] != head:
        raise LockError(
            f"{args.lock_file} records {lock['commit']}, but {lock['branch']} is now {head}; "
            "run scripts/vrnetlab_lock.py update and commit the updated lock before release"
        )
    print(f"vrnetlab lock matches {lock['branch']}@{head}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Maintain the vrnetlab commit paired with dNLab")
    result.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK_FILE, help="dNLab vrnetlab lock file")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("update", help="resolve the declared branch and update the lock")
    sub.add_parser("check-latest", help="fail unless the lock is the declared branch head")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return {"update": cmd_update, "check-latest": cmd_check_latest}[args.command](args)
    except LockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
