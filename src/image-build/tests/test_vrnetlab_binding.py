from __future__ import annotations

import json
import subprocess
from pathlib import Path

import vrnetlab_binding


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def commit_repo(path: Path) -> str:
    git("init", "--initial-branch", "dnlab", str(path))
    (path / "README").write_text("one", encoding="utf-8")
    git("add", "README", cwd=path)
    git("-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-m", "initial", cwd=path)
    return git("rev-parse", "HEAD", cwd=path)


def write_lock(path: Path, repository: Path, commit: str) -> Path:
    path.write_text(json.dumps({
        "schema_version": 1, "repository": str(repository), "branch": "dnlab", "commit": commit,
    }), encoding="utf-8")
    return path


def test_missing_checkout_is_cloned_and_pinned(tmp_path):
    source = tmp_path / "source"
    commit = commit_repo(source)
    target = tmp_path / "vrnetlab"

    status = vrnetlab_binding.ensure_binding(write_lock(tmp_path / "lock.json", source, commit), target)

    assert status.state == "aligned"
    assert status.current_commit == commit
    assert git("branch", "--show-current", cwd=target) == ""


def test_aligned_checkout_does_not_require_remote(tmp_path):
    source = tmp_path / "source"
    commit = commit_repo(source)
    target = tmp_path / "vrnetlab"
    git("clone", str(source), str(target))
    lock = write_lock(tmp_path / "lock.json", tmp_path / "missing-remote", commit)

    status = vrnetlab_binding.ensure_binding(lock, target)

    assert status.state == "aligned"
    assert status.current_commit == commit


def test_misaligned_checkout_degrades_when_remote_is_unavailable(tmp_path):
    source = tmp_path / "source"
    commit_repo(source)
    target = tmp_path / "vrnetlab"
    git("clone", str(source), str(target))

    status = vrnetlab_binding.ensure_binding(
        write_lock(tmp_path / "lock.json", tmp_path / "missing-remote", "a" * 40), target
    )

    assert status.state == "degraded"
    assert status.detail


def test_mismatched_clean_checkout_is_fetched_and_reset_to_lock(tmp_path):
    source = tmp_path / "source"
    locked = commit_repo(source)
    (source / "README").write_text("two", encoding="utf-8")
    git("commit", "-am", "newer", cwd=source)
    target = tmp_path / "vrnetlab"
    git("clone", str(source), str(target))

    status = vrnetlab_binding.ensure_binding(write_lock(tmp_path / "lock.json", source, locked), target)

    assert status.state == "aligned"
    assert git("rev-parse", "HEAD", cwd=target) == locked


def test_dirty_checkout_degrades_without_checkout(tmp_path):
    source = tmp_path / "source"
    commit = commit_repo(source)
    target = tmp_path / "vrnetlab"
    git("clone", str(source), str(target))
    (target / "local-change").write_text("keep", encoding="utf-8")

    status = vrnetlab_binding.ensure_binding(write_lock(tmp_path / "lock.json", source, "a" * 40), target)

    assert status.state == "degraded"
    assert "dirty" in (status.detail or "")
    assert (target / "local-change").exists()


def test_missing_locked_commit_degrades(tmp_path):
    source = tmp_path / "source"
    commit_repo(source)
    target = tmp_path / "vrnetlab"
    git("clone", str(source), str(target))

    status = vrnetlab_binding.ensure_binding(write_lock(tmp_path / "lock.json", source, "a" * 40), target)

    assert status.state == "degraded"
    assert status.requested_commit == "a" * 40
