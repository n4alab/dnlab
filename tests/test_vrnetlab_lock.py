"""Tests for the release-paired vrnetlab lock helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("vrnetlab_lock", ROOT / "scripts" / "vrnetlab_lock.py")
assert SPEC and SPEC.loader
vrnetlab_lock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vrnetlab_lock)


LOCK = {
    "schema_version": 1,
    "repository": "https://example.test/vrnetlab.git",
    "branch": "dnlab",
    "commit": "a" * 40,
}


def write_lock(tmp_path: Path, data: dict = LOCK) -> Path:
    path = tmp_path / "vrnetlab.lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_lock_accepts_complete_schema(tmp_path):
    assert vrnetlab_lock.load_lock(write_lock(tmp_path)) == LOCK


@pytest.mark.parametrize(
    "data",
    [
        {**LOCK, "commit": "ABC"},
        {**LOCK, "extra": True},
        {**LOCK, "schema_version": 2},
    ],
)
def test_load_lock_rejects_invalid_schema(tmp_path, data):
    with pytest.raises(vrnetlab_lock.LockError):
        vrnetlab_lock.load_lock(write_lock(tmp_path, data))


def test_check_latest_fails_when_lock_lags_declared_branch(monkeypatch, tmp_path, capsys):
    path = write_lock(tmp_path)
    monkeypatch.setattr(vrnetlab_lock, "branch_head", lambda _lock: "b" * 40)

    assert vrnetlab_lock.main(["--lock-file", str(path), "check-latest"]) == 2
    assert "run scripts/vrnetlab_lock.py update" in capsys.readouterr().err


def test_update_writes_current_declared_branch_head(monkeypatch, tmp_path):
    path = write_lock(tmp_path)
    monkeypatch.setattr(vrnetlab_lock, "branch_head", lambda _lock: "b" * 40)

    assert vrnetlab_lock.main(["--lock-file", str(path), "update"]) == 0
    assert vrnetlab_lock.load_lock(path)["commit"] == "b" * 40

