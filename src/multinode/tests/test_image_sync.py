"""Tests for the image-sync daemon (M2).

The reconcile core is built out of pure functions + a thin layer that
calls into SSH/docker. Tests here focus on:

* ``_parse_docker_images``    — tolerant of dangling / empty lines
* ``filter_images``           — fnmatch include/exclude precedence
* ``compute_diff``            — missing, stale, and extra images
* ``reconcile_worker``        — orchestration with a stub SSH client
* ``reconcile_once``          — end-to-end with injected probe + clients,
                                 verifies the state JSON shape
* ``read_state_file``         — atomic round-trip
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dnlab_multinode.models.topology import InfraHost
from dnlab_multinode.services import image_sync as isync
from dnlab_multinode.services.hosts_config import (
    HostsConfig, ImageSyncConfig, MgmtDefaults,
)


# ── Fixtures ───────────────────────────────────────────────────────────


class FakeClient:
    """Minimal SSHClient stand-in. Records calls, returns scripted output."""

    def __init__(self, name: str, images: dict[str, str], *,
                 unreachable: bool = False):
        self.name = name
        self.host = f"10.0.0.{100 + len(images)}"
        self._images = dict(images)
        self._unreachable = unreachable
        self.rmi_calls: list[str] = []
        self.push_calls: list[str] = []

    # SSHClient API surface used by image_sync
    def run(self, cmd, timeout=30, check=True):
        if self._unreachable:
            raise RuntimeError("connection refused")
        if "docker images" in cmd:
            return "\n".join(f"{name}\t{iid}" for name, iid in self._images.items())
        raise AssertionError(f"unexpected run: {cmd}")

    def run_no_check(self, cmd, timeout=30):
        if cmd.startswith("docker rmi "):
            name = cmd.split(" ", 2)[2]
            self.rmi_calls.append(name)
            self._images.pop(name, None)
            return 0, "", ""
        raise AssertionError(f"unexpected run_no_check: {cmd}")

    # simulate a successful sync_image_to_host
    def receive_push(self, name: str, image_id: str) -> None:
        self.push_calls.append(name)
        self._images[name] = image_id


def _hosts(include=None, exclude=None, interval=60) -> HostsConfig:
    return HostsConfig(
        master=InfraHost(name="master", host="10.0.0.1",
                         ssh_user="root", ssh_key="~/.ssh/id", is_master=True),
        workers={
            "w1": InfraHost(name="w1", host="10.0.0.2",
                            ssh_user="root", ssh_key="~/.ssh/id"),
            "w2": InfraHost(name="w2", host="10.0.0.3",
                            ssh_user="root", ssh_key="~/.ssh/id"),
        },
        underlay_iface="eth0",
        mgmt_defaults=MgmtDefaults(),
        image_sync=ImageSyncConfig(
            enabled=True,
            include=include or ["vrnetlab/*"],
            exclude=exclude or ["<none>:<none>"],
            interval_seconds=interval,
        ),
    )


# ── Pure helpers ───────────────────────────────────────────────────────


def test_parse_docker_images_skips_dangling_and_empty():
    raw = (
        "vrnetlab/xr:25.2\tsha256:aaa\n"
        "<none>:<none>\tsha256:bbb\n"
        "\n"
        "dnlab-runtime-relay:latest\tsha256:ccc\n"
        "custom/image:<none>\tsha256:ddd\n"
    )
    out = isync._parse_docker_images(raw)
    assert out == {
        "vrnetlab/xr:25.2": "sha256:aaa",
        "dnlab-runtime-relay:latest": "sha256:ccc",
    }


def test_filter_images_include_then_exclude():
    cfg = ImageSyncConfig(
        enabled=True,
        include=["vrnetlab/*", "dnlab-runtime-relay"],
        exclude=["vrnetlab/secret*"],
        interval_seconds=60,
    )
    images = {
        "vrnetlab/xr:1.0":                  "sha:a",
        "vrnetlab/secret-thing:1.0":        "sha:b",
        "dnlab-runtime-relay:latest":"sha:c",
        "dnlab-jumphost:latest":   "sha:d",   # not in include
        "random/other:1":                   "sha:e",
    }
    out = isync.filter_images(images, cfg)
    assert set(out) == {"vrnetlab/xr:1.0", "dnlab-runtime-relay:latest"}


def test_short_helper_names_match_prefixed_repositories():
    cfg = ImageSyncConfig(
        enabled=True,
        include=["dnlab-runtime-relay", "dnlab-mgmt-anchor"],
        exclude=[],
        interval_seconds=60,
    )
    images = {
        "dnlab-local/dnlab-runtime-relay:local": "sha:a",
        "ghcr.io/n4alab/dnlab-mgmt-anchor:0.1.2": "sha:b",
        "ghcr.io/n4alab/dnlab-jumphost:0.1.2": "sha:c",
    }

    out = isync.filter_images(images, cfg)

    assert set(out) == {
        "dnlab-local/dnlab-runtime-relay:local",
        "ghcr.io/n4alab/dnlab-mgmt-anchor:0.1.2",
    }


def test_default_image_sync_keeps_worker_aux_images_and_excludes_postgres():
    cfg = ImageSyncConfig()
    images = {
        "dnlab-runtime-relay:latest": "sha:rr",
        "dnlab-mgmt-anchor:latest": "sha:ma",
        "postgres:16-alpine": "sha:a",
        "postgres:17-alpine": "sha:b",
        "vrnetlab/xr:1.0": "sha:c",
    }

    out = isync.filter_images(images, cfg)

    assert set(out) == {
        "dnlab-runtime-relay:latest",
        "dnlab-mgmt-anchor:latest",
        "vrnetlab/xr:1.0",
    }


def test_compute_diff_missing_stale_extra():
    master = {"a:1": "sha:1", "b:1": "sha:2", "c:1": "sha:3"}
    remote = {"a:1": "sha:1", "b:1": "sha:OLD", "d:1": "sha:9"}
    to_push, to_remove = isync.compute_diff(master, remote)
    assert to_push == ["b:1", "c:1"]      # b is stale, c is missing
    assert to_remove == ["d:1"]           # d is extra


def test_compute_diff_sorted_deterministic():
    master = {"z:1": "a", "m:1": "b", "a:1": "c"}
    remote: dict[str, str] = {}
    to_push, _ = isync.compute_diff(master, remote)
    assert to_push == ["a:1", "m:1", "z:1"]


# ── reconcile_worker ───────────────────────────────────────────────────


def test_reconcile_worker_pushes_missing_and_stale(monkeypatch):
    """Stub sync_image_to_host so the test never shells out."""
    client = FakeClient("w1", {"a:1": "sha:1", "c:1": "sha:9"})

    def _fake_sync(image, ssh_client, master_client=None):
        ssh_client.receive_push(image, "sha:NEW")
        return True

    monkeypatch.setattr(isync, "sync_image_to_host", _fake_sync)

    master = {"a:1": "sha:1", "b:1": "sha:2", "c:1": "sha:3"}  # c is stale
    state = isync.reconcile_worker("w1", client, master, remove_extra=False)

    assert state.reachable is True
    assert state.missing == ["b:1", "c:1"]
    assert sorted(client.push_calls) == ["b:1", "c:1"]
    assert client.rmi_calls == []             # remove_extra=False
    assert state.last_error == ""


def test_reconcile_worker_removes_extra(monkeypatch):
    client = FakeClient("w1", {"keep:1": "sha:K", "gone:1": "sha:G"})
    monkeypatch.setattr(isync, "sync_image_to_host",
                        lambda *a, **kw: True)

    master = {"keep:1": "sha:K"}
    state = isync.reconcile_worker("w1", client, master, remove_extra=True)

    assert state.extra == ["gone:1"]
    assert client.rmi_calls == ["gone:1"]


def test_reconcile_worker_handles_unreachable():
    client = FakeClient("w1", {}, unreachable=True)
    state = isync.reconcile_worker("w1", client, {"a:1": "sha:1"})
    assert state.reachable is False
    assert "connection refused" in state.last_error


# ── reconcile_once end-to-end ──────────────────────────────────────────


def test_reconcile_once_writes_state_file(tmp_path, monkeypatch):
    hosts = _hosts(include=["vrnetlab/*"], exclude=["<none>:<none>"])

    # Master inventory after filtering: vrnetlab/xr:1.0 is the only one
    # that should be propagated. ubuntu:22.04 is filtered out.
    master_probe = lambda: {
        "vrnetlab/xr:1.0": "sha:XR",
        "ubuntu:22.04":    "sha:UB",     # not in include
        "<none>:<none>":   "sha:DA",     # excluded
    }

    clients = {
        "w1": FakeClient("w1", {"vrnetlab/xr:1.0": "sha:XR"}),  # aligned
        "w2": FakeClient("w2", {}),                             # missing
    }
    monkeypatch.setattr(isync, "sync_image_to_host",
                        lambda image, c, **kw: (c.receive_push(image, "sha:XR") or True))

    state_file = tmp_path / "state.json"
    state = isync.reconcile_once(
        hosts, state_file,
        clients=clients, master_probe=master_probe,
    )

    assert state_file.exists()
    data = json.loads(state_file.read_text())

    assert set(data["master"]["images"]) == {"vrnetlab/xr:1.0"}
    assert data["filter"]["include"] == ["vrnetlab/*"]
    assert data["workers"]["w1"]["missing"] == []
    assert data["workers"]["w2"]["missing"] == ["vrnetlab/xr:1.0"]

    # w2 actually received the push through our stub
    assert clients["w2"].push_calls == ["vrnetlab/xr:1.0"]

    # Timings fields are present and sensible
    assert data["last_reconcile_duration_ms"] >= 0
    assert data["interval_seconds"] == 60


def test_daemon_reloads_hosts_file_before_reconcile(tmp_path, monkeypatch):
    initial = _hosts(include=["dnlab-runtime-relay"])
    reloaded = _hosts(include=["*/dnlab-runtime-relay:*"])
    seen_includes = []

    monkeypatch.setattr(isync, "load_hosts_config", lambda path: reloaded)

    def _fake_reconcile(hosts, state_file, *, remove_extra=True):
        seen_includes.append(list(hosts.image_sync.include))
        return isync.SyncState(
            updated_at="2026-07-11T18:00:00+00:00",
            interval_seconds=hosts.image_sync.interval_seconds,
            master_host=hosts.master.host,
            filter_include=list(hosts.image_sync.include),
        )

    monkeypatch.setattr(isync, "reconcile_once", _fake_reconcile)

    daemon = isync.ImageSyncDaemon(
        initial,
        tmp_path / "state.json",
        hosts_file="/etc/dnlab/hosts.yml",
    )
    daemon._do_reconcile()

    assert seen_includes == [["*/dnlab-runtime-relay:*"]]
    assert daemon.hosts is reloaded


def test_state_file_write_is_atomic(tmp_path):
    state = isync.SyncState(
        updated_at="2026-04-13T10:00:00+00:00",
        interval_seconds=60,
        master_host="10.0.0.1",
    )
    target = tmp_path / "nested" / "state.json"
    isync.write_state_file(target, state)
    assert target.exists()
    # temp file should be cleaned up after rename
    assert not (target.with_suffix(target.suffix + ".tmp")).exists()
    data = json.loads(target.read_text())
    assert data["master"]["host"] == "10.0.0.1"


def test_read_state_file_missing_returns_none(tmp_path):
    assert isync.read_state_file(tmp_path / "does-not-exist.json") is None


def test_read_state_file_corrupt_returns_none(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{not json")
    assert isync.read_state_file(p) is None
