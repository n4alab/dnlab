"""Image-sync daemon — keep Docker images aligned master → workers.

This service is the backbone of Milestone 2. The GUI (and any deploy
driven by a clean :class:`~dnlab_multinode.DeployController`) assumes that
every VD image declared in a topology is already present on every host
it may be scheduled on. Keeping that invariant by hand is tedious, so we
run a small daemon on the master that:

* subscribes to ``docker events --filter type=image`` on the local daemon,
* periodically reconciles the worker inventories (every
  ``interval_seconds`` from ``hosts.yml``),
* for each worker, pushes missing images via
  ``docker save | ssh worker docker load`` and removes stale/extra
  images via ``docker rmi`` (non-forced).

Matching a GUI poll path, the daemon publishes its current view of the
world to a state JSON file (default ``/var/lib/dnlab-image-sync/state.json``)
after every reconcile. The GUI reads that file — it never talks to the
daemon directly.

Public entry points:

* :class:`ImageSyncDaemon` — the long-running component.
* :func:`reconcile_once` — one-shot reconcile (used by the CLI
  ``dnlab-image-sync sync`` subcommand and by the test suite).
* :func:`list_master_images` / :func:`list_remote_images` — raw probes.
* :func:`filter_images` — apply the include/exclude patterns from
  ``hosts.yml``.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from dnlab_multinode.services.hosts_config import (
    HostsConfig, ImageSyncConfig, load_hosts_config,
)
from dnlab_multinode.services.paths import PATHS
from dnlab_multinode.services.resources import sync_image_to_host
from dnlab_multinode.services.ssh import SSHClient, create_clients

log = logging.getLogger(__name__)


DEFAULT_STATE_FILE = Path(PATHS.image_sync_state)


# ── Data model ──────────────────────────────────────────────────────────


@dataclass
class WorkerSyncState:
    name: str
    host: str
    reachable: bool = False
    images: dict[str, str] = field(default_factory=dict)   # name:tag → image ID
    missing: list[str] = field(default_factory=list)       # names to be pushed
    extra: list[str] = field(default_factory=list)         # names to be removed
    last_sync_at: str = ""
    last_error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "host": self.host,
            "reachable": self.reachable,
            "images": self.images,
            "missing": self.missing,
            "extra": self.extra,
            "last_sync_at": self.last_sync_at,
            "last_error": self.last_error,
        }


@dataclass
class SyncState:
    updated_at: str = ""
    interval_seconds: int = 300
    reconcile_count: int = 0
    last_reconcile_duration_ms: int = 0
    master_host: str = ""
    master_images: dict[str, str] = field(default_factory=dict)    # filtered
    workers: dict[str, WorkerSyncState] = field(default_factory=dict)
    filter_include: list[str] = field(default_factory=list)
    filter_exclude: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "updated_at": self.updated_at,
            "interval_seconds": self.interval_seconds,
            "reconcile_count": self.reconcile_count,
            "last_reconcile_duration_ms": self.last_reconcile_duration_ms,
            "master": {
                "host": self.master_host,
                "images": self.master_images,
            },
            "workers": {n: w.to_dict() for n, w in self.workers.items()},
            "filter": {
                "include": self.filter_include,
                "exclude": self.filter_exclude,
            },
        }


# ── Pure helpers (unit-testable) ────────────────────────────────────────


def _parse_docker_images(output: str) -> dict[str, str]:
    """Parse ``docker images --format '{{.Repository}}:{{.Tag}}\\t{{.ID}}'``.

    Skips ``<none>:<none>`` entries (dangling images).
    """
    images: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, image_id = parts[0], parts[1]
        if name == "<none>:<none>" or name.endswith(":<none>"):
            continue
        images[name] = image_id
    return images


def filter_images(
    images: dict[str, str],
    config: ImageSyncConfig,
) -> dict[str, str]:
    """Apply the include/exclude patterns from the hosts.yml ``image_sync``
    block.

    An image passes when it matches at least one ``include`` pattern AND
    no ``exclude`` pattern. Patterns are ``fnmatch``-style (``*``, ``?``).
    """
    def _matches(name: str, patterns: list[str]) -> bool:
        # A pattern without ``:`` or a glob wildcard is treated as matching
        # any tag, with or without a registry/path prefix. For example,
        # ``dnlab-runtime-relay`` matches both ``dnlab-runtime-relay:latest``
        # and ``ghcr.io/n4alab/dnlab-runtime-relay:latest``.
        for p in patterns:
            if fnmatch.fnmatchcase(name, p):
                return True
            if ":" not in p and "*" not in p and "?" not in p:
                if (
                    fnmatch.fnmatchcase(name, f"{p}:*")
                    or fnmatch.fnmatchcase(name, f"*/{p}:*")
                ):
                    return True
        return False

    out: dict[str, str] = {}
    for name, image_id in images.items():
        if not _matches(name, config.include):
            continue
        if _matches(name, config.exclude):
            continue
        out[name] = image_id
    return out


def compute_diff(
    master: dict[str, str],
    remote: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Return ``(to_push, to_remove)``.

    * ``to_push`` — images on master but missing on remote, **or** present
      on both with a different image ID (stale tag).
    * ``to_remove`` — images on remote but no longer on master.

    Both lists are sorted for deterministic ordering (tests + GUI).
    """
    to_push: list[str] = []
    for name, master_id in master.items():
        remote_id = remote.get(name)
        if remote_id is None or remote_id != master_id:
            to_push.append(name)

    to_remove = [n for n in remote if n not in master]

    return sorted(to_push), sorted(to_remove)


# ── Probes ──────────────────────────────────────────────────────────────


def list_master_images() -> dict[str, str]:
    """Run ``docker images`` locally and return ``{name:tag: image_id}``."""
    try:
        result = subprocess.run(
            ["docker", "images",
             "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "docker CLI not found on master — install docker or set PATH"
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker images failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return _parse_docker_images(result.stdout)


def list_remote_images(client: SSHClient) -> dict[str, str]:
    """Run ``docker images`` via SSH and return ``{name:tag: image_id}``.

    Raises on SSH error so the caller can flag the worker as unreachable.
    """
    out = client.run(
        "docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}'",
        timeout=30,
    )
    return _parse_docker_images(out)


# ── Reconcile ───────────────────────────────────────────────────────────


def _remove_remote_image(image: str, client: SSHClient) -> bool:
    """Best-effort ``docker rmi`` on a worker. Non-forced: in-use images
    stay put, they'll be retried on the next reconcile."""
    rc, _, err = client.run_no_check(
        f"docker rmi {image}", timeout=30,
    )
    if rc != 0:
        log.info("Skip rmi %s on %s (likely in use): %s",
                 image, client.name, err.strip())
        return False
    return True


def reconcile_worker(
    name: str,
    client: SSHClient,
    master_images: dict[str, str],
    *,
    remove_extra: bool = True,
) -> WorkerSyncState:
    """Sync one worker. Idempotent: safe to call repeatedly."""
    state = WorkerSyncState(name=name, host=client.host)
    try:
        remote = list_remote_images(client)
    except Exception as exc:
        state.reachable = False
        state.last_error = f"list: {exc}"
        log.warning("[%s] list_remote_images failed: %s", name, exc)
        return state

    state.reachable = True
    state.images = remote

    to_push, to_remove = compute_diff(master_images, remote)
    state.missing = list(to_push)
    state.extra = list(to_remove) if remove_extra else []

    errors: list[str] = []

    # Push missing/stale images. Serial per worker on purpose: parallel
    # docker save streams on the same host saturate IO.
    for image in to_push:
        ok = sync_image_to_host(image, client)
        if not ok:
            errors.append(f"push {image}")

    if remove_extra:
        for image in to_remove:
            # Ignore rmi failures — in-use images are expected to survive.
            _remove_remote_image(image, client)

    state.last_sync_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if errors:
        state.last_error = "; ".join(errors)
    return state


def reconcile_once(
    hosts: HostsConfig,
    state_file: Path = DEFAULT_STATE_FILE,
    *,
    clients: dict[str, SSHClient] | None = None,
    master_probe=list_master_images,
    remove_extra: bool = True,
) -> SyncState:
    """Run a single reconcile pass and write the state file.

    ``clients`` and ``master_probe`` are dependency-injection hooks used
    by the test suite; production code leaves both at the default.
    """
    started = time.monotonic()
    cfg = hosts.image_sync

    raw = master_probe()
    filtered = filter_images(raw, cfg)

    own_clients = False
    if clients is None:
        clients = create_clients(hosts.workers)
        own_clients = True
        for c in clients.values():
            try:
                c.connect()
            except Exception as exc:
                log.warning("Cannot connect to %s: %s", c.name, exc)

    try:
        workers: dict[str, WorkerSyncState] = {}
        if clients:
            with ThreadPoolExecutor(max_workers=max(1, len(clients))) as pool:
                futures = {
                    pool.submit(
                        reconcile_worker, name, client, filtered,
                        remove_extra=remove_extra,
                    ): name
                    for name, client in clients.items()
                }
                for f in as_completed(futures):
                    ws = f.result()
                    workers[ws.name] = ws
    finally:
        if own_clients and clients:
            for c in clients.values():
                c.close()

    state = SyncState(
        updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        interval_seconds=cfg.interval_seconds,
        master_host=hosts.master.host,
        master_images=filtered,
        workers=workers,
        filter_include=list(cfg.include),
        filter_exclude=list(cfg.exclude),
        last_reconcile_duration_ms=int((time.monotonic() - started) * 1000),
    )
    write_state_file(state_file, state)
    return state


def write_state_file(path: Path, state: SyncState) -> None:
    """Atomic write via ``tmp + rename``. Creates parent dirs as needed."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        log.warning("Cannot create state dir %s: %s", path.parent, exc)
        return
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True))
        tmp.replace(path)
    except OSError as exc:
        log.warning("Cannot write state file %s: %s", path, exc)


def read_state_file(path: Path = DEFAULT_STATE_FILE) -> dict | None:
    """Return the last published state dict, or ``None`` if missing."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


# ── Daemon loop ─────────────────────────────────────────────────────────


class ImageSyncDaemon:
    """Long-running reconciler.

    Event-driven (``docker events``) + periodic fallback. Thread-safe
    ``stop()`` for systemd shutdown.
    """

    def __init__(
        self,
        hosts: HostsConfig,
        state_file: Path = DEFAULT_STATE_FILE,
        *,
        hosts_file: str | None = None,
        remove_extra: bool = True,
    ):
        self.hosts = hosts
        self.hosts_file = hosts_file
        self.state_file = Path(state_file)
        self.remove_extra = remove_extra
        self._stop = threading.Event()
        self._trigger = threading.Event()
        self._reconcile_count = 0
        self._events_proc: subprocess.Popen | None = None

    # ── public control ────────────────────────────────────────────

    def stop(self) -> None:
        self._stop.set()
        self._trigger.set()
        if self._events_proc and self._events_proc.poll() is None:
            self._events_proc.terminate()

    def trigger_reconcile(self) -> None:
        """Wake the main loop for an immediate reconcile pass.

        Thread-safe and signal-safe (just ``Event.set()``). Called by
        the SIGUSR1 handler in the CLI, or by external coordination
        code that wants to force a refresh (e.g. the GUI's
        ``POST /api/image-sync/reconcile``).
        """
        self._trigger.set()

    def run(self) -> None:
        """Blocking loop. Returns when :meth:`stop` is called."""
        if not self.hosts.image_sync.enabled:
            log.info("image-sync disabled in hosts.yml — daemon exits")
            return

        log.info(
            "image-sync daemon starting (interval=%ds, workers=%s)",
            self.hosts.image_sync.interval_seconds,
            list(self.hosts.workers.keys()),
        )

        events_thread = None
        if shutil.which("docker"):
            events_thread = threading.Thread(
                target=self._docker_events_loop,
                daemon=True, name="image-sync-events",
            )
            events_thread.start()

        # Initial reconcile so the state file exists even before the first
        # event or tick — the GUI polls this file from boot.
        self._do_reconcile()

        interval = max(30, self.hosts.image_sync.interval_seconds)
        while not self._stop.is_set():
            # Wake up on event OR on interval timeout. Events get ~1s of
            # coalescing so a flurry of tag/untag doesn't thrash us.
            triggered = self._trigger.wait(timeout=interval)
            if self._stop.is_set():
                break
            if triggered:
                time.sleep(1)
                self._trigger.clear()
            self._do_reconcile()

        log.info("image-sync daemon stopped (reconciles=%d)",
                 self._reconcile_count)

    # ── internals ─────────────────────────────────────────────────

    def _do_reconcile(self) -> None:
        try:
            if self.hosts_file:
                self.hosts = load_hosts_config(self.hosts_file)
            state = reconcile_once(
                self.hosts, self.state_file,
                remove_extra=self.remove_extra,
            )
            self._reconcile_count += 1
            state.reconcile_count = self._reconcile_count
            write_state_file(self.state_file, state)
            log.info(
                "reconcile #%d done in %dms — master=%d images, workers=%d",
                self._reconcile_count,
                state.last_reconcile_duration_ms,
                len(state.master_images),
                len(state.workers),
            )
        except Exception:
            log.exception("reconcile failed — will retry at next tick")

    def _docker_events_loop(self) -> None:
        """Stream docker events and signal the main loop on image changes."""
        try:
            self._events_proc = subprocess.Popen(
                ["docker", "events",
                 "--filter", "type=image",
                 "--format", "{{.Action}} {{.Actor.Attributes.name}}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True,
            )
        except FileNotFoundError:
            log.warning("docker CLI missing — event stream disabled")
            return
        assert self._events_proc.stdout is not None

        for line in self._events_proc.stdout:
            if self._stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            log.debug("docker event: %s", line)
            # Any image-level event is a reconcile trigger. We coalesce
            # in the main loop, no need to de-dup here.
            self._trigger.set()
