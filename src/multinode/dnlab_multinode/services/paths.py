"""Centralised filesystem paths for dnlab-multinode and dnlab-gui.

Both packages import :data:`PATHS` from this module instead of
hardcoding literal paths in code. The paths are defined in
``/etc/dnlab/paths.yml`` (override location via
``$DNLAB_PATHS_FILE``). Missing keys fall back to the constants in
:data:`_DEFAULTS`, so the loader degrades gracefully on hosts where
the file is not yet deployed.

Rule: any new feature that needs a filesystem path MUST add a key to
``paths.yml`` and read it through :data:`PATHS`. No literal path
strings in code.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


DEFAULT_PATHS_FILE = "/etc/dnlab/paths.yml"

_DEFAULTS: dict[str, str] = {
    "hosts_file":        "/etc/dnlab/hosts.yml",
    "image_sync_state":  "/var/lib/dnlab-image-sync/state.json",
    "lab_cleanup_state": "/var/lib/dnlab-lab-cleanup/state.json",
    "persist_root":      "/var/lib/docker/dnlab-backups",
    "topologies_dir":    "/root/dnlab-topologies",
    "realnet_vni_dir":   "",
    "runtime_operations_dir": "",
    "management_journal_dir": "/var/lib/dnlab/management",
    "management_probe_journal_dir": "/var/lib/dnlab/management-probes",
    "jumphost_journal_dir": "/var/lib/dnlab/jumphost",
    "jumphost_network_journal_dir": "/var/lib/dnlab/jumphost-network",
    "dns_journal_dir": "/var/lib/dnlab/dns",
    "relay_journal_dir": "/var/lib/dnlab/runtime-relay",
    "gui_dir":           "/opt/dnlab-gui",
    "multinode_dir":     "/opt/dnlab-multinode",
    "image_build_dir":   "/opt/dnlab-image-build",
    "vrnetlab_dir":      "/opt/vrnetlab",
    "image_build_workspace": "/var/lib/dnlab-image-build",
    # ``ssh_key``     — orchestrator key (deploy, destroy, image-sync,
    #                   batch maintenance actions).
    # ``gui_ssh_key`` — GUI-only key (interactive console, vd log, and
    #                   any user-facing SSH hop). Separating the two
    #                   keeps audit trails distinct on the destination
    #                   hosts; see /root/dnlab-dev-docs/dnlab-integration.md §5.3.
    "ssh_key":           "/root/.ssh/id_ed25519",
    "gui_ssh_key":       "/root/.ssh/dnlab-gui.key",
    "log_root":          "/var/log/dnlab",
    "tmp_dir":           "/tmp",
    "containerlab_bin":  "/usr/bin/containerlab",
    "docker_socket":     "unix:///var/run/docker.sock",
}


@dataclass(frozen=True)
class Paths:
    hosts_file:        str
    image_sync_state:  str
    lab_cleanup_state: str
    persist_root:      str
    topologies_dir:    str
    realnet_vni_dir:   str
    runtime_operations_dir: str
    management_journal_dir: str
    management_probe_journal_dir: str
    jumphost_journal_dir: str
    jumphost_network_journal_dir: str
    dns_journal_dir: str
    relay_journal_dir: str
    gui_dir:           str
    multinode_dir:     str
    image_build_dir:   str
    vrnetlab_dir:      str
    image_build_workspace: str
    ssh_key:           str
    gui_ssh_key:       str
    log_root:          str
    tmp_dir:           str
    containerlab_bin:  str
    docker_socket:     str


def _load() -> Paths:
    path = os.getenv("DNLAB_PATHS_FILE", DEFAULT_PATHS_FILE)
    data: dict[str, str] = {}
    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expected mapping, got {type(raw).__name__}")
        data = {k: str(v) for k, v in raw.items() if v is not None}
    except FileNotFoundError:
        log.warning("Paths file %s not found — using built-in defaults", path)
    except Exception as exc:
        log.error("Failed to read %s: %s — using built-in defaults", path, exc)

    merged = {**_DEFAULTS, **data}
    if not merged['realnet_vni_dir']:
        merged['realnet_vni_dir']=str(Path(merged['topologies_dir'])/'.realnet-vni')
    extra = set(data) - set(_DEFAULTS)
    if extra:
        log.warning("Ignoring unknown keys in %s: %s", path, sorted(extra))

    return Paths(**{k: merged[k] for k in _DEFAULTS})


PATHS: Paths = _load()


def persist_dir_for(lab: str, vd: str, root: str | None = None) -> str:
    """Host-side directory bind-mounted to /persist inside VD container."""
    return persist_dir_for_node(lab, vd, "", root)


def persist_dir_for_node(
    lab: str,
    vd: str,
    persist_id: str | None = "",
    root: str | None = None,
) -> str:
    """Host-side persist directory for a VD's stable identity."""
    base = (root or PATHS.persist_root).rstrip("/")
    key = str(persist_id or vd)
    return f"{base}/{lab}/{key}"


def as_path(key: str) -> Path:
    """Return a PATHS field as a :class:`pathlib.Path`."""
    return Path(getattr(PATHS, key))
