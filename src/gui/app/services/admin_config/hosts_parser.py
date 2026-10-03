"""Structured parser for dnlab hosts.yml."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .base import ConfigParseError, dump_yaml, load_yaml_mapping, reject_empty


class HostEntry(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(default="", max_length=512)
    ssh_user: str = Field(default="root", max_length=128)
    ssh_key: str | None = Field(default=None, max_length=4096)
    extra: dict[str, Any] = {}


class HostsConfigData(BaseModel):
    master: HostEntry
    workers: list[HostEntry] = []
    extra_infrastructure: dict[str, Any] = {}
    extra_top_level: dict[str, Any] = {}


class HostsConfigModel(BaseModel):
    key: str = "hosts"
    path: str
    exists: bool
    data: HostsConfigData
    warnings: list[str] = []


def parse_hosts_config(content: str, path: Path, exists: bool) -> HostsConfigModel:
    raw = load_yaml_mapping(content, "hosts")
    infra = raw.get("infrastructure") or {}
    if not isinstance(infra, dict):
        raise ConfigParseError("hosts.infrastructure must be a mapping")

    master_raw = infra.get("master") or {}
    if not isinstance(master_raw, dict):
        raise ConfigParseError("hosts.infrastructure.master must be a mapping")
    master = _host_from_mapping("master", master_raw)

    workers_raw = infra.get("workers") or {}
    if not isinstance(workers_raw, dict):
        raise ConfigParseError("hosts.infrastructure.workers must be a mapping")
    workers = [_host_from_mapping(name, value or {}) for name, value in workers_raw.items()]

    extra_infra = {
        key: value for key, value in infra.items()
        if key not in {"master", "workers"}
    }
    extra_top = {
        key: value for key, value in raw.items()
        if key != "infrastructure"
    }
    return HostsConfigModel(
        path=str(path),
        exists=exists,
        data=HostsConfigData(
            master=master,
            workers=workers,
            extra_infrastructure=extra_infra,
            extra_top_level=extra_top,
        ),
    )


def serialize_hosts_config(model: HostsConfigModel, validate_with_orchestrator: bool = True) -> str:
    worker_names: set[str] = set()
    master = _host_to_mapping(model.data.master, include_name=False)
    workers: dict[str, Any] = {}
    for worker in model.data.workers:
        name = reject_empty(worker.name, "worker name")
        if name == "master":
            raise ConfigParseError("worker name cannot be 'master'")
        if name in worker_names:
            raise ConfigParseError(f"duplicate worker name: {name}")
        worker_names.add(name)
        workers[name] = _host_to_mapping(worker, include_name=False)

    infra: dict[str, Any] = {}
    infra.update(model.data.extra_infrastructure or {})
    realnet = infra.get("realnet")
    if isinstance(realnet, dict):
        realnet = dict(realnet)
        if "rr_as" not in realnet and "bgp_as" in realnet:
            realnet["rr_as"] = realnet["bgp_as"]
        if "router_as_pool" not in realnet and "lab_as_pool" in realnet:
            realnet["router_as_pool"] = realnet["lab_as_pool"]
        realnet.pop("bgp_as", None)
        realnet.pop("lab_as_pool", None)
        infra["realnet"] = realnet
    infra["master"] = master
    infra["workers"] = workers
    data: dict[str, Any] = {}
    data.update(model.data.extra_top_level or {})
    plus = data.pop("plus", None)
    if "follow_the_rabbit" not in data and isinstance(plus, dict) and "follow_the_rabbit" in plus:
        data["follow_the_rabbit"] = plus["follow_the_rabbit"]
    data["infrastructure"] = infra
    content = dump_yaml(data)
    if validate_with_orchestrator:
        _validate_hosts_content(content)
    return content


def _host_from_mapping(name: str, raw: dict[str, Any]) -> HostEntry:
    extra = {
        key: value for key, value in raw.items()
        if key not in {"host", "ssh_user", "ssh_key"}
    }
    return HostEntry(
        name=str(name),
        host="" if raw.get("host") is None else str(raw.get("host", "")),
        ssh_user=str(raw.get("ssh_user") or "root"),
        ssh_key=None if raw.get("ssh_key") in (None, "") else str(raw.get("ssh_key")),
        extra=extra,
    )


def _host_to_mapping(host: HostEntry, include_name: bool) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if include_name:
        data["name"] = reject_empty(host.name, "host name")
    data.update(host.extra or {})
    data["host"] = reject_empty(host.host, f"{host.name}.host")
    data["ssh_user"] = reject_empty(host.ssh_user, f"{host.name}.ssh_user")
    if host.ssh_key:
        data["ssh_key"] = host.ssh_key.strip()
    return data


def _validate_hosts_content(content: str) -> None:
    try:
        from dnlab_multinode.services.hosts_config import HostsConfigError, load_hosts_config
    except ModuleNotFoundError as exc:
        raise ConfigParseError("dnlab_multinode is not installed; cannot validate hosts.yml") from exc

    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as fh:
            fh.write(content)
            tmp = fh.name
        load_hosts_config(tmp)
    except HostsConfigError as exc:
        raise ConfigParseError(f"hosts.yml validation failed: {exc}") from exc
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
