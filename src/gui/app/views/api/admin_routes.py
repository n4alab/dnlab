"""Admin infrastructure API.

These endpoints expose site-wide configuration files and local image-build
jobs. Every route is admin-only; callers should still treat writes as
infrastructure changes and expect filesystem permission errors when the
service account cannot update /etc/dnlab.
"""

from __future__ import annotations

import asyncio
import fnmatch
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, WebSocket
import httpx
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
import websockets

from app.auth import audit
from app.auth.db import get_session
from app.auth.deps import authenticate_ws, require_role
from app.auth.models import Role, User
from app.config import settings
from app.security import reject_if_bad_origin
from app.services.shutdown_registry import shutdown_registry
from app.services.admin_config import (
    DevicesConfigModel,
    HostsConfigModel,
    PathsConfigModel,
    parse_devices_config,
    parse_hosts_config,
    parse_paths_config,
    serialize_devices_config,
    serialize_hosts_config,
    serialize_paths_config,
)
from app.services.admin_config.base import ConfigParseError, read_text_or_default
from app.services import realnet_bgp
from app.services import device_catalog
from app.services.paths import DEFAULT_PATHS_FILE, PATHS

router = APIRouter(prefix="/api/admin", tags=["admin"])


class ConfigFileOut(BaseModel):
    key: str
    path: str
    exists: bool
    content: str
    parsed: object | None = None


class ImageBuildRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=64)
    source_path: str | None = Field(default=None, max_length=4096)
    with_persistence: bool = False


class ImageFilenameValidationRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=64)
    filename: str = Field(min_length=1, max_length=4096)


class RealNetBgpConfigRequest(BaseModel):
    rr_as: int
    rr_ip: str
    host_net: str
    router_as_pool: str
    router_ip_pool: str = ""
    realnet_network_pool: str = "100.64.0.0/10"
    rr_password: str = ""


class ImageBuildJobOut(BaseModel):
    id: str
    status: str
    kind: str
    source_path: str | None
    with_persistence: bool
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    returncode: int | None = None
    log: list[str] = []


@dataclass
class _ImageBuildJob:
    id: str
    kind: str
    source_path: str | None
    with_persistence: bool
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: str = "queued"
    returncode: int | None = None
    log: list[str] = field(default_factory=list)


_JOBS: dict[str, _ImageBuildJob] = {}
_JOB_LOG_LIMIT = 1200


def _paths_file() -> Path:
    return Path(os.getenv("DNLAB_PATHS_FILE", DEFAULT_PATHS_FILE))


def _hosts_file() -> Path:
    return Path(settings.DNLAB_MULTINODE_HOSTS or PATHS.hosts_file)


def _devices_file() -> Path:
    return device_catalog.active_path()


def _require_config_writable() -> None:
    if not settings.CONFIG_WRITABLE:
        raise HTTPException(403, "configuration writes are disabled by the hardened Compose profile")


def _image_build_dir() -> Path:
    return Path(os.getenv("DNLAB_IMAGE_BUILD_DIR", PATHS.image_build_dir))


def _image_build_workspace() -> Path:
    return Path(os.getenv("DNLAB_IMAGE_BUILD_WORKSPACE", PATHS.image_build_workspace))


def _cleanup_local_image_build_upload(source_path: str | None) -> None:
    if not source_path:
        return
    try:
        source = Path(source_path).resolve()
        uploads = (_image_build_workspace() / "uploads").resolve()
        if source.is_relative_to(uploads) and source.parent.parent == uploads:
            shutil.rmtree(source.parent, ignore_errors=True)
    except OSError:
        pass


def _vrnetlab_dir() -> Path:
    return Path(os.getenv("DNLAB_VRNETLAB_DIR", PATHS.vrnetlab_dir))


def _config_path(key: Literal["paths", "hosts", "devices"]) -> Path:
    return {
        "paths": _paths_file(),
        "hosts": _hosts_file(),
        "devices": _devices_file(),
    }[key]


@router.get("/config/{key}", response_model=ConfigFileOut)
async def read_config_file(
    key: Literal["paths", "hosts", "devices"],
    _admin: Annotated[User, Depends(require_role(Role.admin))],
) -> ConfigFileOut:
    path = _config_path(key)
    content = device_catalog.catalog_json() if key == "devices" else (
        path.read_text(encoding="utf-8") if path.exists() else _default_content(key)
    )
    parsed = _parse_config(key, content)
    return ConfigFileOut(
        key=key,
        path=str(path),
        exists=path.exists(),
        content=content,
        parsed=parsed,
    )


@router.get("/config/{key}/model")
async def read_config_model(
    key: Literal["paths", "hosts", "devices"],
    _admin: Annotated[User, Depends(require_role(Role.admin))],
):
    path = _config_path(key)
    if key == "devices":
        content, exists = device_catalog.catalog_json(), path.exists()
    else:
        content, exists = read_text_or_default(path, _default_content(key))
    try:
        return _parse_config_model(key, content, path, exists)
    except ConfigParseError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.put("/config/{key}/model")
async def write_config_model(
    key: Literal["paths", "hosts", "devices"],
    body: dict,
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    _require_config_writable()
    path = _config_path(key)
    try:
        model = _model_from_payload(key, body, path)
        content = await _serialize_config_model(key, model)
    except ConfigParseError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(422, f"{key} validation failed: {exc}") from exc

    try:
        backup = device_catalog.write_custom(content) if key == "devices" else _atomic_write(path, content)
    except OSError as exc:
        raise HTTPException(500, f"cannot write {path}: {exc}") from exc
    if key == "devices":
        path = device_catalog.active_path()

    await audit.record(
        db,
        event=f"admin.config.{key}.update",
        user=admin,
        request=request,
        resource=f"file:{path}",
        detail={"backup": str(backup) if backup else None, "mode": "structured"},
    )
    await db.commit()
    return _parse_config_model(key, content, path, True)


@router.get("/realnet-bgp")
async def read_realnet_bgp_config(
    _admin: Annotated[User, Depends(require_role(Role.admin))],
):
    path = _hosts_file()
    content, exists = read_text_or_default(path, _default_content("hosts"))
    try:
        model = parse_hosts_config(content, path, exists)
    except ConfigParseError as exc:
        raise HTTPException(422, str(exc)) from exc
    realnet = dict((model.data.extra_infrastructure or {}).get("realnet") or {})
    data = realnet_bgp.RealNetBgpConfig().as_dict()
    data.update({
        "rr_as": realnet.get("rr_as") or realnet.get("bgp_as") or data["rr_as"],
        "rr_ip": realnet.get("rr_ip") or data["rr_ip"],
        "host_net": realnet.get("host_net") or data["host_net"],
        "router_as_pool": realnet.get("router_as_pool") or realnet.get("lab_as_pool") or data["router_as_pool"],
        "router_ip_pool": realnet.get("router_ip_pool") or data["router_ip_pool"],
        "realnet_network_pool": realnet.get("realnet_network_pool") or data["realnet_network_pool"],
        "rr_password": realnet.get("rr_password") or data["rr_password"],
    })
    return {
        "path": str(path),
        "exists": exists,
        "data": data,
        "rr": realnet_bgp.realnet_bgp_status(data),
    }


@router.put("/realnet-bgp")
async def write_realnet_bgp_config(
    body: RealNetBgpConfigRequest,
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    _require_config_writable()
    path = _hosts_file()
    content, exists = read_text_or_default(path, _default_content("hosts"))
    try:
        model = parse_hosts_config(content, path, exists)
        model, cfg = realnet_bgp.update_hosts_model_realnet_bgp(model, body.model_dump())
        rendered = await _serialize_config_model("hosts", model)
    except (ConfigParseError, realnet_bgp.RealNetBgpError) as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        backup = _atomic_write(path, rendered)
    except OSError as exc:
        raise HTTPException(500, f"cannot write {path}: {exc}") from exc
    await audit.record(
        db,
        event="admin.config.realnet_bgp.update",
        user=admin,
        request=request,
        resource=f"file:{path}",
        detail={"backup": str(backup) if backup else None},
    )
    await db.commit()
    rr_result = await asyncio.to_thread(realnet_bgp.ensure_route_reflector_from_hosts)
    return {"path": str(path), "exists": True, "data": cfg.as_dict(), "rr": rr_result}


@router.post("/realnet-bgp/rr-password")
async def regenerate_realnet_bgp_rr_password(
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    _require_config_writable()
    path = _hosts_file()
    content, exists = read_text_or_default(path, _default_content("hosts"))
    try:
        model = parse_hosts_config(content, path, exists)
        current = dict((model.data.extra_infrastructure or {}).get("realnet") or {})
        current["rr_password"] = realnet_bgp.generate_bgp_password()
        model, cfg = realnet_bgp.update_hosts_model_realnet_bgp(model, current)
        rendered = await _serialize_config_model("hosts", model)
    except (ConfigParseError, realnet_bgp.RealNetBgpError) as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        backup = _atomic_write(path, rendered)
    except OSError as exc:
        raise HTTPException(500, f"cannot write {path}: {exc}") from exc
    await audit.record(
        db,
        event="admin.config.realnet_bgp.rr_password.regenerate",
        user=admin,
        request=request,
        resource=f"file:{path}",
        detail={"backup": str(backup) if backup else None},
    )
    await db.commit()
    rr_result = await asyncio.to_thread(realnet_bgp.ensure_route_reflector_from_hosts)
    return {"path": str(path), "exists": True, "data": cfg.as_dict(), "rr": rr_result}


@router.post("/realnet-bgp/reconcile")
async def reconcile_realnet_bgp_rr(
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    try:
        result = await asyncio.to_thread(realnet_bgp.ensure_route_reflector_from_hosts)
    except Exception as exc:
        raise HTTPException(500, f"realnet-rr reconcile failed: {exc}") from exc
    await audit.record(
        db,
        event="admin.realnet_bgp.rr_reconcile",
        user=admin,
        request=request,
        resource="container:dnlab-realnet-rr",
        detail=result,
    )
    await db.commit()
    return result


@router.get("/image-build/kinds")
async def image_build_kinds(
    _admin: Annotated[User, Depends(require_role(Role.admin))],
):
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_get("/kinds")
    return _local_image_build_kinds()


@router.post("/image-build/validate-filename")
async def validate_image_build_filename(
    body: ImageFilenameValidationRequest,
    _admin: Annotated[User, Depends(require_role(Role.admin))],
):
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_post("/validate-filename", body.model_dump())
    filename = _safe_upload_filename(body.filename)
    _validate_local_image_build_filename(body.kind, filename)
    return {"ok": True, "kind": body.kind, "filename": filename}


@router.post("/image-build/uploads")
async def upload_image_build_source(
    _admin: Annotated[User, Depends(require_role(Role.admin))],
    file: UploadFile = File(...),
):
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_upload(file)
    upload_dir = _image_build_workspace() / "uploads" / secrets.token_hex(8)
    upload_dir.mkdir(parents=True, exist_ok=False)
    filename = _safe_upload_filename(file.filename or "image")
    target = upload_dir / filename
    try:
        with target.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
    finally:
        await file.close()
    return {"source_path": str(target), "filename": filename}


@router.post("/image-build/jobs", response_model=ImageBuildJobOut)
async def create_image_build_job(
    body: ImageBuildRequest,
    _request: Request,
    _admin: Annotated[User, Depends(require_role(Role.admin))],
):
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_post("/jobs", body.model_dump())
    root = _image_build_dir()
    script = root / "build_image.py"
    if not script.exists():
        raise HTTPException(503, f"image-build script not found: {script}")
    module = _load_image_build_module(root)
    self_building = set(getattr(module, "SELF_BUILDING_KINDS", ())) if module else set()
    if body.kind in self_building:
        if body.source_path:
            raise HTTPException(400, f"self-building kind '{body.kind}' does not accept source_path")
        source = None
    else:
        if not body.source_path:
            raise HTTPException(400, f"kind '{body.kind}' requires an uploaded source image")
        source = Path(body.source_path).expanduser()
        if not source.exists():
            raise HTTPException(400, f"source image not found: {source}")
        _validate_local_image_build_source(body.kind, source)

    with_persistence = _local_image_kind_is_persistent(body.kind)
    job = _ImageBuildJob(
        id=secrets.token_hex(8),
        kind=body.kind,
        source_path=str(source) if source else None,
        with_persistence=with_persistence,
    )
    _JOBS[job.id] = job
    asyncio.create_task(_run_image_build_job(job, root, script))
    return _job_out(job)


@router.get("/image-build/jobs", response_model=list[ImageBuildJobOut])
async def list_image_build_jobs(
    _admin: Annotated[User, Depends(require_role(Role.admin))],
) -> list[ImageBuildJobOut]:
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_get("/jobs")
    return [_job_out(j) for j in sorted(_JOBS.values(), key=lambda j: j.created_at, reverse=True)]


@router.post("/image-build/jobs/clear")
async def clear_image_build_jobs(
    _admin: Annotated[User, Depends(require_role(Role.admin))],
) -> dict:
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_post("/jobs/clear", {})
    removed = 0
    for job_id, job in list(_JOBS.items()):
        if job.status in ("queued", "running"):
            continue
        _JOBS.pop(job_id, None)
        removed += 1
    return {"removed": removed}


@router.get("/image-build/jobs/{job_id}", response_model=ImageBuildJobOut)
async def get_image_build_job(
    job_id: str,
    _admin: Annotated[User, Depends(require_role(Role.admin))],
) -> ImageBuildJobOut:
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        return await _image_build_api_get(f"/jobs/{job_id}")
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return _job_out(job)


@router.websocket("/ws/image-build/jobs/{job_id}")
async def ws_image_build_job(ws: WebSocket, job_id: str):
    if await reject_if_bad_origin(ws):
        return
    user = await authenticate_ws(ws)
    if user is None or user.role != Role.admin:
        await ws.close(code=4403)
        return
    if settings.DNLAB_IMAGE_BUILD_API_URL:
        await _relay_image_build_ws(ws, job_id)
        return
    job = _JOBS.get(job_id)
    if not job:
        await ws.close(code=4404)
        return
    await ws.accept()
    sent = 0
    label = f"ws/image-build/jobs/{job_id}"
    async with shutdown_registry.track(label):
        try:
            while True:
                lines = job.log[sent:]
                sent = len(job.log)
                await ws.send_json({"status": job.status, "lines": lines, "returncode": job.returncode})
                if job.status in ("success", "failed"):
                    break
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                await ws.close()
            except RuntimeError:
                pass


async def _image_build_api_get(path: str):
    return await _image_build_api_request("GET", path)


async def _image_build_api_post(path: str, payload: dict):
    return await _image_build_api_request("POST", path, json=payload)


async def _image_build_api_upload(file: UploadFile):
    url = f"{settings.DNLAB_IMAGE_BUILD_API_URL}/uploads"
    try:
        await file.seek(0)
        files = {
            "file": (
                file.filename or "image",
                file.file,
                file.content_type or "application/octet-stream",
            )
        }
        async with httpx.AsyncClient(timeout=None) as client:
            response = await client.post(url, files=files)
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"image-build API upload failed: {exc}") from exc
    finally:
        await file.close()
    if response.status_code >= 400:
        detail = _image_build_error_detail(response)
        raise HTTPException(response.status_code, detail or "image-build upload error")
    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(502, "image-build API returned non-JSON response") from exc


async def _image_build_api_request(method: str, path: str, **kwargs):
    url = f"{settings.DNLAB_IMAGE_BUILD_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            response = await client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"image-build API request failed: {exc}") from exc
    if response.status_code >= 400:
        detail = _image_build_error_detail(response)
        raise HTTPException(response.status_code, detail or "image-build API error")
    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(502, "image-build API returned non-JSON response") from exc


async def _relay_image_build_ws(ws: WebSocket, job_id: str) -> None:
    await ws.accept()
    remote_url = _image_build_ws_url(settings.DNLAB_IMAGE_BUILD_API_URL, f"/ws/jobs/{job_id}")
    try:
        async with websockets.connect(remote_url) as remote:
            async for raw in remote:
                try:
                    await ws.send_json(json.loads(raw))
                except json.JSONDecodeError:
                    await ws.send_text(raw)
    except websockets.ConnectionClosed:
        pass
    except Exception as exc:
        await ws.send_json({"status": "failed", "lines": [f"image-build API websocket failed: {exc}"], "returncode": -1})
    finally:
        try:
            await ws.close()
        except RuntimeError:
            pass


def _image_build_error_detail(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text
    if isinstance(data, dict):
        detail = data.get("detail")
        if isinstance(detail, str):
            return detail
        return json.dumps(detail if detail is not None else data)
    return str(data)


def _image_build_ws_url(base_url: str, path: str) -> str:
    if base_url.startswith("https://"):
        return "wss://" + base_url[len("https://"):] + path
    if base_url.startswith("http://"):
        return "ws://" + base_url[len("http://"):] + path
    return base_url.rstrip("/") + path


def _safe_upload_filename(filename: str) -> str:
    name = Path(filename).name.strip().replace("\x00", "")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "image"


def _local_image_build_kinds() -> dict:
    root = _image_build_dir()
    script = root / "build_image.py"
    module = _load_image_build_module(root)
    if module is None:
        patches = root / "patches"
        patchable = sorted(
            p.stem for p in patches.glob("*.py")
            if p.name != "__init__.py" and not p.name.startswith("_")
        ) if patches.is_dir() else []
        return {
            "root": str(root),
            "vrnetlab_root": str(_vrnetlab_dir()),
            "available": script.exists(),
            "patchable": patchable,
            "vrnetlab": [],
            "kinds": [
                {"kind": kind, "patchable": True, "builder": "dnlab-image-build", "vrnetlab_dir": None,
                 "source_required": kind != "dnlab_frr"}
                for kind in patchable
            ],
        }

    patchable = module.list_patchable_kinds()
    patchable_set = set(patchable)
    vrnetlab_items = module.list_vrnetlab_kinds(_vrnetlab_dir())
    by_kind: dict[str, dict] = {}
    for item in vrnetlab_items:
        kind = item["kind"]
        vrnetlab_dir = Path(item["vrnetlab_dir"])
        image_globs = _image_globs_for_kind_dir(module, vrnetlab_dir)
        by_kind[kind] = {
            "kind": kind,
            "patchable": kind in patchable_set,
            "builder": "dnlab-image-build" if kind in patchable_set else "vrnetlab-make",
            "vrnetlab_dir": item["vrnetlab_dir"],
            "image_globs": image_globs,
            "image_examples": _image_examples_for(vrnetlab_dir, image_globs),
            "source_required": kind not in getattr(module, "SELF_BUILDING_KINDS", ()),
        }
    for kind in patchable:
        by_kind.setdefault(kind, {
            "kind": kind,
            "patchable": True,
            "builder": "dnlab-image-build",
            "vrnetlab_dir": None,
            "image_globs": [],
            "image_examples": [],
            "source_required": kind not in getattr(module, "SELF_BUILDING_KINDS", ()),
        })
    for kind in sorted(getattr(module, "QCOW_RECIPE_KINDS", ())):
        by_kind[kind] = {
            "kind": kind,
            "patchable": False,
            "persistent": True,
            "builder": "dnlab-image-build",
            "vrnetlab_dir": None,
            "image_globs": ["*.zip"],
            "image_examples": [f"{kind}-<release>.zip"],
            "source_required": True,
        }
    return {
        "root": str(root),
        "vrnetlab_root": str(_vrnetlab_dir()),
        "available": script.exists(),
        "patchable": patchable,
        "vrnetlab": sorted(item["kind"] for item in vrnetlab_items),
        "kinds": [by_kind[kind] for kind in sorted(by_kind)],
    }


def _local_image_kind_is_persistent(kind: str) -> bool:
    module = _load_image_build_module(_image_build_dir())
    if module is not None:
        is_persistent = getattr(module, "is_persistent_kind", None)
        if callable(is_persistent):
            return bool(is_persistent(kind))
        return bool(module.has_patch(kind))
    return (_image_build_dir() / "patches" / f"{kind}.py").is_file()


def _validate_local_image_build_source(kind: str, source: Path) -> None:
    """Fail fast when a source filename cannot satisfy the selected kind Makefile."""
    _validate_local_image_build_filename(kind, source.name)


def _validate_local_image_build_filename(kind: str, filename: str) -> None:
    module = _load_image_build_module(_image_build_dir())
    if module is None:
        return
    container_native = getattr(module, "CONTAINER_NATIVE_KINDS", set())
    if kind in container_native:
        return
    if kind in getattr(module, "QCOW_RECIPE_KINDS", set()):
        if not filename.lower().endswith(".zip"):
            raise HTTPException(400, f"kind '{kind}' requires a .zip release bundle")
        return
    try:
        work_dir = Path(module.resolve_vrnetlab_dir(kind, _vrnetlab_dir()))
    except (AttributeError, SystemExit):
        return

    globs = _image_globs_for_kind_dir(module, work_dir)
    examples = _image_examples_for(work_dir, globs)
    if globs and not _matches_image_glob(filename, globs):
        raise HTTPException(400, _image_name_error(kind, filename, globs, examples))

    version = _makefile_version_for(work_dir, filename)
    if version is None:
        return
    if not version or version == filename:
        detail = _image_name_error(kind, filename, globs, examples)
        detail += " The filename also must let the vrnetlab Makefile extract a version."
        raise HTTPException(400, detail)


def _image_globs_for_kind_dir(module, work_dir: Path) -> list[str]:
    try:
        globs = module.image_globs_for(work_dir)
    except Exception:
        globs = _makefile_image_globs(work_dir)
    return [str(p) for p in globs if str(p)] or ["*.zip"]


def _makefile_image_globs(work_dir: Path) -> list[str]:
    raw = _makefile_var(work_dir, "IMAGE_GLOB")
    if not raw:
        return ["*.zip"]
    fmt = _makefile_var(work_dir, "IMAGE_FORMAT") or "qcow2"
    raw = raw.replace("$(IMAGE_FORMAT)", fmt).replace("${IMAGE_FORMAT}", fmt)
    return [part for part in raw.split() if part]


def _makefile_var(work_dir: Path, name: str) -> str | None:
    makefile = work_dir / "Makefile"
    if not makefile.is_file():
        return None
    pat = re.compile(rf"^\s*{re.escape(name)}\s*[:?]?=\s*(.+?)\s*$")
    for line in makefile.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = pat.match(line)
        if match:
            return match.group(1)
    return None


def _matches_image_glob(filename: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(filename, pattern) for pattern in globs)


def _makefile_version_for(work_dir: Path, filename: str) -> str | None:
    makefile = work_dir / "Makefile"
    if not makefile.is_file():
        return None
    try:
        result = subprocess.run(
            ["make", "version-test", f"IMAGE={filename}"],
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0 and "No rule to make target" in result.stderr:
        return None
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def _image_examples_for(work_dir: Path, globs: list[str]) -> list[str]:
    readme = work_dir / "README.md"
    if not readme.is_file():
        return []
    text = readme.read_text(encoding="utf-8", errors="ignore")
    candidates: list[str] = []
    for match in re.finditer(r"```(?:[A-Za-z0-9_-]+)?\s*(.*?)```", text, flags=re.S):
        candidates.extend(_example_tokens(match.group(1)))
    for match in re.finditer(r"`([^`\n]+)`", text):
        candidates.extend(_example_tokens(match.group(1)))
    for line in text.splitlines():
        if re.search(r"\b(example|filename|format|for example)\b", line, flags=re.I):
            candidates.extend(_example_tokens(line))

    examples: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        cleaned = _clean_example_token(candidate)
        if not cleaned or cleaned in seen:
            continue
        if _example_matches_globs(cleaned, globs):
            examples.append(cleaned)
            seen.add(cleaned)
        if len(examples) >= 3:
            break
    return examples


def _example_tokens(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_.$<>:+/-]+\.(?:qcow2|qcow|vmdk|vdi|bin|img|gz)", text, flags=re.I)


def _clean_example_token(token: str) -> str:
    token = token.strip().strip(".,;:()[]{}'\"")
    if ":" in token:
        token = token.rsplit(":", 1)[-1]
    if "/" in token:
        token = token.rsplit("/", 1)[-1]
    return token.strip()


def _example_matches_globs(example: str, globs: list[str]) -> bool:
    concrete = re.sub(r"<[^>]+>", "1", example)
    concrete = concrete.replace("$VERSION", "1").replace("${VERSION}", "1")
    return _matches_image_glob(concrete, globs)


def _image_name_error(kind: str, filename: str, globs: list[str], examples: list[str]) -> str:
    expected = " ".join(globs) if globs else "the selected kind Makefile format"
    detail = f"kind '{kind}' expects image filename matching {expected}, but got '{filename}'."
    if examples:
        detail += f" Example: {', '.join(examples)}."
    else:
        detail += " Check IMAGE_GLOB and VERSION in the vrnetlab kind Makefile."
    return detail


def _load_image_build_module(root: Path):
    script = root / "build_image.py"
    if not script.exists():
        return None
    spec = importlib.util.spec_from_file_location("dnlab_image_build_local", script)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _default_content(key: str) -> str:
    if key == "devices":
        return '{\n  "defaults": {},\n  "vendors": {},\n  "icons": {},\n  "kinds": {}\n}\n'
    if key == "hosts":
        return "infrastructure:\n  master:\n    host: localhost\n    ssh_user: root\n  workers: {}\n"
    return "{}\n"


def _parse_config_model(
    key: Literal["paths", "hosts", "devices"],
    content: str,
    path: Path,
    exists: bool,
):
    if key == "paths":
        return parse_paths_config(content, path, exists)
    if key == "hosts":
        return parse_hosts_config(content, path, exists)
    return parse_devices_config(content, path, exists)


def _model_from_payload(
    key: Literal["paths", "hosts", "devices"],
    payload: dict,
    path: Path,
):
    data = payload.get("data", payload)
    base = {"path": str(path), "exists": path.exists(), "data": data}
    if key == "paths":
        return PathsConfigModel.model_validate(base)
    if key == "hosts":
        return HostsConfigModel.model_validate(base)
    return DevicesConfigModel.model_validate(base)


async def _serialize_config_model(
    key: Literal["paths", "hosts", "devices"],
    model,
) -> str:
    if key == "paths":
        return serialize_paths_config(model)
    if key == "hosts":
        if settings.DNLAB_MULTINODE_API_URL:
            content = serialize_hosts_config(model, validate_with_orchestrator=False)
            await _validate_hosts_with_multinode_api(content)
            return content
        return serialize_hosts_config(model)
    return serialize_devices_config(model)


async def _validate_hosts_with_multinode_api(content: str) -> None:
    url = f"{settings.DNLAB_MULTINODE_API_URL}/hosts/validate"
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            response = await client.post(url, json={"content": content})
    except httpx.HTTPError as exc:
        raise ConfigParseError(f"hosts.yml validation API request failed: {exc}") from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text
        raise ConfigParseError(f"hosts.yml validation failed: {detail or response.status_code}")


def _parse_config(key: str, content: str) -> object:
    try:
        if key == "devices":
            return json.loads(content)
        return yaml.safe_load(content) or {}
    except Exception as exc:
        raise HTTPException(422, f"{key} parse failed: {exc}") from exc


def _atomic_write(path: Path, content: str) -> Path | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(f"{path.name}.{stamp}.bak")
        shutil.copy2(path, backup)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)
    return backup


async def _run_image_build_job(job: _ImageBuildJob, root: Path, script: Path) -> None:
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    cmd = [sys.executable, str(script), job.kind]
    if job.source_path:
        cmd.append(job.source_path)
    job.log.append("$ " + " ".join(cmd))
    proc: asyncio.subprocess.Process | None = None
    token: int | None = None

    def _kill_proc() -> None:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    task = asyncio.current_task()
    if task is not None:
        token = shutdown_registry.register(
            f"image-build/{job.id}",
            task=task,
            callbacks=[_kill_proc],
        )
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            job.log.append(raw.decode("utf-8", errors="replace").rstrip())
            if len(job.log) > _JOB_LOG_LIMIT:
                del job.log[: len(job.log) - _JOB_LOG_LIMIT]
        job.returncode = await proc.wait()
        job.status = "success" if job.returncode == 0 else "failed"
    except asyncio.CancelledError:
        _kill_proc()
        job.log.append("cancelled: service shutdown")
        job.status = "failed"
        job.returncode = -1
    except Exception as exc:
        job.log.append(f"error: {exc}")
        job.status = "failed"
        job.returncode = -1
    finally:
        if token is not None:
            shutdown_registry.unregister(token)
        _cleanup_local_image_build_upload(job.source_path)
        job.finished_at = datetime.now(timezone.utc)


def _job_out(job: _ImageBuildJob) -> ImageBuildJobOut:
    return ImageBuildJobOut(
        id=job.id,
        status=job.status,
        kind=job.kind,
        source_path=job.source_path,
        with_persistence=job.with_persistence,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        returncode=job.returncode,
        log=list(job.log),
    )
