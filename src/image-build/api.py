"""Internal API for dnlab-image-build.

Thin wrapper around build_image.py used by the dockerized GUI transition.
Job state and logs are stored under DNLAB_IMAGE_BUILD_WORKSPACE so operators
can inspect previous build attempts after a service restart.
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import re
import secrets
import shutil
import subprocess
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

import build_image


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "build_image.py"
PATCHES = ROOT / "patches"
LOG_LIMIT = 1200
WORKSPACE = Path(os.getenv("DNLAB_IMAGE_BUILD_WORKSPACE", "/var/lib/dnlab-image-build"))
LOG_ROOT = Path(os.getenv("DNLAB_LOG_ROOT", "/var/log/dnlab"))
VRNETLAB_ROOT = Path(os.getenv("DNLAB_VRNETLAB_DIR", "/opt/vrnetlab"))
JOBS_DIR = WORKSPACE / "jobs"
LOGS_DIR = WORKSPACE / "logs"
UPLOADS_DIR = WORKSPACE / "uploads"


class ImageBuildRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=64)
    source_path: str | None = Field(default=None, max_length=4096)
    with_persistence: bool = False


class ImageFilenameValidationRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=64)
    filename: str = Field(min_length=1, max_length=4096)


@dataclass
class Job:
    id: str
    kind: str
    source_path: str | None
    with_persistence: bool
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: str = "queued"
    returncode: int | None = None
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LIMIT))


app = FastAPI(title="dNLab Image Build API", version="0.1.0")
_jobs: dict[str, Job] = {}
log = logging.getLogger("dnlab_image_build")


@app.on_event("startup")
async def startup() -> None:
    _setup_logging()
    await asyncio.to_thread(_load_jobs)


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/kinds")
async def kinds() -> dict[str, Any]:
    return _kinds_payload()


@app.post("/uploads")
async def upload_image(file: UploadFile = File(...)) -> dict[str, str]:
    _ensure_store()
    filename = _safe_filename(file.filename or "image")
    upload_id = secrets.token_hex(8)
    target_dir = UPLOADS_DIR / upload_id
    target_dir.mkdir(parents=True, exist_ok=False)
    target = target_dir / filename
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


@app.post("/validate-filename")
async def validate_filename(req: ImageFilenameValidationRequest) -> dict[str, Any]:
    filename = _safe_filename(req.filename)
    _validate_image_filename(req.kind, filename)
    return {"ok": True, "kind": req.kind, "filename": filename}


def _validate_image_format(kind: str, source_path: str | None) -> None:
    """Reject a source file whose extension does not match the kind's glob.

    Only applies to vrnetlab kinds (container-native kinds take a remote
    docker image reference, not a local file).
    """
    if kind in build_image.SELF_BUILDING_KINDS:
        if source_path:
            raise HTTPException(400, f"self-building kind '{kind}' does not accept source_path")
        return
    if not source_path:
        raise HTTPException(400, f"kind '{kind}' requires an uploaded source image")
    if kind in build_image.CONTAINER_NATIVE_KINDS:
        return
    # Source must be a previously uploaded file (no arbitrary server paths).
    resolved = Path(source_path).resolve()
    uploads_root = UPLOADS_DIR.resolve()
    if not resolved.is_relative_to(uploads_root):
        raise HTTPException(
            400,
            "source_path must reference an uploaded image "
            f"(under {uploads_root}); got '{source_path}'.",
        )
    if kind in build_image.QCOW_RECIPE_KINDS:
        if Path(source_path).suffix.lower() != ".zip":
            raise HTTPException(400, f"kind '{kind}' requires a .zip release bundle")
        return
    try:
        work_dir = build_image._resolve_vrnetlab_dir(kind, VRNETLAB_ROOT)
    except SystemExit:
        return
    globs = build_image.image_globs_for(work_dir)
    filename = Path(source_path).name
    _validate_image_filename(kind, filename, work_dir=work_dir, globs=globs)


def _validate_image_filename(
    kind: str,
    filename: str,
    *,
    work_dir: Path | None = None,
    globs: list[str] | None = None,
) -> None:
    if kind in build_image.CONTAINER_NATIVE_KINDS:
        return
    if kind in build_image.QCOW_RECIPE_KINDS:
        if not filename.lower().endswith(".qcow2"):
            raise HTTPException(400, f"kind '{kind}' requires a .zip release bundle")
        return
    if work_dir is None:
        try:
            work_dir = build_image._resolve_vrnetlab_dir(kind, VRNETLAB_ROOT)
        except SystemExit:
            return
    globs = globs or build_image.image_globs_for(work_dir)
    examples = _image_examples_for(work_dir, globs)
    if not build_image._matches_image_glob(filename, globs):
        raise HTTPException(400, _image_name_error(kind, filename, globs, examples))

    version = _makefile_version_for(work_dir, filename)
    if version is None:
        return
    if not version or version == filename:
        detail = _image_name_error(kind, filename, globs, examples)
        detail += " The filename also must let the vrnetlab Makefile extract a version."
        raise HTTPException(400, detail)


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
    return build_image._matches_image_glob(concrete, globs)


def _image_name_error(kind: str, filename: str, globs: list[str], examples: list[str]) -> str:
    detail = f"kind '{kind}' expects image filename matching {' '.join(globs)}, but got '{filename}'."
    if examples:
        detail += f" Example: {', '.join(examples)}."
    else:
        detail += " Check IMAGE_GLOB and VERSION in the vrnetlab kind Makefile."
    return detail


@app.post("/jobs")
async def create_job(req: ImageBuildRequest) -> dict[str, Any]:
    if not SCRIPT.exists():
        raise HTTPException(503, f"image-build script not found: {SCRIPT}")
    _validate_image_format(req.kind, req.source_path)
    _ensure_store()
    with_persistence = build_image.is_persistent_kind(req.kind)
    job = Job(
        id=secrets.token_hex(8),
        kind=req.kind,
        source_path=req.source_path,
        with_persistence=with_persistence,
    )
    _jobs[job.id] = job
    _save_job(job)
    asyncio.create_task(_run_job(job))
    return _job_out(job)


@app.post("/jobs/clear")
async def clear_jobs() -> dict[str, int]:
    """Remove finished jobs (and their state/log files); keep active ones."""
    removed = 0
    for job_id, job in list(_jobs.items()):
        if job.status in ("queued", "running"):
            continue
        _jobs.pop(job_id, None)
        _job_state_path(job_id).unlink(missing_ok=True)
        _job_log_path(job_id).unlink(missing_ok=True)
        removed += 1
    return {"removed": removed}


@app.get("/jobs")
async def list_jobs() -> list[dict[str, Any]]:
    return [
        _job_out(job)
        for job in sorted(_jobs.values(), key=lambda item: item.created_at, reverse=True)
    ]


@app.get("/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return _job_out(job)


@app.websocket("/ws/jobs/{job_id}")
async def job_logs(ws: WebSocket, job_id: str) -> None:
    job = _jobs.get(job_id)
    if job is None:
        await ws.close(code=4404)
        return
    await ws.accept()
    sent = 0
    try:
        while True:
            log = list(job.log)
            lines = log[sent:]
            sent = len(log)
            await ws.send_json({
                "status": job.status,
                "lines": lines,
                "returncode": job.returncode,
            })
            if job.status in ("success", "failed"):
                break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return


async def _run_job(job: Job) -> None:
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    _save_job(job)
    cmd = ["python", str(SCRIPT), job.kind]
    if job.source_path:
        cmd.append(job.source_path)
    _append_log(job, "$ " + " ".join(cmd))
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            _append_log(job, raw.decode("utf-8", errors="replace").rstrip())
        job.returncode = await proc.wait()
        job.status = "success" if job.returncode == 0 else "failed"
    except asyncio.CancelledError:
        if proc is not None and proc.returncode is None:
            proc.kill()
        _append_log(job, "cancelled: service shutdown")
        job.status = "failed"
        job.returncode = -1
    except Exception as exc:
        _append_log(job, f"error: {exc}")
        job.status = "failed"
        job.returncode = -1
    finally:
        job.finished_at = datetime.now(timezone.utc)
        _save_job(job)
        _cleanup_uploaded_source(job.source_path)


def _job_out(job: Job) -> dict[str, Any]:
    return {
        "id": job.id,
        "status": job.status,
        "kind": job.kind,
        "source_path": job.source_path,
        "with_persistence": job.with_persistence,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "returncode": job.returncode,
        "log": list(job.log),
    }


def _ensure_store() -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def _cleanup_uploaded_source(source_path: str | None) -> None:
    """Remove only the per-upload directory owned by this service."""
    if not source_path:
        return
    try:
        source = Path(source_path).resolve()
        root = UPLOADS_DIR.resolve()
        if source.is_relative_to(root) and source.parent.parent == root:
            shutil.rmtree(source.parent, ignore_errors=True)
    except OSError:
        log.warning("Could not clean uploaded source %s", source_path, exc_info=True)


def _safe_filename(filename: str) -> str:
    name = Path(filename).name.strip().replace("\x00", "")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "image"


def _kinds_payload() -> dict[str, Any]:
    patchable = build_image.list_patchable_kinds()
    patchable_set = set(patchable)
    vrnetlab_items = build_image.list_vrnetlab_kinds(VRNETLAB_ROOT)
    by_kind: dict[str, dict[str, Any]] = {}
    for item in vrnetlab_items:
        kind = item["kind"]
        vrnetlab_dir = Path(item["vrnetlab_dir"])
        image_globs = build_image.image_globs_for(vrnetlab_dir)
        by_kind[kind] = {
            "kind": kind,
            "patchable": kind in patchable_set,
            "builder": "dnlab-image-build" if kind in patchable_set else "vrnetlab-make",
            "vrnetlab_dir": item["vrnetlab_dir"],
            "image_globs": image_globs,
            "image_examples": _image_examples_for(vrnetlab_dir, image_globs),
            "source_required": kind not in build_image.SELF_BUILDING_KINDS,
        }
    for kind in patchable:
        by_kind.setdefault(kind, {
            "kind": kind,
            "patchable": True,
            "builder": "dnlab-image-build",
            "vrnetlab_dir": None,
            "image_globs": [],
            "image_examples": [],
            "source_required": kind not in build_image.SELF_BUILDING_KINDS,
        })
    for kind in sorted(build_image.QCOW_RECIPE_KINDS):
        by_kind[kind] = {
            "kind": kind,
            "patchable": False,
            "persistent": True,
            "builder": "dnlab-image-build",
            "vrnetlab_dir": None,
            "image_globs": ["*.zip"],
            "image_examples": ["flinos-<release>.zip"],
            "source_required": True,
        }
    kinds = [by_kind[kind] for kind in sorted(by_kind)]
    return {
        "root": str(ROOT),
        "vrnetlab_root": str(VRNETLAB_ROOT),
        "available": SCRIPT.exists(),
        "patchable": patchable,
        "vrnetlab": sorted(item["kind"] for item in vrnetlab_items),
        "kinds": kinds,
    }


def _job_state_path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def _job_log_path(job_id: str) -> Path:
    return LOGS_DIR / f"{job_id}.log"


def _append_log(job: Job, line: str) -> None:
    job.log.append(line)
    _ensure_store()
    with _job_log_path(job.id).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _save_job(job: Job) -> None:
    _ensure_store()
    payload = {
        "id": job.id,
        "kind": job.kind,
        "source_path": job.source_path,
        "with_persistence": job.with_persistence,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "status": job.status,
        "returncode": job.returncode,
        "log_path": str(_job_log_path(job.id)),
    }
    path = _job_state_path(job.id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _load_jobs() -> None:
    _ensure_store()
    _jobs.clear()
    for path in sorted(JOBS_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            job = _job_from_payload(payload)
        except Exception:
            continue
        if job.status in ("queued", "running"):
            job.status = "failed"
            job.returncode = -1
            job.finished_at = datetime.now(timezone.utc)
            _append_log(job, "interrupted: service restarted before job finished")
            _save_job(job)
        _jobs[job.id] = job


def _job_from_payload(payload: dict[str, Any]) -> Job:
    job_id = str(payload["id"])
    job = Job(
        id=job_id,
        kind=str(payload["kind"]),
        source_path=str(payload["source_path"]) if payload.get("source_path") else None,
        with_persistence=bool(payload.get("with_persistence", False)),
        created_at=_parse_dt(payload.get("created_at")) or datetime.now(timezone.utc),
        started_at=_parse_dt(payload.get("started_at")),
        finished_at=_parse_dt(payload.get("finished_at")),
        status=str(payload.get("status") or "failed"),
        returncode=payload.get("returncode"),
    )
    log_path = _job_log_path(job_id)
    if log_path.exists():
        job.log.extend(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-LOG_LIMIT:])
    return job


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _setup_logging() -> None:
    log.setLevel(logging.DEBUG)
    if log.handlers:
        return
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(ch)

    log_dir = LOG_ROOT / "image-build"
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "dnlab-image-build.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    log.addHandler(fh)
    for uv_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logging.getLogger(uv_name).addHandler(fh)
    log.info("Logging initialized -> %s", log_dir / "dnlab-image-build.log")


def main() -> None:
    import uvicorn

    uvicorn.run(
        "api:app",
        host=os.getenv("DNLAB_IMAGE_BUILD_API_HOST", "0.0.0.0"),
        port=int(os.getenv("DNLAB_IMAGE_BUILD_API_PORT", "8082")),
        reload=os.getenv("DNLAB_IMAGE_BUILD_API_RELOAD", "false").lower() == "true",
    )


if __name__ == "__main__":
    main()
