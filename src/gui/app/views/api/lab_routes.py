"""Lab lifecycle API routes.

All lab-scoped endpoints take a ``lab_id: UUID`` path parameter. The
handler resolves the UUID against the ``labs`` table, performs the
read/write authz check (matrix in :mod:`app.auth.labs`), and hands a
:class:`~app.services.lab_resolver.ResolvedLab` to the controller. The
controller never sees a raw string — eliminates any risk of a stale
display-name slipping into the wire layer.

Listing is DB-driven: ``GET /api/labs/`` returns one row for Lab with
the viewer's ``can_write`` flag pre-computed, so the UI knows which
action buttons to disable without a second round trip. A companion
``GET /api/labs/running`` runs the legacy ``clab inspect --all`` for the
home-page "running now" widget — those entries are keyed by netname
which we map back to display name via the DB.
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import audit
from app.auth.db import get_session
from app.auth.deps import get_current_user
from app.auth.labs import can_create_lab, can_write_lab, list_all_labs
from app.auth.models import User
from app.controllers.lab_controller import LabController
from app.models.lifecycle import NodeStopOptions
from app.services.lab_resolver import (
    ResolvedLab, resolve_for_read, resolve_for_write,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/labs", tags=["labs"])
_ctrl = LabController()


class LinkReconcileRequest(BaseModel):
    source: str = Field(min_length=1)
    source_iface: str = Field(min_length=1)
    target: str = Field(min_length=1)
    target_iface: str = Field(min_length=1)


# ── List / create ─────────────────────────────────────────────────

@router.get("/")
async def list_labs(
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    """DB-driven list of every lab the caller can read.

    Everyone reads everything (per the authz matrix) so there's no
    filtering — but each row carries a ``can_write`` boolean so the UI
    can grey out edit/deploy/destroy buttons without a separate probe.
    """
    rows = await list_all_labs(db)
    return [
        {
            "id": str(lab.id),
            "name": lab.name,
            "owner_id": lab.owner_id,
            "owner_username": lab.owner.username if lab.owner else None,
            "can_write": can_write_lab(user, lab, lab.owner),
            "created_at": lab.created_at.isoformat() if lab.created_at else None,
            "updated_at": lab.updated_at.isoformat() if lab.updated_at else None,
        }
        for lab in rows
    ]


@router.get("/running")
async def list_running_labs(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    """Best-effort snapshot of labs with at least one container alive.

    Comes from ``clab inspect --all`` on the master, so it's keyed by
    netname (the ``name:`` field inside the YAML). We map each netname
    back to its Lab row so the UI can show the display name.
    """
    from app.auth.labs import derive_network_name
    from sqlalchemy import select
    from app.auth.models import Lab

    labs = await _ctrl.list_running_labs()
    if not labs:
        return []

    all_labs = (await db.execute(select(Lab))).scalars().all()
    by_netname = {derive_network_name(lb.id): lb for lb in all_labs}

    out = []
    for inspected in labs:
        db_lab = by_netname.get(inspected.name)
        dumped = inspected.model_dump()
        if db_lab is not None:
            dumped["name"] = db_lab.name
            dumped["id"] = str(db_lab.id)
            dumped["orphan"] = False
        else:
            dumped["id"] = None
            dumped["orphan"] = True
        out.append(dumped)
    return out


# ── Per-lab lifecycle ─────────────────────────────────────────────

async def _resolve_write(
    lab_id: UUID,
    db: AsyncSession,
    user: User,
) -> ResolvedLab:
    return await resolve_for_write(db, lab_id, user)


async def _resolve_read(
    lab_id: UUID,
    db: AsyncSession,
    user: User,
) -> ResolvedLab:
    return await resolve_for_read(db, lab_id, user)


@router.get("/{lab_id}/status")
async def lab_status(
    lab_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_read(lab_id, db, user)
    snap = await _ctrl.get_lab_status(lab)
    if snap is None:
        return {
            "id": str(lab.id),
            "name": lab.display_name,
            "status": "stopped",
            "containers": [],
        }
    dumped = snap.model_dump()
    dumped["id"] = str(lab.id)
    return dumped


@router.post("/{lab_id}/deploy")
async def deploy_lab(
    lab_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/deploy (user=%s)", lab_id, user.username)
    result = await _ctrl.deploy(lab)
    await audit.record(
        db, event="lab.deploy", user=user, request=request,
        resource=str(lab.id),
        detail={"display_name": lab.display_name, "success": result.get("success")},
    )
    await db.commit()
    return result


@router.post("/{lab_id}/destroy")
async def destroy_lab(
    lab_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/destroy (user=%s)", lab_id, user.username)
    result = await _ctrl.destroy(lab)
    await audit.record(
        db, event="lab.destroy", user=user, request=request,
        resource=str(lab.id),
        detail={"display_name": lab.display_name, "success": result.get("success")},
    )
    await db.commit()
    return result


@router.post("/{lab_id}/nodes/{node_name}/wipe-disk")
async def wipe_node_disk(
    lab_id: UUID,
    node_name: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info(
        "POST /api/labs/%s/nodes/%s/wipe-disk (user=%s)",
        lab_id, node_name, user.username,
    )
    result = await _ctrl.wipe_node_disk(lab, node_name)
    await audit.record(
        db, event="lab.node_wipe_disk", user=user, request=request,
        resource=str(lab.id),
        detail={
            "display_name": lab.display_name,
            "node": node_name,
            "success": result.get("success"),
            "warnings": result.get("warnings", []),
        },
    )
    await db.commit()
    return result


@router.post("/{lab_id}/nodes/{node_name}/start")
async def start_node(
    lab_id: UUID,
    node_name: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/nodes/%s/start (user=%s)", lab_id, node_name, user.username)
    result = await _ctrl.node_start(lab, node_name)
    await audit.record(
        db, event="lab.node_start", user=user, request=request,
        resource=str(lab.id),
        detail={
            "display_name": lab.display_name,
            "node": node_name,
            "success": result.get("success"),
        },
    )
    await db.commit()
    return result


@router.post("/{lab_id}/nodes/{node_name}/stop")
async def stop_node(
    lab_id: UUID,
    node_name: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
    options: NodeStopOptions | None = None,
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/nodes/%s/stop (user=%s)", lab_id, node_name, user.username)
    force = options.force if options else False
    result = await _ctrl.node_stop(lab, node_name, force=force)
    await audit.record(
        db, event="lab.node_stop", user=user, request=request,
        resource=str(lab.id),
        detail={
            "display_name": lab.display_name,
            "node": node_name,
            "force": force,
            "success": result.get("success"),
        },
    )
    await db.commit()
    return result


@router.post("/{lab_id}/nodes/{node_name}/reconcile")
async def reconcile_node(
    lab_id: UUID,
    node_name: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/nodes/%s/reconcile (user=%s)", lab_id, node_name, user.username)
    result = await _ctrl.node_reconcile(lab, node_name)
    await audit.record(
        db, event="lab.node_reconcile", user=user, request=request,
        resource=str(lab.id),
        detail={
            "display_name": lab.display_name,
            "node": node_name,
            "success": result.get("success"),
        },
    )
    await db.commit()
    return result


@router.post("/{lab_id}/links/reconcile")
async def reconcile_link(
    lab_id: UUID,
    payload: LinkReconcileRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    link = payload.model_dump()
    result = await _ctrl.link_reconcile(lab, link)
    await audit.record(
        db, event="lab.link_reconcile", user=user, request=request,
        resource=str(lab.id),
        detail={"display_name": lab.display_name, **link, "success": result.get("success")},
    )
    await db.commit()
    return result


@router.post("/{lab_id}/nodes/{node_name}/restart")
async def restart_node(
    lab_id: UUID,
    node_name: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/nodes/%s/restart (user=%s)", lab_id, node_name, user.username)
    result = await _ctrl.node_restart(lab, node_name)
    await audit.record(
        db, event="lab.node_restart", user=user, request=request,
        resource=str(lab.id),
        detail={
            "display_name": lab.display_name,
            "node": node_name,
            "success": result.get("success"),
        },
    )
    await db.commit()
    return result


@router.post("/{lab_id}/realnet/{realnet_name}/reconcile")
async def reconcile_realnet(
    lab_id: UUID,
    realnet_name: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await _resolve_write(lab_id, db, user)
    log.info("POST /api/labs/%s/realnet/%s/reconcile (user=%s)", lab_id, realnet_name, user.username)
    result = await _ctrl.realnet_reconcile(lab, realnet_name)
    await audit.record(
        db, event="lab.realnet_reconcile", user=user, request=request,
        resource=str(lab.id),
        detail={
            "display_name": lab.display_name,
            "realnet": realnet_name,
            "success": result.get("success"),
        },
    )
    await db.commit()
    return result


@router.delete("/{lab_id}")
async def delete_lab(
    lab_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Full delete: destroy if running → clean persist → drop YAML → drop row."""
    lab = await _resolve_write(lab_id, db, user)
    log.info("DELETE /api/labs/%s (user=%s)", lab_id, user.username)
    result = await _ctrl.delete_lab(lab)
    if result.get("success"):
        # Drop the DB row last, only after on-disk state is gone — an
        # orphan YAML with no DB row is recoverable (backfill), but an
        # orphan row with no YAML creates a 404 that can't be deleted
        # through the API.
        from sqlalchemy import delete
        from app.auth.models import Lab
        await db.execute(delete(Lab).where(Lab.id == lab.id))
        await audit.record(
            db, event="lab.delete", user=user, request=request,
            resource=str(lab.id),
            detail={"display_name": lab.display_name},
        )
        await db.commit()
    return result
