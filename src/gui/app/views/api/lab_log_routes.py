"""Read-authorized WebSocket for lab-correlated stack log records."""

from __future__ import annotations

import asyncio
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.auth.db import AsyncSessionLocal
from app.auth.deps import authenticate_ws
from app.security import reject_if_bad_origin
from app.services.lab_log_service import LabLogService
from app.services.lab_resolver import resolve_ws

router = APIRouter(tags=["lab-logs"])
_logs = LabLogService()


@router.websocket("/ws/lab-logs/{lab_id}")
async def lab_logs_ws(websocket: WebSocket, lab_id: UUID):
    if await reject_if_bad_origin(websocket):
        return
    user = await authenticate_ws(websocket)
    if user is None:
        await websocket.close(code=4401)
        return
    async with AsyncSessionLocal() as db:
        lab = await resolve_ws(db, lab_id, user)
    if lab is None:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    try:
        await _logs.stream(websocket, lab)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
