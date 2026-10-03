"""Admin-gated user management API.

All endpoints require ``role=admin``. CRUD targets local_db users —
federated users (ldap/oidc/basic_auth) are provisioned lazily at login,
so password/role mutations here would be meaningless. ``GET /`` lists
every user regardless of backend so the UI can show the full roster.

Safety rails enforced on every mutation:

* The last active admin cannot be deleted, demoted, or deactivated —
  otherwise the install becomes unmanageable without direct DB access.
* An admin cannot delete or deactivate their own row (self-lockout).
  Role, email and password changes to self are allowed.

Every mutation emits an :mod:`app.auth.audit` event so the audit_log
trail covers the full user lifecycle.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import audit
from app.auth.db import get_session
from app.auth.deps import require_role
from app.auth.models import AuthBackend, Role, User
from app.auth.password import hash_password
from app.auth.sessions import revoke_all_for_user

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["users"])


# ── Schemas ──────────────────────────────────────────────────────────

class UserRow(BaseModel):
    id: int
    username: str
    email: str | None = None
    role: str
    backend: str
    is_active: bool
    created_at: str | None = None
    last_login_at: str | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: Role = Role.student
    email: str | None = Field(default=None, max_length=255)


class UserPatch(BaseModel):
    role: Role | None = None
    email: str | None = Field(default=None, max_length=255)
    is_active: bool | None = None


class PasswordReset(BaseModel):
    password: str = Field(min_length=8, max_length=256)


# ── Helpers ──────────────────────────────────────────────────────────

async def _count_active_admins(db: AsyncSession, *, exclude_id: int | None = None) -> int:
    stmt = select(func.count(User.id)).where(
        User.role == Role.admin,
        User.is_active.is_(True),
        User.backend == AuthBackend.local_db,
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return int((await db.execute(stmt)).scalar_one())


async def _assistant_exists(db: AsyncSession, *, exclude_id: int | None = None) -> bool:
    stmt = select(User.id).where(
        User.role == Role.assistant,
        User.backend == AuthBackend.local_db,
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return (await db.execute(stmt.limit(1))).scalar_one_or_none() is not None


async def _ensure_assistant_slot(db: AsyncSession, *, exclude_id: int | None = None) -> None:
    if await _assistant_exists(db, exclude_id=exclude_id):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "an assistant user already exists",
        )


def _row(u: User) -> UserRow:
    return UserRow(
        id=u.id,
        username=u.username,
        email=u.email,
        role=u.role.value,
        backend=u.backend.value,
        is_active=u.is_active,
        created_at=u.created_at.isoformat() if u.created_at else None,
        last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
    )


async def _get_or_404(db: AsyncSession, user_id: int) -> User:
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return u


def _only_local_db(u: User) -> None:
    """Credentials and profile email belong to local_db accounts only."""
    if u.backend != AuthBackend.local_db:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"user {u.username!r} uses backend={u.backend.value}; "
            "managed by the upstream directory.",
        )


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/", response_model=list[UserRow])
async def list_users(
    _admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> list[UserRow]:
    rows = (await db.execute(select(User).order_by(User.username))).scalars().all()
    return [_row(u) for u in rows]


@router.post("/", response_model=UserRow, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> UserRow:
    existing = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    if body.role == Role.assistant:
        await _ensure_assistant_slot(db)

    u = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        backend=AuthBackend.local_db,
        is_active=True,
    )
    db.add(u)
    await db.flush()
    await audit.record(
        db, event="user.create", user=admin, request=request,
        resource=f"user:{u.username}",
        detail={"role": u.role.value, "target_id": u.id},
    )
    await db.commit()
    log.info("user.create by=%s target=%s role=%s", admin.username, u.username, u.role.value)
    return _row(u)


@router.patch("/{user_id}", response_model=UserRow)
async def patch_user(
    user_id: int,
    body: UserPatch,
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> UserRow:
    u = await _get_or_404(db, user_id)

    changes: dict[str, object] = {}
    revoke_sessions = False

    if body.role is not None and body.role != u.role:
        if body.role == Role.assistant:
            await _ensure_assistant_slot(db, exclude_id=u.id)
        # Demoting the last active admin would lock everyone out.
        if u.role == Role.admin and body.role != Role.admin:
            remaining = await _count_active_admins(db, exclude_id=u.id)
            if remaining == 0:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "cannot demote the last active admin",
                )
        changes["role"] = (u.role.value, body.role.value)
        u.role = body.role
        revoke_sessions = True

    # ``None`` clears an email address; model_fields_set distinguishes it from
    # an omitted PATCH field.
    if "email" in body.model_fields_set:
        _only_local_db(u)
        if body.email != u.email:
            changes["email"] = (u.email, body.email)
            u.email = body.email

    if body.is_active is not None and body.is_active != u.is_active:
        if u.id == admin.id and body.is_active is False:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "cannot deactivate yourself",
            )
        if (
            u.role == Role.admin
            and u.is_active is True
            and body.is_active is False
        ):
            remaining = await _count_active_admins(db, exclude_id=u.id)
            if remaining == 0:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "cannot deactivate the last active admin",
                )
        changes["is_active"] = (u.is_active, body.is_active)
        u.is_active = body.is_active
        if body.is_active is False:
            revoke_sessions = True

    if changes:
        revoked = await revoke_all_for_user(db, user_id=u.id) if revoke_sessions else 0
        await db.flush()
        await audit.record(
            db, event="user.update", user=admin, request=request,
            resource=f"user:{u.username}",
            detail={
                "target_id": u.id,
                "changes": {k: list(v) for k, v in changes.items()},
                "sessions_revoked": revoked,
            },
        )
        await db.commit()
        log.info("user.update by=%s target=%s changes=%s",
                 admin.username, u.username, list(changes))
    return _row(u)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    user_id: int,
    body: PasswordReset,
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    u = await _get_or_404(db, user_id)
    _only_local_db(u)
    u.password_hash = hash_password(body.password)
    revoked = await revoke_all_for_user(db, user_id=u.id)
    await db.flush()
    await audit.record(
        db, event="user.password_reset", user=admin, request=request,
        resource=f"user:{u.username}",
        detail={"target_id": u.id, "sessions_revoked": revoked},
    )
    await db.commit()
    log.info("user.password_reset by=%s target=%s", admin.username, u.username)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    request: Request,
    admin: Annotated[User, Depends(require_role(Role.admin))],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    u = await _get_or_404(db, user_id)
    if u.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete yourself")
    if u.role == Role.admin and u.is_active:
        remaining = await _count_active_admins(db, exclude_id=u.id)
        if remaining == 0:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "cannot delete the last active admin",
            )
    username = u.username
    await db.delete(u)
    await audit.record(
        db, event="user.delete", user=admin, request=request,
        resource=f"user:{username}",
        detail={"target_id": user_id, "username": username},
    )
    await db.commit()
    log.info("user.delete by=%s target=%s", admin.username, username)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
