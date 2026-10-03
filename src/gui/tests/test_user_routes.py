"""Focused unit tests for admin user mutations."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.auth.models import AuthBackend, Role, User
from app.views.api import user_routes


class _Db:
    def __init__(self, user: User):
        self.user = user
        self.committed = False

    async def get(self, _model, _user_id: int):
        return self.user

    async def flush(self):
        return None

    async def commit(self):
        self.committed = True


def _user(*, backend: AuthBackend = AuthBackend.local_db, **fields) -> User:
    values = {
        "id": 7,
        "username": "target",
        "email": "target@example.test",
        "role": Role.student,
        "backend": backend,
        "is_active": True,
        "password_hash": "old-hash",
    }
    values.update(fields)
    return User(**values)


async def _no_audit(*_args, **_kwargs) -> None:
    return None


def test_patch_can_clear_local_email(monkeypatch) -> None:
    target = _user()
    db = _Db(target)
    monkeypatch.setattr(user_routes.audit, "record", _no_audit)

    async def run() -> None:
        result = await user_routes.patch_user(
            target.id,
            user_routes.UserPatch(email=None),
            SimpleNamespace(),
            _user(id=1, username="admin", role=Role.admin),
            db,
        )
        assert result.email is None
        assert target.email is None
        assert db.committed

    asyncio.run(run())


def test_patch_rejects_federated_email(monkeypatch) -> None:
    target = _user(backend=AuthBackend.ldap)
    monkeypatch.setattr(user_routes.audit, "record", _no_audit)

    async def run() -> None:
        with pytest.raises(HTTPException, match="managed by the upstream directory") as exc:
            await user_routes.patch_user(
                target.id,
                user_routes.UserPatch(email="new@example.test"),
                SimpleNamespace(),
                _user(id=1, username="admin", role=Role.admin),
                _Db(target),
            )
        assert exc.value.status_code == 400

    asyncio.run(run())


def test_role_change_revokes_sessions(monkeypatch) -> None:
    target = _user()
    db = _Db(target)
    revoked: list[int] = []
    monkeypatch.setattr(user_routes.audit, "record", _no_audit)

    async def revoke(_db, *, user_id: int) -> int:
        revoked.append(user_id)
        return 2

    monkeypatch.setattr(user_routes, "revoke_all_for_user", revoke)

    async def run() -> None:
        await user_routes.patch_user(
            target.id,
            user_routes.UserPatch(role=Role.graduate),
            SimpleNamespace(),
            _user(id=1, username="admin", role=Role.admin),
            db,
        )

    asyncio.run(run())
    assert target.role == Role.graduate
    assert revoked == [target.id]


def test_deactivation_revokes_sessions(monkeypatch) -> None:
    target = _user()
    db = _Db(target)
    revoked: list[int] = []
    monkeypatch.setattr(user_routes.audit, "record", _no_audit)

    async def revoke(_db, *, user_id: int) -> int:
        revoked.append(user_id)
        return 1

    monkeypatch.setattr(user_routes, "revoke_all_for_user", revoke)

    async def run() -> None:
        await user_routes.patch_user(
            target.id,
            user_routes.UserPatch(is_active=False),
            SimpleNamespace(),
            _user(id=1, username="admin", role=Role.admin),
            db,
        )

    asyncio.run(run())
    assert target.is_active is False
    assert revoked == [target.id]


def test_password_reset_revokes_sessions(monkeypatch) -> None:
    target = _user()
    db = _Db(target)
    revoked: list[int] = []
    monkeypatch.setattr(user_routes.audit, "record", _no_audit)
    monkeypatch.setattr(user_routes, "hash_password", lambda _password: "new-hash")

    async def revoke(_db, *, user_id: int) -> int:
        revoked.append(user_id)
        return 1

    monkeypatch.setattr(user_routes, "revoke_all_for_user", revoke)

    async def run() -> None:
        response = await user_routes.reset_password(
            target.id,
            user_routes.PasswordReset(password="long-enough"),
            SimpleNamespace(),
            _user(id=1, username="admin", role=Role.admin),
            db,
        )
        assert response.status_code == 204

    asyncio.run(run())
    assert target.password_hash == "new-hash"
    assert revoked == [target.id]
