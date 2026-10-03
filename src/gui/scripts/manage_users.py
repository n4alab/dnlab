#!/usr/bin/env python3
"""CLI user management for the local_db auth backend.

Every invocation authenticates as an admin first — the operator must
prove they hold an admin credential before touching the users table.
If no admin exists yet, the script refuses to run and points at
``scripts/seed_admin.py`` which is the only supported bootstrap path.

Typical flows::

    # Interactive: prompts for admin creds, then executes the subcommand.
    ./venv/bin/python scripts/manage_users.py list
    ./venv/bin/python scripts/manage_users.py add --username alice --role student
    ./venv/bin/python scripts/manage_users.py set-role --username alice --role graduate
    ./venv/bin/python scripts/manage_users.py set-email --username alice --email alice@example.test
    ./venv/bin/python scripts/manage_users.py set-password --username alice
    ./venv/bin/python scripts/manage_users.py disable --username alice
    ./venv/bin/python scripts/manage_users.py enable  --username alice
    ./venv/bin/python scripts/manage_users.py delete  --username alice

    # Non-interactive: admin creds from --as-admin + DNLABGUI_ADMIN_PASSWORD env.
    DNLABGUI_ADMIN_PASSWORD=... ./venv/bin/python scripts/manage_users.py \
        --as-admin root list

Safety rails (mirror the HTTP API):

* The last active admin cannot be deleted, demoted, or deactivated.
* Only one local_db user can have role ``assistant``.
* You cannot delete or deactivate the admin you authenticated as.
* Password/role changes target only ``backend=local_db`` users —
  federated users are managed by their upstream directory.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select  # noqa: E402

from app.auth.db import AsyncSessionLocal  # noqa: E402
from app.auth.models import AuthBackend, Role, User  # noqa: E402
from app.auth.password import hash_password, verify_password  # noqa: E402
from app.auth.sessions import revoke_all_for_user  # noqa: E402
from app.config import settings  # noqa: E402


# ── Exit codes ───────────────────────────────────────────────────────
# 0 success, 2 bootstrap required, 3 auth failure, 4 validation error,
# 5 conflict (dup username, safety rail), 6 not found.


# ── Helpers ──────────────────────────────────────────────────────────

def _fatal(msg: str, code: int = 4) -> None:
    print(f"[manage-users] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def _info(msg: str) -> None:
    print(f"[manage-users] {msg}")


async def _count_active_admins(db, *, exclude_id: int | None = None) -> int:
    stmt = select(func.count(User.id)).where(
        User.role == Role.admin,
        User.is_active.is_(True),
        User.backend == AuthBackend.local_db,
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return int((await db.execute(stmt)).scalar_one())


async def _assistant_exists(db, *, exclude_id: int | None = None) -> bool:
    stmt = select(User.id).where(
        User.role == Role.assistant,
        User.backend == AuthBackend.local_db,
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return (await db.execute(stmt.limit(1))).scalar_one_or_none() is not None


async def _ensure_assistant_slot(db, *, exclude_id: int | None = None) -> None:
    if await _assistant_exists(db, exclude_id=exclude_id):
        _fatal("an assistant user already exists", code=5)


async def _get_user(db, username: str) -> User | None:
    return (
        await db.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()


async def _authenticate_admin(db, username: str, password: str) -> User:
    u = await _get_user(db, username)
    if (
        u is None
        or u.backend != AuthBackend.local_db
        or not u.is_active
        or u.role != Role.admin
        or not u.password_hash
        or not verify_password(u.password_hash, password)
    ):
        _fatal(f"admin authentication failed for user {username!r}", code=3)
    return u  # type: ignore[return-value]


async def _ensure_admin_bootstrap(db) -> None:
    """Abort with a hint toward seed_admin.py when no admin exists yet."""
    n = await _count_active_admins(db)
    if n == 0:
        print(
            "[manage-users] no active admin exists in the local_db backend.\n"
            "               bootstrap one first with:\n"
            "                   ./venv/bin/python scripts/seed_admin.py",
            file=sys.stderr,
        )
        sys.exit(2)


def _require_local_db_backend() -> None:
    if settings.AUTH_BACKEND != "local_db":
        _fatal(
            f"AUTH_BACKEND={settings.AUTH_BACKEND}; user management only "
            "applies to the local_db backend.",
            code=4,
        )


def _prompt_password(prompt: str = "password") -> str:
    while True:
        p1 = getpass.getpass(f"  {prompt}: ")
        p2 = getpass.getpass(f"  confirm : ")
        if p1 and p1 == p2:
            if len(p1) < 8:
                print("  password too short (min 8 chars), try again.")
                continue
            return p1
        print("  empty or mismatch, try again.")


def _fmt_role(role: Role) -> str:
    return role.value


def _parse_role(value: str) -> Role:
    try:
        return Role(value)
    except ValueError:
        _fatal(f"invalid role {value!r}; one of: "
               f"{', '.join(r.value for r in Role)}", code=4)


# ── Subcommands ──────────────────────────────────────────────────────

async def cmd_list(db, _admin: User, _args) -> int:
    rows = (await db.execute(select(User).order_by(User.username))).scalars().all()
    if not rows:
        _info("no users.")
        return 0
    # Fixed-width plaintext table. Tight enough to read in a terminal.
    print(f"{'id':>4}  {'username':<24} {'role':<9} {'backend':<11} "
          f"{'active':<7} last_login")
    for u in rows:
        last = u.last_login_at.isoformat(timespec='seconds') if u.last_login_at else '-'
        print(f"{u.id:>4}  {u.username:<24} {_fmt_role(u.role):<9} "
              f"{u.backend.value:<11} {('yes' if u.is_active else 'no'):<7} {last}")
    return 0


async def cmd_add(db, admin: User, args) -> int:
    if await _get_user(db, args.username) is not None:
        _fatal(f"user {args.username!r} already exists", code=5)
    role = _parse_role(args.role)
    if role == Role.assistant:
        await _ensure_assistant_slot(db)
    password = args.password or os.environ.get("DNLABGUI_USER_PASSWORD")
    if not password:
        if not sys.stdin.isatty():
            _fatal("no TTY and no --password / DNLABGUI_USER_PASSWORD given", code=4)
        password = _prompt_password()
    if len(password) < 8:
        _fatal("password too short (min 8 chars)", code=4)
    u = User(
        username=args.username,
        email=args.email,
        password_hash=hash_password(password),
        role=role,
        backend=AuthBackend.local_db,
        is_active=True,
    )
    db.add(u)
    await db.commit()
    _info(f"created user {args.username!r} role={role.value} by={admin.username}")
    return 0


async def cmd_set_role(db, admin: User, args) -> int:
    u = await _get_user(db, args.username)
    if u is None:
        _fatal(f"user {args.username!r} not found", code=6)
    new_role = _parse_role(args.role)
    if u.role == new_role:
        _info(f"{u.username} already has role={new_role.value}, no change.")
        return 0
    if new_role == Role.assistant:
        await _ensure_assistant_slot(db, exclude_id=u.id)
    if u.role == Role.admin and new_role != Role.admin:
        remaining = await _count_active_admins(db, exclude_id=u.id)
        if remaining == 0:
            _fatal("cannot demote the last active admin", code=5)
    old = u.role
    u.role = new_role
    await revoke_all_for_user(db, user_id=u.id)
    await db.commit()
    _info(f"{u.username}: role {old.value} → {new_role.value} by={admin.username}")
    return 0


async def cmd_set_email(db, admin: User, args) -> int:
    u = await _get_user(db, args.username)
    if u is None:
        _fatal(f"user {args.username!r} not found", code=6)
    if u.backend != AuthBackend.local_db:
        _fatal(
            f"user {u.username!r} backend={u.backend.value}; email "
            "managed by upstream directory",
            code=4,
        )
    email = args.email.strip() or None
    if u.email == email:
        _info(f"{u.username}: email unchanged.")
        return 0
    u.email = email
    await db.commit()
    _info(f"{u.username}: email {'cleared' if email is None else 'updated'} by={admin.username}")
    return 0


async def cmd_set_password(db, admin: User, args) -> int:
    u = await _get_user(db, args.username)
    if u is None:
        _fatal(f"user {args.username!r} not found", code=6)
    if u.backend != AuthBackend.local_db:
        _fatal(
            f"user {u.username!r} backend={u.backend.value}; password "
            "managed by upstream directory",
            code=4,
        )
    password = args.password or os.environ.get("DNLABGUI_USER_PASSWORD")
    if not password:
        if not sys.stdin.isatty():
            _fatal("no TTY and no --password / DNLABGUI_USER_PASSWORD given", code=4)
        password = _prompt_password("new password")
    if len(password) < 8:
        _fatal("password too short (min 8 chars)", code=4)
    u.password_hash = hash_password(password)
    await revoke_all_for_user(db, user_id=u.id)
    await db.commit()
    _info(f"{u.username}: password reset by={admin.username}")
    return 0


async def _set_active(db, admin: User, username: str, active: bool) -> int:
    u = await _get_user(db, username)
    if u is None:
        _fatal(f"user {username!r} not found", code=6)
    if u.is_active == active:
        _info(f"{u.username}: already {'enabled' if active else 'disabled'}.")
        return 0
    if not active:
        if u.id == admin.id:
            _fatal("cannot disable the admin you are authenticated as", code=5)
        if u.role == Role.admin:
            remaining = await _count_active_admins(db, exclude_id=u.id)
            if remaining == 0:
                _fatal("cannot disable the last active admin", code=5)
    u.is_active = active
    if not active:
        await revoke_all_for_user(db, user_id=u.id)
    await db.commit()
    _info(f"{u.username}: {'enabled' if active else 'disabled'} by={admin.username}")
    return 0


async def cmd_enable(db, admin: User, args) -> int:
    return await _set_active(db, admin, args.username, True)


async def cmd_disable(db, admin: User, args) -> int:
    return await _set_active(db, admin, args.username, False)


async def cmd_delete(db, admin: User, args) -> int:
    u = await _get_user(db, args.username)
    if u is None:
        _fatal(f"user {args.username!r} not found", code=6)
    if u.id == admin.id:
        _fatal("cannot delete the admin you are authenticated as", code=5)
    if u.role == Role.admin and u.is_active:
        remaining = await _count_active_admins(db, exclude_id=u.id)
        if remaining == 0:
            _fatal("cannot delete the last active admin", code=5)
    if not args.yes:
        if not sys.stdin.isatty():
            _fatal("refusing to delete non-interactively without --yes", code=4)
        reply = input(f"  delete user {u.username!r} (id={u.id})? [y/N] ").strip().lower()
        if reply != "y":
            _info("aborted.")
            return 0
    username = u.username
    await db.delete(u)
    await db.commit()
    _info(f"deleted user {username!r} by={admin.username}")
    return 0


# ── Entry point ──────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--as-admin",
        help="admin username to authenticate as (default: prompt interactively)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list all users")

    pa = sub.add_parser("add", help="create a new local_db user")
    pa.add_argument("--username", required=True)
    pa.add_argument("--role", default=Role.student.value,
                    help=f"one of: {', '.join(r.value for r in Role)} (default: student)")
    pa.add_argument("--email")
    pa.add_argument("--password", help="new password (else prompt / env)")

    pr = sub.add_parser("set-role", help="change a user's role")
    pr.add_argument("--username", required=True)
    pr.add_argument("--role", required=True)

    pe = sub.add_parser("set-email", help="change or clear a local user's email")
    pe.add_argument("--username", required=True)
    pe.add_argument("--email", required=True, help="empty string clears the email")

    pp = sub.add_parser("set-password", help="reset a user's password")
    pp.add_argument("--username", required=True)
    pp.add_argument("--password", help="new password (else prompt / env)")

    pe = sub.add_parser("enable", help="activate a user")
    pe.add_argument("--username", required=True)

    pd = sub.add_parser("disable", help="deactivate a user")
    pd.add_argument("--username", required=True)

    px = sub.add_parser("delete", help="delete a user")
    px.add_argument("--username", required=True)
    px.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation")

    return p


_DISPATCH = {
    "list": cmd_list,
    "add": cmd_add,
    "set-role": cmd_set_role,
    "set-email": cmd_set_email,
    "set-password": cmd_set_password,
    "enable": cmd_enable,
    "disable": cmd_disable,
    "delete": cmd_delete,
}


async def _run(args) -> int:
    _require_local_db_backend()
    async with AsyncSessionLocal() as db:
        await _ensure_admin_bootstrap(db)

        admin_user = args.as_admin
        admin_pw = os.environ.get("DNLABGUI_ADMIN_PASSWORD")
        if admin_user is None:
            if not sys.stdin.isatty():
                _fatal("no TTY and no --as-admin given", code=4)
            admin_user = input("admin username: ").strip()
            if not admin_user:
                _fatal("admin username cannot be empty", code=4)
        if admin_pw is None:
            if not sys.stdin.isatty():
                _fatal(
                    "non-interactive run requires DNLABGUI_ADMIN_PASSWORD env",
                    code=4,
                )
            admin_pw = getpass.getpass(f"password for {admin_user}: ")

        admin = await _authenticate_admin(db, admin_user, admin_pw)
        return await _DISPATCH[args.cmd](db, admin, args)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
