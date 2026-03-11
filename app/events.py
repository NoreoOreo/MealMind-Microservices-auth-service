import asyncio
import contextlib
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select, delete, insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import selectinload

from app.database import AsyncSessionLocal, init_db
from app.models import Group, Permission, User, group_permissions
from app.redis_client import close_redis
from app.security import ensure_group_exists, get_password_hash
from app.worker import consume_queue


@asynccontextmanager
async def lifespan(app: FastAPI):
    consume_task = None
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_defaults(session)
        await session.commit()
    consume_task = asyncio.create_task(consume_queue())
    try:
        yield
    finally:
        if consume_task:
            consume_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await consume_task
        await close_redis()


async def seed_defaults(session: AsyncSession) -> None:
    """Seed permissions, groups, and service users (idempotent, no drop/recreate)."""
    perms = [
        "auth:read",
        "auth:write",
        "auth:queue",
        "profile:get",
        "profile:write",
        "profile:queue",
        "meal:get",
        "meal:write",
        "meal:queue",
        "ai:queue",
    ]
    existing = {p.name for p in (await session.scalars(select(Permission).where(Permission.name.in_(perms)))).all()}
    for name in perms:
        if name not in existing:
            session.add(Permission(name=name))
    await session.flush()

    perm_map = {p.name: p for p in (await session.scalars(select(Permission))).all()}

    # Ensure groups
    group_names = ["user", "admin", "microserves"]
    groups: dict[str, Group] = {}
    for name in group_names:
        grp = await session.scalar(
            select(Group).options(selectinload(Group.permissions)).where(Group.name == name)
        )
        if not grp:
            grp = await ensure_group_exists(session, name)
        groups[name] = grp

    # Assign permissions
    groups_permissions = {
        "admin": perms,
        "user": ["profile:read", "profile:write", "meal:read", "meal:write"],
        "microserves": ["profile:queue", "meal:queue", "ai:queue"],
    }
    for group_name, perm_names in groups_permissions.items():
        grp = groups[group_name]
        # wipe existing links to avoid lazy loads during assignment
        await session.execute(delete(group_permissions).where(group_permissions.c.group_id == grp.id))
        rows = [
            {"group_id": grp.id, "permission_id": perm_map[name].id}
            for name in perm_names
            if name in perm_map
        ]
        if rows:
            await session.execute(insert(group_permissions), rows)

    # Service users
    service_users = [
        ("profile@admin.com", os.getenv("PROFILE_ADMIN_PASSWORD", "changeme")),
        ("meal@admin.com", os.getenv("MEAL_ADMIN_PASSWORD", "changeme")),
        ("ai@admin.com", os.getenv("AI_ADMIN_PASSWORD", "changeme")),
    ]
    admin_group = groups["admin"]
    micro_group = groups["microserves"]
    for email, password in service_users:
        user = await session.scalar(select(User).where(User.email == email))
        if user:
            continue
        user = User(email=email, hashed_password=get_password_hash(password))
        user.groups.extend([admin_group, micro_group])
        session.add(user)
