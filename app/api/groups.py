from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_session
from app.models import Group, User
from app.schemas import GroupCreate, GroupOut, GroupUpdate
from app.security import ensure_permission_exists, get_current_user, require_permission

router = APIRouter(prefix="/groups", tags=["groups"])


async def set_group_permissions(session: AsyncSession, group: Group, permissions: list[str] | None) -> None:
    if permissions is None:
        return
    group.permissions.clear()
    for name in permissions:
        perm = await ensure_permission_exists(session, name)
        group.permissions.append(perm)


@router.get("", response_model=list[GroupOut])
async def list_groups(
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:read", current_user=current_user)
    groups = (await session.scalars(select(Group).options(selectinload(Group.permissions)))).all()
    return groups


@router.post("", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: GroupCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:write", current_user=current_user)
    existing = await session.scalar(select(Group).where(Group.name == payload.name))
    if existing:
        raise HTTPException(status_code=400, detail="Group already exists")
    group = Group(name=payload.name)
    session.add(group)
    await set_group_permissions(session, group, payload.permissions)
    await session.commit()
    await session.refresh(group)
    return group


@router.put("/{group_id}", response_model=GroupOut)
async def update_group(
    group_id: int,
    payload: GroupUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:write", current_user=current_user)
    group: Group | None = await session.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if payload.name:
        exists = await session.scalar(select(Group).where(Group.name == payload.name, Group.id != group_id))
        if exists:
            raise HTTPException(status_code=400, detail="Group name already used")
        group.name = payload.name
    if payload.permissions is not None:
        await set_group_permissions(session, group, payload.permissions)
    await session.commit()
    await session.refresh(group)
    return group


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:write", current_user=current_user)
    group = await session.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    await session.delete(group)
    await session.commit()
    return None
