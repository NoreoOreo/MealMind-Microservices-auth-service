from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.models import Permission, User
from app.schemas import PermissionCreate, PermissionOut, PermissionUpdate
from app.security import get_current_user, require_permission

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.get("", response_model=list[PermissionOut])
async def list_permissions(
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:read", current_user=current_user)
    perms = (await session.scalars(select(Permission))).all()
    return perms


@router.post("", response_model=PermissionOut, status_code=status.HTTP_201_CREATED)
async def create_permission(
    payload: PermissionCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:write", current_user=current_user)
    existing = await session.scalar(select(Permission).where(Permission.name == payload.name))
    if existing:
        raise HTTPException(status_code=400, detail="Permission already exists")
    perm = Permission(name=payload.name)
    session.add(perm)
    await session.commit()
    await session.refresh(perm)
    return perm


@router.put("/{permission_id}", response_model=PermissionOut)
async def update_permission(
    permission_id: int,
    payload: PermissionUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:write", current_user=current_user)
    perm = await session.get(Permission, permission_id)
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if payload.name:
        exists = await session.scalar(select(Permission).where(Permission.name == payload.name, Permission.id != permission_id))
        if exists:
            raise HTTPException(status_code=400, detail="Permission name already used")
        perm.name = payload.name
    await session.commit()
    await session.refresh(perm)
    return perm


@router.delete("/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(
    permission_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
):
    await require_permission("auth:write", current_user=current_user)
    perm = await session.get(Permission, permission_id)
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    await session.delete(perm)
    await session.commit()
    return None
