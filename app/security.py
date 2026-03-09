import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session
from app.models import Group, Permission, User
from app.schemas import TokenPayload

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
settings = get_settings()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, groups: list[str]) -> tuple[str, int, str]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    jti = str(uuid.uuid4())
    payload = {"sub": subject, "exp": expire, "jti": jti, "groups": groups, "type": "access"}
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, int(expire.timestamp()), jti


def create_refresh_token(subject: str, groups: list[str]) -> tuple[str, int, str]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.refresh_token_expire_minutes)
    jti = str(uuid.uuid4())
    payload = {"sub": subject, "exp": expire, "jti": jti, "groups": groups, "type": "refresh"}
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, int(expire.timestamp()), jti


def decode_token(token: str, expected_type: str | None = None) -> TokenPayload:
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    token_payload = TokenPayload(**payload)
    if expected_type and token_payload.type != expected_type:
        raise JWTError("Invalid token type")
    return token_payload


async def is_token_blacklisted(jti: str) -> bool:
    return False


async def get_current_user(
        token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_session)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token_data = decode_token(token, expected_type="access")
    except JWTError:
        raise credentials_exception

    user = await session.scalar(select(User).where(User.id == token_data.sub))
    if not user:
        raise credentials_exception

    return user


async def require_permission(permission: str, current_user: User = Depends(get_current_user)) -> User:
    user_permissions = {perm.name for group in current_user.groups for perm in group.permissions}
    if permission not in user_permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    return current_user


async def ensure_group_exists(session: AsyncSession, name: str) -> Group:
    group = await session.scalar(select(Group).where(Group.name == name))
    if group:
        return group
    group = Group(name=name)
    session.add(group)
    await session.flush()
    return group


async def ensure_permission_exists(session: AsyncSession, name: str) -> Permission:
    perm = await session.scalar(select(Permission).where(Permission.name == name))
    if perm:
        return perm
    perm = Permission(name=name)
    session.add(perm)
    await session.flush()
    return perm
