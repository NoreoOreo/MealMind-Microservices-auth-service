import base64
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session
from app.models import Group, Permission, User
from app.schemas import TokenPayload

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/oauth/token")
settings = get_settings()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def _normalize_pem(value: str | None) -> str | None:
    if not value:
        return None
    return value.replace("\\n", "\n")


def _encode_signing_key() -> str:
    if settings.jwt_algorithm.startswith("RS"):
        private_key = _normalize_pem(settings.jwt_private_key)
        if not private_key:
            raise JWTError("JWT_PRIVATE_KEY is required for RS* algorithms")
        return private_key
    return settings.jwt_secret_key


def _decode_signing_key() -> str:
    if settings.jwt_algorithm.startswith("RS"):
        public_key = _normalize_pem(settings.jwt_public_key)
        if not public_key:
            raise JWTError("JWT_PUBLIC_KEY is required for RS* algorithms")
        return public_key
    return settings.jwt_secret_key


def _with_common_claims(payload: dict) -> dict:
    if settings.auth_issuer:
        payload["iss"] = settings.auth_issuer
    if settings.auth_audience:
        payload["aud"] = settings.auth_audience
    return payload


def create_access_token(subject: str, groups: list[str], scopes: list[str] | None = None) -> tuple[str, int, str]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    jti = str(uuid.uuid4())
    payload = _with_common_claims(
        {
            "sub": subject,
            "exp": expire,
            "jti": jti,
            "groups": groups,
            "type": "access",
            "scope": " ".join(scopes or []),
        }
    )
    token = jwt.encode(payload, _encode_signing_key(), algorithm=settings.jwt_algorithm, headers={"kid": settings.jwt_key_id})
    return token, int(expire.timestamp()), jti


def create_refresh_token(subject: str, groups: list[str]) -> tuple[str, int, str]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.refresh_token_expire_minutes)
    jti = str(uuid.uuid4())
    payload = _with_common_claims({"sub": subject, "exp": expire, "jti": jti, "groups": groups, "type": "refresh"})
    token = jwt.encode(payload, _encode_signing_key(), algorithm=settings.jwt_algorithm, headers={"kid": settings.jwt_key_id})
    return token, int(expire.timestamp()), jti


def decode_token(token: str, expected_type: str | None = None) -> TokenPayload:
    decode_kwargs = {}
    if settings.auth_issuer:
        decode_kwargs["issuer"] = settings.auth_issuer
    if settings.auth_audience:
        decode_kwargs["audience"] = settings.auth_audience

    payload = jwt.decode(token, _decode_signing_key(), algorithms=[settings.jwt_algorithm], **decode_kwargs)
    token_payload = TokenPayload(**payload)
    if expected_type and token_payload.type != expected_type:
        raise JWTError("Invalid token type")
    return token_payload


def create_id_token(subject: str, email: str, groups: list[str], nonce: str | None = None) -> tuple[str, int, str]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = _with_common_claims(
        {
            "sub": subject,
            "exp": expire,
            "iat": int(now.timestamp()),
            "jti": jti,
            "type": "id",
            "email": email,
            "email_verified": True,
            "groups": groups,
        }
    )
    if nonce:
        payload["nonce"] = nonce
    token = jwt.encode(payload, _encode_signing_key(), algorithm=settings.jwt_algorithm, headers={"kid": settings.jwt_key_id})
    return token, int(expire.timestamp()), jti


def get_oidc_status() -> tuple[bool, str | None]:
    if not settings.oidc_enabled:
        return False, "OIDC is disabled (OIDC_ENABLED=false)."
    if not settings.jwt_algorithm.startswith("RS"):
        return False, "OIDC requires RS* signing (configure JWT_ALGORITHM=RS256 with public/private keys)."
    if not _normalize_pem(settings.jwt_private_key) or not _normalize_pem(settings.jwt_public_key):
        return False, "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured for OIDC."
    if not settings.auth_issuer:
        return False, "AUTH_ISSUER must be configured for OIDC."
    if not settings.auth_audience:
        return False, "AUTH_AUDIENCE must be configured for OIDC."
    return True, None


def _to_base64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).rstrip(b"=").decode("ascii")


def get_jwks() -> dict:
    enabled, reason = get_oidc_status()
    if not enabled:
        raise JWTError(reason or "OIDC is not available")

    public_key = _normalize_pem(settings.jwt_public_key)
    key = serialization.load_pem_public_key(public_key.encode("utf-8"))
    if not isinstance(key, RSAPublicKey):
        raise JWTError("Configured JWT_PUBLIC_KEY is not an RSA public key")

    numbers = key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": settings.jwt_algorithm,
                "kid": settings.jwt_key_id,
                "n": _to_base64url_uint(numbers.n),
                "e": _to_base64url_uint(numbers.e),
            }
        ]
    }


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
