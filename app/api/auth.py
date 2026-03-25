from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.oauth import _issue_user_oauth_tokens
from app.database import get_session
from app.models import User
from app.schemas import LoginRequest, RefreshRequest, TokenPair, UserCreate, UserOut
from app.security import decode_token, ensure_group_exists, get_password_hash, verify_password

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, session: AsyncSession = Depends(get_session)):
    existing = await session.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=payload.email, hashed_password=get_password_hash(payload.password))
    for name in payload.groups or ["user"]:
        group = await ensure_group_exists(session, name)
        user.groups.append(group)

    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_session)):
    user: User | None = await session.scalar(select(User).where(User.email == payload.email))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    return TokenPair(**(await _issue_user_oauth_tokens(user, scopes=[])))


@router.post("/refresh", response_model=TokenPair)
async def refresh_tokens(payload: RefreshRequest, session: AsyncSession = Depends(get_session)):
    try:
        token_data = decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if token_data.type != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a refresh token")

    user: User | None = await session.scalar(select(User).where(User.id == token_data.sub))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return TokenPair(**(await _issue_user_oauth_tokens(user, scopes=[])))
