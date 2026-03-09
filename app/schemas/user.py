from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, model_validator

from .group import GroupOut


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128, description="Repeat password for confirmation")
    groups: Optional[List[str]] = Field(default=None, description="List of group names to assign")

    @model_validator(mode="after")
    def validate_passwords(self) -> "UserCreate":
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class UserOut(UserBase):
    id: str
    is_active: bool
    created_at: datetime
    groups: List[GroupOut] = []

    class Config:
        from_attributes = True


class TokenPair(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    refresh_expires_in: int


class TokenPayload(BaseModel):
    sub: str
    jti: str
    exp: int
    groups: List[str] = []
    type: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str
