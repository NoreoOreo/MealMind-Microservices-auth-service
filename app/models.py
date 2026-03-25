import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", String(36), ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)

group_permissions = Table(
    "group_permissions",
    Base.metadata,
    Column("group_id", String(36), ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", String(36), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    groups: Mapped[list["Group"]] = relationship(
        "Group", secondary=user_groups, back_populates="users", lazy="selectin"
    )


class Group(Base):
    __tablename__ = "groups"
    __table_args__ = (UniqueConstraint("name", name="uq_groups_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    users: Mapped[list[User]] = relationship(
        "User", secondary=user_groups, back_populates="groups", lazy="selectin"
    )
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission", secondary=group_permissions, back_populates="groups", lazy="selectin"
    )


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("name", name="uq_permissions_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    groups: Mapped[list[Group]] = relationship(
        "Group", secondary=group_permissions, back_populates="permissions", lazy="selectin"
    )


class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    __table_args__ = (UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    client_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    client_secret_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    grant_types: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    authorization_codes: Mapped[list["OAuthAuthorizationCode"]] = relationship(
        "OAuthAuthorizationCode", back_populates="client", lazy="selectin"
    )


class OAuthAuthorizationCode(Base):
    __tablename__ = "oauth_authorization_codes"
    __table_args__ = (UniqueConstraint("code", name="uq_oauth_authorization_codes_code"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    code: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    code_challenge: Mapped[str] = mapped_column(String(255), nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(String(16), nullable=False, default="S256")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    client: Mapped[OAuthClient] = relationship("OAuthClient", back_populates="authorization_codes", lazy="selectin")
    user: Mapped[User] = relationship("User", lazy="selectin")
