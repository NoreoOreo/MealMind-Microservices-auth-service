from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class OAuthClientCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    is_confidential: bool = True
    grant_types: list[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    redirect_uris: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_client(self) -> "OAuthClientCreate":
        allowed_grants = {"authorization_code", "refresh_token", "client_credentials", "password"}
        invalid = [grant for grant in self.grant_types if grant not in allowed_grants]
        if invalid:
            raise ValueError(f"Unsupported grant_types: {', '.join(invalid)}")

        if "authorization_code" in self.grant_types and not self.redirect_uris:
            raise ValueError("redirect_uris are required for authorization_code grant")

        if not self.scopes:
            raise ValueError("At least one scope must be provided")

        return self


class OpenIDClientCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    is_confidential: bool = True
    grant_types: list[str] | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    redirect_uris: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_client(self) -> "OpenIDClientCreate":
        if not self.grant_types:
            self.grant_types = ["authorization_code", "refresh_token"]

        allowed_grants = {"authorization_code", "refresh_token", "password"}
        invalid = [grant for grant in self.grant_types if grant not in allowed_grants]
        if invalid:
            raise ValueError(f"Unsupported grant_types for OpenID client: {', '.join(invalid)}")

        if "authorization_code" not in self.grant_types:
            raise ValueError("OpenID client must support authorization_code grant")

        if "openid" not in self.scopes:
            raise ValueError("OpenID scope is required for OpenID client")

        if not self.redirect_uris:
            raise ValueError("redirect_uris are required for OpenID client")

        if not self.is_confidential:
            raise ValueError("OpenID client must be confidential (client_id + client_secret)")

        return self


class OAuthClientOut(BaseModel):
    id: str
    name: str
    client_id: str
    is_confidential: bool
    is_active: bool
    grant_types: list[str]
    scopes: list[str]
    redirect_uris: list[str]
    created_at: datetime


class OAuthClientRegisterResponse(OAuthClientOut):
    client_secret: str | None = None


class OAuthAuthorizeRequest(BaseModel):
    response_type: Literal["code"] = "code"
    client_id: str
    redirect_uri: str
    scope: str = ""
    state: str | None = None
    code_challenge: str
    code_challenge_method: Literal["plain", "S256"] = "S256"
    username: str
    password: str
