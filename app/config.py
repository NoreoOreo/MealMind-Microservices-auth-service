from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = Field(
        default="postgresql+asyncpg://auth:auth@db:5432/auth",
        description="SQLAlchemy database URL"
    )
    jwt_secret_key: str = Field(default="change-me", description="HS256 secret")
    jwt_algorithm: str = Field(default="HS256")
    jwt_private_key: str | None = Field(default=None, description="PEM private key for RS* algorithms")
    jwt_public_key: str | None = Field(default=None, description="PEM public key for RS* algorithms")
    jwt_key_id: str = Field(default="mealmind-auth-key-1", description="JWK key id for OIDC")
    access_token_expire_minutes: int = Field(default=60)
    refresh_token_expire_minutes: int = Field(default=60 * 24 * 7)
    auth_issuer: str = Field(default="http://localhost:8000", description="OAuth2/OIDC issuer URL")
    auth_audience: str | None = Field(default=None, description="Expected JWT audience")
    oidc_enabled: bool = Field(default=False, description="Enable OpenID Connect metadata/userinfo endpoints")
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_queue_key: str = Field(default="auth:queue")
    reset_schema_on_start: bool = Field(default=False, description="Drop & recreate DB schema on startup (destructive)")
    github_oauth_enabled: bool = Field(default=True, description="Enable GitHub OAuth2 login/registration")
    github_client_id: str | None = Field(default=None)
    github_client_secret: str | None = Field(default=None)
    github_redirect_uri: str | None = Field(default=None, description="OAuth callback URL registered in GitHub app")
    github_scope: str = Field(default="read:user user:email")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
