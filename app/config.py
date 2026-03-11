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
    access_token_expire_minutes: int = Field(default=60)
    refresh_token_expire_minutes: int = Field(default=60 * 24 * 7)
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_queue_key: str = Field(default="auth:queue")
    reset_schema_on_start: bool = Field(default=False, description="Drop & recreate DB schema on startup (destructive)")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
