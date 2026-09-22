"""Application configuration management using pydantic-settings."""

from functools import lru_cache
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration settings for CodeSentinel Backend."""

    # Application Info
    APP_NAME: str = "CodeSentinel API"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server Configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS Settings
    ALLOWED_ORIGINS: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # Database Configuration (Phase 10 Persistent Storage)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://codesentinel:codesentinel@localhost:5432/codesentinel",
        description="Database connection string (PostgreSQL production / aiosqlite for tests)",
    )
    DATABASE_ECHO: bool = Field(
        default=False,
        description="Enable SQLAlchemy query echo logging for debugging",
    )

    # Redis Configuration (Placeholder defaults for Phase 4)
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string (activated in Phase 4)"
    )

    # AI Provider Settings (Placeholder defaults for Phase 5)
    AI_PROVIDER: str = "openrouter"
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "anthropic/claude-3.5-sonnet"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "deepseek-coder:6.7b"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
