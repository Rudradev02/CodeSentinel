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

    # Redis & Task Queue Configuration (Phase 11)
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string for caching and Pub/Sub",
    )
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/1",
        description="Celery message broker URL",
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/2",
        description="Celery result backend URL",
    )
    CELERY_TASK_TRACK_STARTED: bool = True
    SSE_KEEPALIVE_SECONDS: int = 15
    CACHE_TTL_SECONDS: int = 86400  # 24 hours

    # AI Provider Settings (Phase 12: Bounded Context AI Enrichment)
    AI_ENABLED: bool = Field(
        default=False,
        description="Enable AI enrichment and remediation layer",
    )
    AI_PROVIDER: str = Field(
        default="openrouter",
        description="Default AI provider: openrouter or ollama",
    )
    AI_TIMEOUT_SECONDS: int = Field(
        default=30,
        description="Provider request timeout in seconds",
    )
    AI_MAX_RETRIES: int = Field(
        default=3,
        description="Maximum retries for transient provider rate limits/errors",
    )
    AI_TEMPERATURE: float = Field(
        default=0.1,
        description="Sampling temperature for deterministic structured triage",
    )
    AI_CONTEXT_TOKEN_LIMIT: int = Field(
        default=2048,
        description="Hard token budget cap for bounded source context extraction",
    )
    OPENROUTER_API_KEY: str = Field(
        default="",
        description="OpenRouter API key for cloud LLM inference",
    )
    OPENROUTER_BASE_URL: str = Field(
        default="https://openrouter.ai/api/v1",
        description="OpenRouter API base endpoint",
    )
    OPENROUTER_MODEL: str = Field(
        default="anthropic/claude-3.5-sonnet",
        description="Configurable OpenRouter model identifier",
    )
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434",
        description="Local Ollama daemon endpoint for air-gapped inference",
    )
    OLLAMA_MODEL: str = Field(
        default="deepseek-coder:6.7b",
        description="Configurable local Ollama model identifier",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @property
    def SYNC_DATABASE_URL(self) -> str:
        """Derive a synchronous database connection string for Celery worker tasks."""
        url = self.DATABASE_URL
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
        elif url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+psycopg2://", 1)
        elif url.startswith("sqlite+aiosqlite://"):
            return url.replace("sqlite+aiosqlite://", "sqlite://", 1)
        return url

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str) -> str:
        if isinstance(v, str):
            if v.startswith("postgresql://"):
                return v.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif v.startswith("postgres://"):
                return v.replace("postgres://", "postgresql+asyncpg://", 1)
        return v

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
