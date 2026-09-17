"""FastAPI main application entry point for CodeSentinel."""

from contextlib import asynccontextmanager
from pathlib import Path
import sys
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure repository root is on sys.path so 'backend' package imports resolve seamlessly
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from backend.app.api.v1.api import api_router
from backend.app.api.v1.endpoints.health import compute_health_status
from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger, setup_logging
from backend.app.schemas.health import HealthResponse

# Initialize logging system
setup_logging()
logger = get_logger("codesentinel.backend")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown hooks."""
    logger.info("Starting CodeSentinel Backend v%s in [%s] mode", settings.APP_VERSION, settings.ENVIRONMENT)
    logger.info("Host: %s:%d, Debug: %s", settings.BACKEND_HOST, settings.BACKEND_PORT, settings.DEBUG)
    yield
    logger.info("Shutting down CodeSentinel Backend gracefully")


# Create FastAPI instance
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="CodeSentinel API — AI-assisted Codebase Architecture & Security Auditor",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Root service health check",
    description="Direct root health endpoint returning backend uptime, version, and component status.",
)
async def root_health() -> HealthResponse:
    """Root health endpoint (/health)."""
    return compute_health_status(settings)


# Mount API v1 router
app.include_router(api_router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG,
    )
