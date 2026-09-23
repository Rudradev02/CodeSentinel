"""FastAPI main application entry point for CodeSentinel."""

from contextlib import asynccontextmanager
from pathlib import Path
import sys
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure repository root is on sys.path so 'backend' package imports resolve seamlessly
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from backend.app.api.v1.api import api_router
from backend.app.api.v1.endpoints.health import compute_health_status
from backend.app.core.config import get_settings
from backend.app.core.exceptions import CodeSentinelAPIException
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


@app.exception_handler(CodeSentinelAPIException)
async def codesentinel_api_exception_handler(
    request: Request, exc: CodeSentinelAPIException
) -> JSONResponse:
    """Handle domain-specific CodeSentinel exceptions with structured error payloads."""
    logger.warning("API domain error: [%s] %s on %s", exc.code, exc.message, request.url.path)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic schema validation failures with standard error envelope."""
    logger.info("Request validation failed on %s: %s", request.url.path, exc.errors())
    return JSONResponse(
        status_code=422,
        content={
            "code": "VALIDATION_ERROR",
            "message": "The request body failed schema validation.",
            "details": {"errors": exc.errors()},
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Catch-all handler for unexpected internal server errors without leaking internals."""
    logger.error("Unhandled internal server error on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "code": "INTERNAL_ANALYSIS_ERROR",
            "message": "An unexpected error occurred during processing.",
            "details": {"error": str(exc), "type": type(exc).__name__} if settings.DEBUG else {},
        },
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
