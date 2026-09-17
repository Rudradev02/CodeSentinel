"""Health check endpoints providing service status, uptime, and component readiness."""

import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends

from backend.app.core.config import Settings, get_settings
from backend.app.schemas.health import HealthResponse

router = APIRouter()

# Track process startup timestamp
START_TIME = time.time()


def compute_health_status(settings: Settings) -> HealthResponse:
    """Evaluate and compile system component health metrics."""
    uptime = max(0.0, time.time() - START_TIME)

    # Check analyzer engine availability safely without coupling to backend logic
    analyzer_status = "unavailable"
    try:
        import analyzer
        from analyzer.models.results import AnalysisResult
        analyzer_status = f"available (v{analyzer.__version__})"
    except Exception:
        analyzer_status = "error_loading_analyzer"

    # NOTE: PostgreSQL and Redis are Phase 4 features; we accurately report them as
    # not configured rather than falsely claiming they are healthy or connected.
    components = {
        "api": "healthy",
        "analyzer_engine": analyzer_status,
        "database": "not_configured (Phase 4)",
        "redis_queue": "not_configured (Phase 4)",
    }

    return HealthResponse(
        status="healthy",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        uptime_seconds=round(uptime, 2),
        timestamp=datetime.now(timezone.utc),
        components=components,
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Get service health and readiness status",
    description="Returns backend uptime, version, and component status. Does not report mock database health."
)
async def get_health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Endpoint handler for /api/v1/health."""
    return compute_health_status(settings)
