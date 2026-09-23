"""Aggregated API v1 router for CodeSentinel Backend."""

from fastapi import APIRouter

from backend.app.api.v1.endpoints import (
    analyze,
    compare,
    enrichment,
    health,
    jobs,
    repositories,
    rules,
    sse,
    trends,
)

api_router = APIRouter()

# Register health check endpoint (/api/v1/health)
api_router.include_router(health.router, tags=["Health"])

# Register static analysis endpoint (/api/v1/analyze)
api_router.include_router(analyze.router, tags=["Analysis"])

# Register differential comparison endpoint (/api/v1/compare)
api_router.include_router(compare.router, tags=["Comparison"])

# Register rule metadata endpoints (/api/v1/rules, /api/v1/rules/{rule_id})
api_router.include_router(rules.router, tags=["Rules"])

# Register repository catalog & analysis history endpoints (/api/v1/repositories)
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"])
api_router.include_router(enrichment.router, prefix="/repositories", tags=["AI Enrichment"])
api_router.include_router(trends.router, prefix="/repositories", tags=["Trends"])

# Register analysis jobs & SSE streaming endpoints (/api/v1/jobs, /api/v1/jobs/{id}/stream)
api_router.include_router(jobs.router, tags=["Jobs"])
api_router.include_router(sse.router, tags=["Jobs"])


