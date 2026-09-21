"""Aggregated API v1 router for CodeSentinel Backend."""

from fastapi import APIRouter

from backend.app.api.v1.endpoints import analyze, health, rules

api_router = APIRouter()

# Register health check endpoint (/api/v1/health)
api_router.include_router(health.router, tags=["Health"])

# Register static analysis endpoint (/api/v1/analyze)
api_router.include_router(analyze.router, tags=["Analysis"])

# Register rule metadata endpoints (/api/v1/rules, /api/v1/rules/{rule_id})
api_router.include_router(rules.router, tags=["Rules"])
