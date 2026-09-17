"""Aggregated API v1 router for CodeSentinel Backend."""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import health

api_router = APIRouter()

# Register health check endpoint (/api/v1/health)
api_router.include_router(health.router, tags=["Health"])
