"""Backend Pydantic request and response schemas."""

from backend.app.schemas.analysis import (
    AnalysisRequest,
    AnalysisResultDTO,
    AnalysisSummaryDTO,
    ComponentCouplingDTO,
    ComponentEdgeDTO,
    ComponentGraphDTO,
    ComponentNodeDTO,
    DeductionDTO,
    DiagnosticDTO,
    EvidenceDTO,
    FindingDTO,
    HealthScoreDTO,
    LocationDTO,
    SubScoreDTO,
)
from backend.app.schemas.errors import APIErrorResponse
from backend.app.schemas.health import HealthResponse
from backend.app.schemas.rules import RuleListResponse, RuleMetadataDTO

from backend.app.schemas.repository import (
    AnalysisHistoryResponse,
    AnalysisSnapshotSummaryDTO,
    RepositoryCreateRequest,
    RepositoryListResponse,
    RepositoryResponse,
    RunAnalysisRequest,
)

__all__ = [
    "AnalysisRequest",
    "AnalysisResultDTO",
    "AnalysisSummaryDTO",
    "ComponentCouplingDTO",
    "ComponentEdgeDTO",
    "ComponentGraphDTO",
    "ComponentNodeDTO",
    "DeductionDTO",
    "DiagnosticDTO",
    "EvidenceDTO",
    "FindingDTO",
    "HealthResponse",
    "HealthScoreDTO",
    "LocationDTO",
    "SubScoreDTO",
    "RuleListResponse",
    "RuleMetadataDTO",
    "APIErrorResponse",
    "RepositoryCreateRequest",
    "RepositoryResponse",
    "RepositoryListResponse",
    "AnalysisSnapshotSummaryDTO",
    "AnalysisHistoryResponse",
    "RunAnalysisRequest",
]
