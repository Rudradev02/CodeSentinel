"""Data models and enums for Phase 21 Incremental Analysis and Persistent Caching."""

from enum import Enum
import hashlib
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class InvalidationReason(str, Enum):
    """Machine-readable taxonomy of analysis invalidation reasons."""
    DIRECT_SOURCE_CHANGE = "DIRECT_SOURCE_CHANGE"
    DEPENDENCY_CHANGE = "DEPENDENCY_CHANGE"
    CALL_TARGET_CHANGE = "CALL_TARGET_CHANGE"
    SIGNATURE_CHANGE = "SIGNATURE_CHANGE"
    CONTRACT_CHANGE = "CONTRACT_CHANGE"
    FIELD_EFFECT_CHANGE = "FIELD_EFFECT_CHANGE"
    SECURITY_BOUNDARY_CHANGE = "SECURITY_BOUNDARY_CHANGE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    RULE_CHANGE = "RULE_CHANGE"
    PARSER_CHANGE = "PARSER_CHANGE"
    SCHEMA_CHANGE = "SCHEMA_CHANGE"
    ANALYZER_VERSION_CHANGE = "ANALYZER_VERSION_CHANGE"
    CACHE_CORRUPTION = "CACHE_CORRUPTION"
    UNKNOWN_DEPENDENCY = "UNKNOWN_DEPENDENCY"
    UNKNOWN = "UNKNOWN"


class FunctionChangeKind(str, Enum):
    """Semantic classification of modifications to a function or method."""
    BODY_CHANGED_ONLY = "BODY_CHANGED_ONLY"
    SIGNATURE_CHANGED = "SIGNATURE_CHANGED"
    CALL_TARGETS_CHANGED = "CALL_TARGETS_CHANGED"
    TYPE_INFORMATION_CHANGED = "TYPE_INFORMATION_CHANGED"
    INHERITANCE_CHANGED = "INHERITANCE_CHANGED"
    UNKNOWN = "UNKNOWN"


class FindingReconciliationState(str, Enum):
    """Finding lifecycle state in incremental re-analysis."""
    REUSED = "REUSED"
    RECOMPUTED = "RECOMPUTED"
    NEW = "NEW"
    RESOLVED = "RESOLVED"


class FileFingerprint(BaseModel):
    """Canonical content-addressed fingerprint for a repository source file."""
    model_config = ConfigDict(frozen=True)

    path: str = Field(..., description="Forward-slash normalized repository-relative path")
    content_hash: str = Field(..., description="SHA-256 hex digest of raw file contents")
    size_bytes: int = Field(default=0, ge=0, description="File size in bytes")
    language: str = Field(..., description="Detected language (PYTHON, JAVASCRIPT, TYPESCRIPT)")
    parser_version: str = Field(default="1.0.0", description="Version of language parser")
    analysis_schema_version: str = Field(default="1.0.0", description="Serialization schema version")
    is_generated: bool = Field(default=False, description="Whether the file appears to be auto-generated")

    def compute_composite_hash(self) -> str:
        """Compute composite SHA-256 hash across content, language, parser, and schema."""
        payload = f"{self.path}:{self.content_hash}:{self.language}:{self.parser_version}:{self.analysis_schema_version}:{self.is_generated}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ConfigFingerprint(BaseModel):
    """Scoped SHA-256 configuration digests governing specific cache layers."""
    model_config = ConfigDict(frozen=True)

    global_hash: str = Field(..., description="Hash across the entire active configuration")
    parsing_hash: str = Field(..., description="Hash of parser and language settings")
    dependency_hash: str = Field(..., description="Hash of path exclusions and component depth")
    cfg_dataflow_hash: str = Field(..., description="Hash of path exploration, CFG, and alias settings")
    callgraph_hash: str = Field(..., description="Hash of call depth, context sensitivity, and type inference")
    contract_hash: str = Field(..., description="Hash of function contract extraction parameters")
    composition_hash: str = Field(..., description="Hash of contract composition depth and security boundaries")
    rules_hash: str = Field(..., description="Hash of active rule activation and severity thresholds")
    reporting_hash: str = Field(..., description="Hash of output format and reporting paths")
    policy_hash: str = Field(default="", description="Hash of declarative security policies and proof obligations")
    framework_model_hash: str = Field(default="", description="Hash of framework capability models and trust boundary semantics")


class ImpactSet(BaseModel):
    """Structured representation of affected files, functions, and contracts."""
    directly_changed_files: set[str] = Field(default_factory=set)
    affected_files: set[str] = Field(default_factory=set)
    affected_functions: set[str] = Field(default_factory=set)
    affected_contracts: set[str] = Field(default_factory=set)
    reusable_files: set[str] = Field(default_factory=set)
    deleted_files: set[str] = Field(default_factory=set)
    renamed_files: dict[str, str] = Field(default_factory=dict)
    invalidation_reasons: dict[str, InvalidationReason] = Field(default_factory=dict)


class IncrementalStats(BaseModel):
    """Telemetry and efficiency metrics for an incremental analysis run."""
    analysis_mode: str = "incremental"
    files_discovered: int = 0
    files_reused: int = 0
    files_reanalyzed: int = 0
    ast_hits: int = 0
    ast_misses: int = 0
    cfg_hits: int = 0
    cfg_misses: int = 0
    graph_hits: int = 0
    graph_misses: int = 0
    contract_hits: int = 0
    contract_misses: int = 0
    composition_hits: int = 0
    composition_misses: int = 0
    taint_summary_hits: int = 0
    taint_summary_misses: int = 0
    finding_hits: int = 0
    finding_recomputed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    hit_ratio: float = 0.0
    estimated_time_saved_seconds: float = 0.0
    invalidations_by_reason: dict[str, int] = Field(default_factory=dict)
