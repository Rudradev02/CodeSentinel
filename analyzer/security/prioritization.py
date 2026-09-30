"""Deterministic priority scoring and priority tier classification for Phase 30.

Computes an explainable Priority Score (0 to 100) combining intrinsic Severity,
static Confidence, verified Exploitability, and Asset Criticality.
Maps findings into actionable remediation priority bands (P0 to P3).
"""

from enum import Enum
import logging
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.models.findings import FindingSeverity

logger = logging.getLogger(__name__)


class PriorityBand(str, Enum):
    P0_IMMEDIATE = "P0_IMMEDIATE"  # 80 to 100: Active, reachable, highly exploitable high/critical findings
    P1_HIGH = "P1_HIGH"            # 60 to 79.99: High severity or exploitable medium findings
    P2_MEDIUM = "P2_MEDIUM"        # 40 to 59.99: Authenticated/constrained flaws or defense-in-depth
    P3_LOW = "P3_LOW"              # 0 to 39.99: Theoretical, low severity, or unexploitable findings


class AssetCriticality(float, Enum):
    TIER_1_PRODUCTION = 1.25
    STANDARD = 1.0
    INTERNAL_TOOL = 0.9
    TEST_FIXTURE = 0.8


SEVERITY_WEIGHTS: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 40.0,
    FindingSeverity.HIGH: 30.0,
    FindingSeverity.MEDIUM: 20.0,
    FindingSeverity.LOW: 10.0,
    FindingSeverity.INFO: 0.0,
}

CONFIDENCE_WEIGHTS: dict[str, float] = {
    "HIGH": 20.0,
    "MEDIUM": 12.0,
    "LOW": 5.0,
}


class PriorityCalculationBreakdown(BaseModel):
    """Detailed breakdown of priority score components."""

    model_config = ConfigDict(frozen=True)

    severity_weight: float
    confidence_weight: float
    exploitability_weight: float
    asset_criticality_multiplier: float
    raw_score: float
    final_score: float
    priority_band: PriorityBand


class PriorityCalculator:
    """Calculates explainable priority score without political or developer bias."""

    @classmethod
    def resolve_severity_weight(cls, severity: str | FindingSeverity) -> float:
        """Map severity level to its [0, 40] contribution weight."""
        if isinstance(severity, str):
            try:
                sev_enum = FindingSeverity(severity.upper())
            except ValueError:
                sev_enum = FindingSeverity.MEDIUM
        else:
            sev_enum = severity
        return SEVERITY_WEIGHTS.get(sev_enum, 20.0)

    @classmethod
    def resolve_confidence_weight(cls, confidence: str) -> float:
        """Map static analysis confidence to its [0, 20] contribution weight."""
        conf_clean = str(confidence).upper()
        return CONFIDENCE_WEIGHTS.get(conf_clean, 12.0)

    @classmethod
    def classify_band(cls, score: float) -> PriorityBand:
        """Classify numerical priority score into actionable P0-P3 band."""
        if score >= 80.0:
            return PriorityBand.P0_IMMEDIATE
        elif score >= 60.0:
            return PriorityBand.P1_HIGH
        elif score >= 40.0:
            return PriorityBand.P2_MEDIUM
        else:
            return PriorityBand.P3_LOW

    @classmethod
    def calculate(
        cls,
        severity: str | FindingSeverity,
        confidence: str,
        exploitability_score: float,
        asset_criticality: float | AssetCriticality = AssetCriticality.STANDARD,
    ) -> PriorityCalculationBreakdown:
        """Compute the deterministic Priority Score (0 to 100) and Priority Band."""
        s_weight = cls.resolve_severity_weight(severity)
        c_weight = cls.resolve_confidence_weight(confidence)
        e_clamped = max(0.0, min(1.0, float(exploitability_score)))
        e_weight = round(40.0 * e_clamped, 4)

        crit_mult = float(asset_criticality.value if isinstance(asset_criticality, AssetCriticality) else asset_criticality)
        raw_score = (s_weight + c_weight + e_weight) * crit_mult
        final_score = round(max(0.0, min(100.0, raw_score)), 2)
        band = cls.classify_band(final_score)

        return PriorityCalculationBreakdown(
            severity_weight=s_weight,
            confidence_weight=c_weight,
            exploitability_weight=e_weight,
            asset_criticality_multiplier=crit_mult,
            raw_score=round(raw_score, 2),
            final_score=final_score,
            priority_band=band,
        )
