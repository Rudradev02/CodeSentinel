"""AI Vulnerability Prioritizer & Exploitability Analysis Service for Phase 30.

Integrates deterministic exploitability scoring, explainable priority calculation,
and LLM-synthesized rationale grounded in verified AST evidence.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Optional
from sqlalchemy.orm import Session

from analyzer.models.boundary import AuthenticationState, AuthorizationState, TrustBoundaryType
from analyzer.models.findings import FindingSeverity
from analyzer.security.exploitability import (
    ExploitabilityAssessment,
    ExploitabilityEvaluator,
    InputControllabilityLevel,
    PathFeasibilityLevel,
)
from analyzer.security.prioritization import (
    AssetCriticality,
    PriorityBand,
    PriorityCalculationBreakdown,
    PriorityCalculator,
)
from backend.app.models.finding import FindingSnapshot
from backend.app.models.triage_feedback import AIPrioritizationRecord
from backend.app.services.ai.orchestrator import AIEnrichmentOrchestrator
from backend.app.services.ai.providers.base import BaseLLMProvider
from backend.app.services.ai.validator import SemanticValidator

logger = logging.getLogger(__name__)

PRIORITIZER_SYSTEM_PROMPT = """You are CodeSentinel Security Prioritizer.
Your goal is to synthesize a concise, objective technical rationale explaining the Exploitability Score and Priority Band calculated by our deterministic static analysis engine.

CRITICAL INVARIANTS:
1. Ground your reasoning strictly in the verified static evidence provided.
2. Under NO circumstances invent external CVEs, unverified WAFs, or network defenses not present in the evidence.
3. Be concise (2 to 4 sentences).
4. Output valid JSON in the format:
{
  "rationale": "Objective technical justification linking source lines, trust boundaries, and sink mechanics."
}
"""


class AIPrioritizerService:
    """Service orchestrating deterministic exploitability, priority scoring, and AI explanation."""

    @staticmethod
    def compute_context_hash(
        finding_id: str,
        rule_id: str,
        severity: str,
        exploitability_score: float,
        factors: dict[str, Any],
    ) -> str:
        """Compute SHA-256 fingerprint of prioritization context for idempotency."""
        payload = {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": severity,
            "exploitability_score": exploitability_score,
            "factors": factors,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def prioritize_finding(
        cls,
        finding_id: str,
        rule_id: str,
        severity: str | FindingSeverity,
        confidence: str = "HIGH",
        boundary: Optional[TrustBoundaryType] = None,
        auth_state: Optional[AuthenticationState] = None,
        authz_state: Optional[AuthorizationState] = None,
        input_controllability: Optional[InputControllabilityLevel] = None,
        path_feasibility: Optional[PathFeasibilityLevel] = None,
        evidence_snippet: str = "",
        guard_count: int = 0,
        asset_criticality: float | AssetCriticality = AssetCriticality.STANDARD,
        source_code: str = "",
        provider: Optional[BaseLLMProvider] = None,
        model_name: Optional[str] = None,
        db: Optional[Session] = None,
        snapshot_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Perform end-to-end exploitability assessment and explainable prioritization.

        Returns complete prioritization dictionary conforming to Phase 30 Section 12.3 schema.
        """
        # 1. Deterministic Exploitability Assessment
        exploitability_assessment = ExploitabilityEvaluator.evaluate(
            boundary=boundary,
            auth_state=auth_state,
            authz_state=authz_state,
            input_controllability=input_controllability,
            path_feasibility=path_feasibility,
            evidence_snippet=evidence_snippet,
            guard_count=guard_count,
        )

        # 2. Deterministic Priority Score & Band Calculation
        priority_breakdown = PriorityCalculator.calculate(
            severity=severity,
            confidence=confidence,
            exploitability_score=exploitability_assessment.exploitability_score,
            asset_criticality=asset_criticality,
        )

        factors_dict = {
            name: {"score": f.score, "evidence": f.evidence}
            for name, f in exploitability_assessment.contributing_factors.items()
        }

        # 3. Rationale Synthesis
        sev_str = severity.value if isinstance(severity, FindingSeverity) else str(severity).upper()
        default_rationale = (
            f"{sev_str} severity flaw with {exploitability_assessment.exploitability_score:.2f} exploitability. "
            f"Assigned {priority_breakdown.priority_band.value} (score: {priority_breakdown.final_score}) based on verified "
            f"{factors_dict['attack_surface']['evidence']} and {factors_dict['authentication']['evidence']}."
        )

        rationale = default_rationale
        if provider is not None:
            user_prompt = (
                f"<prioritization_context>\n"
                f"  <finding_id>{finding_id}</finding_id>\n"
                f"  <rule_id>{rule_id}</rule_id>\n"
                f"  <severity>{sev_str}</severity>\n"
                f"  <exploitability_score>{exploitability_assessment.exploitability_score}</exploitability_score>\n"
                f"  <priority_band>{priority_breakdown.priority_band.value}</priority_band>\n"
                f"  <priority_score>{priority_breakdown.final_score}</priority_score>\n"
                f"  <contributing_factors>{json.dumps(factors_dict)}</contributing_factors>\n"
                f"  <evidence_snippet>{evidence_snippet}</evidence_snippet>\n"
                f"</prioritization_context>\n"
                f"Synthesize an objective, grounded technical rationale in JSON."
            )
            try:
                response = provider.generate_sync(
                    prompt=user_prompt,
                    system_prompt=PRIORITIZER_SYSTEM_PROMPT,
                    model=model_name,
                    temperature=0.1,
                )
                if response.parsed_json and "rationale" in response.parsed_json:
                    candidate_rationale = str(response.parsed_json["rationale"]).strip()
                else:
                    raw_text = response.raw_content.strip()
                    if raw_text.startswith("```"):
                        lines = raw_text.splitlines()
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].startswith("```"):
                            lines = lines[:-1]
                        raw_text = "\n".join(lines).strip()
                    parsed = json.loads(raw_text)
                    candidate_rationale = str(parsed.get("rationale", "")).strip()

                if candidate_rationale:
                    # Stage 3 Grounding validation
                    is_grounded, grounding_diags = SemanticValidator.validate_evidence_grounding(
                        reasoning=candidate_rationale,
                        source_code=source_code or evidence_snippet,
                        evidence_locations=[evidence_snippet] if evidence_snippet else [],
                    )
                    if is_grounded:
                        rationale = candidate_rationale
                    else:
                        logger.warning("AI rationale failed evidence grounding: %s", grounding_diags)
            except Exception as exc:
                logger.warning("AI rationale generation failed, using deterministic summary: %s", exc)

        context_hash = cls.compute_context_hash(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=sev_str,
            exploitability_score=exploitability_assessment.exploitability_score,
            factors=factors_dict,
        )

        result_payload = {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": sev_str,
            "priority_score": priority_breakdown.final_score,
            "priority_band": priority_breakdown.priority_band.value,
            "exploitability_score": exploitability_assessment.exploitability_score,
            "contributing_factors": factors_dict,
            "rationale": rationale,
            "breakdown": priority_breakdown.model_dump(),
            "context_hash": context_hash,
        }

        # 4. Optional Persistence
        if db is not None and snapshot_id:
            record = AIPrioritizationRecord(
                finding_id=finding_id,
                snapshot_id=snapshot_id,
                priority_score=priority_breakdown.final_score,
                priority_band=priority_breakdown.priority_band.value,
                exploitability_score=exploitability_assessment.exploitability_score,
                contributing_factors=factors_dict,
                reasoning_summary=rationale,
                context_hash=context_hash,
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            result_payload["record_id"] = record.id

        return result_payload
