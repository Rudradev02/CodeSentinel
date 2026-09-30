"""Feature engineering pipeline for Phase 30 ML False-Positive Reduction.

Extracts bounded, tabular, non-sensitive features from finding snapshots,
AST data-flow facts, and component graph metrics.
"""

from typing import Any, Optional
from pathlib import Path


SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

CONFIDENCE_WEIGHTS = {
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def is_test_path(file_path: str) -> bool:
    """Determine if a file path is located within a test suite or fixture directory."""
    norm = file_path.replace("\\", "/").lower()
    test_markers = [
        "/test/",
        "/tests/",
        "/testing/",
        "test_",
        "_test.",
        "/fixtures/",
        "/mocks/",
        "/spec/",
        "/specs/",
    ]
    return any(marker in norm for marker in test_markers)


class FeatureExtractor:
    """Extracts strictly bounded tabular feature dictionaries without sensitive code strings."""

    FEATURE_NAMES = [
        "rule_id",
        "language",
        "severity_rank",
        "confidence_rank",
        "category_is_security",
        "evidence_type",
        "source_boundary",
        "sink_category",
        "sanitizer_detected",
        "taint_depth",
        "call_depth",
        "path_certainty",
        "layer",
        "instability",
        "is_test_file",
        "historical_rule_fp_rate",
        "has_prior_suppression",
        "file_depth",
    ]

    @classmethod
    def extract_features(
        cls,
        finding: Any,
        historical_rule_fp_rate: float = 0.0,
        has_prior_suppression: bool = False,
        component_instability: float = 0.5,
        component_layer: str = "UNKNOWN",
    ) -> dict[str, Any]:
        """Extract deterministic feature vector from a FindingSnapshot or Finding object.

        Guarantees:
        - Never includes sensitive source code, snippets, or identifier tokens.
        - Produces clean types suitable for ML model training and inference.
        """
        # Determine attributes whether finding is ORM model or Pydantic model
        rule_id = getattr(finding, "rule_id", "UNKNOWN")
        language = getattr(finding, "language", "plaintext").lower()
        severity = str(getattr(finding, "severity", "MEDIUM")).upper()
        confidence = str(getattr(finding, "confidence", "MEDIUM")).upper()
        category = str(getattr(finding, "category", "SECURITY")).upper()
        file_path = getattr(finding, "file_path", getattr(finding, "file", ""))

        evidence = getattr(finding, "evidence", None) or {}
        if not isinstance(evidence, dict):
            evidence = {}

        evidence_type = str(getattr(finding, "evidence_type", evidence.get("evidence_type", "DETERMINISTIC"))).upper()

        # Extract dataflow properties if present
        dataflow_evidence = evidence.get("dataflow_evidence") or evidence
        source_boundary = str(dataflow_evidence.get("source_boundary", dataflow_evidence.get("boundary_type", "NONE")))
        sink_category = str(dataflow_evidence.get("sink_category", "NONE"))
        sanitizer_detected = 1 if (dataflow_evidence.get("sanitizer_applied") or dataflow_evidence.get("sanitizers")) else 0

        taint_steps = dataflow_evidence.get("taint_steps") or dataflow_evidence.get("steps") or []
        taint_depth = len(taint_steps) if isinstance(taint_steps, list) else 0

        call_chain = dataflow_evidence.get("call_chain") or []
        call_depth = len(call_chain) if isinstance(call_chain, list) else 0

        path_certainty = float(dataflow_evidence.get("path_certainty", 1.0))
        path_certainty = max(0.0, min(1.0, path_certainty))

        # Path metrics
        clean_path = str(file_path).replace("\\", "/").strip("/")
        parts = Path(clean_path).parts
        file_depth = len(parts)
        is_test = 1 if is_test_path(clean_path) else 0

        features = {
            "rule_id": rule_id,
            "language": language,
            "severity_rank": SEVERITY_WEIGHTS.get(severity, 2),
            "confidence_rank": CONFIDENCE_WEIGHTS.get(confidence, 1),
            "category_is_security": 1 if category == "SECURITY" else 0,
            "evidence_type": evidence_type,
            "source_boundary": source_boundary,
            "sink_category": sink_category,
            "sanitizer_detected": sanitizer_detected,
            "taint_depth": taint_depth,
            "call_depth": call_depth,
            "path_certainty": path_certainty,
            "layer": component_layer or "UNKNOWN",
            "instability": round(float(component_instability), 4),
            "is_test_file": is_test,
            "historical_rule_fp_rate": round(float(historical_rule_fp_rate), 4),
            "has_prior_suppression": 1 if has_prior_suppression else 0,
            "file_depth": file_depth,
        }

        return features
