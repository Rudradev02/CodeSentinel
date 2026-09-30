"""Unit tests for Phase 30.3 ML False-Positive Reduction and Triage Feedback."""

from types import SimpleNamespace
import pytest

from backend.app.services.ai.triage_ml.classifier import FalsePositiveClassifier
from backend.app.services.ai.triage_ml.features import FeatureExtractor, is_test_path


def test_is_test_path_detection():
    """Verify test path classifier flags test and mock files accurately."""
    assert is_test_path("tests/test_api.py") is True
    assert is_test_path("src/handlers/user_test.go") is True
    assert is_test_path("app/fixtures/data.json") is True
    assert is_test_path("src/core/auth.py") is False
    assert is_test_path("controllers/orders.go") is False


def test_feature_extractor_structure():
    """Verify FeatureExtractor produces all expected bounded features without code leakage."""
    mock_finding = SimpleNamespace(
        rule_id="SEC-PY-005",
        language="python",
        severity="HIGH",
        confidence="HIGH",
        category="SECURITY",
        file_path="tests/fixtures/test_sql.py",
        evidence_type="DETERMINISTIC",
        evidence={
            "dataflow_evidence": {
                "source_boundary": "HTTP_REQUEST_PARAM",
                "sink_category": "SQL_EXECUTE",
                "sanitizer_applied": True,
                "taint_steps": [1, 2, 3],
                "call_chain": ["a", "b"],
                "path_certainty": 0.95,
            }
        },
    )

    feats = FeatureExtractor.extract_features(
        finding=mock_finding,
        historical_rule_fp_rate=0.75,
        has_prior_suppression=True,
        component_instability=0.45,
        component_layer="PRESENTATION",
    )

    assert feats["rule_id"] == "SEC-PY-005"
    assert feats["language"] == "python"
    assert feats["severity_rank"] == 3
    assert feats["confidence_rank"] == 2
    assert feats["category_is_security"] == 1
    assert feats["source_boundary"] == "HTTP_REQUEST_PARAM"
    assert feats["sink_category"] == "SQL_EXECUTE"
    assert feats["sanitizer_detected"] == 1
    assert feats["taint_depth"] == 3
    assert feats["call_depth"] == 2
    assert feats["path_certainty"] == 0.95
    assert feats["is_test_file"] == 1
    assert feats["historical_rule_fp_rate"] == 0.75
    assert feats["has_prior_suppression"] == 1
    assert feats["layer"] == "PRESENTATION"


def test_classifier_insufficient_data_fallback():
    """Verify classifier rejects small datasets (<50 samples) with INSUFFICIENT_DATA."""
    classifier = FalsePositiveClassifier()

    # Create only 10 feedback records
    records = []
    for i in range(10):
        records.append(
            SimpleNamespace(
                id=f"fb-{i}",
                label="TRUE_POSITIVE" if i % 2 == 0 else "FALSE_POSITIVE",
                feature_snapshot={
                    "rule_id": "SEC-PY-005",
                    "language": "python",
                    "source_boundary": "NONE",
                    "sink_category": "NONE",
                    "layer": "UNKNOWN",
                    "evidence_type": "DETERMINISTIC",
                    "severity_rank": 2,
                    "confidence_rank": 1,
                    "category_is_security": 1,
                    "sanitizer_detected": 0,
                    "taint_depth": 1,
                    "call_depth": 0,
                    "path_certainty": 1.0,
                    "instability": 0.5,
                    "is_test_file": 0,
                    "historical_rule_fp_rate": 0.1,
                    "has_prior_suppression": 0,
                    "file_depth": 2,
                },
            )
        )

    train_res = classifier.train(records)
    assert train_res["status"] == "INSUFFICIENT_DATA"
    assert classifier.is_trained is False

    # Inference should return fallback
    pred = classifier.predict(records[0].feature_snapshot)
    assert pred.status == "INSUFFICIENT_DATA"
    assert pred.fp_likelihood is None


def test_classifier_training_and_prediction():
    """Verify classifier trains when N >= 50 and outputs advisory probabilities."""
    classifier = FalsePositiveClassifier()

    records = []
    # Create 60 records: 30 FPs in test files, 30 TPs in production files
    for i in range(60):
        is_fp = i % 2 == 0
        records.append(
            SimpleNamespace(
                id=f"fb-{i}",
                label="FALSE_POSITIVE" if is_fp else "TRUE_POSITIVE",
                feature_snapshot={
                    "rule_id": "SEC-PY-005" if is_fp else "SEC-PY-001",
                    "language": "python",
                    "source_boundary": "NONE" if is_fp else "HTTP_REQUEST_PARAM",
                    "sink_category": "SQL_EXECUTE",
                    "layer": "TEST" if is_fp else "DATA",
                    "evidence_type": "HEURISTIC" if is_fp else "DETERMINISTIC",
                    "severity_rank": 2,
                    "confidence_rank": 1,
                    "category_is_security": 1,
                    "sanitizer_detected": 1 if is_fp else 0,
                    "taint_depth": 1,
                    "call_depth": 0,
                    "path_certainty": 1.0,
                    "instability": 0.5,
                    "is_test_file": 1 if is_fp else 0,
                    "historical_rule_fp_rate": 0.85 if is_fp else 0.10,
                    "has_prior_suppression": 1 if is_fp else 0,
                    "file_depth": 3,
                },
            )
        )

    train_res = classifier.train(records)
    assert train_res["status"] == "TRAINED"
    assert classifier.is_trained is True
    assert train_res["sample_count"] == 60

    # Predict on a test finding with sanitizer -> expect high FP probability
    test_features = {
        "rule_id": "SEC-PY-005",
        "language": "python",
        "source_boundary": "NONE",
        "sink_category": "SQL_EXECUTE",
        "layer": "TEST",
        "evidence_type": "HEURISTIC",
        "severity_rank": 2,
        "confidence_rank": 1,
        "category_is_security": 1,
        "sanitizer_detected": 1,
        "taint_depth": 1,
        "call_depth": 0,
        "path_certainty": 1.0,
        "instability": 0.5,
        "is_test_file": 1,
        "historical_rule_fp_rate": 0.85,
        "has_prior_suppression": 1,
        "file_depth": 3,
    }

    pred = classifier.predict(test_features)
    assert pred.status == "AVAILABLE"
    assert pred.fp_likelihood is not None
    assert pred.fp_likelihood > 0.5
    assert len(pred.contributing_factors) > 0
    assert pred.training_data_digest is not None
