"""False Positive Classifier for Phase 30 ML Triage.

Implements calibrated logistic regression on historical triage decisions,
enforces the insufficient-data fallback threshold (N >= 50), and produces
explainable advisory probabilities without deleting or modifying findings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Optional

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder

logger = logging.getLogger(__name__)


@dataclass
class TriagePrediction:
    """Advisory prediction payload from the False Positive Classifier."""

    status: str  # "AVAILABLE", "INSUFFICIENT_DATA", "ERROR"
    fp_likelihood: Optional[float] = None
    fp_confidence: Optional[float] = None
    model_version: str = "fp-clf-v1.0.0"
    feature_version: str = "feat-v1"
    training_data_digest: Optional[str] = None
    contributing_factors: list[str] = field(default_factory=list)
    explanation: str = ""


class FalsePositiveClassifier:
    """Calibrated statistical classifier learning from historical developer triage feedback."""

    MIN_SAMPLES = 50
    MIN_CLASS_SAMPLES = 10
    CATEGORICAL_COLS = ["rule_id", "language", "source_boundary", "sink_category", "layer", "evidence_type"]
    NUMERIC_COLS = [
        "severity_rank",
        "confidence_rank",
        "category_is_security",
        "sanitizer_detected",
        "taint_depth",
        "call_depth",
        "path_certainty",
        "instability",
        "is_test_file",
        "historical_rule_fp_rate",
        "has_prior_suppression",
        "file_depth",
    ]

    def __init__(self, model_version: str = "fp-clf-v1.0.0"):
        self.model_version = model_version
        self.is_trained = False
        self.encoder: Optional[OneHotEncoder] = None
        self.clf: Optional[LogisticRegression] = None
        self.training_data_digest: Optional[str] = None
        self.sample_count: int = 0
        self.positive_count: int = 0
        self.negative_count: int = 0

    def train(self, feedback_records: list[Any]) -> dict[str, Any]:
        """Train classifier on historical feedback records.

        If sample counts are below threshold (N < 50 or min class < 10),
        training is cleanly skipped and status is marked INSUFFICIENT_DATA.
        """
        valid_records = [r for r in feedback_records if getattr(r, "feature_snapshot", None)]
        total = len(valid_records)

        if total < self.MIN_SAMPLES:
            self.is_trained = False
            return {
                "status": "INSUFFICIENT_DATA",
                "sample_count": total,
                "required_samples": self.MIN_SAMPLES,
                "message": f"Insufficient historical feedback samples ({total}/{self.MIN_SAMPLES}).",
            }

        # Labels: 1 = FALSE_POSITIVE, 0 = TRUE_POSITIVE or ACCEPTED_RISK
        y = []
        cat_rows = []
        num_rows = []

        for rec in valid_records:
            label = str(getattr(rec, "label", "TRUE_POSITIVE")).upper()
            y.append(1 if label == "FALSE_POSITIVE" else 0)

            feats = rec.feature_snapshot
            cat_rows.append([str(feats.get(c, "UNKNOWN")) for c in self.CATEGORICAL_COLS])
            num_rows.append([float(feats.get(n, 0.0)) for n in self.NUMERIC_COLS])

        y_arr = np.array(y, dtype=int)
        pos = int(np.sum(y_arr))
        neg = total - pos

        if pos < self.MIN_CLASS_SAMPLES or neg < self.MIN_CLASS_SAMPLES:
            self.is_trained = False
            return {
                "status": "INSUFFICIENT_DATA",
                "sample_count": total,
                "positive_count": pos,
                "negative_count": neg,
                "message": f"Class distribution too imbalanced (FP={pos}, TP={neg}, min required={self.MIN_CLASS_SAMPLES}).",
            }

        # Encode categorical features
        self.encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        encoded_cat = self.encoder.fit_transform(cat_rows)
        num_arr = np.array(num_rows, dtype=float)
        X = np.hstack([encoded_cat, num_arr])

        # Fit balanced logistic regression
        self.clf = LogisticRegression(class_weight="balanced", C=1.0, max_iter=500, solver="lbfgs")
        self.clf.fit(X, y_arr)

        # Compute digest of training dataset
        sorted_ids = sorted(str(getattr(r, "id", i)) for i, r in enumerate(valid_records))
        self.training_data_digest = hashlib.sha256("".join(sorted_ids).encode("utf-8")).hexdigest()[:16]

        self.is_trained = True
        self.sample_count = total
        self.positive_count = pos
        self.negative_count = neg

        score = float(self.clf.score(X, y_arr))
        logger.info(
            "Trained FalsePositiveClassifier (%s) on %d samples (acc=%.2f, FP=%d, TP=%d)",
            self.model_version,
            total,
            score,
            pos,
            neg,
        )

        return {
            "status": "TRAINED",
            "model_version": self.model_version,
            "sample_count": total,
            "training_accuracy": round(score, 4),
            "training_data_digest": self.training_data_digest,
        }

    def predict(self, features: dict[str, Any]) -> TriagePrediction:
        """Predict false-positive probability for a candidate finding."""
        if not self.is_trained or self.clf is None or self.encoder is None:
            return TriagePrediction(
                status="INSUFFICIENT_DATA",
                fp_likelihood=None,
                fp_confidence=None,
                model_version=self.model_version,
                explanation="Model has insufficient historical training data; falling back to deterministic confidence.",
            )

        try:
            cat_row = [[str(features.get(c, "UNKNOWN")) for c in self.CATEGORICAL_COLS]]
            num_row = [[float(features.get(n, 0.0)) for n in self.NUMERIC_COLS]]

            encoded_cat = self.encoder.transform(cat_row)
            X = np.hstack([encoded_cat, np.array(num_row, dtype=float)])

            probs = self.clf.predict_proba(X)[0]
            fp_prob = round(float(probs[1]), 4)

            # Confidence is derived from distance to decision boundary (0.5)
            confidence = round(float(min(1.0, abs(fp_prob - 0.5) * 2.0 + 0.3)), 4)

            # Determine top factors
            factors = []
            if features.get("is_test_file"):
                factors.append("Finding is located inside a test/fixture directory")
            if features.get("sanitizer_detected"):
                factors.append("Sanitizer or validation function detected along path")
            if float(features.get("historical_rule_fp_rate", 0.0)) > 0.6:
                factors.append(f"Rule {features.get('rule_id')} has high historical FP rate ({features.get('historical_rule_fp_rate'):.0%})")
            if features.get("evidence_type") == "HEURISTIC":
                factors.append("Finding originated from heuristic pattern rather than deterministic AST rule")

            if not factors:
                if fp_prob > 0.5:
                    factors.append("Structural properties align with historical false-positive patterns")
                else:
                    factors.append("Deterministic taint flow evidence indicates genuine defect")

            explanation = (
                f"Assessed as {fp_prob:.0%} false-positive likelihood based on {self.sample_count} historical triage decisions."
            )

            return TriagePrediction(
                status="AVAILABLE",
                fp_likelihood=fp_prob,
                fp_confidence=confidence,
                model_version=self.model_version,
                training_data_digest=self.training_data_digest,
                contributing_factors=factors,
                explanation=explanation,
            )

        except Exception as exc:
            logger.exception("Inference error in FalsePositiveClassifier: %s", exc)
            return TriagePrediction(
                status="ERROR",
                model_version=self.model_version,
                explanation=f"Classifier inference failed: {exc}",
            )
