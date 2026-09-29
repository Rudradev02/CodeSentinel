"""Unit tests for Phase 28 Central Policy Distribution Service and Monotonic Governance."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest

from analyzer.rules.pack_resolver import MonotonicPolicyViolationError
from analyzer.rules.rule_pack import RuleOverride, RulePack
from backend.app.models.policy import CentralizedRulePack, CentralizedSuppression
from backend.app.services.policy_distribution import CentralPolicyDistributionService


@pytest.fixture
def mock_db():
    db = MagicMock()
    # In-memory storage mock
    storage = []

    def mock_add(item):
        storage.append(item)

    def mock_commit():
        pass

    def mock_refresh(item):
        pass

    db.add = mock_add
    db.commit = mock_commit
    db.refresh = mock_refresh
    db._storage = storage
    return db


class TestCentralPolicyDistributionService:
    """Tests for centralized rule pack and suppression management."""

    def test_register_rule_pack(self, mock_db):
        yaml_content = """
pack_id: "org-baseline-v1"
version: "1.0.0"
name: "Acme Global Baseline"
rule_overrides:
  - rule_id: "SEC-PY-001"
    enabled: true
    severity_override: "CRITICAL"
"""
        record = CentralPolicyDistributionService.register_rule_pack(
            mock_db,
            organization_id="org-acme",
            pack_yaml=yaml_content,
        )
        assert record.pack_id == "org-baseline-v1"
        assert record.version == "1.0.0"
        assert len(record.pack_hash) == 64
        assert len(mock_db._storage) == 1

    def test_register_suppression_validation(self, mock_db):
        now = datetime.now(timezone.utc)

        # 1. Missing ticket reference raises ValueError
        with pytest.raises(ValueError, match="ticket_reference"):
            CentralPolicyDistributionService.register_suppression(
                mock_db,
                organization_id="org-acme",
                rule_id="SEC-PY-001",
                justification="Testing",
                compensating_control="None",
                approved_by="auditor@acme.com",
                ticket_reference="",
                expires_at=now + timedelta(days=30),
            )

        # 2. Expiration in past raises ValueError
        with pytest.raises(ValueError, match="must be in the future"):
            CentralPolicyDistributionService.register_suppression(
                mock_db,
                organization_id="org-acme",
                rule_id="SEC-PY-001",
                justification="Testing",
                compensating_control="None",
                approved_by="auditor@acme.com",
                ticket_reference="SEC-1234",
                expires_at=now - timedelta(days=5),
            )

        # 3. Expiration exceeding 180 days raises ValueError
        with pytest.raises(ValueError, match="cannot exceed 180 days"):
            CentralPolicyDistributionService.register_suppression(
                mock_db,
                organization_id="org-acme",
                rule_id="SEC-PY-001",
                justification="Testing",
                compensating_control="None",
                approved_by="auditor@acme.com",
                ticket_reference="SEC-1234",
                expires_at=now + timedelta(days=200),
            )

        # 4. Valid suppression succeeds
        supp = CentralPolicyDistributionService.register_suppression(
            mock_db,
            organization_id="org-acme",
            rule_id="SEC-PY-001",
            justification="Audited mock token",
            compensating_control="Sandbox isolated",
            approved_by="auditor@acme.com",
            ticket_reference="SEC-1234",
            expires_at=now + timedelta(days=90),
            target_repo_id="repo-gateway",
        )
        assert supp.rule_id == "SEC-PY-001"
        assert supp.ticket_reference == "SEC-1234"
        assert supp.target_repo_id == "repo-gateway"

    def test_monotonic_inheritance_enforcement(self):
        parent = RulePack(
            pack_id="org-locked-parent",
            name="Locked Parent",
            allow_repo_override=False, # Locked against child relaxation
            rule_overrides=[
                RuleOverride(rule_id="SEC-PY-001", enabled=True, severity_override="CRITICAL"),
            ],
        )

        # Child tries to disable locked parent rule
        child_relaxing = RulePack(
            pack_id="child-weakened",
            name="Weakened Child",
            extends=["org-locked-parent"],
            rule_overrides=[
                RuleOverride(rule_id="SEC-PY-001", enabled=False),
            ],
        )

        with pytest.raises(MonotonicPolicyViolationError):
            CentralPolicyDistributionService.verify_monotonic_inheritance(parent, child_relaxing)
