"""Unit tests for Phase 28 Multi-Repository Fleet Compliance Aggregation and Attestation."""

import pytest

from analyzer.compliance.attestation import verify_attestation
from analyzer.compliance.models import (
    ComplianceAssessmentSuite,
    ComplianceControl,
    ComplianceFramework,
    ComplianceStatus,
    ControlEvaluationResult,
    FrameworkAssessmentResult,
)
from analyzer.models.findings import FindingSeverity
from analyzer.models.results import (
    AnalysisResult,
    AnalysisStatus,
    CodebaseHealth,
    RepositoryInfo,
    SubScore,
)
from analyzer.workspace.compliance_rollup import (
    FleetComplianceEvaluator,
    compute_workspace_merkle_root,
)
from analyzer.workspace.models import (
    RepositoryMember,
    WorkspaceConfig,
    WorkspaceManifest,
    WorkspaceRole,
)


@pytest.fixture
def workspace_manifest() -> WorkspaceManifest:
    return WorkspaceManifest(
        workspace_id="ws-payments",
        name="Payments Fleet",
        repositories=[
            RepositoryMember(
                id="repo-gateway",
                path="services/gateway",
                role=WorkspaceRole.PUBLIC_ENTRYPOINT,
                criticality=FindingSeverity.CRITICAL, # Weight 4.0
            ),
            RepositoryMember(
                id="repo-docs",
                path="services/docs",
                role=WorkspaceRole.INTERNAL_SERVICE,
                criticality=FindingSeverity.LOW,      # Weight 0.5
            ),
        ],
    )


class TestWorkspaceMerkleRoot:
    """Tests for Merkle-of-Merkles computation across repositories."""

    def test_merkle_root_determinism(self):
        roots = {
            "repo-b": "bbbb" * 16,
            "repo-a": "aaaa" * 16,
        }
        root1 = compute_workspace_merkle_root(roots)
        root2 = compute_workspace_merkle_root({"repo-a": "aaaa" * 16, "repo-b": "bbbb" * 16})
        assert root1 == root2
        assert len(root1) == 64

    def test_empty_workspace_merkle(self):
        root = compute_workspace_merkle_root({})
        assert len(root) == 64


class TestFleetComplianceEvaluator:
    """Tests for fleet compliance rollup and composite attestation."""

    def test_criticality_weighted_health_score(self, workspace_manifest):
        evaluator = FleetComplianceEvaluator(workspace_manifest)

        # Mock AnalysisResult for repo-gateway (score 80.0, weight 4.0)
        gateway_health = CodebaseHealth(
            overall_score=80.0,
            overall_grade="B",
            architecture_health=SubScore(score=80.0, grade="B"),
            security_posture=SubScore(score=80.0, grade="B"),
        )
        res_gateway = AnalysisResult(
            id="snap-gw",
            status=AnalysisStatus.COMPLETED,
            repository=RepositoryInfo(name="gateway", local_path="/services/gateway"),
            health=gateway_health,
        )

        # Mock AnalysisResult for repo-docs (score 100.0, weight 0.5)
        docs_health = CodebaseHealth(
            overall_score=100.0,
            overall_grade="A",
            architecture_health=SubScore(score=100.0, grade="A"),
            security_posture=SubScore(score=100.0, grade="A"),
        )
        res_docs = AnalysisResult(
            id="snap-docs",
            status=AnalysisStatus.COMPLETED,
            repository=RepositoryInfo(name="docs", local_path="/services/docs"),
            health=docs_health,
        )

        suite = evaluator.aggregate_compliance({
            "repo-gateway": res_gateway,
            "repo-docs": res_docs,
        })

        # Weighted calculation: (80.0 * 4.0 + 100.0 * 0.5) / (4.0 + 0.5) = (320 + 50) / 4.5 = 370 / 4.5 = 82.2
        assert round(suite.composite_health_score, 1) == 82.2
        assert suite.composite_grade == "B"
        assert suite.total_repositories == 2

    def test_strict_violation_propagation(self, workspace_manifest):
        evaluator = FleetComplianceEvaluator(workspace_manifest)

        ctrl_pci = ComplianceControl(
            control_id="PCI-6.2.4",
            framework=ComplianceFramework.PCI_DSS_V4_0,
            name="Vulnerability Mitigation",
            section="Req 6",
            description="Prevent SQLi",
        )

        # Gateway has an active violation on PCI-6.2.4
        ce_gateway = ControlEvaluationResult(
            control=ctrl_pci,
            status=ComplianceStatus.VIOLATED,
            active_violation_count=1,
            compliance_score=0.0,
        )
        fw_gw = FrameworkAssessmentResult(
            framework=ComplianceFramework.PCI_DSS_V4_0,
            overall_score=0.0,
            status=ComplianceStatus.VIOLATED,
            total_controls=1,
            compliant_controls=0,
            partial_controls=0,
            non_compliant_controls=1,
            control_evaluations=[ce_gateway],
        )
        comp_gw = ComplianceAssessmentSuite(
            framework_results={ComplianceFramework.PCI_DSS_V4_0.value: fw_gw}
        )

        # Docs is compliant on PCI-6.2.4
        ce_docs = ControlEvaluationResult(
            control=ctrl_pci,
            status=ComplianceStatus.PROVEN,
            active_violation_count=0,
            compliance_score=1.0,
        )
        fw_docs = FrameworkAssessmentResult(
            framework=ComplianceFramework.PCI_DSS_V4_0,
            overall_score=100.0,
            status=ComplianceStatus.PROVEN,
            total_controls=1,
            compliant_controls=1,
            partial_controls=0,
            non_compliant_controls=0,
            control_evaluations=[ce_docs],
        )
        comp_docs = ComplianceAssessmentSuite(
            framework_results={ComplianceFramework.PCI_DSS_V4_0.value: fw_docs}
        )

        res_gw = AnalysisResult(
            id="gw",
            status=AnalysisStatus.COMPLETED,
            repository=RepositoryInfo(name="gateway", local_path="/services/gateway"),
        )
        res_gw.compliance = comp_gw

        res_docs = AnalysisResult(
            id="docs",
            status=AnalysisStatus.COMPLETED,
            repository=RepositoryInfo(name="docs", local_path="/services/docs"),
        )
        res_docs.compliance = comp_docs

        suite = evaluator.aggregate_compliance({
            "repo-gateway": res_gw,
            "repo-docs": res_docs,
        })

        pci_rollup = suite.framework_rollups[ComplianceFramework.PCI_DSS_V4_0.value]
        # Any active violation in scope marks the fleet control as VIOLATED
        assert pci_rollup.status == ComplianceStatus.VIOLATED
        assert len(pci_rollup.control_rollups) == 1
        ctrl_rollup = pci_rollup.control_rollups[0]
        assert ctrl_rollup.status == ComplianceStatus.VIOLATED
        assert ctrl_rollup.violating_repositories == ["repo-gateway"]

    def test_workspace_attestation_signing_and_verification(self, workspace_manifest):
        evaluator = FleetComplianceEvaluator(workspace_manifest)
        res_gw = AnalysisResult(
            id="gw",
            status=AnalysisStatus.COMPLETED,
            repository=RepositoryInfo(name="gateway", local_path="/services/gateway"),
        )
        res_docs = AnalysisResult(
            id="docs",
            status=AnalysisStatus.COMPLETED,
            repository=RepositoryInfo(name="docs", local_path="/services/docs"),
        )

        suite = evaluator.aggregate_compliance({
            "repo-gateway": res_gw,
            "repo-docs": res_docs,
        })

        secret = "enterprise-master-test-key-42"
        envelope = evaluator.generate_workspace_attestation(suite, secret_key=secret)

        is_valid, msg, statement = verify_attestation(envelope, secret_key=secret)
        assert is_valid is True
        assert "Attestation verified successfully" in msg
        assert statement is not None
        assert statement.predicate.findings_merkle_root == suite.workspace_merkle_root
        assert len(statement.subject) == 2
