"""Multi-repository fleet compliance aggregation, weighted scoring, and workspace attestation (Phase 28)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.compliance.attestation import (
    AttestationPredicate,
    ScanAttestationStatement,
    VerifiableAttestationEnvelope,
    canonical_json_bytes,
    sign_attestation,
)
from analyzer.compliance.models import (
    ComplianceFramework,
    ComplianceStatus,
    ControlEvaluationResult,
    FrameworkAssessmentResult,
)
from analyzer.models.findings import FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.workspace.models import RepositoryMember, WorkspaceManifest

# Asset Criticality Weight Matrix
CRITICALITY_WEIGHTS: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 4.0,
    FindingSeverity.HIGH: 2.5,
    FindingSeverity.MEDIUM: 1.0,
    FindingSeverity.LOW: 0.5,
    FindingSeverity.INFO: 0.2,
}


class WorkspaceControlRollup(BaseModel):
    """Fleet-wide evaluation for a single regulatory control across multiple repositories."""
    model_config = ConfigDict(frozen=True)

    control_id: str
    framework: ComplianceFramework
    status: ComplianceStatus
    fleet_score: float                   # 0.0 to 1.0
    active_violation_count: int
    suppressed_violation_count: int
    violating_repositories: list[str] = Field(default_factory=list)
    compliant_repositories: list[str] = Field(default_factory=list)


class WorkspaceFrameworkRollup(BaseModel):
    """Fleet-wide compliance posture for a regulatory framework."""
    model_config = ConfigDict(frozen=True)

    framework: ComplianceFramework
    overall_score: float                 # 0.0 to 100.0%
    status: ComplianceStatus
    total_controls: int
    proven_controls: int
    violated_controls: int
    partial_controls: int
    unknown_controls: int
    not_assessed_controls: int
    control_rollups: list[WorkspaceControlRollup] = Field(default_factory=list)


class WorkspaceComplianceSuite(BaseModel):
    """Complete multi-framework rollup across all member repositories in a workspace."""
    workspace_id: str
    composite_health_score: float
    composite_grade: str
    total_repositories: int
    framework_rollups: dict[str, WorkspaceFrameworkRollup] = Field(default_factory=dict)
    workspace_merkle_root: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def compute_workspace_merkle_root(repository_merkle_roots: dict[str, str]) -> str:
    """Compute a deterministic Merkle-of-Merkles root combining all repository Merkle roots.
    
    Leaves are domain-separated with \\x00, sorted deterministically by repo_id,
    and pairwise elevated with interior domain prefix \\x01 (RFC 6962).
    """
    if not repository_merkle_roots:
        return hashlib.sha256(b"EMPTY_WORKSPACE").hexdigest()

    # Domain separation for repo root leaves: \x00 + repo_id:merkle_root
    leaf_digests: list[bytes] = []
    for repo_id in sorted(repository_merkle_roots.keys()):
        root_hex = repository_merkle_roots[repo_id]
        payload = f"{repo_id}:{root_hex}".encode("utf-8")
        leaf_hash = hashlib.sha256(b"\x00" + payload).digest()
        leaf_digests.append(leaf_hash)

    current_level = leaf_digests
    while len(current_level) > 1:
        next_level: list[bytes] = []
        i = 0
        while i < len(current_level):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i + 1]
                combined = hashlib.sha256(b"\x01" + left + right).digest()
                next_level.append(combined)
                i += 2
            else:
                isolated = hashlib.sha256(b"\x01" + left + left).digest()
                next_level.append(isolated)
                i += 1
        current_level = next_level

    return current_level[0].hex()


class FleetComplianceEvaluator:
    """Aggregates and scores regulatory compliance across multiple repositories in a workspace."""

    def __init__(self, manifest: WorkspaceManifest):
        self.manifest = manifest

    def aggregate_compliance(
        self,
        repo_results: dict[str, AnalysisResult],
    ) -> WorkspaceComplianceSuite:
        """Calculate weighted compliance and composite health across scanned repositories."""
        # 1. Compute weighted composite health score
        total_weight = 0.0
        weighted_score_acc = 0.0
        repo_merkle_roots: dict[str, str] = {}

        for repo_member in self.manifest.repositories:
            repo_id = repo_member.id
            res = repo_results.get(repo_id)
            if not res:
                continue

            weight = CRITICALITY_WEIGHTS.get(repo_member.criticality, 1.0)
            repo_score = res.health.overall_score if res.health else 100.0
            weighted_score_acc += (repo_score * weight)
            total_weight += weight

            # Extract finding Merkle root
            if hasattr(res, "attestation") and res.attestation and hasattr(res.attestation, "predicate"):
                repo_merkle_roots[repo_id] = res.attestation.predicate.findings_merkle_root
            elif hasattr(res, "merkle_root") and res.merkle_root:
                repo_merkle_roots[repo_id] = res.merkle_root
            else:
                repo_merkle_roots[repo_id] = hashlib.sha256(f"REPO:{repo_id}:EMPTY".encode("utf-8")).hexdigest()

        composite_score = round(weighted_score_acc / max(0.001, total_weight), 1) if total_weight > 0 else 100.0

        if composite_score >= 90.0:
            composite_grade = "A"
        elif composite_score >= 80.0:
            composite_grade = "B"
        elif composite_score >= 70.0:
            composite_grade = "C"
        elif composite_score >= 60.0:
            composite_grade = "D"
        else:
            composite_grade = "F"

        # 2. Aggregate compliance controls across all frameworks
        framework_rollups: dict[str, WorkspaceFrameworkRollup] = {}
        all_frameworks = [
            ComplianceFramework.PCI_DSS_V4_0,
            ComplianceFramework.HIPAA_SECURITY,
            ComplianceFramework.SOC2_TSC,
            ComplianceFramework.NIST_SP_800_53_R5,
        ]

        for fw in all_frameworks:
            # Map control_id -> list of (repo_id, weight, ControlEvaluationResult)
            ctrl_records: dict[str, list[tuple[str, float, ControlEvaluationResult]]] = {}

            for repo_member in self.manifest.repositories:
                repo_id = repo_member.id
                res = repo_results.get(repo_id)
                if not res or not getattr(res, "compliance", None):
                    continue

                comp_suite = getattr(res, "compliance")
                fw_result: Optional[FrameworkAssessmentResult] = None
                if hasattr(comp_suite, "framework_results"):
                    fw_result = comp_suite.framework_results.get(fw.value) or comp_suite.framework_results.get(fw.name)
                elif isinstance(comp_suite, dict) and "framework_results" in comp_suite:
                    fw_result = comp_suite["framework_results"].get(fw.value)

                if not fw_result:
                    continue

                weight = CRITICALITY_WEIGHTS.get(repo_member.criticality, 1.0)
                evaluations = getattr(fw_result, "control_evaluations", [])
                for ce in evaluations:
                    cid = ce.control.control_id if hasattr(ce.control, "control_id") else str(ce.control)
                    ctrl_records.setdefault(cid, []).append((repo_id, weight, ce))

            # Build control rollups
            control_rollups: list[WorkspaceControlRollup] = []
            proven_cnt = 0
            violated_cnt = 0
            partial_cnt = 0
            unknown_cnt = 0
            not_assessed_cnt = 0
            fw_score_acc = 0.0

            for cid, records in ctrl_records.items():
                ctrl_weight_sum = sum(w for _, w, _ in records)
                weighted_ctrl_score = sum(ce.compliance_score * w for _, w, ce in records)
                ctrl_score = round(weighted_ctrl_score / max(0.001, ctrl_weight_sum), 3)

                total_active = sum(ce.active_violation_count for _, _, ce in records)
                total_supp = sum(ce.suppressed_violation_count for _, _, ce in records)
                violating_repos = [r for r, _, ce in records if ce.active_violation_count > 0]
                compliant_repos = [r for r, _, ce in records if ce.status == ComplianceStatus.PROVEN or ce.status == ComplianceStatus.COMPLIANT]

                # Status resolution: any unsuppressed violation fails the control fleet-wide
                if total_active > 0:
                    c_status = ComplianceStatus.VIOLATED
                    violated_cnt += 1
                elif total_supp > 0:
                    c_status = ComplianceStatus.PARTIAL
                    partial_cnt += 1
                elif any(ce.status == ComplianceStatus.PROVEN for _, _, ce in records):
                    c_status = ComplianceStatus.PROVEN
                    proven_cnt += 1
                else:
                    c_status = ComplianceStatus.NOT_ASSESSED
                    not_assessed_cnt += 1

                fw_score_acc += ctrl_score
                control_rollups.append(
                    WorkspaceControlRollup(
                        control_id=cid,
                        framework=fw,
                        status=c_status,
                        fleet_score=ctrl_score,
                        active_violation_count=total_active,
                        suppressed_violation_count=total_supp,
                        violating_repositories=violating_repos,
                        compliant_repositories=compliant_repos,
                    )
                )

            total_ctrls = len(control_rollups)
            fw_overall_score = round((fw_score_acc / max(1, total_ctrls)) * 100.0, 1)

            if violated_cnt > 0:
                fw_status = ComplianceStatus.VIOLATED
            elif partial_cnt > 0:
                fw_status = ComplianceStatus.PARTIAL
            elif proven_cnt > 0:
                fw_status = ComplianceStatus.PROVEN
            else:
                fw_status = ComplianceStatus.NOT_ASSESSED

            framework_rollups[fw.value] = WorkspaceFrameworkRollup(
                framework=fw,
                overall_score=fw_overall_score,
                status=fw_status,
                total_controls=total_ctrls,
                proven_controls=proven_cnt,
                violated_controls=violated_cnt,
                partial_controls=partial_cnt,
                unknown_controls=unknown_cnt,
                not_assessed_controls=not_assessed_cnt,
                control_rollups=control_rollups,
            )

        workspace_merkle = compute_workspace_merkle_root(repo_merkle_roots)

        return WorkspaceComplianceSuite(
            workspace_id=self.manifest.workspace_id,
            composite_health_score=composite_score,
            composite_grade=composite_grade,
            total_repositories=len(self.manifest.repositories),
            framework_rollups=framework_rollups,
            workspace_merkle_root=workspace_merkle,
        )

    def generate_workspace_attestation(
        self,
        compliance_suite: WorkspaceComplianceSuite,
        secret_key: str,
        key_id: str = "workspace-master-key",
    ) -> VerifiableAttestationEnvelope:
        """Sign a composite in-toto v1.0 DSSE attestation statement for the entire workspace."""
        subjects = [
            {"name": r.id, "uri": r.path}
            for r in self.manifest.repositories
        ]

        predicate = AttestationPredicate(
            tool_name="CodeSentinel-WorkspaceFleet",
            tool_version="0.1.0",
            analysis_timestamp=compliance_suite.timestamp.isoformat(),
            findings_merkle_root=compliance_suite.workspace_merkle_root,
            suppressions_digest=hashlib.sha256(f"WORKSPACE:{self.manifest.workspace_id}".encode("utf-8")).hexdigest(),
            compliance_scores={
                fw: rollup.overall_score for fw, rollup in compliance_suite.framework_rollups.items()
            },
            gate_verdict="PASS" if compliance_suite.composite_health_score >= 70.0 else "FAIL",
            cryptographic_assurance="SYMMETRIC_AUTHENTICATION_ONLY",
        )

        statement = ScanAttestationStatement(
            type_="https://in-toto.io/Statement/v1",
            subject=subjects,
            predicateType="https://codesentinel.dev/attestation/workspace/v1",
            predicate=predicate,
        )

        return sign_attestation(statement, secret_key=secret_key, key_id=key_id)
