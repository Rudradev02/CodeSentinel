"""Automated compliance evaluation and gap analysis engine (Phase 26)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from analyzer.compliance.catalogs import get_controls_for_framework
from analyzer.compliance.models import (
    ComplianceAssessmentSuite,
    ComplianceControl,
    ComplianceFramework,
    ComplianceStatus,
    ControlEvaluationResult,
    FrameworkAssessmentResult,
)
from analyzer.models.findings import Finding
from analyzer.models.obligation import ObligationEvaluationState


class ComplianceEvaluator:
    """Evaluates static analysis findings against regulatory compliance control catalogs."""

    def __init__(self, frameworks: Optional[list[ComplianceFramework]] = None):
        self.frameworks = frameworks or [
            ComplianceFramework.PCI_DSS_V4_0,
            ComplianceFramework.HIPAA_SECURITY,
            ComplianceFramework.SOC2_TSC,
            ComplianceFramework.NIST_SP_800_53_R5,
        ]

    def _is_finding_suppressed(self, finding: Finding) -> bool:
        """Determine if a finding is actively suppressed or deferred."""
        # Check evidence dict
        evidence = finding.evidence or {}
        if evidence.get("suppressed") is True or evidence.get("is_suppressed") is True:
            return True
        if evidence.get("lifecycle_state") in ("SUPPRESSED", "DEFERRED"):
            return True

        # Check description or message keywords if marked by suppression engine
        return False

    def evaluate_control(
        self,
        control: ComplianceControl,
        findings: list[Finding],
    ) -> ControlEvaluationResult:
        """Evaluate a single compliance control against detected repository findings."""
        relevant_findings: list[Finding] = []
        violating_findings: list[Finding] = []
        suppressed_findings: list[Finding] = []
        obligation_stats: dict[str, int] = {
            "PROVEN_SAFE": 0,
            "PROVEN_VIOLATION": 0,
            "UNKNOWN": 0,
        }

        rule_set = set(control.mapped_rule_ids)
        policy_set = set(control.mapped_policy_ids)

        for f in findings:
            is_relevant = False
            if f.rule_id in rule_set:
                is_relevant = True
            elif f.evidence and f.evidence.get("policy_id") in policy_set:
                is_relevant = True

            if not is_relevant:
                continue

            relevant_findings.append(f)

            # Inspect proof obligations if present in evidence
            if f.evidence and "proof_obligations" in f.evidence:
                raw_obls = f.evidence["proof_obligations"]
                if isinstance(raw_obls, list):
                    for obl in raw_obls:
                        if isinstance(obl, dict):
                            state = obl.get("state", "UNKNOWN")
                            obligation_stats[state] = obligation_stats.get(state, 0) + 1

            if self._is_finding_suppressed(f):
                suppressed_findings.append(f)
            else:
                violating_findings.append(f)

        # Status and scoring
        total_rel = len(relevant_findings)
        active_viols = len(violating_findings)
        supp_viols = len(suppressed_findings)

        if active_viols == 0 and supp_viols == 0:
            status = ComplianceStatus.COMPLIANT
            score = 1.0
        elif active_viols == 0 and supp_viols > 0:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            score = 0.8
        else:
            status = ComplianceStatus.NON_COMPLIANT
            # Degrade score with active violations
            score = max(0.0, 1.0 - (0.2 * active_viols))

        # Build prioritized remediation actions
        remediation_actions: list[str] = []
        if control.guidance:
            remediation_actions.append(control.guidance)
        for vf in violating_findings[:5]:
            remediation_actions.append(
                f"[{vf.rule_id}] {vf.location.file_path}:{vf.location.line_start} - {vf.remediation}"
            )

        return ControlEvaluationResult(
            control=control,
            status=status,
            total_relevant_findings=total_rel,
            active_violation_count=active_viols,
            suppressed_violation_count=supp_viols,
            violating_findings=violating_findings,
            suppressed_findings=suppressed_findings,
            proof_obligation_stats=obligation_stats,
            compliance_score=round(score, 3),
            remediation_actions=remediation_actions,
        )

    def evaluate_framework(
        self,
        framework: ComplianceFramework,
        findings: list[Finding],
    ) -> FrameworkAssessmentResult:
        """Evaluate all controls for a specific regulatory compliance framework."""
        controls = get_controls_for_framework(framework)
        evaluations: list[ControlEvaluationResult] = []

        compliant_count = 0
        partial_count = 0
        non_compliant_count = 0
        total_unresolved = 0
        total_suppressed = 0
        total_score_acc = 0.0

        for ctrl in controls:
            result = self.evaluate_control(ctrl, findings)
            evaluations.append(result)
            total_score_acc += result.compliance_score
            total_unresolved += result.active_violation_count
            total_suppressed += result.suppressed_violation_count

            if result.status == ComplianceStatus.COMPLIANT:
                compliant_count += 1
            elif result.status in (ComplianceStatus.PARTIALLY_COMPLIANT, ComplianceStatus.PARTIAL):
                partial_count += 1
            else:
                non_compliant_count += 1

        total_ctrls = len(controls)
        if total_ctrls > 0:
            overall_pct = round((total_score_acc / total_ctrls) * 100.0, 1)
        else:
            overall_pct = 100.0

        if non_compliant_count > 0:
            overall_status = ComplianceStatus.NON_COMPLIANT
        elif partial_count > 0:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.COMPLIANT

        return FrameworkAssessmentResult(
            framework=framework,
            overall_score=overall_pct,
            status=overall_status,
            total_controls=total_ctrls,
            compliant_controls=compliant_count,
            partial_controls=partial_count,
            non_compliant_controls=non_compliant_count,
            control_evaluations=evaluations,
            unresolved_violations_count=total_unresolved,
            suppressed_exceptions_count=total_suppressed,
        )

    def assess_suite(
        self,
        findings: list[Finding],
        repository_path: str = "",
        git_commit_hash: Optional[str] = None,
        config_digest: str = "",
    ) -> ComplianceAssessmentSuite:
        """Perform comprehensive assessment across all enabled compliance frameworks."""
        framework_results: dict[str, FrameworkAssessmentResult] = {}
        summary_lines: list[str] = []

        for fw in self.frameworks:
            res = self.evaluate_framework(fw, findings)
            framework_results[fw.value] = res
            summary_lines.append(
                f"- {fw.value}: {res.overall_score}% ({res.status.value}) - "
                f"{res.compliant_controls}/{res.total_controls} controls compliant, "
                f"{res.unresolved_violations_count} unresolved violations."
            )

        exec_summary = (
            f"CodeSentinel Compliance Assessment Suite executed at {datetime.now(timezone.utc).isoformat()}.\n"
            + "\n".join(summary_lines)
        )

        return ComplianceAssessmentSuite(
            timestamp=datetime.now(timezone.utc),
            repository_path=repository_path,
            git_commit_hash=git_commit_hash,
            config_digest=config_digest,
            framework_results=framework_results,
            executive_summary=exec_summary,
        )
