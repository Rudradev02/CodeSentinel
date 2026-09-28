"""Automated compliance evaluation and gap analysis engine (Phase 26/27)."""

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


class ComplianceEvaluator:
    """Evaluates static analysis findings against regulatory compliance control catalogs."""

    def __init__(
        self,
        frameworks: Optional[list[ComplianceFramework]] = None,
        require_proven: bool = False,
    ):
        self.frameworks = frameworks or [
            ComplianceFramework.PCI_DSS_V4_0,
            ComplianceFramework.HIPAA_SECURITY,
            ComplianceFramework.SOC2_TSC,
            ComplianceFramework.NIST_SP_800_53_R5,
        ]
        self.require_proven = require_proven

    def _is_finding_suppressed(self, finding: Finding, now: Optional[datetime] = None) -> bool:
        """Determine if a finding is actively suppressed, checking expiration."""
        evidence = finding.evidence or {}

        # If explicitly marked as expired suppression
        if evidence.get("lifecycle_state") == "EXPIRED_SUPPRESSION":
            return False

        # Check timed deferral expiration
        if "suppression_expires_at" in evidence:
            raw_exp = evidence["suppression_expires_at"]
            if raw_exp:
                try:
                    ref_now = now or datetime.now(timezone.utc)
                    exp_dt = datetime.fromisoformat(str(raw_exp))
                    if exp_dt.tzinfo is None:
                        ref_now = ref_now.replace(tzinfo=None)
                    if ref_now > exp_dt:
                        return False  # Expired suppression reverts finding to active
                except Exception:
                    pass

        if evidence.get("suppressed") is True or evidence.get("is_suppressed") is True:
            return True
        if evidence.get("lifecycle_state") in ("SUPPRESSED", "DEFERRED"):
            return True

        return False

    def evaluate_control(
        self,
        control: ComplianceControl,
        findings: list[Finding],
        require_proven: Optional[bool] = None,
        now: Optional[datetime] = None,
    ) -> ControlEvaluationResult:
        """Evaluate a single compliance control against detected repository findings."""
        strict_mode = self.require_proven if require_proven is None else require_proven
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

            if self._is_finding_suppressed(f, now=now):
                suppressed_findings.append(f)
            else:
                violating_findings.append(f)

        # Status and scoring
        total_rel = len(relevant_findings)
        active_viols = len(violating_findings)
        supp_viols = len(suppressed_findings)

        proven_obls = obligation_stats.get("PROVEN_SAFE", 0)
        violated_obls = obligation_stats.get("PROVEN_VIOLATION", 0)
        unknown_obls = obligation_stats.get("UNKNOWN", 0)

        if active_viols > 0:
            status = ComplianceStatus.NON_COMPLIANT
            score = max(0.0, 1.0 - (0.2 * active_viols))
        elif supp_viols > 0:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            score = 0.8
        else:
            if strict_mode:
                if proven_obls > 0 and violated_obls == 0 and unknown_obls == 0:
                    status = ComplianceStatus.PROVEN
                    score = 1.0
                else:
                    status = ComplianceStatus.UNKNOWN
                    score = 0.5
            else:
                status = ComplianceStatus.COMPLIANT
                score = 1.0

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
            proven_obligations_count=proven_obls,
            violated_obligations_count=violated_obls,
            unknown_obligations_count=unknown_obls,
            compliance_score=round(score, 3),
            remediation_actions=remediation_actions,
            limitations_noted=list(control.static_limitations),
        )

    def evaluate_framework(
        self,
        framework: ComplianceFramework,
        findings: list[Finding],
        require_proven: Optional[bool] = None,
        now: Optional[datetime] = None,
    ) -> FrameworkAssessmentResult:
        """Evaluate all controls for a specific regulatory compliance framework."""
        strict_mode = self.require_proven if require_proven is None else require_proven
        controls = get_controls_for_framework(framework)
        evaluations: list[ControlEvaluationResult] = []

        compliant_count = 0
        partial_count = 0
        non_compliant_count = 0
        proven_count = 0
        violated_count = 0
        unknown_count = 0
        not_assessed_count = 0

        total_unresolved = 0
        total_suppressed = 0
        total_score_acc = 0.0

        for ctrl in controls:
            result = self.evaluate_control(ctrl, findings, require_proven=strict_mode, now=now)
            evaluations.append(result)
            total_score_acc += result.compliance_score
            total_unresolved += result.active_violation_count
            total_suppressed += result.suppressed_violation_count

            if result.status == ComplianceStatus.PROVEN:
                proven_count += 1
                compliant_count += 1
            elif result.status == ComplianceStatus.COMPLIANT:
                compliant_count += 1
                if result.proven_obligations_count > 0:
                    proven_count += 1
                else:
                    unknown_count += 1
            elif result.status in (ComplianceStatus.PARTIALLY_COMPLIANT, ComplianceStatus.PARTIAL):
                partial_count += 1
            elif result.status in (ComplianceStatus.NON_COMPLIANT, ComplianceStatus.VIOLATED):
                non_compliant_count += 1
                violated_count += 1
            elif result.status == ComplianceStatus.UNKNOWN:
                unknown_count += 1
            elif result.status in (ComplianceStatus.NOT_ASSESSED, ComplianceStatus.NOT_APPLICABLE):
                not_assessed_count += 1

        total_ctrls = len(controls)
        if total_ctrls > 0:
            overall_pct = round((total_score_acc / total_ctrls) * 100.0, 1)
        else:
            overall_pct = 100.0

        if non_compliant_count > 0:
            overall_status = ComplianceStatus.NON_COMPLIANT
        elif partial_count > 0:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        elif strict_mode and unknown_count > 0:
            overall_status = ComplianceStatus.UNKNOWN
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
            proven_controls=proven_count,
            violated_controls=violated_count,
            unknown_controls=unknown_count,
            not_assessed_controls=not_assessed_count,
            catalog_version="2026.1",
            mapping_version="2026.1",
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
        require_proven: Optional[bool] = None,
        now: Optional[datetime] = None,
    ) -> ComplianceAssessmentSuite:
        """Perform comprehensive assessment across all enabled compliance frameworks."""
        strict_mode = self.require_proven if require_proven is None else require_proven
        framework_results: dict[str, FrameworkAssessmentResult] = {}
        summary_lines: list[str] = []

        for fw in self.frameworks:
            res = self.evaluate_framework(fw, findings, require_proven=strict_mode, now=now)
            framework_results[fw.value] = res
            summary_lines.append(
                f"- {fw.value}: {res.overall_score}% ({res.status.value}) - "
                f"{res.compliant_controls}/{res.total_controls} controls compliant, "
                f"{res.unresolved_violations_count} unresolved violations."
            )

        ref_time = now or datetime.now(timezone.utc)
        exec_summary = (
            f"CodeSentinel Compliance Assessment Suite executed at {ref_time.isoformat()}.\n"
            + "\n".join(summary_lines)
        )

        return ComplianceAssessmentSuite(
            timestamp=ref_time,
            repository_path=repository_path,
            git_commit_hash=git_commit_hash,
            config_digest=config_digest,
            framework_results=framework_results,
            executive_summary=exec_summary,
        )
