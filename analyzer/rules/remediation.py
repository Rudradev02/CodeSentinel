"""Contextual remediation intelligence engine for CodeSentinel (Phase 25).

Generates framework-specific, obligation-aware, evidence-based remediation
guidance for findings, going beyond static rule-level remediation text.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RemediationContext(BaseModel):
    """Rich, contextual remediation guidance for a specific finding instance."""

    # Static guidance from RuleDefinition
    static_remediation: str = Field(default="", description="Default remediation from rule definition")

    # Framework-specific guidance
    framework_guidance: Optional[str] = Field(default=None, description="Framework-specific fix guidance")
    framework: Optional[str] = Field(default=None, description="Detected framework name")

    # Obligation-specific guidance
    obligation_guidance: list[str] = Field(default_factory=list, description="Per-obligation remediation steps")

    # Evidence-based guidance
    evidence_guidance: Optional[str] = Field(default=None, description="Taint-path-based remediation narrative")

    # Sanitizer suggestions
    suggested_sanitizers: list[str] = Field(default_factory=list, description="Recommended sanitizer functions")
    incompatible_sanitizer_warning: Optional[str] = Field(
        default=None, description="Warning about applied but ineffective sanitizer"
    )

    # Effort estimation
    estimated_effort: str = Field(default="UNKNOWN", description="TRIVIAL, MODERATE, SIGNIFICANT, UNKNOWN")
    fix_pattern: Optional[str] = Field(default=None, description="Fix pattern identifier")


# Framework-specific remediation templates keyed by (policy_id, framework)
REMEDIATION_TEMPLATES: dict[tuple[str, Optional[str]], str] = {
    # SQL injection
    ("POL-SQL-01", "FLASK"): (
        "In Flask, replace raw string formatting with parameterized queries: "
        "`db.session.execute(text(':param'), {'param': value})` or use "
        "database ORM methods like `.filter_by()`."
    ),
    ("POL-SQL-01", "DJANGO"): (
        "In Django, use the ORM `.filter()` API or "
        "`connection.cursor().execute(sql, [params])` for raw queries."
    ),
    ("POL-SQL-01", None): (
        "Use parameterized queries or prepared statements. Never concatenate "
        "user input directly into SQL strings."
    ),
    # Command injection
    ("POL-CMD-01", "FLASK"): (
        "Use `subprocess.run([cmd, arg1, arg2], shell=False)` with explicit "
        "argument lists. Apply `shlex.quote()` if shell=True is unavoidable."
    ),
    ("POL-CMD-01", "DJANGO"): (
        "Use `subprocess.run()` with argument lists. Django management commands "
        "should validate and sanitize all external inputs."
    ),
    ("POL-CMD-01", None): (
        "Use `subprocess.run([cmd, arg1, arg2], shell=False)` with explicit "
        "argument lists. Apply `shlex.quote()` if shell=True is unavoidable."
    ),
    # DOM XSS
    ("POL-DOM-01", "REACT"): (
        "Avoid `dangerouslySetInnerHTML`. Render text content directly or "
        "apply `DOMPurify.sanitize()` before injection. Consider using "
        "React's built-in XSS protection via JSX text interpolation."
    ),
    ("POL-DOM-01", "EXPRESS"): (
        "Use a template engine with auto-escaping (e.g., EJS with `<%= %>`). "
        "For API responses, ensure `Content-Type: application/json`."
    ),
    ("POL-DOM-01", None): (
        "Apply HTML escaping or use a DOM sanitization library like DOMPurify "
        "before inserting user-controlled content into the DOM."
    ),
    # Dynamic code evaluation
    ("POL-EVAL-01", None): (
        "Avoid `eval()` and `Function()` with user input. Use safe alternatives "
        "like `JSON.parse()` for data, or `ast.literal_eval()` in Python."
    ),
    # Authorization
    ("POL-AUTHZ-01", "FLASK"): (
        "Add `@login_required` and role-checking decorators to privileged "
        "endpoints. Use Flask-Login or Flask-Principal for RBAC."
    ),
    ("POL-AUTHZ-01", "DJANGO"): (
        "Add `@login_required` and `@permission_required` decorators. "
        "Use Django's built-in permissions framework."
    ),
    ("POL-AUTHZ-01", None): (
        "Ensure privileged operations check both authentication and "
        "authorization before execution."
    ),
}

# Obligation-kind-specific guidance templates
OBLIGATION_GUIDANCE_TEMPLATES: dict[str, str] = {
    "REQUIRES_AUTHENTICATION": (
        "This endpoint requires authenticated access. Add an authentication "
        "guard (decorator, middleware, or assertion) before the sensitive operation."
    ),
    "REQUIRES_AUTHORIZATION": (
        "This endpoint requires authorization. Add a permission or role check "
        "to verify the caller has the necessary privileges."
    ),
    "REQUIRES_PROPERTY": (
        "The required security property is not established on the tainted data. "
        "Apply the appropriate sanitizer or validation function."
    ),
    "REQUIRES_VALIDATION": (
        "Input data must be validated against expected type/format constraints "
        "before reaching the sensitive operation."
    ),
    "REQUIRES_SANITIZER": (
        "Apply a category-compatible sanitizer to the tainted data before "
        "it reaches the sink operation."
    ),
    "REQUIRES_PARAMETERIZATION": (
        "Use query parameterization instead of string interpolation to prevent "
        "injection attacks."
    ),
}

# Fix pattern to effort mapping
FIX_PATTERN_EFFORT: dict[str, str] = {
    "PARAMETERIZE_QUERY": "TRIVIAL",
    "ADD_AUTH_DECORATOR": "TRIVIAL",
    "ADD_AUTHZ_CHECK": "MODERATE",
    "REPLACE_EVAL": "MODERATE",
    "ADD_SANITIZER": "TRIVIAL",
    "REFACTOR_SHELL_COMMAND": "MODERATE",
    "ADD_INPUT_VALIDATION": "MODERATE",
    "REMOVE_DANGEROUS_INNER_HTML": "TRIVIAL",
}


class RemediationContextBuilder:
    """Builds contextual remediation guidance for a specific finding.

    Combines static rule-level advice with framework-specific templates,
    obligation-level guidance, and evidence-chain narratives.
    """

    @staticmethod
    def build(
        finding: Any,
        framework: Optional[str] = None,
        policy_id: Optional[str] = None,
        obligations: Optional[list[Any]] = None,
        evidence_chain: Optional[Any] = None,
    ) -> RemediationContext:
        """Build a RemediationContext for a finding.

        Args:
            finding: A Finding model instance.
            framework: Detected framework name (e.g., "FLASK", "DJANGO").
            policy_id: Associated policy ID if any.
            obligations: List of PolicyProofObligation instances.
            evidence_chain: Optional SecurityEvidenceChain instance.

        Returns:
            A populated RemediationContext.
        """
        static_remediation = getattr(finding, "remediation", "")
        rule_id = getattr(finding, "rule_id", "")

        # 1. Framework-specific guidance
        framework_upper = framework.upper() if framework else None
        framework_guidance = None
        if policy_id:
            framework_guidance = REMEDIATION_TEMPLATES.get((policy_id, framework_upper))
            if framework_guidance is None:
                framework_guidance = REMEDIATION_TEMPLATES.get((policy_id, None))

        # 2. Obligation-specific guidance
        obligation_guidance: list[str] = []
        fix_pattern: Optional[str] = None
        if obligations:
            for obl in obligations:
                obl_state = getattr(obl, "state", None)
                state_val = obl_state.value if hasattr(obl_state, "value") else str(obl_state or "")
                if state_val in ("PROVEN_VIOLATION", "UNKNOWN"):
                    obl_kind = getattr(obl, "kind", None)
                    kind_val = obl_kind.value if hasattr(obl_kind, "value") else str(obl_kind or "")
                    guidance = OBLIGATION_GUIDANCE_TEMPLATES.get(kind_val)
                    if guidance:
                        obligation_guidance.append(guidance)

                    # Determine fix pattern
                    if kind_val == "REQUIRES_PARAMETERIZATION":
                        fix_pattern = "PARAMETERIZE_QUERY"
                    elif kind_val == "REQUIRES_AUTHENTICATION":
                        fix_pattern = "ADD_AUTH_DECORATOR"
                    elif kind_val == "REQUIRES_AUTHORIZATION":
                        fix_pattern = "ADD_AUTHZ_CHECK"
                    elif kind_val == "REQUIRES_SANITIZER":
                        fix_pattern = "ADD_SANITIZER"

        # 3. Evidence-based guidance
        evidence_guidance: Optional[str] = None
        suggested_sanitizers: list[str] = []
        incompatible_warning: Optional[str] = None

        if evidence_chain is not None:
            source = getattr(evidence_chain, "taint_source", None)
            sink = getattr(evidence_chain, "taint_sink", None)
            sanitizer = getattr(evidence_chain, "sanitizer_evaluation", None)

            if source and sink:
                src_expr = getattr(source, "expression", "unknown source")
                src_line = getattr(source, "line", "?")
                sink_callee = getattr(sink, "callee_name", "unknown sink")
                sink_line = getattr(sink, "line", "?")
                chain_depth = getattr(evidence_chain, "chain_depth", 0)

                if chain_depth > 0:
                    evidence_guidance = (
                        f"Tainted data originates from `{src_expr}` (line {src_line}), "
                        f"propagates through {chain_depth} step(s), and reaches "
                        f"`{sink_callee}()` (line {sink_line}) without adequate sanitization."
                    )
                else:
                    evidence_guidance = (
                        f"Tainted data flows from `{src_expr}` (line {src_line}) "
                        f"directly to `{sink_callee}()` (line {sink_line})."
                    )

            if sanitizer is not None:
                is_compatible = getattr(sanitizer, "is_category_compatible", True)
                if not is_compatible:
                    san_id = getattr(sanitizer, "sanitizer_id", "unknown")
                    sink_cat = getattr(sink, "sink_category", "unknown") if sink else "unknown"
                    incompatible_warning = (
                        f"Applied sanitizer `{san_id}` is not effective against "
                        f"{sink_cat}. Use a category-compatible sanitizer."
                    )

            # Suggest sanitizers based on policy
            if policy_id:
                suggested_sanitizers = _suggest_sanitizers(policy_id)

        # 4. Effort estimation
        estimated_effort = FIX_PATTERN_EFFORT.get(fix_pattern or "", "UNKNOWN")

        return RemediationContext(
            static_remediation=static_remediation,
            framework_guidance=framework_guidance,
            framework=framework,
            obligation_guidance=obligation_guidance,
            evidence_guidance=evidence_guidance,
            suggested_sanitizers=suggested_sanitizers,
            incompatible_sanitizer_warning=incompatible_warning,
            estimated_effort=estimated_effort,
            fix_pattern=fix_pattern,
        )


def _suggest_sanitizers(policy_id: str) -> list[str]:
    """Return suggested sanitizer functions for a given policy."""
    suggestions: dict[str, list[str]] = {
        "POL-SQL-01": ["int()", "float()", "psycopg2.sql.Literal()", "parameterized query"],
        "POL-CMD-01": ["shlex.quote()", "subprocess argument list"],
        "POL-DOM-01": ["DOMPurify.sanitize()", "html.escape()", "sanitizeHtml()"],
        "POL-EVAL-01": ["ast.literal_eval()", "JSON.parse()"],
    }
    return suggestions.get(policy_id, [])
