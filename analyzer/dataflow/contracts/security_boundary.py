"""Rule-specific security boundary compatibility matrix (Phase 20).

Enforces strict sink-to-sanitizer and sink-to-refinement compatibility,
ensuring sanitizers for one category (e.g. DOM escaping) do not falsely
satisfy sinks of another category (e.g. SQL or Command execution).
"""

from typing import Optional
from analyzer.dataflow.contracts.composition import CompatibilityState, ContractGuarantee, ContractRequirement
from analyzer.dataflow.taint.models import SinkCategory


class SecurityBoundaryRuleSpec:
    """Specification of acceptable sanitizers and refinements for a rule category."""

    def __init__(
        self,
        rule_id: str,
        sink_category: SinkCategory,
        accepted_sanitizers: list[SinkCategory],
        accepted_types: list[str],
        accepted_formats: list[str],
        incompatible_sanitizers: list[SinkCategory],
    ):
        self.rule_id = rule_id
        self.sink_category = sink_category
        self.accepted_sanitizers = set(accepted_sanitizers)
        self.accepted_types = set(accepted_types)
        self.accepted_formats = set(accepted_formats)
        self.incompatible_sanitizers = set(incompatible_sanitizers)


# Canonical registry of rule-specific security boundaries
SECURITY_BOUNDARY_SPECS: dict[str, SecurityBoundaryRuleSpec] = {
    "SEC-PY-011": SecurityBoundaryRuleSpec(
        rule_id="SEC-PY-011",
        sink_category=SinkCategory.SQL_EXECUTE,
        accepted_sanitizers=[SinkCategory.SQL_EXECUTE],
        accepted_types=["int", "float", "bool", "integer"],
        accepted_formats=["is_numeric_string"],
        incompatible_sanitizers=[SinkCategory.DOM_INJECTION, SinkCategory.COMMAND_EXECUTE],
    ),
    "SEC-PY-012": SecurityBoundaryRuleSpec(
        rule_id="SEC-PY-012",
        sink_category=SinkCategory.COMMAND_EXECUTE,
        accepted_sanitizers=[SinkCategory.COMMAND_EXECUTE],
        accepted_types=[],
        accepted_formats=["is_alphanumeric_string"],
        incompatible_sanitizers=[SinkCategory.SQL_EXECUTE, SinkCategory.DOM_INJECTION],
    ),
    "SEC-JS-009": SecurityBoundaryRuleSpec(
        rule_id="SEC-JS-009",
        sink_category=SinkCategory.DOM_INJECTION,
        accepted_sanitizers=[SinkCategory.DOM_INJECTION],
        accepted_types=["int", "float", "bool"],
        accepted_formats=["is_numeric_string", "is_alphanumeric_string"],
        incompatible_sanitizers=[SinkCategory.SQL_EXECUTE],
    ),
    "SEC-JS-010": SecurityBoundaryRuleSpec(
        rule_id="SEC-JS-010",
        sink_category=SinkCategory.CODE_EVAL,
        accepted_sanitizers=[SinkCategory.CODE_EVAL],
        accepted_types=["int", "float", "bool"],
        accepted_formats=["is_numeric_string"],
        incompatible_sanitizers=[SinkCategory.DOM_INJECTION, SinkCategory.SQL_EXECUTE],
    ),
}


class SecurityBoundaryModel:
    """Evaluates contract guarantees against rule-specific sink requirements."""

    @classmethod
    def evaluate_boundary(
        cls,
        guarantee: Optional[ContractGuarantee] = None,
        requirement: Optional[ContractRequirement] = None,
        rule_id: Optional[str] = None,
        *,
        sink_rule_id: Optional[str] = None,
        sanitizer_rule_id: Optional[str] = None,
        sink_category: Optional[SinkCategory] = None,
        sanitizer_category: Optional[Any] = None,
    ) -> Any:
        """Evaluate security boundary compatibility between guarantees/sanitizers and sink requirements."""
        if guarantee is None and requirement is None:
            return cls._evaluate_direct(
                sink_rule_id=sink_rule_id or rule_id,
                sanitizer_rule_id=sanitizer_rule_id,
                sink_category=sink_category,
                sanitizer_category=sanitizer_category,
            )

        if guarantee is not None and requirement is not None:
            return cls._evaluate_contract(guarantee, requirement, rule_id=rule_id or sink_rule_id)

        return (CompatibilityState.UNKNOWN, "Incomplete contract boundary arguments")

    @classmethod
    def _evaluate_direct(
        cls,
        sink_rule_id: Optional[str],
        sanitizer_rule_id: Optional[str],
        sink_category: Optional[SinkCategory],
        sanitizer_category: Optional[Any],
    ) -> CompatibilityState:
        if not sanitizer_category:
            return CompatibilityState.UNKNOWN

        san_enum: Optional[SinkCategory] = None
        if isinstance(sanitizer_category, SinkCategory):
            san_enum = sanitizer_category
        elif isinstance(sanitizer_category, str):
            try:
                san_enum = SinkCategory(sanitizer_category)
            except ValueError:
                # Custom or unrecognized sanitizer fails closed
                return CompatibilityState.VIOLATED

        target_rule = sink_rule_id
        if sink_category:
            for rid, spec in SECURITY_BOUNDARY_SPECS.items():
                if spec.sink_category == sink_category:
                    target_rule = rid
                    break

        spec = SECURITY_BOUNDARY_SPECS.get(target_rule or "")
        target_sink = sink_category or (spec.sink_category if spec else None)

        if spec and san_enum:
            if san_enum in spec.incompatible_sanitizers:
                return CompatibilityState.VIOLATED
            if target_sink and san_enum != target_sink and san_enum not in spec.accepted_sanitizers:
                return CompatibilityState.VIOLATED
            if san_enum in spec.accepted_sanitizers:
                return CompatibilityState.SATISFIED

        if target_sink and san_enum:
            if san_enum == target_sink:
                return CompatibilityState.SATISFIED
            else:
                return CompatibilityState.VIOLATED

        return CompatibilityState.UNKNOWN

    @classmethod
    def _evaluate_contract(
        cls,
        guarantee: ContractGuarantee,
        requirement: ContractRequirement,
        rule_id: Optional[str] = None,
    ) -> tuple[CompatibilityState, str]:
        target_rule = rule_id
        if not target_rule and requirement.sink_category:
            for rid, spec in SECURITY_BOUNDARY_SPECS.items():
                if spec.sink_category == requirement.sink_category:
                    target_rule = rid
                    break

        spec = SECURITY_BOUNDARY_SPECS.get(target_rule or "")
        sink_cat = requirement.sink_category or (spec.sink_category if spec else None)

        # 1. Check sanitizer category
        if guarantee.sanitizer_category:
            guar_san = guarantee.sanitizer_category
            if spec:
                if guar_san in spec.incompatible_sanitizers:
                    return (
                        CompatibilityState.VIOLATED,
                        f"Incompatible sanitizer '{guar_san.value}' for sink category '{spec.sink_category.value}'",
                    )
                if guar_san in spec.accepted_sanitizers:
                    return (CompatibilityState.SATISFIED, f"Sanitizer '{guar_san.value}' verified for rule '{spec.rule_id}'")
            elif sink_cat and guar_san == sink_cat:
                return (CompatibilityState.SATISFIED, f"Sanitizer '{guar_san.value}' matches sink '{sink_cat.value}'")
            elif sink_cat and guar_san != sink_cat:
                return (
                    CompatibilityState.VIOLATED,
                    f"Sanitizer '{guar_san.value}' does not match sink '{sink_cat.value}'",
                )

        # 2. Check refinement facts (type or format)
        if guarantee.refinement:
            ref = guarantee.refinement
            # Check type
            if ref.refined_type:
                if spec and ref.refined_type in spec.accepted_types:
                    return (CompatibilityState.SATISFIED, f"Type '{ref.refined_type}' satisfies rule '{spec.rule_id}'")
                if requirement.required_type and ref.refined_type == requirement.required_type:
                    return (CompatibilityState.SATISFIED, f"Type '{ref.refined_type}' matches required type")

            # Check format
            if ref.is_numeric_string:
                if spec and "is_numeric_string" in spec.accepted_formats:
                    return (CompatibilityState.SATISFIED, f"Numeric string format satisfies rule '{spec.rule_id}'")
            if ref.is_alphanumeric_string:
                if spec and "is_alphanumeric_string" in spec.accepted_formats:
                    return (CompatibilityState.SATISFIED, f"Alphanumeric format satisfies rule '{spec.rule_id}'")

        # 3. Absence of proof is UNKNOWN (UNKNOWN != SAFE)
        return (CompatibilityState.UNKNOWN, "Insufficient evidence to prove security boundary safety")
