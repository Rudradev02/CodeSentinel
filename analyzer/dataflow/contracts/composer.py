"""Contract composition and multi-hop compatibility evaluation engine (Phase 20)."""

from typing import Any, Optional
from analyzer.dataflow.cfg.models import PathState, RefinementFact
from analyzer.dataflow.contracts.composition import (
    CompatibilityState,
    ContractCompositionEdge,
    ContractCompositionResult,
    ContractConflict,
    ContractGuarantee,
    ContractRequirement,
)
from analyzer.dataflow.contracts.models import FunctionContract, PreconditionKind, ReturnAliasKind
from analyzer.dataflow.contracts.security_boundary import SecurityBoundaryModel


class ContractComposer:
    """Composes producer contract guarantees with consumer requirements across call boundaries."""

    def __init__(self, max_composition_depth: int = 4, max_conflicts: int = 50):
        self.max_composition_depth = max_composition_depth
        self.max_conflicts = max_conflicts

    def evaluate_guarantee_against_requirement(
        self,
        guarantee: ContractGuarantee,
        requirement: ContractRequirement,
        rule_id: Optional[str] = None,
    ) -> tuple[CompatibilityState, str]:
        """Evaluate whether a single guarantee satisfies a requirement."""
        # 1. First consult rule-specific security boundary model if a sink is involved
        if requirement.sink_category or rule_id:
            return SecurityBoundaryModel.evaluate_boundary(guarantee, requirement, rule_id=rule_id)

        # 2. Type requirements
        if requirement.required_kind == PreconditionKind.TYPE_REFINEMENT:
            if guarantee.refinement and guarantee.refinement.refined_type:
                gt = guarantee.refinement.refined_type
                if requirement.required_type and gt == requirement.required_type:
                    return (CompatibilityState.SATISFIED, f"Type '{gt}' matches required type")
                if requirement.required_type in ("int", "float", "integer") and gt in ("int", "float", "integer"):
                    return (CompatibilityState.SATISFIED, f"Type '{gt}' satisfies numeric requirement")
                if requirement.required_type in ("int", "float") and gt == "str":
                    return (CompatibilityState.VIOLATED, f"Type '{gt}' contradicts numeric requirement")
            return (CompatibilityState.UNKNOWN, "Unproven type requirement")

        # 3. Format requirements
        if requirement.required_kind == PreconditionKind.FORMAT_REFINEMENT:
            if guarantee.refinement:
                if guarantee.refinement.is_numeric_string:
                    return (CompatibilityState.SATISFIED, "Numeric string format satisfies format requirement")
                if guarantee.refinement.is_alphanumeric_string and requirement.required_type == "is_alphanumeric_string":
                    return (CompatibilityState.SATISFIED, "Alphanumeric format matches requirement")
            return (CompatibilityState.UNKNOWN, "Unproven format requirement")

        # 4. Nullity requirements
        if requirement.required_kind == PreconditionKind.NULLITY_REFINEMENT:
            if guarantee.refinement and guarantee.refinement.is_non_null:
                return (CompatibilityState.SATISFIED, "Non-null guarantee satisfies nullity requirement")
            return (CompatibilityState.UNKNOWN, "Unproven nullity requirement")

        return (CompatibilityState.UNKNOWN, "No conclusive proof")

    def detect_conflicts(
        self,
        guarantees: list[ContractGuarantee],
        path_condition: Optional[str] = None,
    ) -> list[ContractConflict]:
        """Detect contradictory facts active along the same path."""
        conflicts: list[ContractConflict] = []
        by_var: dict[str, list[ContractGuarantee]] = {}
        for g in guarantees:
            by_var.setdefault(g.target_var_name, []).append(g)

        for var, g_list in by_var.items():
            if len(g_list) < 2:
                continue
            types_seen = set()
            for g in g_list:
                if g.refinement and g.refinement.refined_type:
                    types_seen.add(g.refinement.refined_type)
            if "int" in types_seen and "str" in types_seen:
                conflicts.append(
                    ContractConflict(
                        variable_name=var,
                        guarantees=g_list,
                        conflict_reason=f"Opposing types {types_seen} claimed simultaneously for '{var}'",
                        path_condition=path_condition,
                    )
                )
        return conflicts

    def compose_multi_hop_chain(
        self,
        guarantees: list[ContractGuarantee],
        callee_contract: FunctionContract,
        caller_arg_names: list[str],
        rule_id: Optional[str] = None,
        current_depth: int = 1,
    ) -> ContractCompositionResult:
        """Compose a set of active guarantees against a callee contract's preconditions."""
        edges: list[ContractCompositionEdge] = []
        conflicts: list[ContractConflict] = self.detect_conflicts(guarantees)

        is_truncated = current_depth > self.max_composition_depth

        if conflicts:
            overall = CompatibilityState.CONFLICTING
        elif is_truncated:
            overall = CompatibilityState.TRUNCATED
        else:
            overall = CompatibilityState.SATISFIED

        # Map each callee precondition to available guarantees
        for pre in callee_contract.preconditions:
            req = ContractRequirement(
                consumer_qn=callee_contract.qualified_name,
                consumer_file=callee_contract.file_path,
                consumer_line=pre.line,
                target_param_index=pre.target_param_index,
                target_param_name=pre.target_param_name,
                target_field_name=pre.target_field_name,
                required_kind=pre.kind,
                required_type=pre.required_type,
                required_sanitizer=pre.required_sanitizer_category,
                sink_category=pre.sink_category,
            )

            # Find matching guarantee by parameter argument position
            matched_g = None
            if pre.target_param_index < len(caller_arg_names):
                arg_name = caller_arg_names[pre.target_param_index]
                for g in guarantees:
                    if g.target_var_name == arg_name:
                        if pre.target_field_name and g.target_field_name:
                            if pre.target_field_name == g.target_field_name:
                                matched_g = g
                                break
                        elif not pre.target_field_name and not g.target_field_name:
                            matched_g = g
                            break

            if matched_g is None:
                # No guarantee exists for this requirement
                edge = ContractCompositionEdge(
                    guarantee=ContractGuarantee(
                        producer_qn="UNKNOWN",
                        producer_file="",
                        producer_line=0,
                        target_var_name=caller_arg_names[pre.target_param_index] if pre.target_param_index < len(caller_arg_names) else "arg",
                    ),
                    requirement=req,
                    compatibility=CompatibilityState.UNKNOWN,
                    details="No upstream guarantee provided for parameter",
                )
                edges.append(edge)
                if overall == CompatibilityState.SATISFIED:
                    overall = CompatibilityState.UNKNOWN
            else:
                compat, details = self.evaluate_guarantee_against_requirement(matched_g, req, rule_id=rule_id)
                edge = ContractCompositionEdge(
                    guarantee=matched_g,
                    requirement=req,
                    compatibility=compat,
                    details=details,
                )
                edges.append(edge)
                if compat == CompatibilityState.VIOLATED:
                    overall = CompatibilityState.VIOLATED
                elif compat == CompatibilityState.UNKNOWN and overall == CompatibilityState.SATISFIED:
                    overall = CompatibilityState.UNKNOWN

        return ContractCompositionResult(
            edges=edges,
            conflicts=conflicts,
            overall_compatibility=overall,
            composition_depth=current_depth,
            is_truncated=is_truncated,
        )
