"""Contract evaluation, precondition verification, and postcondition binding engine (Phase 19)."""

from typing import Any, Optional

from analyzer.dataflow.cfg.models import GuardCondition, PathConstraint, PathFeasibilityStatus, PathState, RefinementFact
from analyzer.dataflow.contracts.models import (
    ContractVerificationStatus,
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.dataflow.taint.models import SinkCategory


class ContractEvaluator:
    """Evaluates callee function contracts against caller active path states."""

    def verify_precondition(
        self,
        precondition: SummaryPrecondition,
        path_state: PathState,
        caller_arg_name: str,
    ) -> ContractVerificationStatus:
        """Verify if a caller's active PathState satisfies a callee SummaryPrecondition.
        
        Strict safety invariant:
        - SATISFIED: Statically proven safe by active refinements.
        - VIOLATED: Statically proven incompatible/contradictory.
        - UNKNOWN: Absence of proof; conservative fallback (UNKNOWN != SAFE).
        """
        # If the path itself is already infeasible, return INFEASIBLE
        if path_state.constraints.feasibility == PathFeasibilityStatus.INFEASIBLE:
            return ContractVerificationStatus.INFEASIBLE

        # If the path was widened or truncated, return that status
        if path_state.constraints.is_widened:
            return ContractVerificationStatus.WIDENED
        if path_state.constraints.is_truncated:
            return ContractVerificationStatus.TRUNCATED

        target_facts = path_state.constraints.refinement_facts.get(caller_arg_name, [])

        # Check field refinement if precondition targets a field (e.g. record.id)
        if precondition.target_field_name:
            field_key = f"{caller_arg_name}.{precondition.target_field_name}"
            field_facts = path_state.constraints.refinement_facts.get(field_key, [])
            target_facts = target_facts + field_facts

        if precondition.kind == PreconditionKind.TYPE_REFINEMENT:
            # Check for positive type match
            for fact in target_facts:
                if fact.refined_type in (precondition.required_type, "int", "float", "bool"):
                    return ContractVerificationStatus.SATISFIED
                if fact.is_numeric_string and precondition.required_type in ("int", "float"):
                    return ContractVerificationStatus.SATISFIED

            # Check for proven incompatibility (e.g. int required, but known str)
            for fact in target_facts:
                if fact.refined_type == "str" and precondition.required_type in ("int", "float", "bool"):
                    return ContractVerificationStatus.VIOLATED

            # Absence of proof is UNKNOWN, not VIOLATED
            return ContractVerificationStatus.UNKNOWN

        elif precondition.kind == PreconditionKind.FORMAT_REFINEMENT:
            for fact in target_facts:
                if fact.is_numeric_string:
                    return ContractVerificationStatus.SATISFIED
                if fact.is_alphanumeric_string and precondition.required_type in ("is_alphanumeric_string", "is_numeric_string"):
                    return ContractVerificationStatus.SATISFIED

            return ContractVerificationStatus.UNKNOWN

        elif precondition.kind == PreconditionKind.SANITIZER_CATEGORY:
            req_cat = precondition.required_sanitizer_category
            for fact in target_facts:
                if fact.applicable_sanitizer_category == req_cat or (
                    isinstance(req_cat, SinkCategory) and fact.applicable_sanitizer_category == req_cat.value
                ):
                    return ContractVerificationStatus.SATISFIED
                # Incompatible sanitizer category observed (e.g. DOM sanitizer on Command sink)
                if fact.applicable_sanitizer_category and fact.applicable_sanitizer_category != req_cat:
                    return ContractVerificationStatus.VIOLATED

            return ContractVerificationStatus.UNKNOWN

        elif precondition.kind == PreconditionKind.NULLITY_REFINEMENT:
            for fact in target_facts:
                if fact.is_non_null:
                    return ContractVerificationStatus.SATISFIED
            return ContractVerificationStatus.UNKNOWN

        return ContractVerificationStatus.UNKNOWN

    def bind_postconditions(
        self,
        contract: FunctionContract,
        trigger: PostconditionTrigger,
        caller_arg_names: list[str],
        caller_path_state: PathState,
        return_var_name: Optional[str] = None,
    ) -> list[RefinementFact]:
        """Bind matching postconditions to caller arguments or return variable."""
        injected_facts: list[RefinementFact] = []

        for post in contract.postconditions:
            if post.trigger != trigger and post.trigger != PostconditionTrigger.UNCONDITIONAL:
                continue

            # 1. Postcondition applies to return value itself
            if post.applies_to_return and return_var_name:
                if post.produced_refinement:
                    bound_fact = post.produced_refinement.model_copy()
                    bound_fact.variable_name = return_var_name
                    caller_path_state.constraints.add_refinement(bound_fact)
                    injected_facts.append(bound_fact)

            # 2. Postcondition applies to a parameter (e.g. validator refining arg)
            elif post.target_param_index is not None and post.target_param_index < len(caller_arg_names):
                caller_arg = caller_arg_names[post.target_param_index]
                if caller_arg and post.produced_refinement:
                    bound_fact = post.produced_refinement.model_copy()
                    if post.target_field_name:
                        bound_fact.variable_name = f"{caller_arg}.{post.target_field_name}"
                    else:
                        bound_fact.variable_name = caller_arg
                    caller_path_state.constraints.add_refinement(bound_fact)
                    injected_facts.append(bound_fact)

        return injected_facts

    def compose_path_conditions(
        self,
        caller_condition: Optional[str],
        callee_condition: Optional[str],
    ) -> Optional[str]:
        """Compose and simplify caller condition with callee contract condition."""
        if not caller_condition and not callee_condition:
            return None
        if not caller_condition:
            return callee_condition
        if not callee_condition:
            return caller_condition

        # Deduplication
        if caller_condition == callee_condition:
            return caller_condition

        c1 = caller_condition.strip()
        c2 = callee_condition.strip()

        # Check trivial contradiction: P and not P
        if c1 == f"not {c2}" or c2 == f"not {c1}" or f"not ({c1})" == c2 or f"not ({c2})" == c1:
            return "INFEASIBLE_CONTRADICTION"

        # Deterministic sorting
        parts = sorted([c1, c2])
        return f"{parts[0]} and {parts[1]}"
