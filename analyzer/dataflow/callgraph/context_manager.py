"""Context management, bounding, and constant-aware branch refinement (Phase 16)."""

import ast
from typing import Any, Optional
from analyzer.dataflow.types.models import CallContext, ConstantBool


class ConstantBranchEvaluator:
    """Evaluates literal boolean branch conditions for contextual branch refinement."""

    @staticmethod
    def evaluate_python_condition(
        test_node: ast.expr,
        param_names: list[str],
        constant_args: dict[int, ConstantBool],
    ) -> ConstantBool:
        """Evaluate if an AST condition can be statically resolved from constant args."""
        # Case 1: if sanitize:
        if isinstance(test_node, ast.Name):
            var_name = test_node.id
            if var_name in param_names:
                p_idx = param_names.index(var_name)
                return constant_args.get(p_idx, ConstantBool.UNKNOWN)

        # Case 2: if not sanitize:
        if isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not):
            inner = ConstantBranchEvaluator.evaluate_python_condition(
                test_node.operand, param_names, constant_args
            )
            if inner == ConstantBool.TRUE:
                return ConstantBool.FALSE
            elif inner == ConstantBool.FALSE:
                return ConstantBool.TRUE

        # Case 3: Literal boolean in code: if True: / if False:
        if isinstance(test_node, ast.Constant) and isinstance(test_node.value, bool):
            return ConstantBool.TRUE if test_node.value else ConstantBool.FALSE

        return ConstantBool.UNKNOWN


class ContextManager:
    """Manages active call-string contexts, enforcing per-function and global bounds."""

    def __init__(
        self,
        max_k: int = 2,
        max_contexts_per_function: int = 8,
        max_total_contexts: int = 1000,
    ):
        self.max_k = max_k
        self.max_contexts_per_function = max_contexts_per_function
        self.max_total_contexts = max_total_contexts
        self.contexts_by_function: dict[str, dict[str, CallContext]] = {}
        self.total_contexts_count: int = 0
        self.truncation_reasons: set[str] = set()

    def get_or_create_context(
        self,
        callee_qn: str,
        parent: CallContext,
        call_site_id: str,
        arg_taints: list[bool],
        constant_args: Optional[dict[int, ConstantBool]] = None,
        receiver_type: Optional[str] = None,
    ) -> tuple[CallContext, bool]:
        """Obtain a bounded CallContext.
        
        Returns:
            (context, is_widened)
        """
        fn_contexts = self.contexts_by_function.setdefault(callee_qn, {})

        # Derive prospective context
        candidate = CallContext.push_call_site(
            parent=parent,
            call_site_id=call_site_id,
            arg_taints=arg_taints,
            constant_args=constant_args,
            receiver_type=receiver_type,
            max_k=self.max_k,
        )

        # If already known for this function, return existing
        if candidate.context_id in fn_contexts:
            return fn_contexts[candidate.context_id], False

        # Check bounds: per-function limit or global limit
        if len(fn_contexts) >= self.max_contexts_per_function:
            self.truncation_reasons.add("MAX_CONTEXTS_PER_FUNCTION")
            # Widen: fallback to merged/widened context
            widened = CallContext(
                context_id="WIDENED",
                call_string=candidate.call_string,
                argument_taint_mask=[True] * len(arg_taints),
                constant_args={},
                receiver_type=receiver_type,
                depth=candidate.depth,
            )
            return widened, True

        if self.total_contexts_count >= self.max_total_contexts:
            self.truncation_reasons.add("MAX_TOTAL_CONTEXTS")
            widened = CallContext(
                context_id="WIDENED",
                call_string=candidate.call_string,
                argument_taint_mask=[True] * len(arg_taints),
                constant_args={},
                receiver_type=receiver_type,
                depth=candidate.depth,
            )
            return widened, True

        # Register new context
        fn_contexts[candidate.context_id] = candidate
        self.total_contexts_count += 1
        return candidate, False
