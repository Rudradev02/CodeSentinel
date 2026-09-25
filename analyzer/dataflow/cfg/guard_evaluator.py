"""Propositional guard and refinement fact evaluator (Phase 18).

Decomposes boolean expressions (AND, OR, NOT, chained comparisons) into propositional
guard conditions and produces path-specific value refinements (type, format, nullity,
sanitizer category) without blindly setting global TaintState = SANITIZED.
"""

import ast
import re
from typing import Optional

from analyzer.dataflow.cfg.models import (
    GuardCondition,
    PredicateOp,
    RefinementFact,
)


class GuardEvaluator:
    """Evaluates AST branch condition expressions under a strict trust model."""

    def __init__(
        self,
        registered_validators: Optional[set[str]] = None,
    ):
        self.registered_validators = registered_validators or {
            "is_valid", "validate_id", "is_safe_int", "is_safe_token",
            "is_valid_email", "is_alphanumeric",
        }

    def evaluate_python_condition(
        self,
        node: ast.AST,
        expected_value: bool = True,
    ) -> tuple[list[GuardCondition], list[RefinementFact]]:
        """Extract guard conditions and refinement facts from a Python condition AST node."""
        conditions: list[GuardCondition] = []
        refinements: list[RefinementFact] = []

        raw_expr = ast.unparse(node) if hasattr(ast, "unparse") else "<expr>"
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)

        # 1. Boolean NOT: invert expected_value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.evaluate_python_condition(node.operand, not expected_value)

        # 2. Boolean AND / OR
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                # Under True expected_value, all children must hold
                if expected_value:
                    for val in node.values:
                        c, r = self.evaluate_python_condition(val, True)
                        conditions.extend(c)
                        refinements.extend(r)
                return conditions, refinements
            elif isinstance(node.op, ast.Or):
                # Under False expected_value, all children must be False
                if not expected_value:
                    for val in node.values:
                        c, r = self.evaluate_python_condition(val, False)
                        conditions.extend(c)
                        refinements.extend(r)
                return conditions, refinements

        # 3. Call expressions: isinstance, isdigit, isalnum, re.match, shlex.quote, etc.
        if isinstance(node, ast.Call):
            fn_name = self._get_call_name(node)

            # 3a. isinstance(var, type)
            if fn_name == "isinstance" and len(node.args) >= 2:
                var_name = self._extract_var_name(node.args[0])
                type_name = self._extract_type_name(node.args[1])
                if var_name and type_name:
                    cond = GuardCondition(
                        variable_name=var_name,
                        predicate_op=PredicateOp.IS_INSTANCE,
                        expected_value=expected_value,
                        argument_literal=type_name,
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    if expected_value:
                        refinements.append(
                            RefinementFact(
                                variable_name=var_name,
                                refined_type=type_name,
                                is_non_null=True,
                                provenance_line=line,
                            )
                        )
                return conditions, refinements

            # 3b. var.isdigit() or var.isnumeric()
            if fn_name.endswith(".isdigit") or fn_name.endswith(".isnumeric"):
                var_name = fn_name.rsplit(".", 1)[0]
                if var_name:
                    cond = GuardCondition(
                        variable_name=var_name,
                        predicate_op=PredicateOp.IS_DIGIT,
                        expected_value=expected_value,
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    if expected_value:
                        refinements.append(
                            RefinementFact(
                                variable_name=var_name,
                                is_numeric_string=True,
                                is_non_null=True,
                                provenance_line=line,
                            )
                        )
                return conditions, refinements

            # 3c. var.isalnum()
            if fn_name.endswith(".isalnum"):
                var_name = fn_name.rsplit(".", 1)[0]
                if var_name:
                    cond = GuardCondition(
                        variable_name=var_name,
                        predicate_op=PredicateOp.IS_ALPHA,
                        expected_value=expected_value,
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    if expected_value:
                        refinements.append(
                            RefinementFact(
                                variable_name=var_name,
                                is_alphanumeric_string=True,
                                is_non_null=True,
                                provenance_line=line,
                            )
                        )
                return conditions, refinements

            # 3d. Anchored regex: re.match(r'^...$', var)
            if fn_name in ("re.match", "re.fullmatch") and len(node.args) >= 2:
                pattern_str = self._extract_literal_str(node.args[0])
                var_name = self._extract_var_name(node.args[1])
                if pattern_str and var_name:
                    # Require anchored pattern (^...$ or \A...\Z) for valid full string validation
                    is_anchored = (
                        (pattern_str.startswith("^") or pattern_str.startswith(r"\A"))
                        and (pattern_str.endswith("$") or pattern_str.endswith(r"\Z"))
                    )
                    if is_anchored:
                        cond = GuardCondition(
                            variable_name=var_name,
                            predicate_op=PredicateOp.ANCHORED_REGEX,
                            expected_value=expected_value,
                            argument_literal=pattern_str,
                            raw_expression=raw_expr,
                            line=line,
                            col=col,
                        )
                        conditions.append(cond)
                        if expected_value:
                            is_num = bool(re.search(r"^\^?\s*\\d\+\s*\$?$", pattern_str))
                            is_alnum = bool(re.search(r"^\^?\[a-zA-Z0-9_\]\+\$?$", pattern_str))
                            refinements.append(
                                RefinementFact(
                                    variable_name=var_name,
                                    is_numeric_string=is_num,
                                    is_alphanumeric_string=is_alnum or is_num,
                                    is_non_null=True,
                                    provenance_line=line,
                                )
                            )
                return conditions, refinements

            # 3e. Category-specific sanitizers: shlex.quote(var), html.escape(var)
            if fn_name == "shlex.quote" and len(node.args) >= 1:
                var_name = self._extract_var_name(node.args[0])
                if var_name and expected_value:
                    refinements.append(
                        RefinementFact(
                            variable_name=var_name,
                            applicable_sanitizer_category="COMMAND_EXECUTE",
                            is_non_null=True,
                            provenance_line=line,
                        )
                    )
                return conditions, refinements

            # 3f. Explicit registered validator function
            short_fn = fn_name.split(".")[-1]
            if short_fn in self.registered_validators and len(node.args) >= 1:
                var_name = self._extract_var_name(node.args[0])
                if var_name:
                    cond = GuardCondition(
                        variable_name=var_name,
                        predicate_op=PredicateOp.REGISTERED_VALIDATOR,
                        expected_value=expected_value,
                        argument_literal=short_fn,
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    if expected_value:
                        refinements.append(
                            RefinementFact(
                                variable_name=var_name,
                                is_non_null=True,
                                provenance_line=line,
                            )
                        )
                return conditions, refinements

        # 4. Comparisons: var is None, var is not None, var == "CONST"
        if isinstance(node, ast.Compare):
            left_var = self._extract_var_name(node.left)
            if left_var and len(node.ops) == 1 and len(node.comparators) == 1:
                op = node.ops[0]
                right = node.comparators[0]

                # is None / is not None
                if isinstance(op, ast.Is) and isinstance(right, ast.Constant) and right.value is None:
                    cond = GuardCondition(
                        variable_name=left_var,
                        predicate_op=PredicateOp.IS_NONE,
                        expected_value=expected_value,
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    if not expected_value:
                        refinements.append(RefinementFact(variable_name=left_var, is_non_null=True, provenance_line=line))
                    return conditions, refinements

                if isinstance(op, ast.IsNot) and isinstance(right, ast.Constant) and right.value is None:
                    cond = GuardCondition(
                        variable_name=left_var,
                        predicate_op=PredicateOp.IS_NOT_NONE,
                        expected_value=expected_value,
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    if expected_value:
                        refinements.append(RefinementFact(variable_name=left_var, is_non_null=True, provenance_line=line))
                    return conditions, refinements

                # == "CONST" or != "CONST"
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant):
                    is_eq = isinstance(op, ast.Eq)
                    eff_eq = is_eq if expected_value else not is_eq
                    pred_op = PredicateOp.EQUALS_CONST if eff_eq else PredicateOp.NOT_EQUALS_CONST
                    cond = GuardCondition(
                        variable_name=left_var,
                        predicate_op=pred_op,
                        expected_value=True,
                        argument_literal=str(right.value),
                        raw_expression=raw_expr,
                        line=line,
                        col=col,
                    )
                    conditions.append(cond)
                    return conditions, refinements

        # 5. Simple name truthy / falsy: if x:
        if isinstance(node, ast.Name):
            var_name = node.id
            pred = PredicateOp.TRUTHY if expected_value else PredicateOp.FALSY
            cond = GuardCondition(
                variable_name=var_name,
                predicate_op=pred,
                expected_value=True,
                raw_expression=raw_expr,
                line=line,
                col=col,
            )
            conditions.append(cond)
            if expected_value:
                refinements.append(RefinementFact(variable_name=var_name, is_non_null=True, provenance_line=line))
            return conditions, refinements

        return conditions, refinements

    def evaluate_jsts_condition(
        self,
        cond_str: str,
        expected_value: bool = True,
    ) -> tuple[list[GuardCondition], list[RefinementFact]]:
        """Evaluate JS/TS string condition expressions into guard conditions and refinement facts."""
        conditions: list[GuardCondition] = []
        refinements: list[RefinementFact] = []
        clean = cond_str.strip()

        # Invert for !()
        if clean.startswith("!(") and clean.endswith(")"):
            return self.evaluate_jsts_condition(clean[2:-1], not expected_value)
        if clean.startswith("!"):
            return self.evaluate_jsts_condition(clean[1:], not expected_value)

        # typeof x === 'number'
        m_type = re.match(r"^typeof\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*===?\s*['\"]([a-zA-Z]+)['\"]$", clean)
        if m_type:
            var_name, t_name = m_type.groups()
            cond = GuardCondition(
                variable_name=var_name,
                predicate_op=PredicateOp.IS_INSTANCE,
                expected_value=expected_value,
                argument_literal=t_name,
                raw_expression=clean,
            )
            conditions.append(cond)
            if expected_value and t_name in ("number", "boolean"):
                refinements.append(
                    RefinementFact(
                        variable_name=var_name,
                        refined_type=t_name,
                        is_non_null=True,
                    )
                )
            return conditions, refinements

        # Number.isInteger(x)
        m_int = re.match(r"^Number\.isInteger\(([a-zA-Z_$][a-zA-Z0-9_$]*)\)$", clean)
        if m_int:
            var_name = m_int.group(1)
            cond = GuardCondition(
                variable_name=var_name,
                predicate_op=PredicateOp.IS_DIGIT,
                expected_value=expected_value,
                raw_expression=clean,
            )
            conditions.append(cond)
            if expected_value:
                refinements.append(
                    RefinementFact(
                        variable_name=var_name,
                        refined_type="number",
                        is_numeric_string=True,
                        is_non_null=True,
                    )
                )
            return conditions, refinements

        # Simple truthy variable: req.isValid or isValid
        if re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$.]*$", clean):
            cond = GuardCondition(
                variable_name=clean,
                predicate_op=PredicateOp.TRUTHY if expected_value else PredicateOp.FALSY,
                expected_value=True,
                raw_expression=clean,
            )
            conditions.append(cond)
            if expected_value:
                refinements.append(RefinementFact(variable_name=clean, is_non_null=True))

        return conditions, refinements

    def _get_call_name(self, call_node: ast.Call) -> str:
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            val = self._extract_var_name(call_node.func.value)
            return f"{val}.{call_node.func.attr}" if val else call_node.func.attr
        return ""

    def _extract_var_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return None

    def _extract_names(self, node: ast.AST) -> list[str]:
        names: list[str] = []
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                names.append(n.id)
        return names

    def _extract_type_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, (ast.Tuple, ast.List)):
            types = [self._extract_type_name(elt) for elt in node.elts]
            valid_types = [t for t in types if t]
            return ",".join(valid_types) if valid_types else None
        return None

    def _extract_literal_str(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
