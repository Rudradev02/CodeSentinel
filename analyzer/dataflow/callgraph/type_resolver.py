"""Type-aware call site resolution for Python and JavaScript/TypeScript (Phase 16)."""

from typing import Optional

from analyzer.dataflow.callgraph.models import (
    CallEdge,
    CallResolutionType,
    FunctionDefinition,
    UnresolvedCall,
    UnresolvedReason,
)
from analyzer.dataflow.callgraph.resolver import CallResolver
from analyzer.dataflow.types.models import TypeConfidence, TypeEnvironment
from analyzer.models.parse import ImportStatement


class TypeAwareCallResolver:
    """Enriches CallResolver with receiver type inference evidence and class dispatch."""

    def __init__(
        self,
        functions: list[FunctionDefinition],
        base_resolver: Optional[CallResolver] = None,
    ):
        self.base_resolver = base_resolver or CallResolver(functions)
        self.functions_by_qn: dict[str, FunctionDefinition] = {f.qualified_name: f for f in functions}
        self.methods_by_class: dict[str, dict[str, FunctionDefinition]] = {}

        # Index methods by class qualified name and short class name
        for f in functions:
            if f.is_method and f.class_name:
                short_cls = f.class_name
                self.methods_by_class.setdefault(short_cls, {})[f.name] = f
                if f.module_path:
                    full_cls = f"{f.module_path}.{short_cls}"
                    self.methods_by_class.setdefault(full_cls, {})[f.name] = f

    def resolve_call(
        self,
        caller: FunctionDefinition,
        callee_expr: str,
        line: int,
        col: int,
        arg_count: int,
        type_env: Optional[TypeEnvironment] = None,
        is_dynamic: bool = False,
        imports: Optional[list[ImportStatement]] = None,
        enclosing_class: Optional[str] = None,
    ) -> tuple[Optional[CallEdge], Optional[UnresolvedCall]]:
        """Resolve call site using receiver type evidence before falling back to base resolution."""
        caller_file = caller.file_path.replace("\\", "/")
        callee_clean = callee_expr.strip().split("(", 1)[0].strip()

        # Check if callee is a method call on a receiver expression (e.g. repo.find_by_id or self.db.execute)
        if "." in callee_clean and type_env:
            parts = callee_clean.rsplit(".", 1)
            receiver_expr = parts[0].strip()
            method_name = parts[1].strip()

            # Lookup receiver type binding
            binding = None
            if receiver_expr in type_env.bindings:
                binding = type_env.get_type(receiver_expr)
            elif receiver_expr.startswith("self."):
                field_name = receiver_expr.split(".", 1)[1].strip()
                binding = type_env.get_field_type("self", field_name)
            elif receiver_expr.startswith("this."):
                field_name = receiver_expr.split(".", 1)[1].strip()
                binding = type_env.get_field_type("this", field_name)

            if binding:
                # 1. KNOWN or LIKELY receiver type
                if binding.confidence in (TypeConfidence.KNOWN, TypeConfidence.LIKELY):
                    candidate_classes = [binding.qualified_type_name, binding.type_name]
                    target_method: Optional[FunctionDefinition] = None
                    for cls_name in candidate_classes:
                        if cls_name in self.methods_by_class:
                            if method_name in self.methods_by_class[cls_name]:
                                target_method = self.methods_by_class[cls_name][method_name]
                                break

                    if target_method:
                        norm_target_file = target_method.file_path.replace("\\", "/")
                        res_type = (
                            CallResolutionType.RESOLVED_LOCAL
                            if norm_target_file == caller_file
                            else CallResolutionType.RESOLVED_IMPORT
                        )
                        edge_id = CallEdge.create_deterministic_id(
                            caller.qualified_name, target_method.qualified_name, caller_file, line, col
                        )
                        edge = CallEdge(
                            id=edge_id,
                            caller_qualified_name=caller.qualified_name,
                            callee_qualified_name=target_method.qualified_name,
                            call_site_file=caller_file,
                            call_site_line=line,
                            call_site_col=col,
                            resolution_type=res_type,
                            argument_count=arg_count,
                            is_method_call=True,
                            receiver_type=binding.qualified_type_name,
                            receiver_confidence=binding.confidence.value,
                        )
                        return edge, None

                # 2. AMBIGUOUS receiver type
                elif binding.confidence == TypeConfidence.AMBIGUOUS:
                    sorted_candidates = sorted(binding.candidate_types)
                    edge_id = CallEdge.create_deterministic_id(
                        caller.qualified_name, f"AMBIGUOUS:{method_name}", caller_file, line, col
                    )
                    edge = CallEdge(
                        id=edge_id,
                        caller_qualified_name=caller.qualified_name,
                        callee_qualified_name=None,
                        call_site_file=caller_file,
                        call_site_line=line,
                        call_site_col=col,
                        resolution_type=CallResolutionType.UNRESOLVED,
                        argument_count=arg_count,
                        is_method_call=True,
                        unresolved_reason=UnresolvedReason.AMBIGUOUS,
                        receiver_type="AMBIGUOUS",
                        receiver_confidence=TypeConfidence.AMBIGUOUS.value,
                        candidate_targets=sorted_candidates,
                    )
                    unres = UnresolvedCall(
                        caller_qualified_name=caller.qualified_name,
                        callee_expression=callee_clean,
                        call_site_file=caller_file,
                        call_site_line=line,
                        call_site_col=col,
                        reason=UnresolvedReason.AMBIGUOUS,
                    )
                    return edge, unres

        # Fallback to base CallResolver
        return self.base_resolver.resolve_call(
            caller=caller,
            callee_expr=callee_expr,
            line=line,
            col=col,
            arg_count=arg_count,
            is_dynamic=is_dynamic,
            imports=imports,
            enclosing_class=enclosing_class,
        )
