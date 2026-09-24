"""Call site resolution for Python and JavaScript/TypeScript."""

from typing import Optional

from analyzer.dataflow.callgraph.models import (
    CallEdge,
    CallResolutionType,
    FunctionDefinition,
    UnresolvedCall,
    UnresolvedReason,
)
from analyzer.models.parse import ImportCategory, ImportStatement


class CallResolver:
    """Resolves function call expressions to repository FunctionDefinition targets."""

    def __init__(self, functions: list[FunctionDefinition]):
        self.functions_by_qn: dict[str, FunctionDefinition] = {f.qualified_name: f for f in functions}
        self.functions_by_file: dict[str, list[FunctionDefinition]] = {}
        self.functions_by_name: dict[str, list[FunctionDefinition]] = {}

        for f in functions:
            norm_file = f.file_path.replace("\\", "/")
            self.functions_by_file.setdefault(norm_file, []).append(f)
            self.functions_by_name.setdefault(f.name, []).append(f)

    def resolve_call(
        self,
        caller: FunctionDefinition,
        callee_expr: str,
        line: int,
        col: int,
        arg_count: int,
        is_dynamic: bool = False,
        imports: Optional[list[ImportStatement]] = None,
        enclosing_class: Optional[str] = None,
    ) -> tuple[Optional[CallEdge], Optional[UnresolvedCall]]:
        """Resolve a single call site to either a CallEdge or an UnresolvedCall record.
        
        Resolution hierarchy:
        1. Dynamic check -> UNRESOLVED(DYNAMIC_CALL)
        2. Local scope lookup within same class / module -> RESOLVED_LOCAL
        3. Import lookup -> RESOLVED_IMPORT
        4. Target outside repository / external -> UNRESOLVED(EXTERNAL_MODULE / MISSING_IMPORT)
        """
        caller_file = caller.file_path.replace("\\", "/")
        norm_imports = imports or []

        # 1. Check for dynamic call invocation
        if is_dynamic or callee_expr.startswith("getattr(") or callee_expr.startswith("globals()"):
            unres = UnresolvedCall(
                caller_qualified_name=caller.qualified_name,
                callee_expression=callee_expr,
                call_site_file=caller_file,
                call_site_line=line,
                call_site_col=col,
                reason=UnresolvedReason.DYNAMIC_CALL,
            )
            return None, unres

        callee_clean = callee_expr.strip()

        # 2. Check local method call: self.method(...) or this.method(...)
        if callee_clean.startswith(("self.", "this.")) and (enclosing_class or caller.class_name):
            target_cls = enclosing_class or caller.class_name
            method_name = callee_clean.split(".", 1)[1].strip()
            # Look for target_cls.method_name in caller's file
            expected_qn = f"{caller.module_path}.{target_cls}.{method_name}" if caller.module_path else f"{target_cls}.{method_name}"
            target_fn = self.functions_by_qn.get(expected_qn)
            if target_fn:
                edge_id = CallEdge.create_deterministic_id(caller.qualified_name, expected_qn, caller_file, line, col)
                edge = CallEdge(
                    id=edge_id,
                    caller_qualified_name=caller.qualified_name,
                    callee_qualified_name=expected_qn,
                    call_site_file=caller_file,
                    call_site_line=line,
                    call_site_col=col,
                    resolution_type=CallResolutionType.RESOLVED_LOCAL,
                    argument_count=arg_count,
                    is_method_call=True,
                )
                return edge, None

        # 3. Direct local function call (e.g. build_query(...) where build_query is in same file)
        if "." not in callee_clean:
            file_fns = self.functions_by_file.get(caller_file, [])
            local_matches = [f for f in file_fns if f.name == callee_clean and not f.is_method]
            if local_matches:
                target_fn = local_matches[0]
                edge_id = CallEdge.create_deterministic_id(
                    caller.qualified_name, target_fn.qualified_name, caller_file, line, col
                )
                edge = CallEdge(
                    id=edge_id,
                    caller_qualified_name=caller.qualified_name,
                    callee_qualified_name=target_fn.qualified_name,
                    call_site_file=caller_file,
                    call_site_line=line,
                    call_site_col=col,
                    resolution_type=CallResolutionType.RESOLVED_LOCAL,
                    argument_count=arg_count,
                    is_method_call=False,
                )
                return edge, None

        # 4. Import resolution
        # Case A: from module import func_name -> callee_clean == "func_name"
        for imp in norm_imports:
            if callee_clean in imp.imported_names:
                if imp.dependency_category == ImportCategory.EXTERNAL:
                    unres = UnresolvedCall(
                        caller_qualified_name=caller.qualified_name,
                        callee_expression=callee_clean,
                        call_site_file=caller_file,
                        call_site_line=line,
                        call_site_col=col,
                        reason=UnresolvedReason.EXTERNAL_MODULE,
                    )
                    return None, unres

                if imp.resolved_path:
                    norm_target_file = imp.resolved_path.replace("\\", "/")
                    target_file_fns = self.functions_by_file.get(norm_target_file, [])
                    matched_fns = [f for f in target_file_fns if f.name == callee_clean]
                    if matched_fns:
                        target_fn = matched_fns[0]
                        edge_id = CallEdge.create_deterministic_id(
                            caller.qualified_name, target_fn.qualified_name, caller_file, line, col
                        )
                        edge = CallEdge(
                            id=edge_id,
                            caller_qualified_name=caller.qualified_name,
                            callee_qualified_name=target_fn.qualified_name,
                            call_site_file=caller_file,
                            call_site_line=line,
                            call_site_col=col,
                            resolution_type=CallResolutionType.RESOLVED_IMPORT,
                            argument_count=arg_count,
                            is_method_call=target_fn.is_method,
                        )
                        return edge, None

        # Case B: import module -> callee_clean == "module.func_name"
        if "." in callee_clean:
            parts = callee_clean.split(".")
            mod_alias = parts[0]
            func_name = parts[-1]

            for imp in norm_imports:
                imp_base = imp.source_module.split(".")[-1]
                if mod_alias == imp_base or mod_alias in imp.imported_names:
                    if imp.dependency_category == ImportCategory.EXTERNAL:
                        unres = UnresolvedCall(
                            caller_qualified_name=caller.qualified_name,
                            callee_expression=callee_clean,
                            call_site_file=caller_file,
                            call_site_line=line,
                            call_site_col=col,
                            reason=UnresolvedReason.EXTERNAL_MODULE,
                        )
                        return None, unres

                    if imp.resolved_path:
                        norm_target_file = imp.resolved_path.replace("\\", "/")
                        target_file_fns = self.functions_by_file.get(norm_target_file, [])
                        matched_fns = [f for f in target_file_fns if f.name == func_name]
                        if matched_fns:
                            target_fn = matched_fns[0]
                            edge_id = CallEdge.create_deterministic_id(
                                caller.qualified_name, target_fn.qualified_name, caller_file, line, col
                            )
                            edge = CallEdge(
                                id=edge_id,
                                caller_qualified_name=caller.qualified_name,
                                callee_qualified_name=target_fn.qualified_name,
                                call_site_file=caller_file,
                                call_site_line=line,
                                call_site_col=col,
                                resolution_type=CallResolutionType.RESOLVED_IMPORT,
                                argument_count=arg_count,
                                is_method_call=target_fn.is_method,
                            )
                            return edge, None

        # 5. Check if simple name exists anywhere uniquely in repository
        candidates = self.functions_by_name.get(callee_clean, [])
        if len(candidates) == 1:
            target_fn = candidates[0]
            edge_id = CallEdge.create_deterministic_id(
                caller.qualified_name, target_fn.qualified_name, caller_file, line, col
            )
            edge = CallEdge(
                id=edge_id,
                caller_qualified_name=caller.qualified_name,
                callee_qualified_name=target_fn.qualified_name,
                call_site_file=caller_file,
                call_site_line=line,
                call_site_col=col,
                resolution_type=CallResolutionType.RESOLVED_IMPORT,
                argument_count=arg_count,
                is_method_call=target_fn.is_method,
            )
            return edge, None
        elif len(candidates) > 1:
            unres = UnresolvedCall(
                caller_qualified_name=caller.qualified_name,
                callee_expression=callee_clean,
                call_site_file=caller_file,
                call_site_line=line,
                call_site_col=col,
                reason=UnresolvedReason.AMBIGUOUS,
            )
            return None, unres

        # 6. Default to unresolved external module or missing import
        unres = UnresolvedCall(
            caller_qualified_name=caller.qualified_name,
            callee_expression=callee_clean,
            call_site_file=caller_file,
            call_site_line=line,
            call_site_col=col,
            reason=UnresolvedReason.EXTERNAL_MODULE if "." in callee_clean else UnresolvedReason.MISSING_IMPORT,
        )
        return None, unres
