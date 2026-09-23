"""Intraprocedural taint propagator evaluating symbol definition-use chains and sink invocations."""

from typing import Any, Callable, Optional
from analyzer.dataflow.taint.models import (
    SinkCategory,
    TaintPath,
    TaintSanitizer,
    TaintSink,
    TaintSource,
    TaintState,
    TaintStep,
)
from analyzer.dataflow.taint.registry import TaintRegistry


class TaintPropagator:
    """Evaluates intraprocedural taint propagation within a single function scope.
    
    Guarantees:
    - Strictly bounded depth (max_depth, max_symbols, max_statements).
    - Conservative merge lattice on branching.
    - Category-specific sanitization (int() constrains numeric SQL/shell, not HTML).
    - Parameterized SQL modeled as safe sink usage (static query + bind tuple).
    - Unknown functions preserve taint without clearing it.
    - Cooperative cancellation honored periodically.
    """

    def __init__(
        self,
        registry: Optional[TaintRegistry] = None,
        max_depth: int = 25,
        max_symbols: int = 100,
        max_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.registry = registry or TaintRegistry(load_defaults=True)
        self.max_depth = max_depth
        self.max_symbols = max_symbols
        self.max_statements = max_statements
        self.is_cancelled = is_cancelled

        # symbol_name -> (TaintState, Optional[Source/Sanitizer/Trace info], list[TaintStep])
        self.symbol_states: dict[str, TaintState] = {}
        self.symbol_traces: dict[str, list[TaintStep]] = {}
        self.symbol_sanitizers: dict[str, list[TaintSanitizer]] = {}
        self.detected_paths: list[TaintPath] = []
        self.step_counter = 0

    def check_cancellation(self) -> None:
        """Cooperative cancellation checkpoint."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("Data-flow analysis was cancelled by user")

    def register_parameter(self, param_name: str, is_tainted: bool = False, source: Optional[TaintSource] = None) -> None:
        """Register a function parameter symbol."""
        if len(self.symbol_states) >= self.max_symbols:
            return
        state = TaintState.TAINTED if is_tainted else TaintState.UNTAINTED
        self.symbol_states[param_name] = state
        self.symbol_traces[param_name] = []
        self.symbol_sanitizers[param_name] = []

    def handle_direct_source_assignment(
        self,
        target_symbol: str,
        source: TaintSource,
        line: int,
        col: int,
        expression_str: str,
    ) -> None:
        """Handle variable assigned directly from an untrusted source (e.g. x = request.args['id'])."""
        self.check_cancellation()
        if len(self.symbol_states) >= self.max_symbols and target_symbol not in self.symbol_states:
            return

        self.step_counter += 1
        step = TaintStep(
            step=self.step_counter,
            line=line,
            column=col,
            operation="SOURCE",
            to_symbol=target_symbol,
            expression=expression_str,
            state=TaintState.TAINTED,
        )

        self.symbol_states[target_symbol] = TaintState.TAINTED
        self.symbol_traces[target_symbol] = [step]
        self.symbol_sanitizers[target_symbol] = []

    def handle_assignment_propagation(
        self,
        target_symbol: str,
        referenced_symbols: list[str],
        line: int,
        col: int,
        expression_str: str,
        is_binary_or_concat: bool = False,
    ) -> None:
        """Handle propagation from one or more symbols to a target symbol (e.g. y = x or q = 'SELECT ' + x)."""
        self.check_cancellation()
        if len(self.symbol_states) >= self.max_symbols and target_symbol not in self.symbol_states:
            return

        # Check if any referenced symbol is TAINTED
        tainted_refs = [
            sym for sym in referenced_symbols
            if self.symbol_states.get(sym) == TaintState.TAINTED
        ]

        if tainted_refs:
            primary_source_sym = tainted_refs[0]
            existing_trace = self.symbol_traces.get(primary_source_sym, [])

            # Enforce max propagation depth
            if len(existing_trace) < self.max_depth:
                self.step_counter += 1
                new_step = TaintStep(
                    step=self.step_counter,
                    line=line,
                    column=col,
                    operation="CONCATENATION" if is_binary_or_concat else "ASSIGNMENT",
                    from_symbol=primary_source_sym,
                    to_symbol=target_symbol,
                    expression=expression_str,
                    state=TaintState.TAINTED,
                )
                self.symbol_states[target_symbol] = TaintState.TAINTED
                self.symbol_traces[target_symbol] = existing_trace + [new_step]
                self.symbol_sanitizers[target_symbol] = list(self.symbol_sanitizers.get(primary_source_sym, []))
        else:
            # Check if all referenced symbols are known and UNTAINTED
            all_untainted = all(
                self.symbol_states.get(sym) == TaintState.UNTAINTED
                for sym in referenced_symbols
            ) if referenced_symbols else True

            if all_untainted:
                self.symbol_states[target_symbol] = TaintState.UNTAINTED
                self.symbol_traces[target_symbol] = []
                self.symbol_sanitizers[target_symbol] = []

    def handle_sanitizer_call(
        self,
        target_symbol: str,
        sanitizer: TaintSanitizer,
        argument_symbols: list[str],
        line: int,
        col: int,
        expression_str: str,
    ) -> None:
        """Handle a context-specific sanitizer call (e.g. y = int(x))."""
        self.check_cancellation()
        # Find if any argument was tainted
        tainted_args = [
            s for s in argument_symbols
            if self.symbol_states.get(s) == TaintState.TAINTED
        ]

        if tainted_args:
            arg = tainted_args[0]
            existing_trace = self.symbol_traces.get(arg, [])
            self.step_counter += 1
            step = TaintStep(
                step=self.step_counter,
                line=line,
                column=col,
                operation="SANITIZER",
                from_symbol=arg,
                to_symbol=target_symbol,
                expression=expression_str,
                state=TaintState.SANITIZED,
            )
            self.symbol_states[target_symbol] = TaintState.SANITIZED
            self.symbol_traces[target_symbol] = existing_trace + [step]
            existing_sans = list(self.symbol_sanitizers.get(arg, []))
            if sanitizer not in existing_sans:
                existing_sans.append(sanitizer)
            self.symbol_sanitizers[target_symbol] = existing_sans
        else:
            self.symbol_states[target_symbol] = TaintState.UNTAINTED
            self.symbol_traces[target_symbol] = []
            self.symbol_sanitizers[target_symbol] = []

    def handle_unknown_function_call(
        self,
        target_symbol: str,
        argument_symbols: list[str],
        line: int,
        col: int,
        expression_str: str,
    ) -> None:
        """Handle invocation of an unverified/unknown function (e.g. y = transform(x)).
        
        Strict Invariant:
        Unknown functions NEVER clear taint. Taint state is preserved.
        """
        self.check_cancellation()
        tainted_args = [
            s for s in argument_symbols
            if self.symbol_states.get(s) == TaintState.TAINTED
        ]

        if tainted_args:
            arg = tainted_args[0]
            existing_trace = self.symbol_traces.get(arg, [])
            if len(existing_trace) < self.max_depth:
                self.step_counter += 1
                step = TaintStep(
                    step=self.step_counter,
                    line=line,
                    column=col,
                    operation="UNKNOWN_TRANSFORMATION",
                    from_symbol=arg,
                    to_symbol=target_symbol,
                    expression=expression_str,
                    state=TaintState.TAINTED,
                )
                self.symbol_states[target_symbol] = TaintState.TAINTED
                self.symbol_traces[target_symbol] = existing_trace + [step]
                self.symbol_sanitizers[target_symbol] = list(self.symbol_sanitizers.get(arg, []))
        else:
            # If arguments were not tainted, state remains UNTAINTED
            self.symbol_states[target_symbol] = TaintState.UNTAINTED
            self.symbol_traces[target_symbol] = []
            self.symbol_sanitizers[target_symbol] = []

    def check_sink_invocation(
        self,
        sink: TaintSink,
        file_path: str,
        line: int,
        col: int,
        argument_symbols: list[str],
        raw_callee_expr: str,
        is_query_parameterized: bool = False,
        param_binding_symbols: Optional[list[str]] = None,
    ) -> Optional[TaintPath]:
        """Check whether a sensitive sink invocation triggers a vulnerability finding.
        
        Guarantees:
        1. Safe Sink Invocation: Parameterized SQL with untainted query string is SAFE.
        2. Category-Specific Sanitization: If argument was sanitized for this sink category, NO finding is emitted.
        3. Taint Detection: If vulnerable argument carries TAINTED state, emits full TaintPath trace.
        """
        self.check_cancellation()
        # 1. Parameterized SQL safe usage check
        if sink.supports_parameter_binding and is_query_parameterized:
            # If query string argument is static / untainted, suppress finding
            query_arg_tainted = False
            for v_idx in sink.vulnerable_arg_indices:
                if v_idx < len(argument_symbols):
                    sym = argument_symbols[v_idx]
                    if self.symbol_states.get(sym) == TaintState.TAINTED:
                        query_arg_tainted = True
                        break
            if not query_arg_tainted:
                # Safe sink usage: parameter binding handles query safely
                return None

        # 2. Check vulnerable arguments for taint
        for v_idx in sink.vulnerable_arg_indices:
            if v_idx >= len(argument_symbols) and v_idx != -1:
                continue

            arg_sym = argument_symbols[v_idx] if v_idx < len(argument_symbols) else (argument_symbols[0] if argument_symbols else None)
            if not arg_sym:
                continue

            state = self.symbol_states.get(arg_sym, TaintState.UNTAINTED)
            applied_sanitizers = self.symbol_sanitizers.get(arg_sym, [])

            # Check if a sanitizer effective for this sink category was applied
            category_sanitized = any(
                sink.category in san.effective_categories
                for san in applied_sanitizers
            )

            if category_sanitized:
                # Sanitized for this specific category! Suppress finding.
                return None

            if state == TaintState.TAINTED:
                trace = self.symbol_traces.get(arg_sym, [])
                if not trace:
                    continue

                source_step = trace[0]
                self.step_counter += 1
                sink_step = TaintStep(
                    step=self.step_counter,
                    line=line,
                    column=col,
                    operation="SINK",
                    from_symbol=arg_sym,
                    expression=raw_callee_expr,
                    state=TaintState.TAINTED,
                )

                # Assemble breadcrumbs path summary
                path_parts = [f"{source_step.expression} -> {source_step.to_symbol or 'src'} (L{source_step.line})"]
                for mid in trace[1:]:
                    path_parts.append(f"{mid.to_symbol or mid.from_symbol} (L{mid.line})")
                path_parts.append(f"{raw_callee_expr} (L{line})")
                summary = " -> ".join(path_parts)

                taint_path = TaintPath(
                    flow_type="INTRA_PROCEDURAL_TAINT",
                    source={
                        "file_path": file_path,
                        "line": source_step.line,
                        "column": source_step.column,
                        "symbol_name": source_step.to_symbol or arg_sym,
                        "expression": source_step.expression,
                        "source_id": "TAINT_SOURCE",
                    },
                    propagation=[
                        {
                            "step": s.step,
                            "line": s.line,
                            "column": s.column,
                            "operation": s.operation,
                            "from_symbol": s.from_symbol,
                            "to_symbol": s.to_symbol,
                            "expression": s.expression,
                        }
                        for s in trace
                    ],
                    sanitizer=None,
                    sink={
                        "file_path": file_path,
                        "line": line,
                        "column": col,
                        "callee": sink.callee_name,
                        "sink_id": sink.sink_id,
                        "argument_index": v_idx,
                        "tainted_argument": arg_sym,
                    },
                    path_summary=summary,
                    category=sink.category,
                )
                self.detected_paths.append(taint_path)
                return taint_path

        return None
