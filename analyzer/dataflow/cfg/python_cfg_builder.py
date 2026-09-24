"""Python AST Control Flow Graph (CFG) Builder (Phase 18).

Constructs intraprocedural CFGs with basic blocks, branching edges, statement-level
exception routing, finally block traversal, and early-exit reachability pruning.
"""

import ast
from typing import Any, Callable, Optional

from analyzer.dataflow.cfg.models import (
    BasicBlock,
    BranchKind,
    CFGEdge,
    ControlFlowGraph,
)
from analyzer.models.errors import AnalysisCancelledError


class PythonCFGBuilder:
    """Builds a ControlFlowGraph from a Python AST FunctionDef or AsyncFunctionDef."""

    def __init__(
        self,
        max_blocks: int = 64,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.max_blocks = max_blocks
        self.is_cancelled = is_cancelled
        self._block_counter = 0
        self._blocks: dict[str, BasicBlock] = {}
        self._edges: list[CFGEdge] = []
        self._fn_qn = ""
        self._file_path = ""
        self._has_loops = False
        self._has_exceptions = False

    def build_cfg(
        self,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        function_qualified_name: Optional[str] = None,
    ) -> ControlFlowGraph:
        """Construct deterministic intraprocedural CFG for a single function."""
        self._check_cancellation()
        self._block_counter = 0
        self._blocks = {}
        self._edges = []
        self._fn_qn = function_qualified_name or fn_node.name
        self._file_path = file_path
        self._has_loops = False
        self._has_exceptions = False

        # Virtual entry and exit blocks
        entry_bb = self._create_block(start_line=fn_node.lineno, end_line=fn_node.lineno, is_entry=True)
        exit_bb = self._create_block(
            start_line=getattr(fn_node, "end_lineno", fn_node.lineno) or fn_node.lineno,
            end_line=getattr(fn_node, "end_lineno", fn_node.lineno) or fn_node.lineno,
            is_exit=True,
        )

        if not fn_node.body:
            self._add_edge(entry_bb.id, exit_bb.id, BranchKind.UNCONDITIONAL)
        else:
            # Build body from entry to exit
            first_body_block = self._create_block(start_line=fn_node.body[0].lineno, end_line=fn_node.body[0].lineno)
            self._add_edge(entry_bb.id, first_body_block.id, BranchKind.UNCONDITIONAL)

            curr_block = first_body_block
            curr_block = self._process_statement_list(
                statements=fn_node.body,
                current_block=curr_block,
                exit_block_id=exit_bb.id,
            )

            # If the last block didn't terminate, connect it to exit
            if curr_block and not curr_block.is_early_exit:
                self._add_edge(curr_block.id, exit_bb.id, BranchKind.UNCONDITIONAL)

        # Populate predecessors and successors on all blocks
        for edge in self._edges:
            src = self._blocks.get(edge.source_block_id)
            tgt = self._blocks.get(edge.target_block_id)
            if src and tgt:
                if tgt.id not in src.successors:
                    src.successors.append(tgt.id)
                if src.id not in tgt.predecessors:
                    tgt.predecessors.append(src.id)

        return ControlFlowGraph(
            function_qualified_name=self._fn_qn,
            file_path=self._file_path,
            entry_block_id=entry_bb.id,
            exit_block_id=exit_bb.id,
            blocks=self._blocks,
            edges=self._edges,
            has_loops=self._has_loops,
            has_exceptions=self._has_exceptions,
        )

    def _check_cancellation(self) -> None:
        if self.is_cancelled and self.is_cancelled():
            raise AnalysisCancelledError("CFG construction was cancelled by user")

    def _create_block(
        self,
        start_line: int,
        end_line: int,
        is_entry: bool = False,
        is_exit: bool = False,
        is_early_exit: bool = False,
        is_exceptional: bool = False,
        is_finally: bool = False,
    ) -> BasicBlock:
        b_id = f"bb_{self._block_counter}"
        self._block_counter += 1
        bb = BasicBlock(
            id=b_id,
            function_qualified_name=self._fn_qn,
            file_path=self._file_path,
            start_line=start_line,
            end_line=end_line,
            is_entry=is_entry,
            is_exit=is_exit,
            is_early_exit=is_early_exit,
            is_exceptional=is_exceptional,
            is_finally=is_finally,
        )
        self._blocks[b_id] = bb
        return bb

    def _add_edge(
        self,
        src_id: str,
        tgt_id: str,
        kind: BranchKind,
        condition_expr: Optional[str] = None,
        condition_ast: Optional[Any] = None,
    ) -> None:
        edge = CFGEdge(
            source_block_id=src_id,
            target_block_id=tgt_id,
            kind=kind,
            condition_expr=condition_expr,
            condition_ast=condition_ast,
        )
        self._edges.append(edge)

    def _process_statement_list(
        self,
        statements: list[ast.stmt],
        current_block: BasicBlock,
        exit_block_id: str,
        break_target_id: Optional[str] = None,
        continue_target_id: Optional[str] = None,
        enclosing_except_ids: Optional[list[str]] = None,
        enclosing_finally_id: Optional[str] = None,
    ) -> Optional[BasicBlock]:
        """Process a list of statements into basic blocks, updating CFG structure."""
        curr = current_block

        for stmt in statements:
            self._check_cancellation()

            if len(self._blocks) >= self.max_blocks:
                # Exceeded maximum block budget: add unconditional edge to exit and stop splitting
                if curr and not curr.is_early_exit:
                    self._add_edge(curr.id, exit_block_id, BranchKind.UNCONDITIONAL)
                return None

            # 1. Early-exit statements: return, raise, sys.exit
            if isinstance(stmt, (ast.Return, ast.Raise)):
                curr.statements.append(stmt)
                curr.end_line = max(curr.end_line, getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno)
                curr.is_early_exit = True
                target_exit = enclosing_finally_id or exit_block_id
                self._add_edge(curr.id, target_exit, BranchKind.EARLY_EXIT)
                return None

            # 2. Assert statements: split into True continuation and False AssertionError exit
            elif isinstance(stmt, ast.Assert):
                curr.statements.append(stmt)
                curr.end_line = max(curr.end_line, getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno)
                cond_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else "assert"

                # False branch: AssertionError early-exit
                assert_fail_block = self._create_block(
                    start_line=stmt.lineno,
                    end_line=getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno,
                    is_early_exit=True,
                )
                self._add_edge(
                    curr.id,
                    assert_fail_block.id,
                    BranchKind.FALSE_BRANCH,
                    condition_expr=f"not ({cond_str})",
                    condition_ast=stmt.test,
                )
                target_assert_exit = enclosing_finally_id or exit_block_id
                self._add_edge(assert_fail_block.id, target_assert_exit, BranchKind.EARLY_EXIT)

                # True continuation branch: next statements
                true_block = self._create_block(
                    start_line=stmt.lineno,
                    end_line=getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno,
                )
                self._add_edge(
                    curr.id,
                    true_block.id,
                    BranchKind.TRUE_BRANCH,
                    condition_expr=cond_str,
                    condition_ast=stmt.test,
                )
                curr = true_block

            # 3. If-Else conditionals
            elif isinstance(stmt, ast.If):
                cond_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else "cond"
                curr.statements.append(stmt.test)
                curr.end_line = stmt.lineno

                # Decision point is current block
                decision_block = curr

                # True branch
                true_entry = self._create_block(
                    start_line=stmt.body[0].lineno if stmt.body else stmt.lineno,
                    end_line=stmt.body[0].lineno if stmt.body else stmt.lineno,
                )
                self._add_edge(
                    decision_block.id,
                    true_entry.id,
                    BranchKind.TRUE_BRANCH,
                    condition_expr=cond_str,
                    condition_ast=stmt.test,
                )
                true_exit = self._process_statement_list(
                    statements=stmt.body,
                    current_block=true_entry,
                    exit_block_id=exit_block_id,
                    break_target_id=break_target_id,
                    continue_target_id=continue_target_id,
                    enclosing_except_ids=enclosing_except_ids,
                    enclosing_finally_id=enclosing_finally_id,
                )

                # Follow/join block
                follow_block = self._create_block(
                    start_line=stmt.lineno,
                    end_line=stmt.lineno,
                )

                if stmt.orelse:
                    false_entry = self._create_block(
                        start_line=stmt.orelse[0].lineno,
                        end_line=stmt.orelse[0].lineno,
                    )
                    self._add_edge(
                        decision_block.id,
                        false_entry.id,
                        BranchKind.FALSE_BRANCH,
                        condition_expr=f"not ({cond_str})",
                        condition_ast=stmt.test,
                    )
                    false_exit = self._process_statement_list(
                        statements=stmt.orelse,
                        current_block=false_entry,
                        exit_block_id=exit_block_id,
                        break_target_id=break_target_id,
                        continue_target_id=continue_target_id,
                        enclosing_except_ids=enclosing_except_ids,
                        enclosing_finally_id=enclosing_finally_id,
                    )
                    if false_exit and not false_exit.is_early_exit:
                        self._add_edge(false_exit.id, follow_block.id, BranchKind.UNCONDITIONAL)
                else:
                    # No else branch: false branch goes directly to follow block
                    self._add_edge(
                        decision_block.id,
                        follow_block.id,
                        BranchKind.FALSE_BRANCH,
                        condition_expr=f"not ({cond_str})",
                        condition_ast=stmt.test,
                    )

                if true_exit and not true_exit.is_early_exit:
                    self._add_edge(true_exit.id, follow_block.id, BranchKind.UNCONDITIONAL)

                curr = follow_block

            # 4. Loops (While, For)
            elif isinstance(stmt, (ast.While, ast.For)):
                self._has_loops = True
                loop_header = self._create_block(start_line=stmt.lineno, end_line=stmt.lineno)
                self._add_edge(curr.id, loop_header.id, BranchKind.UNCONDITIONAL)

                cond_str = ""
                cond_ast = None
                if isinstance(stmt, ast.While):
                    cond_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else "while_cond"
                    cond_ast = stmt.test
                else:
                    cond_str = f"iter({ast.unparse(stmt.iter)})" if hasattr(ast, "unparse") else "for_iter"

                loop_exit_block = self._create_block(start_line=stmt.lineno, end_line=stmt.lineno)
                self._add_edge(loop_header.id, loop_exit_block.id, BranchKind.LOOP_EXIT)

                # Loop body
                if stmt.body:
                    body_entry = self._create_block(start_line=stmt.body[0].lineno, end_line=stmt.body[0].lineno)
                    self._add_edge(
                        loop_header.id,
                        body_entry.id,
                        BranchKind.TRUE_BRANCH,
                        condition_expr=cond_str,
                        condition_ast=cond_ast,
                    )
                    body_exit = self._process_statement_list(
                        statements=stmt.body,
                        current_block=body_entry,
                        exit_block_id=exit_block_id,
                        break_target_id=loop_exit_block.id,
                        continue_target_id=loop_header.id,
                        enclosing_except_ids=enclosing_except_ids,
                        enclosing_finally_id=enclosing_finally_id,
                    )
                    if body_exit and not body_exit.is_early_exit:
                        self._add_edge(body_exit.id, loop_header.id, BranchKind.LOOP_BACK)

                curr = loop_exit_block

            # 5. Break & Continue
            elif isinstance(stmt, ast.Break):
                curr.statements.append(stmt)
                curr.is_early_exit = True
                if break_target_id:
                    self._add_edge(curr.id, break_target_id, BranchKind.UNCONDITIONAL)
                return None

            elif isinstance(stmt, ast.Continue):
                curr.statements.append(stmt)
                curr.is_early_exit = True
                if continue_target_id:
                    self._add_edge(curr.id, continue_target_id, BranchKind.UNCONDITIONAL)
                return None

            # 6. Try-Except-Finally
            elif isinstance(stmt, ast.Try):
                self._has_exceptions = True
                follow_after_try = self._create_block(start_line=stmt.lineno, end_line=stmt.lineno)

                # Finally block if present
                finally_block = None
                if stmt.finalbody:
                    finally_block = self._create_block(
                        start_line=stmt.finalbody[0].lineno,
                        end_line=stmt.finalbody[-1].lineno,
                        is_finally=True,
                    )
                    fin_exit = self._process_statement_list(
                        statements=stmt.finalbody,
                        current_block=finally_block,
                        exit_block_id=exit_block_id,
                    )
                    if fin_exit and not fin_exit.is_early_exit:
                        self._add_edge(fin_exit.id, follow_after_try.id, BranchKind.FINALLY_EXIT)

                # Except handlers
                handler_blocks: list[BasicBlock] = []
                for handler in stmt.handlers:
                    h_block = self._create_block(
                        start_line=handler.lineno,
                        end_line=handler.end_lineno or handler.lineno,
                        is_exceptional=True,
                    )
                    handler_blocks.append(h_block)
                    target_h_exit = finally_block.id if finally_block else follow_after_try.id
                    h_exit = self._process_statement_list(
                        statements=handler.body,
                        current_block=h_block,
                        exit_block_id=exit_block_id,
                        enclosing_finally_id=finally_block.id if finally_block else None,
                    )
                    if h_exit and not h_exit.is_early_exit:
                        self._add_edge(h_exit.id, target_h_exit, BranchKind.UNCONDITIONAL)

                # Try body
                try_entry = self._create_block(start_line=stmt.body[0].lineno, end_line=stmt.body[0].lineno)
                self._add_edge(curr.id, try_entry.id, BranchKind.UNCONDITIONAL)

                # Link exceptional edges from try body statements to handlers
                for h_block in handler_blocks:
                    self._add_edge(try_entry.id, h_block.id, BranchKind.EXCEPTIONAL)

                try_exit = self._process_statement_list(
                    statements=stmt.body,
                    current_block=try_entry,
                    exit_block_id=exit_block_id,
                    enclosing_except_ids=[h.id for h in handler_blocks],
                    enclosing_finally_id=finally_block.id if finally_block else None,
                )

                normal_target = finally_block.id if finally_block else follow_after_try.id
                if try_exit and not try_exit.is_early_exit:
                    if stmt.orelse:
                        orelse_entry = self._create_block(start_line=stmt.orelse[0].lineno, end_line=stmt.orelse[0].lineno)
                        self._add_edge(try_exit.id, orelse_entry.id, BranchKind.UNCONDITIONAL)
                        orelse_exit = self._process_statement_list(
                            statements=stmt.orelse,
                            current_block=orelse_entry,
                            exit_block_id=exit_block_id,
                            enclosing_finally_id=finally_block.id if finally_block else None,
                        )
                        if orelse_exit and not orelse_exit.is_early_exit:
                            self._add_edge(orelse_exit.id, normal_target, BranchKind.UNCONDITIONAL)
                    else:
                        self._add_edge(try_exit.id, normal_target, BranchKind.UNCONDITIONAL)

                curr = follow_after_try

            # 7. Standard sequential statements (Assign, Expr, etc.)
            else:
                curr.statements.append(stmt)
                curr.end_line = max(curr.end_line, getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno)

                # If this statement is inside a try block and can raise, add exceptional edge
                if enclosing_except_ids and isinstance(stmt, (ast.Call, ast.Subscript, ast.Attribute, ast.BinOp)):
                    for h_id in enclosing_except_ids:
                        self._add_edge(curr.id, h_id, BranchKind.EXCEPTIONAL)

        return curr
