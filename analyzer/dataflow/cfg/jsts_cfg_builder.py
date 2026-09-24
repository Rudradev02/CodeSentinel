"""JavaScript / TypeScript Tree-sitter Control Flow Graph (CFG) Builder (Phase 18).

Constructs intraprocedural CFGs for JS/TS function CSTs with basic blocks, branching,
early exits (return, throw), try/catch/finally routing, and loops.
"""

from typing import Any, Callable, Optional
from tree_sitter import Node

from analyzer.dataflow.cfg.models import (
    BasicBlock,
    BranchKind,
    CFGEdge,
    ControlFlowGraph,
)
from analyzer.models.errors import AnalysisCancelledError
from analyzer.rules.js_ast_helper import node_text


class JSTSCFGBuilder:
    """Builds a ControlFlowGraph from a JavaScript or TypeScript function CST Node."""

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
        fn_node: Node,
        source_bytes: bytes,
        file_path: str,
        function_qualified_name: Optional[str] = None,
    ) -> ControlFlowGraph:
        """Construct deterministic intraprocedural CFG for a JS/TS function."""
        self._check_cancellation()
        self._block_counter = 0
        self._blocks = {}
        self._edges = []
        self._fn_qn = function_qualified_name or "<anonymous>"
        self._file_path = file_path
        self._has_loops = False
        self._has_exceptions = False

        start_line = fn_node.start_point[0] + 1
        end_line = fn_node.end_point[0] + 1

        entry_bb = self._create_block(start_line=start_line, end_line=start_line, is_entry=True)
        exit_bb = self._create_block(start_line=end_line, end_line=end_line, is_exit=True)

        body_node = self._find_body(fn_node)
        if not body_node:
            self._add_edge(entry_bb.id, exit_bb.id, BranchKind.UNCONDITIONAL)
        else:
            first_body_block = self._create_block(start_line=start_line, end_line=start_line)
            self._add_edge(entry_bb.id, first_body_block.id, BranchKind.UNCONDITIONAL)

            curr_block = self._process_body(
                body_node=body_node,
                source_bytes=source_bytes,
                current_block=first_body_block,
                exit_block_id=exit_bb.id,
            )

            if curr_block and not curr_block.is_early_exit:
                self._add_edge(curr_block.id, exit_bb.id, BranchKind.UNCONDITIONAL)

        # Build predecessors and successors
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
            raise AnalysisCancelledError("JS/TS CFG construction was cancelled by user")

    def _find_body(self, fn_node: Node) -> Optional[Node]:
        for child in fn_node.children:
            if child.type == "statement_block":
                return child
        body = fn_node.child_by_field_name("body")
        if body and body.type == "statement_block":
            return body
        return None

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
    ) -> None:
        edge = CFGEdge(
            source_block_id=src_id,
            target_block_id=tgt_id,
            kind=kind,
            condition_expr=condition_expr,
        )
        self._edges.append(edge)

    def _process_body(
        self,
        body_node: Node,
        source_bytes: bytes,
        current_block: BasicBlock,
        exit_block_id: str,
        break_target_id: Optional[str] = None,
        continue_target_id: Optional[str] = None,
        enclosing_catch_id: Optional[str] = None,
        enclosing_finally_id: Optional[str] = None,
    ) -> Optional[BasicBlock]:
        curr = current_block

        for child in body_node.children:
            self._check_cancellation()

            if len(self._blocks) >= self.max_blocks:
                if curr and not curr.is_early_exit:
                    self._add_edge(curr.id, exit_block_id, BranchKind.UNCONDITIONAL)
                return None

            c_type = child.type
            line = child.start_point[0] + 1

            # 1. Early-exit: return, throw
            if c_type in ("return_statement", "throw_statement"):
                curr.statements.append(child)
                curr.end_line = child.end_point[0] + 1
                curr.is_early_exit = True
                target_exit = enclosing_finally_id or exit_block_id
                self._add_edge(curr.id, target_exit, BranchKind.EARLY_EXIT)
                return None

            # 2. If-Else conditionals
            elif c_type == "if_statement":
                cond_node = child.child_by_field_name("condition")
                consequence = child.child_by_field_name("consequence")
                alternative = child.child_by_field_name("alternative")

                cond_str = node_text(cond_node, source_bytes).strip() if cond_node else "cond"
                curr.end_line = line
                decision_block = curr

                # True branch
                t_line = consequence.start_point[0] + 1 if consequence else line
                true_entry = self._create_block(start_line=t_line, end_line=t_line)
                self._add_edge(
                    decision_block.id,
                    true_entry.id,
                    BranchKind.TRUE_BRANCH,
                    condition_expr=cond_str,
                )

                true_block_target = consequence
                if consequence and consequence.type == "statement_block":
                    true_exit = self._process_body(
                        body_node=consequence,
                        source_bytes=source_bytes,
                        current_block=true_entry,
                        exit_block_id=exit_block_id,
                        break_target_id=break_target_id,
                        continue_target_id=continue_target_id,
                        enclosing_catch_id=enclosing_catch_id,
                        enclosing_finally_id=enclosing_finally_id,
                    )
                else:
                    true_exit = true_entry

                # Follow/join block
                follow_block = self._create_block(start_line=line, end_line=line)

                # Alternative (else)
                if alternative:
                    # Unwrap else_clause if present
                    alt_stmt = alternative
                    if alternative.type == "else_clause":
                        alt_stmt = alternative.children[1] if len(alternative.children) > 1 else alternative

                    a_line = alt_stmt.start_point[0] + 1 if alt_stmt else line
                    false_entry = self._create_block(start_line=a_line, end_line=a_line)
                    self._add_edge(
                        decision_block.id,
                        false_entry.id,
                        BranchKind.FALSE_BRANCH,
                        condition_expr=f"!({cond_str})",
                    )
                    if alt_stmt and alt_stmt.type == "statement_block":
                        false_exit = self._process_body(
                            body_node=alt_stmt,
                            source_bytes=source_bytes,
                            current_block=false_entry,
                            exit_block_id=exit_block_id,
                            break_target_id=break_target_id,
                            continue_target_id=continue_target_id,
                            enclosing_catch_id=enclosing_catch_id,
                            enclosing_finally_id=enclosing_finally_id,
                        )
                    else:
                        false_exit = false_entry

                    if false_exit and not false_exit.is_early_exit:
                        self._add_edge(false_exit.id, follow_block.id, BranchKind.UNCONDITIONAL)
                else:
                    self._add_edge(
                        decision_block.id,
                        follow_block.id,
                        BranchKind.FALSE_BRANCH,
                        condition_expr=f"!({cond_str})",
                    )

                if true_exit and not true_exit.is_early_exit:
                    self._add_edge(true_exit.id, follow_block.id, BranchKind.UNCONDITIONAL)

                curr = follow_block

            # 3. Loops (while, for)
            elif c_type in ("while_statement", "for_statement"):
                self._has_loops = True
                loop_header = self._create_block(start_line=line, end_line=line)
                self._add_edge(curr.id, loop_header.id, BranchKind.UNCONDITIONAL)

                cond_node = child.child_by_field_name("condition")
                cond_str = node_text(cond_node, source_bytes).strip() if cond_node else "loop_cond"

                loop_exit_block = self._create_block(start_line=line, end_line=line)
                self._add_edge(loop_header.id, loop_exit_block.id, BranchKind.LOOP_EXIT)

                body = child.child_by_field_name("body")
                if body and body.type == "statement_block":
                    b_line = body.start_point[0] + 1
                    body_entry = self._create_block(start_line=b_line, end_line=b_line)
                    self._add_edge(loop_header.id, body_entry.id, BranchKind.TRUE_BRANCH, condition_expr=cond_str)
                    body_exit = self._process_body(
                        body_node=body,
                        source_bytes=source_bytes,
                        current_block=body_entry,
                        exit_block_id=exit_block_id,
                        break_target_id=loop_exit_block.id,
                        continue_target_id=loop_header.id,
                        enclosing_catch_id=enclosing_catch_id,
                        enclosing_finally_id=enclosing_finally_id,
                    )
                    if body_exit and not body_exit.is_early_exit:
                        self._add_edge(body_exit.id, loop_header.id, BranchKind.LOOP_BACK)

                curr = loop_exit_block

            # 4. Break & Continue
            elif c_type == "break_statement":
                curr.statements.append(child)
                curr.is_early_exit = True
                if break_target_id:
                    self._add_edge(curr.id, break_target_id, BranchKind.UNCONDITIONAL)
                return None

            elif c_type == "continue_statement":
                curr.statements.append(child)
                curr.is_early_exit = True
                if continue_target_id:
                    self._add_edge(curr.id, continue_target_id, BranchKind.UNCONDITIONAL)
                return None

            # 5. Try-Catch-Finally
            elif c_type == "try_statement":
                self._has_exceptions = True
                follow_after_try = self._create_block(start_line=line, end_line=line)

                # Catch clause
                catch_block = None
                for c in child.children:
                    if c.type == "catch_clause":
                        c_body = c.child_by_field_name("body")
                        if c_body:
                            c_line = c_body.start_point[0] + 1
                            catch_block = self._create_block(start_line=c_line, end_line=c_line, is_exceptional=True)
                            c_exit = self._process_body(
                                body_node=c_body,
                                source_bytes=source_bytes,
                                current_block=catch_block,
                                exit_block_id=exit_block_id,
                            )
                            if c_exit and not c_exit.is_early_exit:
                                self._add_edge(c_exit.id, follow_after_try.id, BranchKind.UNCONDITIONAL)

                # Try body
                try_body = child.child_by_field_name("body")
                if try_body and try_body.type == "statement_block":
                    t_line = try_body.start_point[0] + 1
                    try_entry = self._create_block(start_line=t_line, end_line=t_line)
                    self._add_edge(curr.id, try_entry.id, BranchKind.UNCONDITIONAL)
                    if catch_block:
                        self._add_edge(try_entry.id, catch_block.id, BranchKind.EXCEPTIONAL)
                    try_exit = self._process_body(
                        body_node=try_body,
                        source_bytes=source_bytes,
                        current_block=try_entry,
                        exit_block_id=exit_block_id,
                        enclosing_catch_id=catch_block.id if catch_block else None,
                    )
                    if try_exit and not try_exit.is_early_exit:
                        self._add_edge(try_exit.id, follow_after_try.id, BranchKind.UNCONDITIONAL)

                curr = follow_after_try

            # 6. Normal statement (declarations, expressions)
            else:
                curr.statements.append(child)
                curr.end_line = child.end_point[0] + 1

        return curr
