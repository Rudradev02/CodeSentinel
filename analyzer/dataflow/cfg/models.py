"""Domain models for Phase 18 Control Flow Graph (CFG) and Bounded Path-Sensitive Analysis."""

from enum import Enum
from typing import Any, Optional, Union
from pydantic import BaseModel, Field


class BranchKind(str, Enum):
    """Classification of CFG edge branches."""
    UNCONDITIONAL = "UNCONDITIONAL"
    TRUE_BRANCH = "TRUE_BRANCH"
    FALSE_BRANCH = "FALSE_BRANCH"
    EARLY_EXIT = "EARLY_EXIT"          # return, raise, throw, sys.exit
    LOOP_BACK = "LOOP_BACK"            # loop iteration back-edge
    LOOP_EXIT = "LOOP_EXIT"            # loop termination edge
    EXCEPTIONAL = "EXCEPTIONAL"        # raising statement -> except block
    FINALLY_ENTRY = "FINALLY_ENTRY"    # normal/exceptional exit -> finally block
    FINALLY_EXIT = "FINALLY_EXIT"      # finally exit -> continuation/re-raise


class CFGEdge(BaseModel):
    """Directed edge connecting basic blocks."""
    source_block_id: str
    target_block_id: str
    kind: BranchKind
    condition_expr: Optional[str] = None
    condition_ast: Optional[Any] = Field(default=None, exclude=True)


class BasicBlock(BaseModel):
    """Sequence of statements entered only at beginning and exited only at end."""
    id: str                             # Deterministic block ID (e.g. "bb_0")
    function_qualified_name: str
    file_path: str
    start_line: int
    end_line: int
    statements: list[Any] = Field(default_factory=list, exclude=True)
    is_entry: bool = False
    is_exit: bool = False
    is_early_exit: bool = False         # Block terminates with return/raise/sys.exit
    is_exceptional: bool = False        # Except handler block
    is_finally: bool = False            # Finally cleanup block
    predecessors: list[str] = Field(default_factory=list)
    successors: list[str] = Field(default_factory=list)


class ControlFlowGraph(BaseModel):
    """Intraprocedural control flow graph for a single function."""
    function_qualified_name: str
    file_path: str
    entry_block_id: str
    exit_block_id: str
    blocks: dict[str, BasicBlock] = Field(default_factory=dict)
    edges: list[CFGEdge] = Field(default_factory=list)
    has_loops: bool = False
    has_exceptions: bool = False

    def get_successors(self, block_id: str) -> list[tuple[BasicBlock, CFGEdge]]:
        """Return list of (successor_block, edge) pairs for a block."""
        result = []
        for edge in self.edges:
            if edge.source_block_id == block_id:
                target_block = self.blocks.get(edge.target_block_id)
                if target_block:
                    result.append((target_block, edge))
        return result

    def get_predecessors(self, block_id: str) -> list[tuple[BasicBlock, CFGEdge]]:
        """Return list of (predecessor_block, edge) pairs for a block."""
        result = []
        for edge in self.edges:
            if edge.target_block_id == block_id:
                source_block = self.blocks.get(edge.source_block_id)
                if source_block:
                    result.append((source_block, edge))
        return result


class PredicateOp(str, Enum):
    """Recognized propositional guard predicate operators."""
    IS_INSTANCE = "IS_INSTANCE"          # isinstance(x, (int, float))
    IS_DIGIT = "IS_DIGIT"                # x.isdigit()
    IS_ALPHA = "IS_ALPHA"                # x.isalnum()
    IS_NONE = "IS_NONE"                  # x is None
    IS_NOT_NONE = "IS_NOT_NONE"          # x is not None
    EQUALS_CONST = "EQUALS_CONST"        # x == "STATIC"
    NOT_EQUALS_CONST = "NOT_EQUALS_CONST"# x != "STATIC"
    ANCHORED_REGEX = "ANCHORED_REGEX"    # re.match(r'^[a-z]+$', x)
    REGISTERED_VALIDATOR = "REGISTERED_VALIDATOR" # Statically analyzed or config-whitelisted validator
    TRUTHY = "TRUTHY"                    # if x:
    FALSY = "FALSY"                      # if not x:
    COMPOSITE_AND = "COMPOSITE_AND"      # c1 and c2
    COMPOSITE_OR = "COMPOSITE_OR"        # c1 or c2
    COMPOSITE_NOT = "COMPOSITE_NOT"      # not c


class GuardCondition(BaseModel):
    """Single propositional guard predicate."""
    variable_name: str
    predicate_op: PredicateOp
    expected_value: bool                 # True on matching branch, False on alternative
    argument_literal: Optional[str] = None
    raw_expression: str = ""
    line: int = 0
    col: int = 0


class CompositeCondition(BaseModel):
    """Boolean composition of guard conditions (AND, OR, NOT)."""
    operator: PredicateOp               # COMPOSITE_AND, COMPOSITE_OR, COMPOSITE_NOT
    children: list[Union[GuardCondition, "CompositeCondition"]] = Field(default_factory=list)


class RefinementFact(BaseModel):
    """Path-specific value refinement fact evaluated by rule sinks."""
    variable_name: str
    refined_type: Optional[str] = None        # e.g. "int", "bool"
    is_numeric_string: bool = False           # e.g. from isdigit()
    is_alphanumeric_string: bool = False      # e.g. from isalnum()
    is_non_null: bool = False                 # e.g. from is not None
    applicable_sanitizer_category: Optional[str] = None # e.g. SinkCategory.COMMAND_EXECUTE
    provenance_line: int = 0


class PathFeasibilityStatus(str, Enum):
    """Explicit feasibility status of a path constraint."""
    FEASIBLE = "FEASIBLE"
    INFEASIBLE = "INFEASIBLE"
    UNKNOWN_GUARD = "UNKNOWN_GUARD"
    UNKNOWN_CONTROL_FLOW = "UNKNOWN_CONTROL_FLOW"
    WIDENED = "WIDENED"
    TRUNCATED = "TRUNCATED"


class PathConstraint(BaseModel):
    """Conjunction of guard conditions and refinement facts along an active path."""
    conditions: list[GuardCondition] = Field(default_factory=list)
    refinement_facts: dict[str, list[RefinementFact]] = Field(default_factory=dict) # var -> facts
    feasibility: PathFeasibilityStatus = PathFeasibilityStatus.FEASIBLE
    contradiction_reason: Optional[str] = None
    is_widened: bool = False
    is_truncated: bool = False

    def add_condition(self, cond: GuardCondition) -> None:
        self.conditions.append(cond)

    def add_refinement(self, fact: RefinementFact) -> None:
        self.refinement_facts.setdefault(fact.variable_name, []).append(fact)

    def has_refinement_for(self, var_name: str, check_fn: Any) -> bool:
        facts = self.refinement_facts.get(var_name, [])
        return any(check_fn(f) for f in facts)


class PathState(BaseModel):
    """Analysis state along a specific execution path within a function."""
    path_id: str
    current_block_id: str
    constraints: PathConstraint = Field(default_factory=PathConstraint)
    var_states: dict[str, str] = Field(default_factory=dict) # var -> TaintState string
    alias_bindings: dict[str, list[str]] = Field(default_factory=dict) # var -> candidate object IDs
    field_states: dict[str, str] = Field(default_factory=dict) # base.field -> TaintState string
    call_chain: list[Any] = Field(default_factory=list)
    branch_depth: int = 0
    is_terminated: bool = False
