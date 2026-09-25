# CodeSentinel Phase 19 Implementation Plan
## Path-Sensitive Interprocedural Contracts, Function Summaries & Cross-Function Guard/Taint Reasoning

---

## 1. Executive Summary

CodeSentinel is an offline-first, repository-local static architecture and security analyzer. Phase 18 successfully established intraprocedural Control-Flow Graph (CFG) analysis, propositional guard evaluation, and path-sensitive taint verification within individual function scopes and across immediate caller-callee invocation boundaries. 

However, in real-world application architectures, security-critical data paths routinely traverse layered multi-hop architectures:
```text
Controller (HTTP Route & Parameter Ingestion)
    ↓
Validator (Propositional Helper / Predicate Function)
    ↓
Service (Domain Business Logic & Normalization)
    ↓
Repository / Adapter (Field Mapping & Entity Assembly)
    ↓
Sink (Parameterized / Raw Database Execution or OS Command)
```

In Phase 18, cross-function reasoning is fundamentally constrained:
1. **Validator Semantic Isolation**: A helper function returning a boolean validation result (e.g. `def is_valid_id(val): return isinstance(val, int)`) does not export a formal contract to its callers. A caller branching on `if is_valid_id(val):` sees only an arbitrary boolean return, without proof that the True branch refines `val` to an integer.
2. **Conditional Transformation Decay**: Functions that conditionally sanitize or normalize data (e.g. `def process(x, sanitize=False): return clean(x) if sanitize else x`) cannot express path-governed return taint across hops without literal constant propagation.
3. **Multi-Hop Guard Erasure**: Caller guards established in a top-level controller do not survive through intermediate service layers unless inlined or carried through unadulterated variable bindings.
4. **Field Mutation Loss**: Functions that sanitize object fields (e.g. `def sanitize_record(rec): rec.id = clean(rec.id)`) record raw field writes, but cannot express under what path conditions or guards those mutations occurred.

**Phase 19** resolves these gaps by establishing a **Bounded Path-Sensitive Function Contract and Context-Sensitive Summary Evaluation Subsystem**. Rather than attempting unbounded symbolic execution or naive interprocedural AST inlining (both of which cause combinatorial explosion), Phase 19 synthesizes and evaluates formal, deterministic **Function Contracts** defining:
- **Preconditions**: Inferred or explicit obligations on parameters, types, formats, nullity, or sanitizer categories that a caller must prove before invoking a callee sink.
- **Postconditions**: Proven return relationships and argument refinement facts produced upon function completion (e.g. `return == True ==> argument[0]` is refined to `int`).
- **Conditional Effects**: Taint transfers, sanitization events, and field writes gated by deterministic path conditions.
- **Context-Sensitive Evaluation**: Bounded specialization on literal arguments, boolean flags, and receiver types ($k \le 2$).
- **Monotonic Safety**: Strict adherence to the safety invariant: `UNKNOWN != SAFE`, `WIDENED != SAFE`, `TRUNCATED != SAFE`, and `UNRESOLVED != SAFE`.

Phase 19 maintains CodeSentinel's core architectural commitments: 100% offline determinism, zero external runtime dependencies, zero database schema migrations, and immutable baseline differential matching.

---

## 2. Repository State Verification

The active repository was inspected and verified as of commit `b938aca`:

### 2.1 Test Suite & Build Verification
- **Full Test Suite**: 522 passing tests (425 in `analyzer/tests/`, 97 in `backend/tests/`, 1 skipped).
- **Phase 18 Coverage**: 48 targeted tests across CFG construction, path exploration, guard evaluation, reporting, CLI, and backward compatibility.
- **Frontend Build**: Production build (`tsc -b && vite build` in `frontend/`) completes cleanly with 0 TypeScript diagnostics and 0 bundle errors.
- **Multi-Run Determinism**: Verified identical finding IDs, counts, and path-sensitivity summaries over 5 consecutive runs.

### 2.2 Analyzer Boundary & Independence
- The `analyzer/` package has **0 imports** of FastAPI, SQLAlchemy, Celery, Redis, PostgreSQL drivers, or AI SDKs.
- Static analysis operates 100% offline on local disk without executing analyzed code or spawning subshells.

### 2.3 Persistence & DTO Schema
- `analysis_snapshots.call_graph_summary` is a nullable JSON column (`sa.JSON()`) added in migration `0006_phase15_callgraph_summary.py`.
- Phase 16 (`type_resolution`, `context_sensitivity`), Phase 17 (`alias_analysis`), and Phase 18 (`path_sensitivity`) all reside within this existing column.
- Phase 19 contract metrics will be added to `CallGraphSummaryDTO` as an optional nested object with **zero database migrations**.

### 2.4 Verified Discrepancies Between Phase 18 Walkthrough and Active Repository
An audit of the Phase 18 implementation revealed the following discrepancies between documentation and source code:
1. **Rule Base Modification**: Section 28 of `PHASE_18_IMPLEMENTATION_PLAN.md` proposed modifying `analyzer/security/base_rule.py` to inspect `RefinementFacts`. In actual implementation, sink refinement checks were integrated into `analyzer/dataflow/taint/propagator.py` (intraprocedural) and `analyzer/dataflow/interprocedural/propagator.py` (`_is_guard_satisfying_sink`), leaving `base_rule.py` completely untouched. Phase 19 maintains this architectural pattern and will NOT modify `base_rule.py`.
2. **Test Count Terminology**: Phrasing in the Phase 18 walkthrough ("48 new tests and 522 pre-existing tests") conflated the total with pre-existing tests. The verified repository reality is: **474 pre-Phase-18 tests + 48 Phase-18 tests = 522 total passing tests**.
3. **Propagator Loop Recursion**: `InterproceduralTaintPropagator._collect_python_statements_with_path_context` recurses on `ast.If` and `ast.Try` up to `max_branch_depth = 6`, but loops (`ast.For`, `ast.While`) are processed at the current block level without loop unrolling in interprocedural statement flattening. Phase 19 contract extraction will rely on the CFG builder and `PathExplorer` rather than ad-hoc statement recursion.
4. **Validator Refinement Depth**: While `GuardEvaluator` recognizes `registered_validators` (`is_valid`, `validate_id`), it currently generates only generic nullity refinements (`is_non_null = True`). It cannot infer return-to-parameter refinement postconditions from the callee function's AST body.

---

## 3. Phase 18 Baseline

Phase 18 established the control-flow and path-sensitivity foundation in CodeSentinel:

```text
AST / Tree-sitter
      ↓
CFG (python_cfg_builder.py, jsts_cfg_builder.py)
      ↓
Bounded Path Explorer (path_explorer.py, k <= 8, max_states = 128)
      ↓
Guard Evaluator (guard_evaluator.py: isinstance, isdigit, anchored regex, AND/OR/NOT)
      ↓
Refinement Facts (models.py: RefinementFact, PathConstraint)
      ↓
Path Feasibility (models.py: PathFeasibilityStatus, contradiction pruning)
      ↓
Immediate Caller-Callee Sink Checks (propagator.py: _is_guard_satisfying_sink)
      ↓
Evidence Enrichment (SARIF property bags, Terminal/MD, UI trace viewer)
```

### Verified Phase 18 Parameter Defaults
- `max_active_paths` = 8 (maximum active paths per function before widening)
- `max_total_path_states` = 128 (maximum explored path states per function)
- `max_branch_depth` = 6 (maximum nested branch depth)
- `max_conditions_per_path` = 16 (maximum accumulated guard conditions before truncation)
- `max_cfg_blocks` = 64 (maximum basic blocks analyzed per function CFG)

---

## 4. Confirmed Phase 18 Limitations

Phase 19 addresses the following verified limitations:

### 4.1 Validator Contract Gap
A function such as:
```python
def is_valid_id(value):
    return isinstance(value, int)
```
returns a boolean whose semantic relationship with `value` is not exported to the caller. Callers testing `if is_valid_id(val):` treat the check as an opaque condition, failing to deduce that `val` is refined to `int` on the True branch.

### 4.2 Conditional Transformation Gap
A function such as:
```python
def process(value, sanitize=False):
    if sanitize:
        return sanitize_value(value)
    return value
```
cannot be summarized path-sensitively without context-specific argument specialization. A static summary cannot claim `process()` always sanitizes `value`, nor that it always preserves taint.

### 4.3 Multi-Hop Contract Gap
In a call chain:
```text
Controller → Validator → Service → Repository → Sink
```
guards established upstream decay at intermediate boundaries unless inlined or carried through unadulterated variable bindings.

### 4.4 Field Mutation Gap
Cross-function field modifications:
```python
def sanitize_account(account):
    account.user_id = normalize(account.user_id)
```
record field transfers, but cannot express under what path conditions or guards the field update occurred.

---

## 5. Phase 19 Goals

1. **Formal Function Contract Domain Model**: Implement `FunctionContract`, `SummaryPrecondition`, `SummaryPostcondition`, and `ConditionalTaintEffect` decoupled from global taint states.
2. **Intraprocedural Contract Synthesis**: Automatically synthesize function contracts during base summarization from CFG paths and return statements for Python and JS/TS.
3. **Boolean Validator Postcondition Binding**: Infer that boolean validator functions (e.g. `return isinstance(x, int)`) establish postconditions (`RETURN_EQUALS_TRUE ==> x is int`) and bind those refinements in callers testing `if validator(x):`.
4. **Callee Precondition Verification**: Infer callee sink preconditions (e.g. SQL sink requires numeric or sanitized argument) and verify whether the caller's active path state satisfies them.
5. **Path-Gated Conditional Effects**: Summarize taint transfers, sanitizers, and field updates with governing path conditions (`path_condition ==> effect`).
6. **Bounded Context-Sensitive Contract Cache**: Extend `ContextSummaryManager` with deterministic contract caching keyed by function, context ID, argument types, and full canonical configuration hash.
7. **Recursive Call Handling**: Handle direct recursion, mutual recursion, and SCC loops via Tarjan's SCC algorithm, bounded fixed-point iteration ($\le 5$), and monotonic widening to `UNKNOWN`.
8. **Multi-Hop Trace Evidence**: Propagate contract verification evidence across multi-hop call chains into SARIF v2.1.0, terminal reports, markdown reports, and the frontend trace viewer.
9. **Conservative Safety & Invariance**: Preserve `UNKNOWN != SAFE`, 100% offline determinism, and immutable baseline comparator signatures.

---

## 6. Non-Goals

Phase 19 explicitly excludes the following out-of-scope capabilities:
1. **No External SMT/SAT Solvers**: Zero dependencies on Z3, CVC5, or external binaries. Path condition evaluation remains pure Python propositional logic.
2. **No Dynamic Code Execution**: Zero execution or importing of analyzed repository files in Python or Node.js runtimes.
3. **No Unbounded Symbolic Execution**: No interprocedural symbolic state branching. Function calls are composed via summaries, not full path inlining.
4. **No Arbitrary Function Trust by Name**: Functions named `validate()`, `sanitize()`, or `clean()` are **never** trusted automatically unless statically proven by their AST bodies or explicitly registered in repository configuration.
5. **No Database Schema Alterations**: No new database tables, columns, or Alembic migrations. All metrics persist in the existing `call_graph_summary` JSON column.
6. **No Alteration of Primary Finding ID Formula**: Finding IDs remain invariant hashes of rule ID and source coordinates. Contracts are stored in finding `evidence` and SARIF property bags.
7. **No Independent Taint Lattice**: Phase 19 strictly uses the existing canonical `TaintState` (`TAINTED`, `UNTAINTED`, `SANITIZED`, `UNKNOWN`).

---

## 7. Existing Components to Reuse

| Existing Component | Source File | Phase 19 Usage Strategy | Classification |
| :--- | :--- | :--- | :--- |
| `ControlFlowGraph`, `BasicBlock`, `CFGEdge` | `analyzer/dataflow/cfg/models.py` | Traversed to find return blocks, exit conditions, and statement guards. | **REUSE AS-IS** |
| `GuardCondition`, `PredicateOp`, `RefinementFact` | `analyzer/dataflow/cfg/models.py` | Atomic building blocks of preconditions, postconditions, and refinement facts. | **REUSE AS-IS** |
| `PathConstraint`, `PathFeasibilityStatus`, `PathState` | `analyzer/dataflow/cfg/models.py` | Represents path state during contract extraction and caller-side evaluation. | **REUSE AS-IS** |
| `PythonCFGBuilder`, `JSTSCFGBuilder` | `analyzer/dataflow/cfg/` | Generates CFGs from which function contracts are extracted. | **REUSE AS-IS** |
| `GuardEvaluator` | `analyzer/dataflow/cfg/guard_evaluator.py` | Evaluates AST condition expressions into `GuardCondition`s and `RefinementFact`s. | **REUSE AS-IS** |
| `PathExplorer` | `analyzer/dataflow/cfg/path_explorer.py` | Explores bounded feasible paths within function bodies to extract contracts. | **REUSE AS-IS** |
| `TaintState`, `SinkCategory` | `analyzer/dataflow/taint/models.py` | Canonical taint states and sink classifications. | **REUSE AS-IS** |
| `RichSummaryTransfer`, `TransferDirection` | `analyzer/dataflow/callgraph/models.py` | Extended and paired with conditional path guards. | **REUSE & EXTEND** |
| `CallContext`, `ContextManager` | `analyzer/dataflow/callgraph/context_manager.py` | Manages call-string context IDs and constant argument masks ($k \le 2$). | **REUSE AS-IS** |
| `ContextSummaryManager` | `analyzer/dataflow/callgraph/context_summarizer.py` | Extended to cache and specialize `FunctionContract`s. | **REQUIRES EXTENSION** |
| `InterproceduralTaintPropagator` | `analyzer/dataflow/interprocedural/propagator.py` | Extended to apply caller-side contracts and verify callee preconditions. | **REQUIRES EXTENSION** |
| `CallChainStep` | `analyzer/dataflow/callgraph/models.py` | Enriched with contract verification metadata. | **REQUIRES EXTENSION** |
| `BaselineComparator` | `analyzer/comparison/diff.py` | Compares current findings against baseline. | **REUSE AS-IS (INVARIANT)** |
| `CallGraphSummaryDTO` | `backend/app/schemas/callgraph.py` | Additive extension with `ContractSummaryDTO`. | **REQUIRES EXTENSION** |
| `InterproceduralTraceViewer.tsx` | `frontend/src/components/findings/` | Updated to render contract and precondition badges. | **REQUIRES EXTENSION** |

---

## 8. Architecture Changes

The Phase 19 architecture pipeline inserts contract synthesis and evaluation into the interprocedural engine:

```text
Intraprocedural Stage:
AST / Tree-sitter
      ↓
CFG Builder (python_cfg_builder.py, jsts_cfg_builder.py)
      ↓
Path Explorer (path_explorer.py)
      ↓
Feasible Exit / Return Paths
      ↓
Contract Extractor (analyzer/dataflow/contracts/extractor.py)
      ↓
FunctionContract (Preconditions, Postconditions, Conditional Effects)

Interprocedural Stage:
Caller Call Site
      ↓
Lookup Callee Contract from ContextSummaryManager
      ↓
Precondition Verification Engine
      ├─ SATISFIED ──> Prune Callee Sink (Safe)
      ├─ VIOLATED  ──> Flag Vulnerability with DETERMINISTIC confidence
      └─ UNKNOWN   ──> Conservative Taint Propagation (UNKNOWN != SAFE)
      ↓
Caller Evaluates Call Result (e.g. if is_valid(arg):)
      ↓
Postcondition Binder ──> Injects RefinementFacts into Caller PathState
      ↓
Downstream Propagation (Refinements survive across hops)
      ↓
Evidence Enrichment (SARIF codeFlows, Terminal/MD, Frontend Trace Viewer)
```

---

## 9. Function Contract Model

Contract models reside in `analyzer/dataflow/contracts/models.py`:

```python
"""Domain models for Phase 19 Interprocedural Contracts and Function Summaries."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.cfg.models import GuardCondition, PredicateOp, RefinementFact
from analyzer.dataflow.taint.models import SinkCategory, TaintState


class ContractVerificationStatus(str, Enum):
    """Formal verification state of a contract precondition or postcondition."""
    SATISFIED = "SATISFIED"          # Statically proven satisfied; safe to prune or refine
    VIOLATED = "VIOLATED"            # Statically proven violated; defect confirmed
    UNKNOWN = "UNKNOWN"              # Insufficient static information; conservative fallback
    INFEASIBLE = "INFEASIBLE"        # Contradictory path condition; path unreachable
    WIDENED = "WIDENED"              # Resource bounds exceeded; widened conservatively
    TRUNCATED = "TRUNCATED"          # Call depth or condition count truncated
    UNRESOLVED = "UNRESOLVED"        # Target function could not be resolved


class PreconditionKind(str, Enum):
    """Classification of caller obligations at a callee boundary."""
    TYPE_REFINEMENT = "TYPE_REFINEMENT"              # e.g. param must be int/float
    FORMAT_REFINEMENT = "FORMAT_REFINEMENT"          # e.g. param must be alphanumeric/numeric string
    NULLITY_REFINEMENT = "NULLITY_REFINEMENT"        # e.g. param must be non-null
    SANITIZER_CATEGORY = "SANITIZER_CATEGORY"        # e.g. param must have COMMAND_EXECUTE sanitizer


class PostconditionTrigger(str, Enum):
    """Caller-side observation triggering postcondition application."""
    RETURN_EQUALS_TRUE = "RETURN_EQUALS_TRUE"        # if f(x): or assert f(x)
    RETURN_EQUALS_FALSE = "RETURN_EQUALS_FALSE"      # if not f(x):
    RETURN_NOT_NONE = "RETURN_NOT_NONE"              # if f(x) is not None:
    RETURN_EXACT_CONST = "RETURN_EXACT_CONST"        # if f(x) == "SAFE":
    UNCONDITIONAL = "UNCONDITIONAL"                  # Normal return unconditionally produces fact


class SummaryPrecondition(BaseModel):
    """Requirement that a caller must satisfy to avoid triggering a callee sink."""
    target_param_index: int
    target_param_name: str
    target_field_name: Optional[str] = None
    kind: PreconditionKind
    required_type: Optional[str] = None
    required_sanitizer_category: Optional[SinkCategory] = None
    sink_category: Optional[SinkCategory] = None
    raw_condition: str = ""
    line: int = 0
    provenance_sink_id: Optional[str] = None


class SummaryPostcondition(BaseModel):
    """Guaranteed fact established upon function completion when trigger holds."""
    trigger: PostconditionTrigger
    trigger_literal: Optional[str] = None
    target_param_index: Optional[int] = None
    target_param_name: Optional[str] = None
    target_field_name: Optional[str] = None
    applies_to_return: bool = False
    produced_refinement: Optional[RefinementFact] = None
    produced_taint_state: Optional[TaintState] = None
    applicable_sanitizer_category: Optional[SinkCategory] = None
    confidence: str = "HIGH"
    provenance_line: int = 0


class ConditionalTaintEffect(BaseModel):
    """Taint transfer or sanitizer effect valid only under a specific path condition."""
    from_param_index: int
    to_return: bool = False
    to_sink_category: Optional[SinkCategory] = None
    to_field_name: Optional[str] = None
    sanitizer_category: Optional[SinkCategory] = None
    governing_path_condition: Optional[str] = None
    governing_guards: list[GuardCondition] = Field(default_factory=list)
    taint_state: TaintState = TaintState.TAINTED


class FunctionContract(BaseModel):
    """Formal interprocedural contract for a function scope."""
    qualified_name: str
    file_path: str
    context_id: str = "ROOT"
    is_pure: bool = False
    preconditions: list[SummaryPrecondition] = Field(default_factory=list)
    postconditions: list[SummaryPostcondition] = Field(default_factory=list)
    conditional_effects: list[ConditionalTaintEffect] = Field(default_factory=list)
    is_widened: bool = False
    extraction_truncated: bool = False
    contract_hash: str = ""
```

---

## 10. Contract Extraction

Contract extraction is executed by `analyzer/dataflow/contracts/extractor.py` using intraprocedural CFGs:

### 10.1 Extraction Algorithm
1. **CFG & Path Traversal**: Invoke `PythonCFGBuilder` or `JSTSCFGBuilder` and run `PathExplorer.explore_paths(cfg)` to extract all feasible paths terminating in `is_exit = True` or `is_early_exit = True`.
2. **Return Expression Correlation**:
   - For each exit path, inspect the return statement AST expression and the path's accumulated `PathConstraint`.
   - **Direct Return**: `return isinstance(x, int)`:
     - On the True evaluation path, synthesize `SummaryPostcondition(trigger=RETURN_EQUALS_TRUE, target_param_name="x", produced_refinement=RefinementFact(refined_type="int", is_non_null=True))`.
     - On the False evaluation path, synthesize `SummaryPostcondition(trigger=RETURN_EQUALS_FALSE, target_param_name="x", produced_refinement=None)`.
   - **Branch-Correlated Return**:
     ```python
     if isinstance(x, int):
         return True
     return False
     ```
     - Path 1 returns literal `True` with active constraint `isinstance(x, int) == True`. Synthesizes `RETURN_EQUALS_TRUE ==> x is int`.
     - Path 2 returns literal `False` with active constraint `isinstance(x, int) == False`.
   - **Opposite / Negative Correlation**:
     ```python
     if isinstance(x, int):
         return False
     return True
     ```
     - Path 1 returns literal `False` with active constraint `isinstance(x, int) == True`. Synthesizes `RETURN_EQUALS_FALSE ==> x is int`.
     - Path 2 returns literal `True` with active constraint `isinstance(x, int) == False`.
   - **Uncorrelated Return**:
     ```python
     if isinstance(x, int):
         return some_unknown_function(x)
     return False
     ```
     - Return value is governed by an unknown call; correlation cannot be proven statically $\implies$ emit **NO** postcondition (`UNKNOWN`).
3. **Precondition Extraction from Internal Sinks**:
   - Inspect internal sinks reachable from parameters.
   - For `SQL_EXECUTE`, record `SummaryPrecondition(kind=TYPE_REFINEMENT, required_type="int", sink_category=SQL_EXECUTE)`.
   - For `COMMAND_EXECUTE`, record `SummaryPrecondition(kind=FORMAT_REFINEMENT, required_type="is_alphanumeric_string", sink_category=COMMAND_EXECUTE)`.
4. **Extraction Bounds**:
   - `max_preconditions_per_contract` = 8
   - `max_postconditions_per_contract` = 16
   - `max_effects_per_contract` = 16
   - `max_condition_length` = 256 characters

---

## 11. Preconditions

### 11.1 Source-to-Sink Provenance
Every `SummaryPrecondition` retains complete provenance:
- Originating sink ID (e.g. `SQL_EXECUTE_CURSOR`)
- Target parameter index and name
- Required refinement kind and value
- Source file and line number

### 11.2 Verification Semantics at Call Sites
When caller invokes `callee(arg0)`:
- **`SATISFIED`**: The caller's active `PathState` contains an active `RefinementFact` for `arg0` that meets or exceeds the required precondition.
- **`VIOLATED`**: The caller's active `PathState` contains a contradictory fact (e.g. `refined_type == "str"` when `int` is required, or a disjoint type).
- **`UNKNOWN`**: The caller's active `PathState` has no refinement facts for `arg0`. Missing proof is **always** classified as `UNKNOWN`, **never** as `VIOLATED`.
- **`INFEASIBLE`**: The call site is located on an unreachable/contradictory path.

---

## 12. Postconditions

### 12.1 Caller Binding Mechanics
When a caller branches on a callee result:
```python
if is_valid(data):
    # True branch
else:
    # False branch
```
1. Resolve callee contract for `is_valid`.
2. On True branch: match postconditions with `trigger == RETURN_EQUALS_TRUE`. Map callee parameter indices to caller arguments $\implies$ inject produced `RefinementFact` into caller's active `PathConstraint`.
3. On False branch: match postconditions with `trigger == RETURN_EQUALS_FALSE`.

### 12.2 Strict Trust Boundaries
- Custom functions are **never** granted postconditions merely because their name is `validate`, `sanitize`, `clean`, or `check`.
- A postcondition is generated **only** if the return statement has a proven correlation with an atomic `GuardCondition` recognized by `GuardEvaluator`.

---

## 13. Conditional Effects

For functions with path-dependent data flow:
```python
def format_input(val, sanitize=False):
    if sanitize:
        return shlex.quote(val)
    return val
```
Contract extraction generates:
1. `ConditionalTaintEffect(from_param_index=0, to_return=True, governing_path_condition="sanitize == True", sanitizer_category=COMMAND_EXECUTE, taint_state=SANITIZED)`
2. `ConditionalTaintEffect(from_param_index=0, to_return=True, governing_path_condition="sanitize == False", taint_state=TAINTED)`

At caller call sites:
- `format_input(cmd, sanitize=True)`: Evaluates constant argument `sanitize=True` $\implies$ matches Effect 1 $\implies$ return value receives `COMMAND_EXECUTE` sanitizer.
- `format_input(cmd, sanitize=False)`: Evaluates constant argument `sanitize=False` $\implies$ matches Effect 2 $\implies$ return value remains `TAINTED`.
- `format_input(cmd, sanitize=unknown_var)`: Unknown condition $\implies$ conservative join $\implies$ return value remains `TAINTED` (`UNKNOWN != SAFE`).

---

## 14. Context-Sensitive Evaluation

### 14.1 Distinction of Dimension Budgets
To prevent confusion between distinct analysis dimensions, Phase 19 formalizes exact boundaries:
- **`max_call_depth`** (default: 5): Maximum call-chain traversal depth from an entry point.
- **`max_k`** (default: 2): Maximum call-string context suffix length for context IDs.
- **`max_contexts_per_function`** (default: 8): Maximum specialized contexts created per function before widening.
- **`max_summary_iterations`** (default: 5): Maximum fixed-point iterations for recursive SCC resolution.
- **`max_branch_depth`** (default: 6): Maximum intraprocedural branch depth explored per function CFG.

### 14.2 Literal Argument Context Specialization
Context specialization applies strictly to:
- Literal booleans (`True`, `False`)
- Literal integers and small enums
- Receiver type identities (from Phase 16/17 type inference)

Arbitrary complex expressions do NOT spawn new contexts; they reuse the `ROOT` context to prevent context explosion.

---

## 15. Taint / Alias / Field Integration

### 15.1 Reuse of Canonical Taint State
- Phase 19 strictly reuses `analyzer.dataflow.taint.models.TaintState`. No secondary taint lattice is introduced.
- Refinement facts remain decoupled from global taint states.

### 15.2 Field Mutations & Strong/Weak Updates
- When summarizing `def update(obj): obj.token = clean(obj.token)`:
  - Generates `SummaryPostcondition(target_param_index=0, target_field_name="token", produced_refinement=...)`.
- **Strong Update Policy**: A strong field update is applied at the caller site **only** if Phase 17 alias analysis proves the target abstract object has a singleton points-to set ($|P| = 1$) AND has not escaped outside the function scope.
- **Weak Update Policy**: If the object has multiple points-to targets or may be aliased elsewhere, a weak update (union join) is applied.

---

## 16. Path Condition Composition

When composing path conditions across interprocedural boundaries:
$$C_{\text{composite}} = C_{\text{caller}} \land C_{\text{callsite}} \land C_{\text{contract}}$$

### 16.1 Composition Algorithm
1. **Variable Substitution**: Callee parameter names are substituted with caller argument expressions.
2. **Deterministic Ordering**: Conditions are sorted canonically by `(variable_name, predicate_op, argument_literal or "")`.
3. **Idempotence & Deduplication**: Duplicate predicates are eliminated ($P \land P \equiv P$).
4. **Contradiction Detection**:
   - $P \land \neg P \implies \text{INFEASIBLE}$.
   - `x is None` $\land$ `x is not None` $\implies \text{INFEASIBLE}$.
   - Disjoint type refinements (e.g. `int` and `str` where type model proves disjointness) $\implies \text{INFEASIBLE}$.
5. **Length Bounds**: Capped at `max_conditions_per_path` (default: 16). Exceeding conditions are truncated with `is_truncated = True`.

---

## 17. Recursive / SCC Handling

### 17.1 Tarjan's SCC Resolution Algorithm
1. Build repository call graph.
2. Compute Strongly Connected Components (SCCs) using Tarjan's algorithm.
3. Order SCCs topologically in reverse (bottom-up: leaf functions first, callers last).
4. For cyclic SCCs ($A \to B \to A$):
   - Initialize contracts with empty effects.
   - Iterate contract extraction across the SCC up to `max_summary_iterations = 5`.
   - Test for fixed-point convergence: if all preconditions, postconditions, and conditional effects match the prior iteration, terminate cleanly.
   - If iterations reach 5 without convergence:
     - Mark contracts as `is_widened = True`.
     - Degrade unproven postconditions to `UNKNOWN`.
     - Retain conservative taint transfers.

### 17.2 Active Call Stack Cycle Guard
During propagation traversal, maintain `active_call_stack: list[str]`. If callee $F \in \text{active\_call\_stack}$, abort deeper recursion and consume $F$'s current summary state.

---

## 18. Unknown / Widened / Truncated Semantics

Phase 19 enforces strict status separation:

| Status | Meaning | Action on Downstream Sinks | Action on Callers |
| :--- | :--- | :--- | :--- |
| `SATISFIED` | Precondition proven satisfied by caller facts | Prune sink finding (safe) | Refinements confirmed |
| `VIOLATED` | Precondition proven violated by caller facts | Flag immediate finding | Incompatibility recorded |
| `UNKNOWN` | Insufficient evidence to prove or disprove | Fall back to standard taint rule | Postconditions NOT applied |
| `INFEASIBLE` | Contradictory path condition | Prune path entirely | Unreachable |
| `WIDENED` | Budget limit exceeded during summarization | Fall back to standard taint rule | Postconditions NOT applied |
| `TRUNCATED` | Depth or condition budget reached | Fall back to standard taint rule | Traversal halted |
| `UNRESOLVED` | Dynamic dispatch or unresolvable callee | Fall back to standard taint rule | No contract available |

**Core Rule**: `UNKNOWN != SAFE`, `WIDENED != SAFE`, `TRUNCATED != SAFE`, `UNRESOLVED != SAFE`.

---

## 19. Cache Design

Contract caching extends `analyzer/dataflow/callgraph/context_summarizer.py`:

### 19.1 Deterministic Cache Key
```python
def make_contract_cache_key(
    qualified_name: str,
    context_id: str,
    argument_types: list[str],
    full_config_hash: str,
) -> tuple[str, str, str, str]:
    return (
        qualified_name,
        context_id,
        ":".join(argument_types),
        full_config_hash,  # Full SHA-256 digest; never truncated
    )
```

### 19.2 Memory Bounds & Deterministic Eviction
- **Capacity Bound**: Capped at `max_cached_contracts = 2000`.
- **Eviction Strategy**: Deterministic stable eviction: when capacity is exceeded, evict entries based on oldest insertion timestamp with canonical key tie-breaking.
- **Bounded Dimensions per Contract**:
  - `max_preconditions_per_contract = 8`
  - `max_postconditions_per_contract = 16`
  - `max_effects_per_contract = 16`

---

## 20. Configuration & CLI

### 20.1 Three-Tier Configuration Precedence
1. **Tier 1: Explicit CLI Flags** (highest precedence)
2. **Tier 2: Repository Configuration** (`.codesentinel.yml` / `.codesentinel.json`)
3. **Tier 3: Built-in AnalysisConfig Defaults** (lowest precedence)

### 20.2 Configuration Options

| Option Name | Type | Default | Valid Range | CLI Flag | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `disable_interprocedural_contracts` | `bool` | `False` | `True/False` | `--disable-interprocedural-contracts` | Disables Phase 19 contracts; falls back to Phase 18 immediate guard checks. |
| `max_call_depth` | `int` | `5` | `1 <= d <= 20` | `--max-call-depth` | Maximum call depth for interprocedural propagation and contract traversal. |
| `max_summary_iterations` | `int` | `5` | `1 <= i <= 20` | `--max-summary-iterations` | Maximum fixed-point iterations for recursive SCC contract resolution. |
| `max_contexts_per_function` | `int` | `8` | `1 <= c <= 32` | `--max-contexts-per-function` | Maximum specialized contexts evaluated per function before widening. |
| `max_effects_per_summary` | `int` | `16` | `4 <= e <= 64` | `--max-effects-per-summary` | Maximum conditional effects extracted per function summary. |
| `max_field_effect_depth` | `int` | `3` | `1 <= f <= 8` | `--max-field-effect-depth` | Maximum nested field traversal depth for contract postconditions. |
| `max_cached_contracts` | `int` | `2000` | `100 <= m <= 10000` | `--max-cached-contracts` | Maximum cached contract entries before deterministic eviction. |

---

## 21. Backend / Persistence Impact

### 21.1 Zero Migrations Justification
- `analysis_snapshots.call_graph_summary` is a nullable JSON column (`sa.JSON()`).
- Phase 16, 17, and 18 all store their metrics in this column without database migrations.
- Phase 19 contract metrics will be stored as an optional nested field `contracts` in `CallGraphSummaryDTO`.
- **Database Migrations Required**: **ZERO (`Alembic` migration count = 0)**.

### 21.2 Schema Extension (`backend/app/schemas/callgraph.py`)
```python
class ContractSummaryDTO(BaseModel):
    """Path-sensitive interprocedural contract analysis metrics (Phase 19)."""
    contracts_generated: int = Field(default=0, ge=0)
    preconditions_verified: int = Field(default=0, ge=0)
    postconditions_propagated: int = Field(default=0, ge=0)
    multi_hop_guards_resolved: int = Field(default=0, ge=0)
    contracts_widened: int = Field(default=0, ge=0)
    recursive_sccs_resolved: int = Field(default=0, ge=0)


class CallGraphSummaryDTO(BaseModel):
    # Existing Phase 15-18 fields retained unchanged...
    path_sensitivity: Optional[PathSensitivitySummaryDTO] = None
    # Phase 19 additive field:
    contracts: Optional[ContractSummaryDTO] = None
```

### 21.3 Backward Compatibility
Snapshots from Phases 15–18 that lack the `contracts` field parse cleanly with `contracts = None`.

---

## 22. SARIF & Reporting

### 22.1 SARIF v2.1.0 Enrichment
Thread flow step locations in `runs[0].results[].codeFlows` are enriched with contract metadata within their `properties` bags:
```json
{
  "location": {
    "physicalLocation": {
      "artifactLocation": { "uri": "services/user_service.py", "uriBaseId": "%SRCROOT%" },
      "region": { "startLine": 42, "startColumn": 8 }
    },
    "message": {
      "text": "Call: validate_id() -> execute_query(user_id) [Contract: validate_id() establishes user_id is int] [Precondition: SATISFIED]"
    }
  },
  "properties": {
    "pathCondition": "validate_id(user_id) == True",
    "branchTaken": "TRUE_BRANCH",
    "contractStatus": "SATISFIED",
    "preconditionKind": "TYPE_REFINEMENT",
    "postconditionTrigger": "RETURN_EQUALS_TRUE",
    "contractId": "urn:codesentinel:contract:app.services:validate_id:ctx-1"
  }
}
```

### 22.2 Concrete SARIF Validation Mechanism
Validation against the official OASIS SARIF v2.1.0 JSON schema is executed via `jsonschema.validate()` in `analyzer/tests/test_phase19_reporters.py` using the OASIS schema file `sarif-schema-2.1.0.json`.

---

## 23. Frontend Changes

### 23.1 `frontend/src/types/api.ts`
Extend `CallChainStepDTO` with optional contract fields:
```typescript
export interface CallChainStepDTO {
  // Existing Phase 15-18 fields...
  path_condition?: string;
  branch_taken?: string;
  guard_predicate?: string;
  path_status?: string;
  // Phase 19 additive fields:
  contract_status?: 'SATISFIED' | 'VIOLATED' | 'UNKNOWN' | 'WIDENED' | 'TRUNCATED' | 'UNRESOLVED';
  contract_effect?: string;
  precondition_kind?: string;
}
```

### 23.2 `frontend/src/components/findings/InterproceduralTraceViewer.tsx`
Render visual contract status badges using the existing design system:
- **`Precondition: SATISFIED`**: Emerald badge (`bg-emerald-950 text-emerald-300 border-emerald-800/60`).
- **`Precondition: VIOLATED`**: Rose badge (`bg-rose-950 text-rose-300 border-rose-800/60`).
- **`Precondition: UNKNOWN`**: Amber badge (`bg-amber-950 text-amber-300 border-amber-800/60`).
- **`Contract: <effect>`**: Indigo pill displaying the proven contract transformation.
- **Visual Discipline**: Never render `UNKNOWN`, `WIDENED`, `TRUNCATED`, or `UNRESOLVED` as green or safe.

---

## 24. Finding Identity & Baseline Compatibility

### 24.1 Primary Finding ID Invariance
Primary finding IDs are generated deterministically:
$$\text{Finding ID} = \text{UUIDv5}(\text{FINDING\_NAMESPACE}, \text{rule\_id} : \text{file\_path} : \text{line\_start} : \text{col\_start})$$
Contract information is stored **strictly in finding `evidence` dictionaries**, leaving primary finding IDs completely unchanged.

### 24.2 Baseline Differential Compatibility
- The `BaselineComparator` implementation in `analyzer/comparison/diff.py` remains **100% untouched**.
- Matching tiers (exact signature, fuzzy snippet, fuzzy location, ID fallback) remain invariant.
- **Legitimate Finding Deltas**: Phase 19 may legitimately produce `NEW` findings (for previously skipped branches) and `RESOLVED` findings (for guarded sinks whose contracts prove safety). Baseline comparison correctly categorizes these as genuine differential transitions.

---

## 25. Health Score Compatibility

- Health scores are computed from deduplicated findings. Multiple call contexts targeting the same sink invocation produce a single finding; findings are not duplicated per call context.
- No health penalty formula changes are introduced.

---

## 26. Testing Strategy

Testing requires: **all 522 pre-Phase-19 tests pass with zero regressions + comprehensive targeted Phase 19 coverage across 11 categories**:

```text
Test Suite Component                   Focus Area
────────────────────────────────────────────────────────────────────────────
A. Contract Model                      SummaryPrecondition, SummaryPostcondition, triggers
B. Validator Contracts                 Direct return, branch-correlated, negative, unknown
C. Multi-Hop Reasoning                 2-hop, 3-hop, and 4-hop contract propagation
D. Conditional Context                 Literal true, literal false, unknown boolean contexts
E. Taint & Sanitizer Contracts         Category-specific sanitizers, format refinements
F. Alias & Field Contracts             Argument field updates, receiver mutations, weak updates
G. Recursion & SCC Widening            Direct recursion, mutual recursion, SCC convergence
H. External & Dynamic Calls            Intrinsic models, registered contracts, UNRESOLVED fallback
I. Path Condition Composition          Conjunction, simplification, contradiction pruning
J. Full Regression Suite               100% pass rate across all 522 existing tests
K. Multi-Run Determinism               5 consecutive identical analysis executions
```

---

## 27. End-to-End Fixtures

### Scenario A — Proven Boolean Validator
```python
def is_valid_id(value):
    return isinstance(value, int)

def handle(request):
    value = request.args["id"]
    if is_valid_id(value):
        cursor.execute(f"SELECT * FROM users WHERE id = {value}")
```
*Expected*: Callee `is_valid_id` exports postcondition `RETURN_EQUALS_TRUE ==> value is int`. Caller binds refinement on True branch; SQL injection sink precondition is satisfied (**0 findings emitted**).

### Scenario B — Multi-Hop Contract Chain
```python
# controller.py -> validator.py -> service.py -> repository.py -> cursor.execute()
```
*Expected*: Integer refinement proven in `controller.py` propagates through `service.py` into `repository.py`, discharging callee precondition across 3 hops (**0 findings emitted**).

### Scenario C — Conditional Sanitizer Parameter
```python
def process(data, sanitize=False):
    return shlex.quote(data) if sanitize else data

def test_safe(req):
    os.system(process(req.args['cmd'], sanitize=True))   # Safe

def test_vuln(req):
    os.system(process(req.args['cmd'], sanitize=False))  # Vulnerable
```
*Expected*: `sanitize=True` context prunes command injection; `sanitize=False` context flags `SEC-PY-010` vulnerability (**1 finding emitted**).

### Scenario D — Unknown Custom Validator
```python
def custom_check(value):
    return external_lib.check(value)

def handle(request):
    value = request.args['id']
    if custom_check(value):
        cursor.execute(f"SELECT * FROM u WHERE id = {value}")
```
*Expected*: `custom_check` cannot be proven statically $\implies$ status is `UNKNOWN`. Rule retains conservative behavior and flags SQL injection (**1 finding emitted**).

### Scenario E — Recursive Function Termination
```python
def walk(node):
    if not node:
        return None
    return walk(node.next)
```
*Expected*: Fixed-point iteration terminates within 5 iterations; contracts widen cleanly without infinite loops.

### Scenario F — Field Mutation Sanitizer
```python
def sanitize_payload(obj):
    obj.token = "".join(c for c in obj.token if c.isalnum())

def handle(req):
    sanitize_payload(req)
    os.system(f"echo {req.token}")
```
*Expected*: Field postcondition attaches `is_alphanumeric_string = True` to `req.token`; command injection is suppressed (**0 findings emitted**).

### Scenario G — Contradictory Types Across Function Boundary
```python
def callee(val):
    if isinstance(val, str):
        sink(val)

def caller(val):
    if isinstance(val, int):
        callee(val)
```
*Expected*: Composite path condition `isinstance(val, int) and isinstance(val, str)` is detected as `INFEASIBLE`; path is pruned.

### Scenario H — Summary Widening Budget Exhaustion
A synthetic fixture with 12 sequential boolean branches exceeding summary budgets widens cleanly to `WIDENED` without hanging.

### Scenario I — Unresolved Dynamic Dispatch
```python
handler = getattr(module, dynamic_name)
handler(value)
```
*Expected*: Edge classified as `DYNAMIC_CALL`; degrades to `UNRESOLVED` without crashing; sinks inside candidates retain conservative warnings.

### Scenario J — Baseline Compatibility
Running the same repository through Phase 18 and Phase 19 modes produces zero baseline drift in finding ID formatting and comparator key semantics.

---

## 28. Performance Benchmarks

Performance will be measured against synthetic multi-file benchmark fixtures:
- **Small Benchmark**: 100 functions, 20 call chains.
- **Medium Benchmark**: 500 functions, 100 call chains.
- **Large Benchmark**: 1000 functions, 300 call chains.

### Measurement Dimensions
1. **Wall-clock runtime** (seconds)
2. **Peak memory utilization** (MB RSS)
3. **Contracts generated count**
4. **Contract cache hit/miss ratio**
5. **Preconditions verified count**
6. **Paths widened / truncated count**

*Explicit Note*: Performance numbers are empirical measurements on documented hardware and configuration, NOT theoretical or universal polynomial guarantees.

---

## 29. Security & Trust Boundaries

1. **Zero Execution of Analyzed Code**: The analyzer never executes, evals, or imports analyzed code.
2. **Zero Network / Remote API Calls**: Analysis runs 100% locally and offline.
3. **Strict Validator Trust Model**: Function names containing `validate`, `sanitize`, `clean`, `verify`, or `safe` are **NEVER** trusted by name alone. Trust requires AST proof or explicit user configuration in `.codesentinel.yml`.
4. **Denial-of-Service Resistance**: Resource bounds (`max_call_depth`, `max_summary_iterations`, `max_cached_contracts`) prevent combinatorial path explosions from consuming excessive memory or CPU.

---

## 30. Documentation Updates (Upon Implementation)

When Phase 19 is implemented, the following documentation files will be updated:
- `README.md`: Overview of Phase 19 interprocedural contracts and CLI flags.
- `docs/ARCHITECTURE.md`: Section 13 detailing the Function Contract Model and verification semantics.
- `docs/API.md`: Documentation of `ContractSummaryDTO`.
- `docs/SARIF.md`: Specification of contract property bags (`properties.contractStatus`, `properties.preconditionKind`).
- `docs/ROADMAP.md`: Mark Phase 19 as COMPLETE; align Phase 20 scope.

---

## 31. Risks & Mitigations

| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| **Combinatorial Contract Explosion** | Analysis hangs or runs out of memory on deep call graphs. | Hard bounds: `max_call_depth = 5`, `max_effects_per_summary = 16`, `max_cached_contracts = 2000` with deterministic stable eviction. |
| **False Negatives from Unsound Validator Inference** | Complex validator body misidentified as establishing safety. | Strict trust model: only explicitly supported AST patterns (isinstance, isdigit, anchored regex) generate postconditions. Complex code degrades to `UNKNOWN`. |
| **Mutual Recursion Infinite Loops** | Cycles in call graph cause infinite summarization loops. | Tarjan's SCC grouping with hard convergence limit `max_summary_iterations = 5` and widening. |
| **Dynamic Language Ambiguity** | `getattr()`, dynamic dispatch, or monkey-patching obscures callee. | Conservative fallback to `UNRESOLVED`; taint is preserved and sinks are flagged. |
| **Cache Memory Bloat** | Large codebases generate thousands of context summaries. | Deterministic stable eviction capping cache size at 2,000 entries with bounded contract dimensions. |

---

## 32. Implementation Sequence

The implementation is divided into 18 logical, verifiable stages:

```text
Stage 1: Repository Baseline Verification & Test Harness Setup
Stage 2: Contract Domain Models (analyzer/dataflow/contracts/models.py)
Stage 3: Contract Extraction from Python CFG
Stage 4: Contract Extraction from JS/TS CFG
Stage 5: Return / Refinement Correlation Engine
Stage 6: Context-Sensitive Contract Cache in ContextSummaryManager
Stage 7: Path-Condition Composition & Normalization
Stage 8: Caller-Side Precondition Evaluation Engine
Stage 9: Caller-Side Postcondition Binding & Refinement Injection
Stage 10: Taint, Alias, and Field Mutation Contract Integration
Stage 11: Recursive SCC Tarjan Decomposition & Fixed-Point Solver
Stage 12: Resource Limits and Widening Controls
Stage 13: SARIF v2.1.0 & Terminal/Markdown Reporting
Stage 14: Backend DTO & API Snapshot Persistence Integration
Stage 15: Frontend Trace Viewer Contract Visualization
Stage 16: CLI and Repository Configuration Integration
Stage 17: Comprehensive Unit, Integration, Determinism & Benchmark Tests
Stage 18: Documentation Updates (README, ARCHITECTURE, API, SARIF, ROADMAP)
```

---

## 33. Completion Gates

Phase 19 will be considered complete when and only when all 14 gates pass:

- [ ] **Gate 1 (Analyzer Boundary)**: 0 imports of FastAPI, SQLAlchemy, Celery, Redis, or AI SDKs in `analyzer/`.
- [ ] **Gate 2 (Contract Correctness)**: Validator functions correctly synthesize `SummaryPostcondition` and bind refinements to callers.
- [ ] **Gate 3 (Multi-Hop Propagation)**: Multi-hop call chains (up to 4 hops) propagate contracts and discharge callee preconditions.
- [ ] **Gate 4 (Context Bounding)**: Literal argument context specialization is bounded by $k \le 2$ and `max_contexts_per_function = 8`.
- [ ] **Gate 5 (Recursion & SCCs)**: Recursive functions ($A \to B \to A$) converge or widen within 5 iterations without hanging.
- [ ] **Gate 6 (Unknown Safety)**: `UNKNOWN`, `WIDENED`, `TRUNCATED`, and `UNRESOLVED` states never silently become `SAFE`.
- [ ] **Gate 7 (Finding Identity)**: Finding IDs remain 100% invariant between Phase 18 and Phase 19.
- [ ] **Gate 8 (Baseline Invariance)**: `BaselineComparator` implementation remains unchanged; unchanged fixtures produce clean differential matches.
- [ ] **Gate 9 (SARIF Compliance)**: Enriched SARIF v2.1.0 output validates cleanly against the official OASIS JSON schema.
- [ ] **Gate 10 (Determinism)**: 5 consecutive analysis runs produce byte-for-byte identical findings, finding IDs, and summary metrics under identical inputs/environment.
- [ ] **Gate 11 (Regression Suite)**: All 522 pre-existing tests pass with zero regressions.
- [ ] **Gate 12 (Frontend Build)**: Production build (`npm run build`) in `frontend/` succeeds with 0 TypeScript diagnostics.
- [ ] **Gate 13 (Performance Benchmarks)**: Benchmark measurements captured and documented for small, medium, and large synthetic fixtures.
- [ ] **Gate 14 (Documentation)**: Planned documentation changes in `README.md`, `ROADMAP.md`, `ARCHITECTURE.md`, `API.md`, and `SARIF.md` are completely drafted.

---

## 34. Final Acceptance Checklist

- [x] Actual Phase 18 repository state inspected.
- [x] Phase 18 walkthrough discrepancies verified against source.
- [x] Existing contract/summary abstractions inspected before creating new ones.
- [x] Existing CFG/path/refinement systems reused.
- [x] Existing taint lattice reused.
- [x] Existing alias/points-to/field systems reused.
- [x] Validator postconditions require proven return/refinement correlation.
- [x] Missing proof is UNKNOWN, not VIOLATED.
- [x] Sink preconditions retain source-to-sink provenance.
- [x] Context sensitivity is clearly distinguished from path sensitivity.
- [x] Cache key uses complete semantic configuration identity (full SHA-256).
- [x] Cache size and contract dimensions are bounded.
- [x] Recursive SCC handling is bounded.
- [x] Widening is conservative.
- [x] Finding identity remains compatible.
- [x] Baseline comparator implementation remains unchanged.
- [x] Phase 19 is allowed to produce legitimate NEW/RESOLVED findings.
- [x] SARIF validation has a concrete mechanism (`jsonschema` against OASIS schema).
- [x] Database migration decision is based on actual schema inspection (zero migrations).
- [x] Performance claims are empirical rather than theoretical guarantees.
- [x] Determinism is scoped to identical inputs/environment.
- [x] No analyzed code execution is introduced.
- [x] No automatic validator trust by function name.
- [x] No implementation work performed.

---

```text
Phase 19 status:
PLAN ONLY — IMPLEMENTATION NOT STARTED
```
