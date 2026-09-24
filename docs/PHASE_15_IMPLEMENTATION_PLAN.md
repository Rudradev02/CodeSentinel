# Phase 15 — Interprocedural Data-Flow Analysis, Call Graph Intelligence & Cross-Function Taint Propagation

> **Phase 15 Master Architecture & Implementation Plan**  
> **Status**: APPROVED FOR IMPLEMENTATION PLANNING  
> **Repository**: `E:\AI-Workspace\projects\CodeSentinel`  
> **Target Baseline**: Post-Phase 14 (359 automated tests passing, 1 skipped)  
> **Scope**: Static Call Graph Construction, Bounded Function Summaries, Cross-Function Taint Propagation, Interprocedural Security Rules, SARIF `codeFlows` Cross-Function Evidence, Persistence, Frontend Visualization, and CLI Integration.

---

## 1. Executive Summary

Phase 15 advances CodeSentinel's static analysis engine from **bounded intraprocedural taint tracking** (Phase 13) to **bounded interprocedural data-flow analysis** with static call graph construction, function summaries, and cross-function taint propagation.

### Current Limitation

Phase 13 introduced intraprocedural taint propagation within individual function scopes. The `TaintPropagator` in `analyzer/dataflow/taint/propagator.py` tracks taint from sources (e.g., `request.args['id']`) through variable assignments, string operations, and sanitizers to dangerous sinks — but **only within a single function body**. When a tainted variable is passed as an argument to another function, or when a function returns a value derived from tainted input, the taint trail is lost at the function boundary.

This means the following real-world vulnerability pattern is **invisible** to the current analyzer:

```python
# File: utils/query.py
def build_query(user_input):
    return f"SELECT * FROM users WHERE id = {user_input}"

# File: views.py
from utils.query import build_query

def handle_request(request):
    user_id = request.args['id']          # ← Source (tainted)
    query = build_query(user_id)          # ← Cross-function call (taint lost)
    cursor.execute(query)                 # ← Sink (appears clean)
```

Phase 15 closes this gap by constructing a bounded, deterministic static call graph, computing per-function taint summaries ("parameter 0 flows to return value"), and propagating taint across function call boundaries within configurable depth limits.

### What Phase 15 Adds

1. **Static Call Graph**: Repository-wide function-to-function call resolution using existing import/dependency data and AST function definitions.
2. **Function Summaries**: Lightweight taint transfer specifications summarizing how each function's parameters relate to its return value and its sink invocations.
3. **Cross-Function Taint Propagation**: Bounded interprocedural taint tracking that follows tainted data through function call chains up to a configurable depth.
4. **New Security Rules**: `SEC-PY-011` (Interprocedural SQL Injection), `SEC-PY-012` (Interprocedural Command Injection), `SEC-JS-009` (Interprocedural DOM XSS), `SEC-JS-010` (Interprocedural Eval Injection).
5. **Cross-Function SARIF Evidence**: Multi-location `codeFlows` with `threadFlowLocations` spanning multiple files and functions.
6. **Persistence & API**: Call graph summary storage, interprocedural finding persistence, and read-only API endpoints.
7. **Frontend Visualization**: Cross-function taint trace viewer with multi-file breadcrumb navigation.

---

## 2. Actual Phase 1–14 Baseline

The following classification is based on actual file inspection of the repository on disk, not plan documents.

### Phase 14 Capability Verification

| Capability | Classification | Evidence |
| :--- | :--- | :--- |
| `.codesentinel.yml` / `.codesentinel.json` config | **IMPLEMENTED** | `analyzer/config/repo_config.py` (251 lines), `analyzer/config/file_loader.py` (93 lines), Pydantic `RepoConfig` with `extra="forbid"`, SHA-256 `compute_hash()`. |
| Configuration loading & discovery | **IMPLEMENTED** | `load_repo_config()` discovers `.codesentinel.yml`, `.codesentinel.yaml`, `.codesentinel.json` in priority order. YAML via `yaml.safe_load()`, JSON via stdlib. |
| CLI configuration precedence | **IMPLEMENTED** | `analyzer/cli/main.py` (803 lines) loads repo config via `load_repo_config()`, merges with CLI flags under strict precedence (CLI > YAML > Defaults). |
| Longitudinal trend APIs | **IMPLEMENTED** | `backend/app/services/trend_service.py` (226 lines), `TrendService.get_repository_trends()`, `backend/app/api/v1/endpoints/trends.py` (endpoint implemented). |
| Trend frontend | **IMPLEMENTED** | `frontend/src/components/trends/TrendsView.tsx`, `HealthTrajectoryChart.tsx`, `DefectVelocityChart.tsx`, `SeverityVolumeChart.tsx`, `ComponentDriftCard.tsx` — all present with pure React SVG charts. |
| Markdown reporting | **IMPLEMENTED** | `analyzer/reporting/markdown_reporter.py` (194 lines), `MarkdownReporter` extending `BaseReporter`. |
| HTML reporting | **IMPLEMENTED** | `analyzer/reporting/html_reporter.py` (238 lines), standalone zero-CDN HTML with `Content-Security-Policy`. |
| JUnit reporting | **IMPLEMENTED** | `analyzer/reporting/junit_reporter.py` (84 lines), standard xUnit XML generation with `xml.sax.saxutils`. |
| GitLab-compatible reporting | **IMPLEMENTED** | `analyzer/reporting/gitlab_reporter.py` (50 lines), `gl-code-quality-report.json` schema. |
| Pre-commit integration | **IMPLEMENTED** | `.pre-commit-hooks.yaml` in repository root with `codesentinel` hook. |
| CI/CD reporting | **IMPLEMENTED** | All 7 report formats available via `--format` CLI flag. |
| Historical trend calculations | **IMPLEMENTED** | `TrendService` computes health trajectory, defect velocity, severity volume, component drift from `AnalysisSnapshot` records. |
| Configuration hashing | **IMPLEMENTED** | `RepoConfig.compute_hash()` generates SHA-256 from canonical JSON serialization. |
| Reporter abstraction | **IMPLEMENTED** | `analyzer/reporting/base.py` defines `BaseReporter` ABC with `render()` and `render_comparison()`. |
| Database migration `0005` | **IMPLEMENTED** | `backend/alembic/versions/0005_phase14_trend_indexes.py` (composite timeline indexes). |
| Trend schemas | **IMPLEMENTED** | `backend/app/schemas/trend.py` (3829 bytes) with `LongitudinalTrendDTO`. |

**Phase 14 Verdict: FULLY IMPLEMENTED** — all 14 planned capabilities are present in actual code.

### Complete Phase 1–14 Rule Catalog (27 Rules)

| Rule ID | Category | Phase | Status |
| :--- | :--- | :--- | :--- |
| SEC-PY-001 | Hardcoded Secrets | 3 | IMPLEMENTED |
| SEC-PY-002 | Debug Mode | 3 | IMPLEMENTED |
| SEC-PY-003 | Subprocess Shell | 3 | IMPLEMENTED |
| SEC-PY-004 | Eval/Exec | 3 | IMPLEMENTED |
| SEC-PY-005 | Raw SQL | 3 | IMPLEMENTED |
| SEC-PY-006 | Weak Hash | 3 | IMPLEMENTED |
| SEC-PY-007 | CORS Misconfiguration | 3 | IMPLEMENTED |
| SEC-PY-008 | CSRF Disabled | 3 | IMPLEMENTED |
| SEC-PY-009 | SQL Injection (Intra-Taint) | 13 | IMPLEMENTED |
| SEC-PY-010 | Command Injection (Intra-Taint) | 13 | IMPLEMENTED |
| SEC-JS-001 | eval() | 3 | IMPLEMENTED |
| SEC-JS-002 | Function Constructor | 3 | IMPLEMENTED |
| SEC-JS-003 | dangerouslySetInnerHTML | 3 | IMPLEMENTED |
| SEC-JS-004 | Client Secrets | 3 | IMPLEMENTED |
| SEC-JS-005 | Unsafe URL | 3 | IMPLEMENTED |
| SEC-JS-006 | Local Storage Secrets | 3 | IMPLEMENTED |
| SEC-JS-007 | DOM XSS (Intra-Taint) | 13 | IMPLEMENTED |
| SEC-JS-008 | Eval Injection (Intra-Taint) | 13 | IMPLEMENTED |
| ARC-001 | Circular Dependencies | 3 | IMPLEMENTED |
| ARC-002 | Excessive Fan-Out | 3 | IMPLEMENTED |
| ARC-003 | God Module | 3 | IMPLEMENTED |
| ARC-004 | Deep Dependency Chain | 3 | IMPLEMENTED |
| ARC-005 | Layer Boundary Inversion | 7 | IMPLEMENTED |
| ARC-006 | Component Circular Dependency | 7 | IMPLEMENTED |
| ARC-007 | SDP Violation | 7 | IMPLEMENTED |
| ARC-008 | Orphaned Export | 7 | IMPLEMENTED |
| ARC-009 | Centrality Bottleneck | 13 | IMPLEMENTED |

---

## 3. Phase 15 Gap Analysis

### What Currently Exists

The analyzer's data-flow subsystem (`analyzer/dataflow/`) contains:

- **`symbol.py`**: `Scope`, `Definition`, `Reference`, `SymbolTable` — lexical scoping limited to individual function bodies.
- **`taint/models.py`**: `TaintSource`, `TaintSink`, `TaintSanitizer`, `TaintPath` with `flow_type = "INTRA_PROCEDURAL_TAINT"`.
- **`taint/propagator.py`**: `TaintPropagator` — single-function-scope taint tracking. Unknown function calls **preserve taint** on arguments (conservative) but do **not** model return values or callee behavior.
- **`taint/registry.py`**: `TaintRegistry` — declarative source/sink/sanitizer catalog. No function summary or call resolution capability.
- **`python_visitor.py`**: `PythonDataFlowAnalyzer` iterates `ast.FunctionDef` / `ast.AsyncFunctionDef` nodes, analyzing each function independently.
- **`js_visitor.py`**: Parallel JS/TS visitor analyzing function scopes via Tree-sitter.

### What Does NOT Exist

| Missing Capability | Impact |
| :--- | :--- |
| **Call graph** | No function-to-function call edges. Cannot determine what function `build_query(user_id)` resolves to. |
| **Function discovery** | Functions are discovered per-file during taint analysis, but there is no repository-wide function index. |
| **Function summaries** | No specification of "parameter 0 flows to return value" or "parameter 1 flows to sink SQL_EXECUTE". |
| **Cross-function taint** | Taint is lost at every function call boundary. The propagator handles `handle_assignment` and `handle_call_with_sink`, but not `handle_call_with_callee_resolution`. |
| **Cross-file taint** | Taint does not flow across `import` boundaries even when both files are analyzed. |
| **Interprocedural rules** | SEC-PY-009/010 and SEC-JS-007/008 detect only single-function taint paths. |
| **Multi-file SARIF evidence** | `codeFlows` contain only single-file `threadFlowLocations`. |

### Why Existing Phases Do Not Solve This

- **Phase 2** built dependency resolution for import graph construction but never extracted function-level call information.
- **Phase 6** enhanced module resolution and architecture graph accuracy, but the graph operates at file/module granularity, not function granularity.
- **Phase 7** introduced component-level architecture metrics, operating at directory/package granularity.
- **Phase 13** explicitly scoped taint analysis as "intraprocedural" and bounded the implementation to single function bodies. The `TaintPropagator` constructor accepts `max_depth`, `max_symbols`, `max_statements` — all function-scope parameters.
- **Phase 12** AI enrichment operates downstream of findings; it cannot discover vulnerabilities that the deterministic analyzer fails to detect.

---

## 4. Selected Phase 15 Theme

**Interprocedural Data-Flow Analysis, Call Graph Intelligence & Cross-Function Taint Propagation**

This is the highest-value remaining technical capability because:

1. **It addresses the most critical false negative category**: multi-function vulnerability chains are the most common real-world exploitation pattern (OWASP A03:2021 Injection).
2. **It builds directly on Phase 13 infrastructure**: the `TaintPropagator`, `TaintRegistry`, `SymbolTable`, and `TaintPath` models provide the foundation.
3. **It leverages Phase 2/6 dependency resolution**: import edges and module resolution already exist; extending to function-level call resolution is architecturally natural.
4. **It fills a measurable detection gap**: every SEC-PY-009/010 and SEC-JS-007/008 finding currently requires the entire source-to-sink chain to exist within a single function.

---

## 5. Why Phase 15?

### Current Limitation
The analyzer cannot track tainted data across function call boundaries. When a developer properly modularizes code — extracting database query construction, input validation, or command building into separate functions — the analyzer loses the taint trail and produces **false negatives** (missed vulnerabilities).

### What Users/Developers Cannot Currently Do
- Detect SQL injection where query construction is in a utility function and execution is in a route handler.
- Detect command injection where user input is passed through a sanitization wrapper that fails to properly sanitize.
- Detect DOM XSS where event handler data flows through multiple React component helper functions before reaching a dangerous sink.
- Understand the full exploitation path from HTTP input to database execution across the codebase.

### Why Existing Phases Do Not Solve It
Phase 13 was explicitly designed as intraprocedural, bounded to single function scopes. The `TaintPropagator` was architected with function-scope limits (`max_depth`, `max_symbols`, `max_statements`) and has no mechanism to resolve function calls to their implementations.

### What Phase 15 Adds
1. A deterministic static call graph mapping caller→callee relationships across the repository.
2. Per-function taint transfer summaries enabling efficient interprocedural analysis without re-analyzing callees.
3. Cross-function taint propagation following tainted arguments through call chains to distant sinks.
4. New interprocedural security rules detecting multi-function vulnerability chains.
5. Multi-file SARIF `codeFlows` evidence with `threadFlowLocations` spanning the full call path.

### Why This Belongs in Phase 15
This is the natural next step in CodeSentinel's analysis maturity progression: syntax matching (Phase 3) → intraprocedural data-flow (Phase 13) → interprocedural data-flow (Phase 15). It depends on all prior phases being complete and extends the existing taint infrastructure rather than replacing it.

---

## 6. Architecture

### 6.1 High-Level Data Flow

```
Repository Files
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                 Phase 2/6: Existing Infrastructure            │
│  File Discovery → AST Parsing → Dependency Resolution         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Phase 15.1: Function Discovery                   │
│  Extract FunctionDefinition records from all parsed files      │
│  Build repository-wide function index keyed by qualified name  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Phase 15.2: Static Call Graph                     │
│  Resolve call expressions to FunctionDefinitions using         │
│  import edges + symbol tables + name resolution                │
│  Produce CallGraph with CallEdge records                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Phase 15.3: Function Summary Generation          │
│  Run intraprocedural taint analysis (Phase 13) per function    │
│  Extract parameter→return and parameter→sink transfer specs   │
│  Produce FunctionSummary records                               │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Phase 15.4: Interprocedural Propagation          │
│  At each call site: look up callee summary                     │
│  Map caller argument taint states to callee parameter states  │
│  Propagate callee return taint back to caller variable         │
│  Detect cross-function Source → Function → ... → Sink paths   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Phase 15.5: Evidence & Finding Generation         │
│  Construct multi-file TaintPath evidence                       │
│  Generate interprocedural findings with cross-file evidence   │
│  Map to SARIF codeFlows with multi-file threadFlowLocations   │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Architectural Boundary Preservation

Phase 15 strictly preserves the foundational separation:

```
analyzer/ = deterministic, static, offline analysis
  - NO imports of FastAPI, SQLAlchemy, PostgreSQL, Redis, Celery, HTTP clients, OpenRouter, Ollama
  - All new modules (call_graph/, interprocedural/) remain in analyzer/dataflow/

backend/ = API, persistence, orchestration
  - Persists interprocedural findings via existing FindingSnapshot
  - Optional call graph summary persistence via new DB columns

frontend/ = visualization, workflow
  - Cross-function taint trace viewer
  - Call graph mini-visualization in finding detail

AI = advisory downstream capability (Phase 12)
  - No changes to AI pipeline in Phase 15
```

### 6.3 New Module Structure

```
analyzer/dataflow/
├── __init__.py                    (existing)
├── symbol.py                      (existing, unchanged)
├── python_visitor.py              (existing, extended)
├── js_visitor.py                  (existing, extended)
├── taint/
│   ├── __init__.py                (existing)
│   ├── models.py                  (existing, extended with InterproceduralTaintPath)
│   ├── propagator.py              (existing, extended with callee summary lookup)
│   └── registry.py                (existing, unchanged)
├── callgraph/                     (NEW)
│   ├── __init__.py
│   ├── models.py                  (FunctionDefinition, CallEdge, CallGraph, FunctionSummary)
│   ├── discovery.py               (Function discovery from ASTs)
│   ├── resolver.py                (Call site to callee resolution)
│   ├── summarizer.py              (Function taint summary generation)
│   └── graph_builder.py           (CallGraph construction orchestrator)
└── interprocedural/               (NEW)
    ├── __init__.py
    ├── propagator.py              (InterproceduralTaintPropagator)
    └── rules.py                   (SEC-PY-011, SEC-PY-012, SEC-JS-009, SEC-JS-010)
```

---

## 7. Analyzer Design

### 7.1 Function Discovery (`analyzer/dataflow/callgraph/discovery.py`)

Extracts function definition records from already-parsed ASTs:

```
FunctionDefinition:
  qualified_name: str            # e.g., "utils.query.build_query"
  file_path: str                 # e.g., "utils/query.py"
  language: str                  # "PYTHON" | "JAVASCRIPT" | "TYPESCRIPT"
  name: str                      # "build_query"
  line_start: int
  line_end: int
  col_start: int
  parameters: list[ParameterDef] # name, position, has_default, type_hint
  is_method: bool                # True if defined inside a class
  is_async: bool
  is_constructor: bool           # __init__ / constructor
  class_name: Optional[str]      # Enclosing class if is_method
  module_path: str               # Dot-separated module path
  decorators: list[str]          # Decorator names (for framework detection)
```

**Python**: Walk `ast.FunctionDef`, `ast.AsyncFunctionDef` nodes. Extract `node.args.args`, compute `qualified_name` from module path + class hierarchy + function name.

**JavaScript/TypeScript**: Walk Tree-sitter `function_declaration`, `arrow_function`, `method_definition`, `function_expression` nodes. Resolve named exports and class method definitions.

**Bounds**:
- `max_functions_per_file`: 200 (skip files with more functions to avoid pathological generated code)
- `max_total_functions`: 5,000 (repository-wide cap)

### 7.2 Call Graph Models (`analyzer/dataflow/callgraph/models.py`)

```
CallEdge:
  caller_qualified_name: str     # "views.handle_request"
  callee_qualified_name: str     # "utils.query.build_query"
  call_site_file: str            # "views.py"
  call_site_line: int
  call_site_col: int
  resolution_type: str           # "RESOLVED_LOCAL" | "RESOLVED_IMPORT" | "UNRESOLVED"
  argument_count: int
  is_method_call: bool

CallGraph:
  functions: dict[str, FunctionDefinition]
  edges: list[CallEdge]
  unresolved_calls: list[UnresolvedCall]
  resolution_stats: ResolutionStats

ResolutionStats:
  total_call_sites: int
  resolved_local: int
  resolved_import: int
  unresolved: int
  resolution_rate: float         # resolved / total

UnresolvedCall:
  caller_qualified_name: str
  callee_expression: str         # "unknown_lib.process()"
  call_site_file: str
  call_site_line: int
  reason: str                    # "EXTERNAL_MODULE" | "DYNAMIC_CALL" | "MISSING_IMPORT" | "AMBIGUOUS"
```

### 7.3 Call Resolution (`analyzer/dataflow/callgraph/resolver.py`)

Call resolution uses existing Phase 2/6 import resolution and parsed symbol tables:

1. **Direct local call**: `build_query(x)` — resolve `build_query` to a `FunctionDefinition` in the same file via scope lookup.
2. **Import-qualified call**: `from utils.query import build_query` — resolve via Phase 2/6 import edges. Match `build_query` to a `FunctionDefinition` in the resolved target module.
3. **Attribute call**: `self.validate(x)` — resolve `self` to the enclosing class, find `validate` method in that class definition.
4. **Module attribute call**: `query_utils.build_query(x)` — resolve `query_utils` import to module, find `build_query` in that module.

**What is NOT resolved (by design)**:
- **Dynamic calls**: `getattr(obj, method_name)()`, `globals()[name]()` — classified as `UNRESOLVED` with reason `DYNAMIC_CALL`.
- **Higher-order functions**: `map(process, items)` — the function reference is tracked, but callback invocations are not resolved.
- **Callbacks**: `button.on_click(handler)` — tracked as unresolved indirect call.
- **External library calls**: `pandas.read_csv()` — classified as `UNRESOLVED` with reason `EXTERNAL_MODULE`.
- **Recursive calls**: Detected and bounded to prevent infinite analysis.
- **Mutual recursion**: Detected via cycle detection in the call graph; analysis is bounded by `max_call_depth`.

### 7.4 Function Summary Generation (`analyzer/dataflow/callgraph/summarizer.py`)

For each `FunctionDefinition`, generate a `FunctionSummary`:

```
FunctionSummary:
  qualified_name: str
  file_path: str
  parameters: list[ParameterDef]
  taint_transfers: list[TaintTransfer]
  sink_invocations: list[SummarySinkInvocation]
  sanitizer_applications: list[SummarySanitizerApplication]
  returns_tainted: bool          # True if any parameter taint reaches return
  is_identity: bool              # True if return == parameter[0] (passthrough)
  is_summarized: bool            # False if function exceeds analysis bounds

TaintTransfer:
  from_param_index: int          # Which parameter receives taint
  to_return: bool                # Does taint reach the return value?
  to_sink_category: Optional[SinkCategory]  # Does it reach a specific sink?
  via_operations: list[str]      # ["string_format", "concatenation"]
  sanitized_by: Optional[str]    # Sanitizer applied in path

SummarySinkInvocation:
  sink_id: str
  sink_category: SinkCategory
  receiving_param_index: int     # Which parameter's taint reaches this sink
  line: int
  is_parameterized: bool         # True if safe parameterized form detected

SummarySanitizerApplication:
  sanitizer_id: str
  applied_to_param_index: int
  effective_categories: list[SinkCategory]
```

**Summary generation process**:
1. For each function, run the existing Phase 13 `TaintPropagator` with each parameter individually marked as `TAINTED`.
2. Track which tainted parameters reach which return statements and which sinks.
3. Record sanitizer applications.
4. Store the resulting `FunctionSummary` in a `dict[str, FunctionSummary]`.

**Bounds**:
- `max_summary_iterations`: 3 (for mutually recursive functions, iterate summary computation at most 3 times until fixed-point)
- `max_function_body_statements`: 500 (skip summarization for excessively large functions; mark as `is_summarized = False`)

### 7.5 Interprocedural Taint Propagation (`analyzer/dataflow/interprocedural/propagator.py`)

```
InterproceduralTaintPropagator:
  call_graph: CallGraph
  summaries: dict[str, FunctionSummary]
  registry: TaintRegistry
  max_call_depth: int = 5
  max_path_count: int = 50
  max_evidence_steps: int = 30
  is_cancelled: Optional[Callable[[], bool]]
```

**Algorithm**:
1. Begin at each entry-point function (functions containing known taint sources in Phase 13 registry).
2. Run intraprocedural analysis on the entry-point function.
3. At each call site with resolved callee:
   a. Look up `FunctionSummary` for the callee.
   b. Map caller argument taint states to callee parameter indices.
   c. If callee summary indicates `TaintTransfer(from_param_index=i, to_return=True)`, mark the call site return value as `TAINTED`.
   d. If callee summary indicates `SummarySinkInvocation(receiving_param_index=i)`, record an interprocedural taint path through the callee.
   e. If callee has sanitizer applications, update taint state accordingly.
4. Continue propagation in the caller function with updated taint states.
5. Repeat recursively up to `max_call_depth`.
6. Collect all detected interprocedural taint paths.

**Interprocedural Evidence**:

```
InterproceduralTaintPath:
  flow_type: str = "INTER_PROCEDURAL_TAINT"
  source: dict[str, Any]          # Same as TaintPath.source
  call_chain: list[CallChainStep] # Ordered list of function calls
  sink: dict[str, Any]            # Same as TaintPath.sink
  path_summary: str
  category: SinkCategory
  total_depth: int
  files_involved: list[str]

CallChainStep:
  caller_function: str            # Qualified name
  callee_function: str            # Qualified name
  caller_file: str
  callee_file: str
  call_site_line: int
  call_site_col: int
  argument_index: int             # Which argument carries taint
  callee_param_name: str          # Parameter name in callee receiving taint
  taint_action: str               # "PROPAGATE_THROUGH" | "REACHES_SINK" | "SANITIZED"
```

### 7.6 Interprocedural Security Rules

Four new security rules extending CodeSentinel's data-flow security rules to interprocedural analysis:

| Rule ID | Name | Category | Sink | Severity | Confidence | Implementation Path |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-PY-011` | Interprocedural SQL Injection | SECURITY | `SQL_EXECUTE` | HIGH | HIGH | `analyzer/security/python/sec_py_011_sql_interprocedural.py` |
| `SEC-PY-012` | Interprocedural Command Injection | SECURITY | `COMMAND_EXECUTE` | CRITICAL | HIGH | `analyzer/security/python/sec_py_012_subprocess_interprocedural.py` |
| `SEC-JS-009` | Interprocedural DOM XSS | SECURITY | `DOM_INJECTION` | HIGH | HIGH | `analyzer/security/javascript/sec_js_009_dom_xss_interprocedural.py` |
| `SEC-JS-010` | Interprocedural Eval Injection | SECURITY | `CODE_EVAL` | CRITICAL | HIGH | `analyzer/security/javascript/sec_js_010_eval_interprocedural.py` |

These rules follow CodeSentinel's established rule hierarchy, subclassing `BaseSecurityRule` from `analyzer/security/base_rule.py`, registering with `PYTHON_RULES` and `JAVASCRIPT_RULES` catalogs, and reusing the existing `TaintRegistry` source/sink/sanitizer definitions. They differ from single-function taint rules (SEC-PY-009/010 and SEC-JS-007/008) in that they detect taint paths spanning multiple functions across call boundaries (call chain depth >= 1).

**Evidence structure** follows the existing `Finding.evidence` dictionary pattern with `flow_type = "INTER_PROCEDURAL_TAINT"` and a structured `call_chain` array.

### 7.7 Pipeline Integration

The `AnalysisPipeline.run()` method in `analyzer/engine/pipeline.py` gains two new stages:

```
Stage Name               Progress %    Position
─────────────────────────────────────────────────
INGESTION                5%            Existing
DISCOVERY                15%           Existing
DETECTION                25%           Existing
PARSING                  45%           Existing
DEPENDENCIES             55%           Existing (adjusted)
ARCHITECTURE_GRAPH       60%           Existing (adjusted)
CENTRALITY               65%           Existing (adjusted)
CALL_GRAPH               72%           NEW - Function discovery & call resolution
INTER_PROCEDURAL         80%           NEW - Summary generation & cross-function taint
DATA_FLOW                85%           Existing (adjusted)
RULES                    92%           Existing (adjusted)
HEALTH_SCORING           97%           Existing (adjusted)
COMPLETED                100%          Existing
```

---

## 8. Backend Design

### 8.1 Persistence Model Extensions

The `FindingSnapshot` model already stores `evidence` as a JSON column. Interprocedural findings use the same column with the `flow_type = "INTER_PROCEDURAL_TAINT"` discriminator. No new database tables are required for finding storage.

A new lightweight `CallGraphSummary` JSON field is added to `AnalysisSnapshot` to persist aggregate call graph statistics:

```
AnalysisSnapshot.call_graph_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

Contents:
```json
{
  "total_functions": 142,
  "total_call_edges": 287,
  "resolved_local": 198,
  "resolved_import": 52,
  "unresolved": 37,
  "resolution_rate": 0.87,
  "summarized_functions": 135,
  "unsummarized_functions": 7,
  "interprocedural_findings_count": 3,
  "max_call_depth_reached": 3
}
```

### 8.2 Database Migration: `0006_phase15_callgraph_summary`

```
Revision: 0006_phase15
Revises: 0005_phase14
Operations:
  - Add nullable JSON column 'call_graph_summary' to 'analysis_snapshots' table
```

**Rollback**: Drop the `call_graph_summary` column from `analysis_snapshots`.
Note: No new secondary indexes are required for `call_graph_summary` because the column is accessed only during snapshot reconstruction and direct single-snapshot API lookup, never for multi-row range filtering.

### 8.3 Persistence Service Extension

`PersistenceService.persist_snapshot()` in `backend/app/services/persistence.py` is extended to:
1. Extract `call_graph_summary` from `AnalysisResult` if present.
2. Store it in `AnalysisSnapshot.call_graph_summary`.
3. Interprocedural findings are persisted identically to intraprocedural findings via the existing `FindingSnapshot` mechanism (which serializes `f.evidence` directly into `FindingSnapshot.evidence`).

### 8.4 Reconstruction & Schema Extension

1. **Reconstruction**: In `backend/app/services/persistence.py`, `reconstruct_analysis_dto()` currently reconstructs `dataflow_evidence` with:
   ```python
   dataflow_evidence=f.evidence if (f.evidence and f.evidence.get("flow_type") == "INTRA_PROCEDURAL_TAINT") else None
   ```
   This MUST be updated to accept both intraprocedural and interprocedural taint flows:
   ```python
   dataflow_evidence=f.evidence if (f.evidence and f.evidence.get("flow_type") in ("INTRA_PROCEDURAL_TAINT", "INTER_PROCEDURAL_TAINT")) else None
   ```
   Without this update, interprocedural findings would have their `dataflow_evidence` stripped to `None` during API snapshot reconstruction.
2. **Analysis Result Schema**: In `backend/app/schemas/analysis.py`:
   - Update `AnalysisResultDTO` to include `call_graph_summary: Optional[dict[str, Any]] = None`.
   - Update `FindingDTO.dataflow_evidence` field description to: `"Intraprocedural or interprocedural taint flow trace if applicable"`.
   - `backend/app/schemas/callgraph.py`: Define `CallGraphSummaryDTO` with fields matching the stored summary payload.

---

## 9. Frontend Design

### 9.1 Component Architecture

```
frontend/src/components/findings/
├── FindingsExplorer.tsx          (existing, unchanged - hosts MonacoViewer)
├── MonacoViewer.tsx              (existing, extended to branch on flow_type)
├── FindingDetailDrawer.tsx       (existing, unchanged - dedicated to AI Enrichment)
├── TaintTraceViewer.tsx          (existing, intraprocedural trace viewer)
└── InterproceduralTraceViewer.tsx (NEW - cross-function, multi-file trace viewer)

frontend/src/types/
└── api.ts                        (extended with InterproceduralTaintTraceDTO and union in FindingDTO)
```

### 9.2 InterproceduralTraceViewer Component

A new component renders cross-function taint paths as a vertical breadcrumb trail with file-switching and source/sink highlights:

```
┌─────────────────────────────────────────────────────┐
│  📁 views.py:12  SOURCE                             │
│  ├─ user_id = request.args['id']                    │
│                                                     │
│  📞 views.py:13 → utils/query.py:build_query()      │
│  │  Argument: user_id → parameter: user_input       │
│                                                     │
│  📁 utils/query.py:2  PROPAGATION                   │
│  ├─ return f"SELECT * FROM users WHERE id={...}"    │
│  │  Returns tainted string to caller                │
│                                                     │
│  📁 views.py:14  SINK                               │
│  ├─ cursor.execute(query)                           │
│  └─ ⚠️ SQL_EXECUTE with tainted input               │
└─────────────────────────────────────────────────────┘
```

### 9.3 Finding Viewer Integration

`MonacoViewer.tsx` is the component that embeds data-flow traces above the Monaco code editor for any finding possessing `dataflow_evidence` (lines 66–71 of `MonacoViewer.tsx`). It is utilized across both `FindingsExplorer.tsx` and `DifferentialView.tsx`.

`MonacoViewer.tsx` is extended to inspect `finding.dataflow_evidence.flow_type`:
- When `flow_type === "INTER_PROCEDURAL_TAINT"`, it renders:
  ```tsx
  <InterproceduralTraceViewer trace={finding.dataflow_evidence as InterproceduralTaintTraceDTO} />
  ```
- When `flow_type === "INTRA_PROCEDURAL_TAINT"`, it renders:
  ```tsx
  <TaintTraceViewer trace={finding.dataflow_evidence as TaintTraceDTO} />
  ```

> [!NOTE]
> `FindingDetailDrawer.tsx` is exclusively dedicated to Phase 12 AI Enrichment (patch preview, verification status) and does not host the source viewer or data-flow traces.

### 9.4 Types Extension

`frontend/src/types/api.ts` is updated:

```typescript
export interface CallChainStepDTO {
  caller_function: string;
  callee_function: string;
  caller_file: string;
  callee_file: string;
  call_site_line: number;
  call_site_col: number;
  argument_index: number;
  callee_param_name: string;
  taint_action: string;
}

export interface InterproceduralTaintTraceDTO {
  flow_type: 'INTER_PROCEDURAL_TAINT';
  source: TaintTraceDTO['source'];
  call_chain: CallChainStepDTO[];
  sanitizer?: TaintTraceDTO['sanitizer'];
  sink: TaintTraceDTO['sink'];
  path_summary: string;
  total_depth: number;
  files_involved: string[];
}

// In FindingDTO:
export interface FindingDTO {
  // ... existing fields ...
  dataflow_evidence?: TaintTraceDTO | InterproceduralTaintTraceDTO | null;
}
```

### 9.5 State Machine

| State | Display |
| :--- | :--- |
| **Loading** | Skeleton cards with "Loading interprocedural trace..." |
| **Empty** | "No cross-function taint paths detected in this finding." |
| **Error** | Alert banner with retry button. |
| **Partial** | Show available steps; indicate truncation if `total_depth` exceeds `max_evidence_steps`. |
| **Stale** | Badge: "This trace is from a previous analysis run." |
| **Cancelled** | "Analysis was cancelled before interprocedural analysis completed." |

---

## 10. CLI Design

### 10.1 New CLI Options

| Flag | Type | Default | Config Equivalent | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--max-call-depth` | `int` | `5` | `analysis.max_call_depth` | Maximum function call chain depth for interprocedural taint propagation. |
| `--disable-interprocedural` | `flag` | `False` | `analysis.interprocedural` (set to `false`) | Skip interprocedural analysis entirely (faster local scans). |

### 10.2 Configuration Equivalent

In `.codesentinel.yml`:

```yaml
version: 1
analysis:
  max_call_depth: 5
  interprocedural: true   # Set to false to disable Phase 15 analysis
```

### 10.3 Exit Code Compatibility

No changes to exit code semantics. Interprocedural findings follow the same `--fail-on` severity policy as all other findings.

### 10.4 Backward Compatibility

Existing CLI behavior is unchanged. The `--disable-interprocedural` flag provides an opt-out for users who need faster local scans. By default, interprocedural analysis is enabled.

---

## 11. Database Design

### 11.1 Migration `0006_phase15`

| Change | Purpose | Rollback |
| :--- | :--- | :--- |
| Add `call_graph_summary` (JSON, nullable) to `analysis_snapshots` | Store aggregate call graph statistics per analysis run | Drop column `call_graph_summary` |

**Primary key**: Existing `analysis_snapshots.id` (UUID).
**Foreign keys**: None added — reuses existing snapshot model.
**Indexes**: No new indexes required (the column is accessed only during snapshot reconstruction and single-snapshot API lookup, never queried for multi-row range filtering).
**Immutability**: `call_graph_summary` is written once during snapshot persistence and never updated.
**Repository isolation**: Enforced by existing `repository_id` foreign key on `analysis_snapshots`.

The next migration number is `0006` (after existing `0005_phase14_trend_indexes.py`).

---

## 12. API Design

### 12.1 Existing Endpoint Extension

**`GET /api/v1/repositories/{repository_id}/analyses/{analysis_id}`**

The response DTO already includes findings with `evidence` JSON. Interprocedural findings are returned with `flow_type = "INTER_PROCEDURAL_TAINT"` in their evidence. No new endpoint is required.

### 12.2 New Read-Only Endpoint: Call Graph Summary

```http
GET /api/v1/repositories/{repository_id}/analyses/{analysis_id}/callgraph
```

| Field | Value |
| :--- | :--- |
| Method | `GET` |
| Path | `/api/v1/repositories/{repository_id}/analyses/{analysis_id}/callgraph` |
| Request | None (path parameters only) |
| Response | `CallGraphSummaryDTO` (JSON) |
| Status 200 | Call graph summary returned |
| Status 404 | Repository or analysis not found |
| Status 404 | No call graph data available (analysis predates Phase 15) |
| Repository isolation | Cross-repository `analysis_id` lookups return 404 |
| Router registration | Mounted in `backend/app/api/v1/api.py` via `api_router.include_router(callgraph.router, prefix="/repositories", tags=["Call Graph"])` |
| Authorization | None (local developer tool) |

**Response schema**:
```json
{
  "analysis_id": "uuid",
  "total_functions": 142,
  "total_call_edges": 287,
  "resolved_local": 198,
  "resolved_import": 52,
  "unresolved": 37,
  "resolution_rate": 0.87,
  "summarized_functions": 135,
  "unsummarized_functions": 7,
  "interprocedural_findings_count": 3,
  "max_call_depth_reached": 3
}
```

---

## 13. Security

### 13.1 Relevant Security Considerations

| Threat | Relevance | Mitigation |
| :--- | :--- | :--- |
| **Path traversal via function file paths** | Function definitions reference file paths; ensure normalization | All file paths normalized via existing `_norm_path()` and `Path.resolve()` |
| **Resource exhaustion via deep call chains** | Recursive or deeply nested call graphs could exhaust memory | `max_call_depth = 5`, `max_total_functions = 5000`, `max_path_count = 50` |
| **Resource exhaustion via circular calls** | Mutual recursion could cause infinite analysis | Cycle detection in call graph; circular edges bounded by `max_summary_iterations = 3` |
| **Repository isolation in persistence** | Cross-repository function resolution | Function discovery scoped to single repository. Call resolution only resolves within the analyzed repository. |
| **Secret leakage in evidence** | Interprocedural evidence may include code snippets | Existing Phase 5 `redact_secret()` applied to all evidence snippets |
| **Symlink escaping** | Function file paths could follow symlinks outside repository | `followlinks=False` enforced in existing Phase 6 ingestion |
| **Large-input denial of service** | Repository with thousands of functions | Bounded by `max_total_functions` and `max_functions_per_file` |

### 13.2 Untrusted Repository Content

The call graph analyzer processes AST structures, never executes code. Function names, parameter names, and file paths from the repository are treated as untrusted strings. They are:
- Normalized before use as dictionary keys.
- HTML-escaped before rendering in reports (existing reporter escaping).
- Never evaluated as code.

---

## 14. Determinism

### 14.1 Deterministic Guarantees

| Element | Determinism Strategy |
| :--- | :--- |
| **Function qualified names** | Constructed from `module_path + class_name + function_name` using POSIX-normalized file paths |
| **Call edge ordering** | Sorted by `(caller_qualified_name, call_site_line, call_site_col, callee_qualified_name)` |
| **Function summary** | Computed from deterministic intraprocedural taint analysis (Phase 13) |
| **Interprocedural findings** | UUIDv5 generated from `f"{rule_id}:{source_file}:{source_line}:{sink_file}:{sink_line}:{call_chain_signature}"` |
| **Call chain signature** | Deterministic string from sorted call chain steps |
| **Evidence ordering** | `call_chain` steps ordered by traversal order (caller→callee depth-first) |

### 14.2 What Is NOT in Canonical Output

- Internal `CallGraph` and `FunctionSummary` objects are intermediate computation artifacts, not part of the canonical `AnalysisResult` serialization.
- Only `call_graph_summary` (aggregate statistics) and interprocedural findings (with evidence) are canonical.
- No `uuid4`, timestamps, randomness, or machine-specific identifiers in canonical call graph or finding output.

---

## 15. Resource Limits

| Resource | Limit | Rationale |
| :--- | :--- | :--- |
| `max_functions_per_file` | 200 | Prevents pathological generated code from overwhelming discovery |
| `max_total_functions` | 5,000 | Repository-wide function index cap |
| `max_call_depth` | 5 (configurable) | Bounds interprocedural traversal to prevent exponential blowup |
| `max_path_count` | 50 | Maximum interprocedural taint paths per analysis run |
| `max_evidence_steps` | 30 | Maximum steps in a single interprocedural evidence trace |
| `max_summary_iterations` | 3 | Fixed-point iterations for mutually recursive functions |
| `max_function_body_statements` | 500 | Skip summarization for excessively large functions |
| `max_call_edges` | 10,000 | Repository-wide call edge cap |
| `max_unresolved_calls` | 1,000 | Limit unresolved call tracking to prevent memory bloat |

All limits are checked at their respective pipeline stages with cooperative cancellation.

---

## 16. Cancellation

Phase 15 reuses Phase 11's cooperative cancellation protocol. No new cancellation mechanism is introduced.

### 16.1 Cancellation Checkpoints

| Stage | Checkpoint Location | Partial State Handling |
| :--- | :--- | :--- |
| Function Discovery | After each file's function extraction | Partial function index discarded |
| Call Graph Construction | After each batch of call resolutions | Partial call graph discarded |
| Summary Generation | After each function summary | Partial summaries discarded |
| Interprocedural Propagation | After each entry-point function analysis | Partial findings discarded |

### 16.2 Job Marking

If cancellation occurs during Phase 15 stages:
- The job is marked as `CANCELLED` (existing Phase 11 behavior).
- No interprocedural findings are persisted.
- Intraprocedural findings from Phase 13 (which complete before Phase 15 stages) are still available.
- The `call_graph_summary` field is `null` in the snapshot.

---

## 17. Caching

Phase 15 reuses Phase 11's existing `AnalysisCacheService` with Redis.

### 17.1 Cache Key Components

The existing cache key includes:
- Repository path
- Git commit SHA
- Configuration hash (`config_hash`)

Phase 15 does not introduce new cache key dimensions. If the commit SHA and config hash match, the entire analysis (including interprocedural results) is served from cache.

### 17.2 Function Summary Cache

Function summaries are transient, computed during analysis and discarded after the pipeline completes. They are NOT persisted in Redis or PostgreSQL independently. The rationale: function summaries are cheap to recompute from ASTs, and caching them independently creates stale-summary risks when code changes.

---

## 18. Reporting Compatibility

Interprocedural findings integrate with all existing report formats:

| Format | Integration Strategy |
| :--- | :--- |
| **Terminal** | `analyzer/reporting/terminal.py` detects `flow_type == "INTER_PROCEDURAL_TAINT"` and formats the `call_chain` as an indented breadcrumb trail (`caller() [file:line] -> callee() [file:line]`) rather than printing raw Python dictionaries. |
| **JSON** | Interprocedural evidence serialized in `Finding.evidence` JSON (standard canonical output). |
| **SARIF** | `analyzer/reporting/sarif.py` produces `codeFlows` spanning multiple files: step locations use the step's specific `caller_file` and `callee_file` rather than hardcoding to `rel_uri`, and all involved files are registered in `artifact_uris`. |
| **Markdown** | `analyzer/reporting/markdown_reporter.py` detects `flow_type in ("INTRA_PROCEDURAL_TAINT", "INTER_PROCEDURAL_TAINT")` and renders collapsible `<details>` blocks with multi-file breadcrumbs and call sites. |
| **HTML** | `analyzer/reporting/html_reporter.py` detects `flow_type in ("INTRA_PROCEDURAL_TAINT", "INTER_PROCEDURAL_TAINT")` and renders an interactive cross-file step viewer with file badges. |
| **JUnit** | `analyzer/reporting/junit_reporter.py` emits `<failure>` elements showing the multi-file call chain summary in the failure message. |
| **GitLab** | Findings mapped to primary sink location (GitLab schema only supports a single physical file location). |

No new reporter classes are created. Existing reporters are extended to handle `flow_type == "INTER_PROCEDURAL_TAINT"`.

---

## 19. Baseline Compatibility

### 19.1 Finding Identity Stability

Interprocedural findings use UUIDv5 generated from a deterministic signature:
```
f"{rule_id}:{source_file}:{source_line}:{sink_file}:{sink_line}:{call_chain_hash}"
```

The `call_chain_hash` is a SHA-256 of the sorted call chain step qualified names.

### 19.2 Comparison Behavior

Phase 9's `BaselineComparator` handles interprocedural findings using the same multi-tier matching:

1. **Exact ID match**: UUIDv5 finding ID comparison.
2. **Exact signature match**: `(rule_id, normalized_sink_path, sink_line, normalized_snippet)`.
3. **Fuzzy snippet match**: `(rule_id, normalized_sink_path, normalized_snippet)` across line shifts.
4. **Fuzzy location match**: `(rule_id, normalized_sink_path, sink_line)` across minor changes.

Interprocedural findings are classified as `NEW`, `RESOLVED`, `MODIFIED`, or `UNCHANGED` using the same algorithm.

### 19.3 Migration Compatibility

Baselines generated before Phase 15 do not contain interprocedural findings. When compared against a Phase 15 analysis:
- All interprocedural findings are classified as `NEW` (correct behavior).
- No false `RESOLVED` classifications occur (interprocedural rule IDs are distinct: SEC-PY-011/012, SEC-JS-009/010).

---

## 20. SARIF Compatibility

### 20.1 Cross-Function `codeFlows`

Interprocedural taint paths map to SARIF v2.1.0 `codeFlows` with `threadFlowLocations` spanning multiple files:

```json
{
  "codeFlows": [
    {
      "threadFlows": [
        {
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "views.py" },
                  "region": { "startLine": 12, "startColumn": 4 }
                },
                "message": { "text": "SOURCE: user_id = request.args['id']" }
              },
              "kinds": ["source"],
              "nestingLevel": 0
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "views.py" },
                  "region": { "startLine": 13, "startColumn": 4 }
                },
                "message": { "text": "CALL: build_query(user_id) → utils/query.py:build_query" }
              },
              "kinds": ["call"],
              "nestingLevel": 0
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "utils/query.py" },
                  "region": { "startLine": 2, "startColumn": 4 }
                },
                "message": { "text": "PROPAGATION: user_input flows to return via f-string" }
              },
              "kinds": ["pass"],
              "nestingLevel": 1
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "views.py" },
                  "region": { "startLine": 14, "startColumn": 4 }
                },
                "message": { "text": "SINK: cursor.execute(query) — SQL_EXECUTE with tainted input" }
              },
              "kinds": ["sink"],
              "nestingLevel": 0
            }
          ]
        }
      ]
    }
  ]
}
```

### 20.2 Rule Metadata

New rules are registered in the SARIF `tool.driver.rules` array with:
- `id`: `SEC-PY-011`, `SEC-PY-012`, `SEC-JS-009`, `SEC-JS-010`
- `shortDescription`: Interprocedural variant name
- `fullDescription`: Detailed description with cross-function context
- `properties.tags`: `["security", "interprocedural", "taint-analysis"]`

### 20.3 Schema Validation

SARIF output continues to validate against the official OASIS SARIF v2.1.0 JSON schema. The `codeFlows` with multi-file `threadFlowLocations` is a standard SARIF feature.

---

## 21. Health Score Compatibility

### 21.1 Interprocedural Finding Deductions

Interprocedural findings affect the health score through the canonical `HealthScoreCalculator` in `analyzer/architecture/health.py`. In CodeSentinel, health deductions are calculated generically based on finding severity according to `SEVERITY_DEDUCTIONS`, with a per-rule cap of `MAX_DEDUCTION_PER_RULE = 45.0`:

| Rule ID | Category | Severity | Deduction per Finding | Rule Cap | Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-PY-011` | SECURITY | HIGH | 15.0 points | 45.0 points | Cross-function SQL injection is HIGH severity |
| `SEC-PY-012` | SECURITY | CRITICAL | 25.0 points | 45.0 points | Cross-function command injection is CRITICAL severity |
| `SEC-JS-009` | SECURITY | HIGH | 15.0 points | 45.0 points | Cross-function DOM XSS is HIGH severity |
| `SEC-JS-010` | SECURITY | CRITICAL | 25.0 points | 45.0 points | Cross-function eval injection is CRITICAL severity |

No custom point deduction logic or new database tables are required for health scoring. The existing `calculate_sub_score` loop automatically processes these rules using their declared `severity`.

### 21.2 No Double-Counting with Intraprocedural Rules

Intraprocedural rules (`SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`) strictly detect taint paths where both source and sink reside within the **same function scope** (call chain depth = 0).

Interprocedural rules (`SEC-PY-011`, `SEC-PY-012`, `SEC-JS-009`, `SEC-JS-010`) strictly detect taint paths that cross at least one **function call boundary** (call chain depth >= 1).

Because the two rule categories operate on disjoint call depth criteria, a given tainted data-flow trace will not double-trigger across both intraprocedural and interprocedural rules. Furthermore, `HealthScoreCalculator` enforces non-double-counting and per-rule caps (`MAX_DEDUCTION_PER_RULE = 45.0`), preventing score distortions.

---

## 22. Testing Strategy

### 22.1 Unit Tests (`analyzer/tests/`)

| Test File | Scope |
| :--- | :--- |
| `test_phase15_function_discovery.py` | FunctionDefinition extraction from Python AST and JS/TS Tree-sitter for classes, methods, nested functions, async functions, decorators |
| `test_phase15_call_resolution.py` | Call site to callee resolution: local calls, imported calls, method calls, attribute calls, unresolved calls, dynamic calls |
| `test_phase15_function_summary.py` | Summary generation: parameter→return taint, parameter→sink taint, sanitizer application, identity functions, recursive functions |
| `test_phase15_interprocedural_propagation.py` | Cross-function taint propagation: 2-hop chains, 3-hop chains, sanitization in callee, parameterized sinks in callee |
| `test_phase15_interprocedural_rules.py` | SEC-PY-011, SEC-PY-012, SEC-JS-009, SEC-JS-010: positive cases, negative cases, sanitized cases |
| `test_phase15_determinism.py` | Repeated analysis produces identical call graphs, summaries, and findings |
| `test_phase15_resource_limits.py` | Bounds enforcement: max_call_depth, max_total_functions, max_path_count |
| `test_phase15_cancellation.py` | Cooperative cancellation during function discovery, call graph construction, summary generation |
| `test_phase15_cli.py` | `--max-call-depth`, `--disable-interprocedural` flag handling |
| `test_phase15_config.py` | `.codesentinel.yml` `max_call_depth` and `interprocedural` fields |
| `test_phase15_sarif.py` | Multi-file `codeFlows` generation, SARIF schema validity |
| `test_phase15_reporters.py` | Terminal, Markdown, HTML, JUnit, GitLab handling of interprocedural evidence |

### 22.2 Integration Tests (`backend/tests/`)

| Test File | Scope |
| :--- | :--- |
| `test_phase15_boundary_independence.py` | Verify zero backend/DB/queue imports in `analyzer/dataflow/callgraph/` and `analyzer/dataflow/interprocedural/` |
| `test_phase15_persistence.py` | Snapshot persistence with `call_graph_summary`, interprocedural finding evidence roundtrip |
| `test_phase15_api_callgraph.py` | `GET .../callgraph` endpoint returns 200/404 correctly |

### 22.3 Regression Tests

All Phase 1–14 tests must remain passing (359 passed, 1 skipped). Phase 15 does not modify the behavior of any existing rule or pipeline stage.

### 22.4 Edge Case Tests

Covered in §30.

---

## 23. E2E Scenarios

### E2E Scenario 1: Cross-Function SQL Injection (Python)

```text
Repository:
  utils/db.py:
    def build_query(user_input):
        return f"SELECT * FROM users WHERE id = {user_input}"

  views.py:
    from utils.db import build_query
    def handle_request(request):
        user_id = request.args['id']
        query = build_query(user_id)
        cursor.execute(query)

Command: codesentinel analyze . --format sarif
Expected:
  1. Function discovery: build_query, handle_request found.
  2. Call graph: handle_request → build_query resolved via import.
  3. Summary: build_query: param[0] flows to return (TAINTED, via f-string).
  4. Interprocedural: request.args['id'] → user_id → build_query(user_id) → return → query → cursor.execute(query).
  5. Finding: SEC-PY-011 with INTER_PROCEDURAL_TAINT evidence.
  6. SARIF: codeFlows spanning views.py and utils/db.py.
```

### E2E Scenario 2: Sanitized Cross-Function Call (Negative)

```text
Repository:
  sanitizer.py:
    import shlex
    def safe_cmd(user_input):
        return shlex.quote(user_input)

  handler.py:
    from sanitizer import safe_cmd
    import subprocess
    def run_command(request):
        cmd_arg = request.args['cmd']
        safe_arg = safe_cmd(cmd_arg)
        subprocess.run(['echo', safe_arg])

Expected:
  1. Summary: safe_cmd: param[0] flows to return (SANITIZED by shlex.quote for COMMAND_EXECUTE).
  2. Interprocedural: Taint is sanitized before reaching subprocess.run sink.
  3. No SEC-PY-012 finding.
```

### E2E Scenario 3: Multi-Hop Chain (3 Functions)

```text
Repository:
  input.py:
    def get_user_data(request):
        return request.form['data']

  transform.py:
    def format_query(data):
        return f"INSERT INTO logs VALUES ('{data}')"

  execute.py:
    from input import get_user_data
    from transform import format_query
    def process(request):
        data = get_user_data(request)
        sql = format_query(data)
        db.execute(sql)

Expected:
  SEC-PY-011 with 3-hop call chain: get_user_data → format_query → db.execute.
```

### E2E Scenario 4: Disabled Interprocedural Analysis

```text
Command: codesentinel analyze . --disable-interprocedural
Expected:
  1. Function discovery, call graph, and summary stages are skipped.
  2. Only intraprocedural findings (SEC-PY-009, SEC-PY-010, etc.) are reported.
  3. Pipeline completes faster.
  4. Exit code behavior unchanged.
```

---

## 24. Documentation Updates

| Document | Update |
| :--- | :--- |
| `docs/ROADMAP.md` | Add Phase 15 section. Mark as COMPLETE upon implementation. |
| `docs/ARCHITECTURE.md` | Document call graph construction, function summary architecture, and interprocedural propagation. |
| `docs/SECURITY_RULES.md` | Add SEC-PY-011, SEC-PY-012, SEC-JS-009, SEC-JS-010 rule specifications. |
| `docs/SARIF.md` | Document multi-file `codeFlows` for interprocedural findings. |
| `docs/API.md` | Document `GET .../callgraph` endpoint. |
| `README.md` | Update feature list with interprocedural analysis capability. |

---

## 25. Non-Goals

Phase 15 explicitly does NOT include:

1. **Remote GitHub ingestion**: CodeSentinel remains local/CI-mounted only.
2. **GitHub OAuth / multi-user authentication / RBAC / multi-tenancy**: Out of scope.
3. **Autonomous remediation / auto-patching**: Findings are reported; code is never modified.
4. **Complete call graph resolution**: Dynamic calls, higher-order functions, callbacks, and external library internals are intentionally unresolved.
5. **Whole-program analysis**: Analysis is bounded by `max_call_depth` and function caps. CodeSentinel does not attempt full whole-program data-flow.
6. **Type inference engine**: Call resolution uses name-based matching and import resolution, not type inference.
7. **Points-to analysis / heap modeling**: Variable aliases through object attributes are not deeply tracked.
8. **Cross-language taint**: Taint does not flow between Python and JavaScript files (even in full-stack repositories).
9. **IDE/LSP integration**: Deferred to a future phase.
10. **Custom rule/plugin framework**: Deferred; rules remain built-in.
11. **Performance benchmarking infrastructure**: Phase 15 adds bounds but does not establish formal benchmark suites.

---

## 26. Work Breakdown

### Workstream 15.1: Call Graph Foundation Models

| Field | Value |
| :--- | :--- |
| **Goal** | Define Pydantic models for `FunctionDefinition`, `CallEdge`, `CallGraph`, `FunctionSummary`, and `InterproceduralTaintPath` |
| **Existing dependencies** | `analyzer/dataflow/taint/models.py`, `analyzer/models/findings.py` |
| **Files to create** | `analyzer/dataflow/callgraph/__init__.py`, `analyzer/dataflow/callgraph/models.py` |
| **Files to modify** | `analyzer/dataflow/taint/models.py` (add `InterproceduralTaintPath`) |
| **Architecture** | Pure Pydantic models with deterministic serialization |
| **Tests** | Model construction, serialization roundtrip, deterministic ID generation |
| **Completion criteria** | All models instantiable with valid data; UUIDv5 generation deterministic |

### Workstream 15.2: Function Discovery

| Field | Value |
| :--- | :--- |
| **Goal** | Extract `FunctionDefinition` records from Python ASTs and JS/TS Tree-sitter trees |
| **Existing dependencies** | `analyzer/parsing/python_parser.py`, `analyzer/parsing/javascript_parser.py`, `analyzer/parsing/typescript_parser.py` |
| **Files to create** | `analyzer/dataflow/callgraph/discovery.py` |
| **Architecture** | AST visitors producing `FunctionDefinition` records with qualified names |
| **Data flow** | ParsedFile ASTs → FunctionDefinition list |
| **Tests** | Discovery from classes, nested functions, async functions, decorators, methods; `max_functions_per_file` enforcement |
| **Completion criteria** | Function discovery produces deterministic, complete results for Python and JS/TS |

### Workstream 15.3: Call Resolution

| Field | Value |
| :--- | :--- |
| **Goal** | Resolve call expressions to `FunctionDefinition` targets using import edges and scope analysis |
| **Existing dependencies** | `analyzer/dependencies/resolver.py`, `analyzer/dataflow/symbol.py` |
| **Files to create** | `analyzer/dataflow/callgraph/resolver.py` |
| **Architecture** | Multi-strategy resolution: local scope → import binding → attribute access |
| **Data flow** | AST call nodes + FunctionDefinition index + import edges → CallEdge list |
| **Tests** | Local calls, imported calls, method calls, unresolved calls, dynamic calls |
| **Completion criteria** | Resolution handles all documented strategies; unresolved calls correctly classified |

### Workstream 15.4: Call Graph Builder

| Field | Value |
| :--- | :--- |
| **Goal** | Orchestrate function discovery + call resolution into a complete `CallGraph` |
| **Existing dependencies** | Workstreams 15.1, 15.2, 15.3 |
| **Files to create** | `analyzer/dataflow/callgraph/graph_builder.py` |
| **Architecture** | Orchestrator combining discovery and resolution with resource limits |
| **Data flow** | ParsedFiles + DiscoveredFiles + DependencyEdges → CallGraph |
| **Tests** | Multi-file call graph construction, cycle detection, resource limit enforcement |
| **Completion criteria** | CallGraph with correct edges, resolution stats, and bounded execution |

### Workstream 15.5: Function Summary Generation

| Field | Value |
| :--- | :--- |
| **Goal** | Generate `FunctionSummary` records by running intraprocedural taint analysis per function |
| **Existing dependencies** | `analyzer/dataflow/taint/propagator.py`, `analyzer/dataflow/python_visitor.py`, `analyzer/dataflow/js_visitor.py` |
| **Files to create** | `analyzer/dataflow/callgraph/summarizer.py` |
| **Architecture** | Per-function intraprocedural taint analysis with parameter-taint seeding |
| **Data flow** | FunctionDefinition + AST + TaintRegistry → FunctionSummary |
| **Tests** | Param-to-return, param-to-sink, sanitizer detection, recursive function handling, identity functions |
| **Completion criteria** | Summaries correctly capture taint transfer semantics for test corpus |

### Workstream 15.6: Interprocedural Taint Propagator

| Field | Value |
| :--- | :--- |
| **Goal** | Propagate taint across function call boundaries using summaries |
| **Existing dependencies** | Workstreams 15.4, 15.5, `analyzer/dataflow/taint/propagator.py` |
| **Files to create** | `analyzer/dataflow/interprocedural/__init__.py`, `analyzer/dataflow/interprocedural/propagator.py` |
| **Architecture** | Bounded depth-first traversal of call graph with summary-based taint transfer |
| **Data flow** | TaintSource + CallGraph + FunctionSummaries → InterproceduralTaintPath list |
| **Tests** | 2-hop, 3-hop, sanitized chains, recursive chains, depth-bounded termination |
| **Security** | `max_call_depth`, `max_path_count`, cancellation checkpoints |
| **Completion criteria** | Interprocedural paths detected for all E2E scenarios; no false positives on sanitized chains |

### Workstream 15.7: Interprocedural Security Rules

| Field | Value |
| :--- | :--- |
| **Goal** | Implement SEC-PY-011, SEC-PY-012, SEC-JS-009, SEC-JS-010 |
| **Existing dependencies** | Workstream 15.6, `analyzer/security/base_rule.py`, `analyzer/rules/registry.py` |
| **Files to create** | `analyzer/security/python/sec_py_011_sql_interprocedural.py`, `analyzer/security/python/sec_py_012_subprocess_interprocedural.py`, `analyzer/security/javascript/sec_js_009_dom_xss_interprocedural.py`, `analyzer/security/javascript/sec_js_010_eval_interprocedural.py` |
| **Files to modify** | `analyzer/security/python/__init__.py` (register in `PYTHON_RULES`), `analyzer/security/javascript/__init__.py` (register in `JAVASCRIPT_RULES`), `analyzer/rules/engine.py` |
| **Tests** | Positive, negative, sanitized, cross-file, multi-hop for each rule |
| **Completion criteria** | Rules registered, findings generated with correct evidence, health deductions evaluated via standard severity penalties |

### Workstream 15.8: Pipeline Integration

| Field | Value |
| :--- | :--- |
| **Goal** | Integrate call graph, summaries, and interprocedural analysis into `AnalysisPipeline` |
| **Existing dependencies** | Workstreams 15.4, 15.5, 15.6, 15.7 |
| **Files to modify** | `analyzer/engine/pipeline.py` (add CALL_GRAPH and INTER_PROCEDURAL stages), `analyzer/config/settings.py` (add `max_call_depth`, `interprocedural` fields), `analyzer/config/repo_config.py` (add config fields) |
| **CLI** | `analyzer/cli/main.py` (add `--max-call-depth`, `--disable-interprocedural`) |
| **Tests** | Full pipeline E2E with interprocedural findings, `--disable-interprocedural` bypass |
| **Completion criteria** | Pipeline produces interprocedural findings alongside intraprocedural findings |

### Workstream 15.9: Persistence & API

| Field | Value |
| :--- | :--- |
| **Goal** | Persist call graph summaries and serve via API |
| **Existing dependencies** | Workstream 15.8 |
| **Files to create** | `backend/alembic/versions/0006_phase15_callgraph_summary.py`, `backend/app/api/v1/endpoints/callgraph.py`, `backend/app/schemas/callgraph.py` |
| **Files to modify** | `backend/app/models/snapshot.py` (add `call_graph_summary` JSON column), `backend/app/schemas/analysis.py` (add `call_graph_summary` to `AnalysisResultDTO`, update `FindingDTO.dataflow_evidence`), `backend/app/services/persistence.py` (persist `call_graph_summary`, update `reconstruct_analysis_dto` line 419 to accept `INTER_PROCEDURAL_TAINT`), `backend/app/api/v1/api.py` (mount callgraph router with `prefix="/repositories"`) |
| **Database** | Migration `0006_phase15` adding `call_graph_summary` nullable JSON column to `analysis_snapshots` |
| **Tests** | Migration upgrade/downgrade, persistence roundtrip, API endpoint 200/404, repository isolation |
| **Completion criteria** | Snapshot contains call graph summary; API returns correct data; interprocedural `dataflow_evidence` preserved |

### Workstream 15.10: Reporting Extensions

| Field | Value |
| :--- | :--- |
| **Goal** | Extend all reporters to handle interprocedural evidence |
| **Existing dependencies** | Workstream 15.8 |
| **Files to modify** | `analyzer/reporting/terminal.py` (clean call chain formatting), `analyzer/reporting/sarif.py` (multi-file `threadFlowLocations` and `artifact_uris`), `analyzer/reporting/markdown_reporter.py` (support `INTER_PROCEDURAL_TAINT`), `analyzer/reporting/html_reporter.py` (cross-file step pills), `analyzer/reporting/junit_reporter.py` |
| **Tests** | Each reporter correctly renders `INTER_PROCEDURAL_TAINT` evidence |
| **Completion criteria** | All formats produce valid output with interprocedural traces without crashes |

### Workstream 15.11: Frontend Visualization

| Field | Value |
| :--- | :--- |
| **Goal** | Build `InterproceduralTraceViewer` and integrate with code viewer |
| **Existing dependencies** | Workstream 15.9 |
| **Files to create** | `frontend/src/components/findings/InterproceduralTraceViewer.tsx` |
| **Files to modify** | `frontend/src/types/api.ts` (export `CallChainStepDTO`, `InterproceduralTaintTraceDTO`, union in `FindingDTO`), `frontend/src/components/findings/MonacoViewer.tsx` (detect `INTER_PROCEDURAL_TAINT` and render `InterproceduralTraceViewer`), `frontend/src/api/client.ts` (add `getCallGraphSummary` method) |
| **Tests** | TypeScript typecheck (`npm.cmd run typecheck`), Vite build (`npm.cmd run build`) |
| **Completion criteria** | Interprocedural findings render cross-file breadcrumb trace above Monaco code editor |

### Workstream 15.12: E2E Verification & Documentation

| Field | Value |
| :--- | :--- |
| **Goal** | Full E2E verification, documentation updates, boundary tests |
| **Existing dependencies** | All prior workstreams |
| **Files to modify** | `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_RULES.md`, `docs/SARIF.md`, `docs/API.md`, `README.md` |
| **Tests** | All test suites pass, boundary independence verified, SARIF schema validation |
| **Completion criteria** | All completion gates met (§29) |

---

## 27. Dependency Graph

```
[15.1: Call Graph Models]
         │
         ├──────────────────────────────┐
         ▼                              ▼
[15.2: Function Discovery]    [15.3: Call Resolution]
         │                              │
         └──────────┬───────────────────┘
                    ▼
         [15.4: Call Graph Builder]
                    │
                    ▼
         [15.5: Function Summary Generation]
                    │
                    ▼
         [15.6: Interprocedural Taint Propagator]
                    │
                    ▼
         [15.7: Interprocedural Security Rules]
                    │
                    ▼
         [15.8: Pipeline Integration]
                    │
         ┌──────────┼──────────────────┐
         ▼          ▼                  ▼
[15.9: Persistence  [15.10: Reporting  [15.11: Frontend
 & API]              Extensions]        Visualization]
         │          │                  │
         └──────────┼──────────────────┘
                    ▼
         [15.12: E2E Verification & Documentation]
```

---

## 28. Risk Register

| Risk | Probability | Impact | Mitigation |
| :--- | :--- | :--- | :--- |
| **Call resolution accuracy too low** | Medium | Medium | Implement multi-strategy resolution (local, import, attribute). Track `resolution_rate` metric. If rate <60% on test corpus, narrow rule confidence to MEDIUM. |
| **Performance regression on large repositories** | Medium | High | Enforce all resource limits (§15). Add `--disable-interprocedural` bypass. Profile on test fixtures before integration. |
| **False positives from incorrect summaries** | Medium | High | Conservative summary generation: if taint flow is uncertain, mark as `is_summarized = False` and exclude from interprocedural analysis. |
| **Non-deterministic call graph ordering** | Low | High | Sort all collections by deterministic keys. Use UUIDv5 for identifiers. Add determinism regression tests. |
| **Analyzer boundary pollution** | Low | Critical | Verify zero backend/DB imports in new `analyzer/dataflow/callgraph/` and `analyzer/dataflow/interprocedural/` modules with AST boundary tests. |
| **Baseline incompatibility** | Low | Medium | New rule IDs (SEC-PY-011/012, SEC-JS-009/010) are distinct from existing rules. Baselines without interprocedural findings produce correct `NEW` classifications. |
| **Resource exhaustion on pathological input** | Low | High | `max_call_depth`, `max_total_functions`, `max_path_count`, `max_call_edges` all enforced. Cooperative cancellation at each stage. |
| **Mutual recursion infinite loop** | Low | High | `max_summary_iterations = 3` with fixed-point detection. Cycle detection in call graph before propagation. |
| **Persistence schema migration failure** | Low | Medium | Simple additive migration (nullable JSON column). Tested with `alembic upgrade head` and `alembic downgrade`. |

---

## 29. Verification Matrix

| Area | Verification | Expected Result |
| :--- | :--- | :--- |
| **Call Graph Models** | `pytest analyzer/tests/test_phase15_*models*.py -v` | Pass: All model constructors, serialization, deterministic IDs |
| **Function Discovery** | `pytest analyzer/tests/test_phase15_function_discovery.py -v` | Pass: Python and JS/TS function extraction |
| **Call Resolution** | `pytest analyzer/tests/test_phase15_call_resolution.py -v` | Pass: All resolution strategies, unresolved classification |
| **Function Summaries** | `pytest analyzer/tests/test_phase15_function_summary.py -v` | Pass: Param→return, param→sink, sanitizer detection |
| **Interprocedural Propagation** | `pytest analyzer/tests/test_phase15_interprocedural_propagation.py -v` | Pass: 2-hop, 3-hop, sanitized, bounded depth |
| **Interprocedural Rules** | `pytest analyzer/tests/test_phase15_interprocedural_rules.py -v` | Pass: SEC-PY-011/012, SEC-JS-009/010 positive and negative |
| **Determinism** | `pytest analyzer/tests/test_phase15_determinism.py -v` | Pass: Identical canonical output on repeated analysis |
| **Resource Limits** | `pytest analyzer/tests/test_phase15_resource_limits.py -v` | Pass: All limits enforced, no unbounded execution |
| **Cancellation** | `pytest analyzer/tests/test_phase15_cancellation.py -v` | Pass: Cooperative cancellation at each stage |
| **CLI** | `pytest analyzer/tests/test_phase15_cli.py -v` | Pass: `--max-call-depth`, `--disable-interprocedural` |
| **Boundary Independence** | `pytest backend/tests/test_phase15_boundary_independence.py -v` | Pass: Zero backend/DB/queue imports in analyzer/ |
| **SARIF** | `pytest analyzer/tests/test_phase15_sarif.py -v` | Pass: Valid SARIF 2.1.0 with multi-file codeFlows |
| **Reporters** | `pytest analyzer/tests/test_phase15_reporters.py -v` | Pass: All formats handle interprocedural evidence |
| **Database Migration** | `alembic -c backend/alembic.ini upgrade head` | `0006_phase15` applies cleanly |
| **API** | `pytest backend/tests/test_phase15_api_callgraph.py -v` | Pass: 200/404 responses correct |
| **Persistence** | `pytest backend/tests/test_phase15_persistence.py -v` | Pass: call_graph_summary roundtrip |
| **Full Analyzer Suite** | `pytest analyzer/tests -v` | All ~280+ tests pass with zero regressions |
| **Full Backend Suite** | `pytest backend/tests -v` | All ~90+ tests pass with zero regressions |
| **Frontend Typecheck** | `npm.cmd run typecheck` | 0 TypeScript errors |
| **Frontend Build** | `npm.cmd run build` | Vite production build passes |

---

## 30. Edge Cases

| Edge Case | Expected Behavior |
| :--- | :--- |
| **Empty repository** | Zero functions discovered; zero call edges; interprocedural analysis skipped cleanly |
| **Single-file repository** | Functions discovered within the file; local calls resolved; imported calls unresolved |
| **No functions in repository** | `CallGraph.functions` is empty; interprocedural analysis skipped; existing intraprocedural analysis still runs |
| **Recursive function** | Self-call detected; summary computed once; recursive call edge marked; `max_summary_iterations` prevents infinite loop |
| **Mutually recursive functions** | Cycle detected in call graph; summaries iterated up to `max_summary_iterations = 3`; conservative (TAINTED) result if no fixed-point |
| **Function with >500 statements** | Marked `is_summarized = False`; excluded from interprocedural propagation; intraprocedural analysis still applies |
| **File with >200 functions** | File skipped for function discovery; warning diagnostic emitted |
| **Repository with >5000 functions** | Discovery stops at 5000; remaining functions ignored; diagnostic emitted |
| **Dynamic call expressions** | Classified as `UNRESOLVED` with reason `DYNAMIC_CALL` |
| **Higher-order function arguments** | Function reference tracked but callback invocation not resolved |
| **`*args` / `**kwargs` parameters** | Taint transfer is conservative: if any argument is tainted, all variadic params are tainted |
| **Default parameter values** | Default values are not tainted sources; only caller arguments introduce taint |
| **Lambda functions** | Treated as anonymous `FunctionDefinition`; qualified name uses `<lambda>` placeholder |
| **Nested function definitions** | Inner functions discovered; calls to inner functions resolved within enclosing scope |
| **Class constructors (`__init__`)** | Treated as regular methods; `is_constructor = True` for metadata |
| **Decorated functions** | Decorators recorded but not executed; function identity preserved |
| **Property getters/setters** | Treated as methods; `@property` noted in decorators |
| **Star imports (`from module import *`)** | Symbols from star imports are marked as partially resolved; call resolution may be ambiguous |
| **Shadowed function names** | Scope-based resolution prefers innermost scope (existing behavior from Phase 13 `SymbolTable`) |
| **Generated files (large)** | `max_functions_per_file` prevents pathological processing |
| **Deleted/missing import targets** | Call resolution returns `UNRESOLVED` with reason `MISSING_IMPORT` |
| **Mixed Python/JS repository** | Functions indexed per-language; no cross-language taint propagation |
| **Unsupported language files** | Skipped during function discovery (existing ingestion behavior) |

---

## 31. Completion Gates

| Gate | Objective Criterion |
| :--- | :--- |
| **Functional correctness** | All E2E scenarios (§23) pass; all interprocedural rules detect true positive cases and reject true negative cases |
| **Architecture boundary** | Zero backend/DB/queue/AI imports in `analyzer/dataflow/callgraph/` and `analyzer/dataflow/interprocedural/` (verified by AST boundary tests) |
| **Determinism** | Repeated analysis of the same repository produces identical call graph statistics, function summaries, and interprocedural findings |
| **Security** | All resource limits enforced; no unbounded execution; evidence snippets pass secret redaction |
| **Resource limits** | `max_call_depth`, `max_total_functions`, `max_path_count`, `max_call_edges` all enforced under test |
| **Cancellation** | Cooperative cancellation halts analysis cleanly at each new stage; no partial corrupt state |
| **CLI compatibility** | Existing CLI behavior unchanged; new flags accepted; exit codes preserved |
| **API compatibility** | Existing endpoints return unchanged responses; new `callgraph` endpoint returns 200/404 |
| **Frontend correctness** | TypeScript typecheck passes (0 errors); Vite production build passes (0 errors) |
| **Reporting compatibility** | All 7 report formats handle interprocedural evidence without rendering errors |
| **Baseline compatibility** | Baselines from Phase 14 produce correct `NEW`/`RESOLVED` classifications when compared against Phase 15 results |
| **SARIF compatibility** | SARIF output validates against official OASIS v2.1.0 JSON schema |
| **Test coverage** | All Phase 15 test suites pass; all Phase 1–14 tests pass with zero regressions |
| **Documentation** | All documentation files listed in §24 updated |

---

## 32. Implementation Order

| Step | Workstream | Rationale |
| :--- | :--- | :--- |
| 1 | **15.1**: Call Graph Foundation Models | All subsequent workstreams depend on the data model definitions |
| 2 | **15.2**: Function Discovery | Call resolution requires a function index to resolve against |
| 3 | **15.3**: Call Resolution | Call graph builder requires both discovery and resolution |
| 4 | **15.4**: Call Graph Builder | Summary generation requires a complete call graph |
| 5 | **15.5**: Function Summary Generation | Interprocedural propagation requires summaries to transfer taint across call boundaries |
| 6 | **15.6**: Interprocedural Taint Propagator | Security rules depend on interprocedural path detection |
| 7 | **15.7**: Interprocedural Security Rules | Pipeline integration requires rules to be registered |
| 8 | **15.8**: Pipeline Integration | Persistence, reporting, and frontend depend on pipeline producing results |
| 9 | **15.9**: Persistence & API | Frontend visualization depends on API data availability |
| 10 | **15.10**: Reporting Extensions | Can proceed in parallel with 15.9 and 15.11 |
| 11 | **15.11**: Frontend Visualization | Can proceed in parallel with 15.9 and 15.10 |
| 12 | **15.12**: E2E Verification & Documentation | Must be last; verifies all prior workstreams |

Steps 9, 10, and 11 can be implemented in parallel once step 8 is complete.

---

## 33. Final Implementation Checklist

- [ ] Repository baseline verified (Post-Phase 14: 359 tests passing, 1 skipped)
- [ ] Phase 14 implementation verified (all 14 capabilities confirmed in code)
- [ ] Phase 15 scope selected from actual gaps (interprocedural data-flow analysis)
- [ ] Call graph models defined (`FunctionDefinition`, `CallEdge`, `CallGraph`, `FunctionSummary`)
- [ ] Function discovery implemented (Python AST + JS/TS Tree-sitter)
- [ ] Call resolution implemented (local, import, attribute, unresolved)
- [ ] Call graph builder implemented (orchestrator with resource limits)
- [ ] Function summary generation implemented (per-function taint transfer specs)
- [ ] Interprocedural taint propagator implemented (bounded depth-first traversal)
- [ ] Interprocedural security rules implemented (SEC-PY-011, SEC-PY-012, SEC-JS-009, SEC-JS-010)
- [ ] Pipeline integration completed (CALL_GRAPH and INTER_PROCEDURAL stages)
- [ ] CLI extended (`--max-call-depth`, `--disable-interprocedural`)
- [ ] Configuration extended (`.codesentinel.yml` fields)
- [ ] Database migration created (`0006_phase15` adding `call_graph_summary` to `analysis_snapshots`)
- [ ] Persistence extended (`call_graph_summary` persisted; `reconstruct_analysis_dto` supports `INTER_PROCEDURAL_TAINT`)
- [ ] API endpoint created (`GET /api/v1/repositories/{id}/analyses/{aid}/callgraph`)
- [ ] Terminal reporter extended (interprocedural traces formatted as breadcrumbs)
- [ ] SARIF reporter extended (multi-file `codeFlows` and complete `artifact_uris`)
- [ ] Markdown reporter extended (collapsible interprocedural traces)
- [ ] HTML reporter extended (interactive cross-file traces)
- [ ] JUnit reporter extended (multi-file failure messages)
- [ ] Frontend `InterproceduralTraceViewer` component created
- [ ] Frontend `MonacoViewer.tsx` extended to branch on `flow_type === 'INTER_PROCEDURAL_TAINT'`
- [ ] Frontend types extended (`InterproceduralTaintTraceDTO`, `CallChainStepDTO`, union in `FindingDTO`)
- [ ] Frontend API client extended (`getCallGraphSummary` endpoint)
- [ ] Health score deductions verified via standard `SEVERITY_DEDUCTIONS` (HIGH=15.0, CRITICAL=25.0, cap=45.0)
- [ ] Baseline comparison verified (correct NEW/RESOLVED for new rule IDs)
- [ ] Determinism tests passing (repeated analysis produces identical output)
- [ ] Resource limit tests passing (all bounds enforced)
- [ ] Cancellation tests passing (cooperative cancellation at each stage)
- [ ] Boundary independence tests passing (zero forbidden imports)
- [ ] SARIF schema validation passing
- [ ] All Phase 1–14 tests passing (zero regressions)
- [ ] TypeScript typecheck passing (0 errors)
- [ ] Vite production build passing (0 errors)
- [ ] Documentation updated (ROADMAP, ARCHITECTURE, SECURITY_RULES, SARIF, API, README)
- [ ] Non-goals documented and scoped
- [ ] All completion gates met
