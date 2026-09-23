# Phase 13 — Advanced Static Analysis, Intraprocedural Data-Flow & Taint Tracking

> **Phase 13 Master Architecture & Implementation Plan (Corrected & Hardened)**  
> **Status:** APPROVED FOR PLANNING  
> **Target Subsystems:** `analyzer/dataflow/`, `analyzer/security/`, `analyzer/architecture/`, `backend/`, `frontend/`, `docs/`  
> **Analyzer Invariant:** Strictly **zero** imports of backend, database, Celery, Redis, HTTP clients, or LLM providers in `analyzer/`.

---

## 1. Executive Summary

Phase 13 advances CodeSentinel's static analysis engine by transitioning from single-node syntactic pattern matching to **bounded intraprocedural data-flow tracking**, alongside **repository-local component graph centrality analysis**.

Prior to Phase 13, CodeSentinel identified security risks either through direct AST construct inspection (e.g., `shell=True` in `subprocess.run`, `dangerouslySetInnerHTML`, raw string formatting directly inside `cursor.execute`) or architectural structural smells (cycles, layer inversions, god modules). Phase 13 introduces the capability to trace untrusted user inputs across variable definitions, reassignments, string operations, and aliases within a single function scope until they either reach a defensive sanitizer, safe parameter binding, or trigger a sensitive sink.

Additionally, Phase 13 elevates the architectural component graph by calculating **Betweenness, In-Degree, and Out-Degree Centrality** over repository-local subsystems, detecting **High-Centrality Architectural Bottlenecks** (`ARC-009`) where a component lies on a disproportionately high volume of shortest dependency paths.

### Core Architectural Axioms
1. **Static & Offline**: Analysis relies entirely on static syntax trees (Python stdlib `ast`, Tree-sitter for JS/TS) and NetworkX graph models. There is zero execution of audited repository code, zero runtime tracing, and zero dynamic instrumentation.
2. **Semantically Deterministic**: Given identical repository contents, analyzer configuration, parser/runtime versions, rule definitions, and relevant environment assumptions, Phase 13 analysis produces semantically deterministic results (identical finding IDs, identical evidence structures, stable ordering, and consistent health scoring).
3. **Decoupled Advisory AI**: The static engine produces authoritative, evidence-rich findings. Downstream Phase 12 AI operates strictly as an advisory reviewer to assess contextual false positives and propose unified diffs.

---

## 2. Current Repository Assessment

Following a comprehensive inspection of the actual repository state on disk after Phase 12:

1. **Analyzer Engine (`analyzer/`)**:
   - `AnalysisPipeline` (`analyzer/engine/pipeline.py`) executes 8 sequential stages (`INGESTION`, `DISCOVERY`, `DETECTION`, `PARSING`, `DEPENDENCIES`, `ARCHITECTURE_GRAPH`, `RULES`, `HEALTH_SCORING`).
   - Python parsing (`analyzer/parsing/python_parser.py`) uses Python 3's native `ast` module.
   - JavaScript/TypeScript parsing (`analyzer/parsing/javascript_parser.py`, `typescript_parser.py`) uses `tree_sitter_javascript` and `tree_sitter_typescript`.
   - `ParsedFile` (`analyzer/models/parse.py`) normalizes imports, exports, symbols (`SymbolDefinition`), and line counts.
   - Graph engine (`analyzer/architecture/`) uses `networkx.DiGraph` to build file-level `ArchitectureGraph` and package-level `ComponentGraph`.
   - Rule engines (`analyzer/rules/engine.py`) execute 14 security rules (`SEC-PY-001`–`008`, `SEC-JS-001`–`006`) and 8 architecture rules (`ARC-001`–`008`).
   - Finding model (`analyzer/models/findings.py`) provides `Finding` with deterministic UUIDv5 (`f"{rule_id}:{file_path}:{line}:{col}"`), `SourceLocation`, and `evidence: dict[str, Any]`.
2. **Backend Service (`backend/`)**:
   - PostgreSQL 17 managed via SQLAlchemy 2.0 Async (FastAPI) and Sync (`psycopg2-binary`, Celery workers).
   - Alembic migration chain: `0001_phase10_initial_schema.py`, `0002_phase11_analysis_jobs.py`, `0003_phase12_ai_enrichment.py`.
   - Asynchronous analysis task queue (`run_analysis_task`) with Redis pub/sub progress streaming (`GET /api/v1/jobs/{id}/stream`) and cooperative cancellation (`is_cancelled`).
   - Dedicated Celery AI task queue (`run_ai_enrichment_task` on queue `ai_enrichment`).
   - `FindingSnapshot` stores `evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON)`.
   - `ComponentSnapshot` stores component coupling metrics ($C_a, C_e, I, \text{LOC}, \text{files}$).
3. **Frontend Dashboard (`frontend/`)**:
   - React 19 + TypeScript + Vite + Tailwind CSS.
   - `FindingsExplorer.tsx` features master-detail findings list, Monaco read-only viewer (`MonacoViewer.tsx`), and slide-over AI triage drawer (`FindingDetailDrawer.tsx` with `@monaco-editor/react` `<DiffEditor />`).
   - `ArchitectureGraph.tsx` renders component topology via `@xyflow/react` with an inspector panel displaying layer badges, $C_a$, $C_e$, instability $I$, and member files.
4. **Current Test Suite**:
   - 303 tests passing, 1 skipped, 0 regressions across analyzer and backend.
   - Zero external imports in `analyzer/` verified by AST boundary tests.

---

## 3. Phase 13 Goals

1. **Intraprocedural Data-Flow Engine**: Construct bounded symbol definition and reference tracking for local variables, parameters, and assignments within a single function/method scope.
2. **Declarative Taint Model**: Introduce formal `TaintSource`, `TaintSink`, and `TaintSanitizer` specifications decoupled from rule evaluation logic.
3. **Context-Aware Taint Propagation**: Track taint state transitions (`UNTAINTED`, `TAINTED`, `SANITIZED`, `UNKNOWN`) across aliases, binary operations, string formatting, and function calls.
4. **Model Parameterized Sinks Separately**: Distinguish dangerous string formatting in queries from safe parameterized query bindings.
5. **New Security Rules**:
   - `SEC-PY-009`: SQL Injection via Data-Flow (multi-step variable propagation into raw SQL execution).
   - `SEC-PY-010`: Command Injection via Data-Flow (user input propagated into subprocess/system execution).
   - `SEC-JS-007`: DOM-Based Cross-Site Scripting (XSS) via Data-Flow (untrusted inputs into dangerous DOM sinks).
   - `SEC-JS-008`: Dynamic Code Execution via Data-Flow (untrusted inputs into `eval` or `Function`).
6. **Graph Centrality Intelligence**:
   - Compute Betweenness Centrality, In-Degree Centrality, and Out-Degree Centrality over the repository-local `ComponentGraph`.
   - Exclude external libraries, standard library modules, and unresolved nodes.
7. **New Architecture Rule**:
   - `ARC-009`: Architectural Bottleneck / High Centrality Component (detects components with betweenness centrality $\ge$ configurable threshold in codebases with $\ge 5$ components).
8. **Explainable Taint & Centrality Evidence**:
   - Provide structured step-by-step breadcrumb paths (`Source -> Assignment -> Call -> Sink`) for security findings.
   - Display centrality metrics and bottleneck badges in the architecture graph panel.
9. **Preserve All Prior Invariants**:
   - Zero dynamic code execution.
   - Zero AI / backend dependencies in `analyzer/`.
   - Phase 11 cancellation and SSE progress compatibility.
   - Phase 12 AI triage and diff viewer compatibility.

---

## 4. Existing Architecture Reuse

| Existing Component | File Path | Reuse Strategy in Phase 13 |
| :--- | :--- | :--- |
| **Python AST Parser** | `analyzer/parsing/python_parser.py` | Reuse AST parsing trees; traverse native AST nodes (`FunctionDef`, `Assign`, `Call`, `Name`, `Attribute`). |
| **JS/TS Tree-Sitter Parser** | `analyzer/parsing/javascript_parser.py` | Reuse Tree-Sitter syntax trees to inspect function scopes, variable declarators, and call expressions. |
| **Finding Model** | `analyzer/models/findings.py` | Store structured taint traces in `Finding.evidence` without altering the core schema. |
| **Rule Registry & Engine** | `analyzer/rules/registry.py`, `engine.py` | Register `SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`, `ARC-009` through existing registries. |
| **Component Graph** | `analyzer/architecture/components.py` | Compute centrality directly on the existing `ComponentGraph` NetworkX instance. |
| **Progress Reporting** | `analyzer/engine/pipeline.py` | Add progress callbacks for `CENTRALITY` (75%) and `DATA_FLOW` (82%) stages. |
| **Job Cancellation** | `analyzer/engine/pipeline.py` | Check `is_cancelled()` inside data-flow loops per file and per function. |
| **Database Persistence** | `backend/app/models/finding.py` | `FindingSnapshot.evidence` JSON column persists structured taint paths with zero schema changes. |
| **AI Context Builder** | `backend/app/services/ai/context_builder.py` | Taint finding location points to the sink; context builder extracts enclosing function containing the full flow. |
| **Monaco Viewer** | `frontend/src/components/findings/MonacoViewer.tsx` | Highlight sink line and allow jumping to source/propagation lines from taint breadcrumbs. |
| **Architecture Canvas** | `frontend/src/components/architecture/ArchitectureGraph.tsx` | Render centrality gauges and bottleneck badges in the existing inspector drawer. |

---

## 5. Proposed Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   analyzer/ Package                                    │
│  (STRICTLY INDEPENDENT - Zero Backend, Database, Celery, Redis, or AI Imports)         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  1. Ingestion & File Discovery                                                         │
│  2. Language & Framework Detection                                                     │
│  3. AST Parsing (Python AST / JS Tree-sitter)                                          │
│  4. Dependency Resolution & Repository Graph                                           │
│  5. Component Graph Builder                                                            │
│  6. [NEW] Centrality Calculator (analyzer/architecture/centrality.py)                  │
│     └── Computes Betweenness, In-Degree, Out-Degree over local ComponentGraph          │
│  7. [NEW] Intraprocedural Data-Flow Engine (analyzer/dataflow/)                        │
│     ├── Scope & Symbol Table Builder (symbol.py)                                       │
│     ├── Declarative Taint Rules (taint/registry.py)                                    │
│     └── Taint Propagator (taint/propagator.py)                                         │
│  8. Rule Evaluation:                                                                   │
│     ├── Standard Rules (SEC-PY-001..008, SEC-JS-001..006, ARC-001..008)              │
│     ├── [NEW] Data-Flow Rules (SEC-PY-009, SEC-PY-010, SEC-JS-007, SEC-JS-008)       │
│     └── [NEW] Centrality Rule (ARC-009)                                                │
│  9. Codebase Health Scoring & Deterministic Serialization                              │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ AnalysisResult (with Taint & Centrality Evidence)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   backend/ Package                                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  - AnalysisJob Celery Task streams real-time DATA_FLOW and CENTRALITY progress via SSE │
│  - Cooperative cancellation checks honored per-function and statement batches          │
│  - PersistenceService saves structured taint evidence in finding_snapshots.evidence    │
│  - Migration 0004_phase13: Adds betweenness_centrality to component_snapshots          │
│  - Phase 12 AI ContextBuilder extracts bounded enclosing scope for LLM triage          │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ REST API
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   frontend/ Client                                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  - FindingsExplorer: Interactive Taint Flow Breadcrumb (Source -> Var -> Sink)         │
│  - MonacoViewer: Line navigation to source, sanitizers, and sink locations             │
│  - ArchitectureGraph: Centrality score gauges & Architectural Bottleneck alerts        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Symbol and Scope Model

Located in `analyzer/dataflow/symbol.py`.

### 6.1 Deterministic Scope Representation
A scope represents an isolated lexical namespace. Scope identifiers **must be strictly deterministic** and constructed from stable physical coordinates and qualified names. Random UUIDs are prohibited.

```python
class ScopeKind(str, Enum):
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    ASYNC_FUNCTION = "ASYNC_FUNCTION"
    BLOCK = "BLOCK"  # For JS/TS block scoping (let/const)

class Scope(BaseModel):
    # Deterministic ID format: "{rel_file_path}::{scope_kind}::{qualified_name}::{line_start}:{col_start}"
    id: str = Field(..., description="Deterministic scope identifier")
    name: str = Field(..., description="Local identifier or function name")
    qualified_name: str = Field(..., description="Full lexical path (e.g. MyClass.process_data)")
    kind: ScopeKind
    line_start: int
    line_end: int
    col_start: int = 0
    parent_id: Optional[str] = None
    children_ids: list[str] = Field(default_factory=list)
    definitions: dict[str, list["Definition"]] = Field(default_factory=dict)
    references: list["Reference"] = Field(default_factory=list)
```

### 6.2 Symbol Definitions and References
```python
class DefinitionKind(str, Enum):
    PARAMETER = "PARAMETER"
    ASSIGNMENT = "ASSIGNMENT"
    REASSIGNMENT = "REASSIGNMENT"
    IMPORT_BINDING = "IMPORT_BINDING"

class Definition(BaseModel):
    symbol_name: str
    kind: DefinitionKind
    line: int
    col: int
    scope_id: str
    raw_expr: Optional[str] = None

class Reference(BaseModel):
    symbol_name: str
    line: int
    col: int
    scope_id: str
    is_write: bool = False
    resolving_definition: Optional[Definition] = None
```

### 6.3 Variable Shadowing Resolution
When resolving a symbol reference:
1. Lookup symbol in the current active `Scope.definitions`. If multiple definitions exist (e.g. reassignment), select the latest definition where `def.line <= ref.line`.
2. If not found in current scope, walk up `parent_id` scope pointers iteratively (`Function -> Enclosing Class -> Module`).
3. If an inner scope defines `x = safe_value()`, it creates a distinct `Definition` in the inner scope's symbol table. References inside `foo()` resolve to the local definition, **shadowing** the outer scope's `x = request.args["id"]` without mutating the outer definition's taint state.
4. Exiting the function scope leaves outer scope variables completely untainted.

---

## 7. Data-Flow Engine

Located in `analyzer/dataflow/engine.py`.

The intraprocedural data-flow engine operates on individual function scopes:
`IntraproceduralDataFlowEngine.analyze_function(func_node, file_path, lines)`

It performs:
- Symbol definition and reference tracking.
- Use-definition relationships.
- Assignment propagation and alias tracking.
- Bounded expression propagation.
- Limited branch merging.
- Intraprocedural taint propagation.

Control-flow tracking is a **bounded static approximation**, not a complete program semantic proof.

### Supported Operations Matrix
| Operation | Example | Engine Handling |
| :--- | :--- | :--- |
| **Direct Assignment** | `y = x` | Propagates taint state from `x` to `y`. |
| **Reassignment** | `x = transform(x)` | Updates `x`'s active definition; preserves taint unless `transform` is a registered context-specific sanitizer. |
| **Multi-Variable Chaining** | `a = src; b = a; c = b` | Creates definition-use chain `src -> a -> b -> c`. |
| **Binary Operations** | `q = "SELECT " + uid` | If any operand is `TAINTED`, the resulting expression is `TAINTED`. |
| **String Formatting (f-string)**| `q = f"SELECT {uid}"` | Scans all formatted values in `ast.JoinedStr`; if any value is tainted, result is tainted. |
| **Format Methods** | `q = "...".format(uid)` | Checks positional and keyword arguments; if tainted, marks result tainted. |
| **Function Call Arguments** | `exec(uid)` | Checks if argument matches sink parameter index and resolves argument's taint state. |
| **Dictionary/Subscript Access** | `val = req.args["id"]` | Taint source on container subscript passes taint to assigned target `val`. |
| **Attribute Access** | `val = req.user.name` | Tainted base object taints attribute value. |
| **Tuple/List Unpacking** | `a, b = src, "safe"` | Positional mapping: `a` inherits `src` taint; `b` is `UNTAINTED`. |

### Deliberately Bounded Scope
- **No Global/Interprocedural Propagation**: Callee returns from other files are treated as conservative values, not tracked cross-file.
- **No Pointer/Memory Aliasing**: Python references are tracked lexically by variable name, not memory address.
- **No Dynamic Metaprogramming**: `eval`, `getattr` dynamic string lookups do not propagate symbolic taint.

---

## 8. Branch and Merge Semantics

Conditionals and control branching require conservative, deterministic merge semantics:

### 1. `if / else` Branching
```python
if cond:
    value = request.args["id"]  # TAINTED
else:
    value = "default_id"        # UNTAINTED
cursor.execute(value)
```
- **Merge Behavior**: The engine performs a conservative union merge. If a symbol is `TAINTED` on *any* branch reaching the join point, its merged state is `TAINTED`. It does not assume `cond` is always false.
- State Lattice Merge:
  - $\text{TAINTED} \sqcup \text{UNTAINTED} = \text{TAINTED}$
  - $\text{TAINTED} \sqcup \text{SANITIZED} = \text{TAINTED}$
  - $\text{TAINTED} \sqcup \text{UNKNOWN} = \text{TAINTED}$
  - $\text{SANITIZED} \sqcup \text{UNTAINTED} = \text{SANITIZED}$
  - $\text{UNKNOWN} \sqcup \text{UNTAINTED} = \text{UNKNOWN}$

### 2. Loops (`for`, `while`)
- Analyzed up to a **fixed-point limit of 2 iterations**.
- Iteration 1 evaluates the loop body with pre-loop symbol states.
- Iteration 2 re-evaluates loop-carried variable dependencies. If taint states reach a fixed point or cycle, loop evaluation terminates. Unbounded looping is prohibited.

### 3. Exception Blocks (`try / except`)
- Symbol definitions in the `try` block up to a call that may raise are merged conservatively with assignments in the `except` block.

### 4. Early Returns / Breaks
- Statements following an unconditional `return`, `break`, or `raise` in a block are pruned from reaching downstream sinks in that block.

---

## 9. Taint Source Model

Located in `analyzer/dataflow/taint/models.py` and `registry.py`.

A `TaintSource` declares an external input vector that introduces untrusted data into the execution flow.

```python
class SourceCategory(str, Enum):
    HTTP_PARAM = "HTTP_PARAM"
    HTTP_BODY = "HTTP_BODY"
    HTTP_HEADER = "HTTP_HEADER"
    COOKIE = "COOKIE"
    ENV_VAR = "ENV_VAR"
    CLI_INPUT = "CLI_INPUT"
    DOM_INPUT = "DOM_INPUT"

class TaintSource(BaseModel):
    source_id: str
    language: str
    category: SourceCategory
    framework: Optional[str] = None
    pattern_type: str  # "ATTRIBUTE", "SUBSCRIPT", "CALL"
    base_object: str   # e.g. "request", "location", "document"
    member: str        # e.g. "args", "GET", "search"
    description: str
```

### Declarative Source Catalog
#### Python Sources:
- `FLASK_ARGS`: `request.args`, `request.values`, `request.form`
- `FLASK_JSON`: `request.get_json()`, `request.json`, `request.data`
- `DJANGO_GET_POST`: `request.GET`, `request.POST`, `request.COOKIES`
- `STDLIB_INPUT`: `input()`, `sys.stdin.read()`, `sys.argv`
- `ENV_VAR`: `os.environ[...]`, `os.environ.get(...)`, `os.getenv(...)`

#### JavaScript / TypeScript Sources:
- `BROWSER_LOCATION`: `location.search`, `location.hash`, `location.href`, `window.location.*`
- `BROWSER_COOKIE`: `document.cookie`
- `BROWSER_NAME`: `window.name`
- `EXPRESS_PARAMS`: `req.query`, `req.body`, `req.params`, `req.headers`

---

## 10. Taint Sink Model & Parameterized Queries

Located in `analyzer/dataflow/taint/models.py`.

A `TaintSink` declares a sensitive security-critical operation whose execution with untrusted data constitutes a vulnerability.

```python
class SinkCategory(str, Enum):
    SQL_EXECUTE = "SQL_EXECUTE"
    COMMAND_EXECUTE = "COMMAND_EXECUTE"
    CODE_EVAL = "CODE_EVAL"
    DOM_INJECTION = "DOM_INJECTION"
    FILE_PATH = "FILE_PATH"

class TaintSink(BaseModel):
    sink_id: str
    language: str
    category: SinkCategory
    rule_id: str
    callee_name: str                        # e.g. "execute", "run", "innerHTML"
    module_or_object: Optional[str] = None  # e.g. "subprocess", "cursor"
    vulnerable_arg_indices: list[int] = Field(default_factory=lambda: [0])
    supports_parameter_binding: bool = False
    parameter_binding_arg_index: Optional[int] = None  # e.g. 1 in cursor.execute(query, params)
    description: str
    severity: FindingSeverity
    confidence: FindingConfidence
```

### Modeling Parameterized SQL Separately:
CodeSentinel explicitly distinguishes **safe sink usage** from **dangerous sink usage**:
```python
# Case A: Dangerous Sink Usage (Dynamic query passed to execute)
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)  # Trigger SEC-PY-009

# Case B: Safe Sink Usage (Static query + parameterized binding)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # SAFE: No finding emitted
```
Parameterized query invocation is modeled as a safe sink invocation property, **not** as a sanitizer function on `user_id`. When `cursor.execute` is called:
1. Argument 0 (the SQL statement) is evaluated. If Argument 0 is static / untainted, **no SQL injection finding is emitted**, even if tainted variables appear in Argument 1 (the parameter tuple/dict).
2. If Argument 0 is dynamic and carries taint from `request.args`, `SEC-PY-009` is emitted.

### Declarative Sink Catalog
#### Python Sinks:
- `SQL_EXECUTE`: `cursor.execute()`, `cursor.executemany()`, `connection.execute()`, `engine.execute()`, `session.execute()` (Rule: `SEC-PY-009`)
- `COMMAND_RUN`: `subprocess.run()`, `subprocess.Popen()`, `subprocess.call()`, `subprocess.check_output()`, `os.system()`, `os.popen()` (Rule: `SEC-PY-010`)

#### JavaScript / TypeScript Sinks:
- `DOM_INNER_HTML`: `element.innerHTML`, `element.outerHTML`, `document.write()`, `document.writeln()` (Rule: `SEC-JS-007`)
- `EVAL_EXEC`: `eval()`, `new Function()`, `setTimeout(string, ...)`, `setInterval(string, ...)` (Rule: `SEC-JS-008`)

---

## 11. Context-Specific Sanitizer Model

Located in `analyzer/dataflow/taint/models.py`.

Sanitizers are **strictly context-specific**, not universal. A function that neutralizes numeric injection does not sanitize string injection or HTML injection.

```python
class TaintSanitizer(BaseModel):
    sanitizer_id: str
    language: str
    effective_categories: list[SinkCategory]
    callee_pattern: str       # e.g. "int", "shlex.quote", "DOMPurify.sanitize"
    description: str
    strength: str             # "NUMERIC_CONSTRAINT", "SHELL_ESCAPE", "HTML_STRIP"
```

### Sanitizer Effect Matrix
| Sanitizer | Target Sink Category | Context & Strength | Semantics |
| :--- | :--- | :--- | :--- |
| `int(x)`, `float(x)` | `SQL_EXECUTE`, `COMMAND_EXECUTE` | `NUMERIC_CONSTRAINT` | Value constrained to numeric representation. Prevents SQL/command injection in numeric positions. Does **not** sanitize HTML/XSS. |
| `shlex.quote(x)` | `COMMAND_EXECUTE` | `SHELL_ESCAPE` | Shell metacharacters quoted for POSIX shell arguments. Does **not** sanitize SQL. |
| `DOMPurify.sanitize(x)` | `DOM_INJECTION` | `HTML_STRIP` | Strips executable script elements from HTML markup. Does **not** sanitize SQL or commands. |
| `html.escape(x)` | `DOM_INJECTION` | `HTML_ENCODE` | Encodes HTML entities (`&`, `<`, `>`, `"`, `'`). |
| `encodeURIComponent(x)` | `DOM_INJECTION` | `URI_ENCODE` | Encodes URI parameters. Context-specific to URLs; does not sanitize raw HTML blocks. |

### Conservative Unknown Function Rule:
**Unknown functions NEVER clear taint.** If `x` is `TAINTED` and code invokes `y = custom_transform(x)`, `y` transitions to `UNKNOWN` with taint preserved, or remains `TAINTED`. The engine logs `custom_transform` as an unverified intermediate propagation step.

---

## 12. Taint Propagation Algorithm

Located in `analyzer/dataflow/taint/propagator.py`.

```
                    Statement Sequence
                            │
                            ▼
               ┌─────────────────────────┐
               │ Identify Active Scope   │
               └────────────┬────────────┘
                            │
                            ▼
           ┌───────────────────────────────────┐
           │ Is Statement an Assignment?       │
           ├───────────────────────────────────┤
           │ Evaluate RHS taint state:         │
           │ 1. Direct Source (request.args)   │ ──> State: TAINTED
           │ 2. Tainted Variable (y = x)       │ ──> State: TAINTED
           │ 3. BinaryOp / F-String with Taint │ ──> State: TAINTED
           │ 4. Category-Specific Sanitizer    │ ──> State: SANITIZED for category
           │ 5. Unknown Call (y = func(x))     │ ──> State: TAINTED (Propagated)
           │ 6. Literal / Constant             │ ──> State: UNTAINTED
           └────────────────┬──────────────────┘
                            │
                            ▼
           ┌───────────────────────────────────┐
           │ Record Definition & Step in Trace │
           └────────────────┬──────────────────┘
                            │
                            ▼
           ┌───────────────────────────────────┐
           │ Is Statement a Call to Sink?      │
           ├───────────────────────────────────┤
           │ Parameterized Query Binding?      │ ──> Safe: No Finding
           │ If sink argument is TAINTED:      │ ──> Emit Finding + Taint Evidence Trace
           │ If sink argument is SANITIZED:    │ ──> Suppress finding
           │ If sink argument is UNTAINTED:    │ ──> No Finding
           └───────────────────────────────────┘
```

---

## 13. Python Coverage

Python data-flow tracking is implemented via native AST visitor (`ast.NodeVisitor`) in `analyzer/dataflow/python_visitor.py`.

### Handled AST Constructs:
1. `ast.FunctionDef`, `ast.AsyncFunctionDef`: Creates isolated function scope; tracks parameters.
2. `ast.Assign`, `ast.AnnAssign`: Evaluates target symbols against expressions.
3. `ast.AugAssign`: Evaluates `x += y` (inherits taint if either operand is tainted).
4. `ast.JoinedStr`: Traverses all values in f-strings.
5. `ast.BinOp`: Evaluates `Add` (concatenation) and `Mod` (`%` formatting).
6. `ast.Call`: Evaluates sources (`request.args.get`), sanitizers (`int()`), safe parameter bindings, and dangerous sinks (`cursor.execute`).

---

## 14. JavaScript / TypeScript Coverage

JavaScript and TypeScript data-flow tracking is implemented in `analyzer/dataflow/js_visitor.py` using Tree-sitter CST nodes.

### Handled CST Constructs:
1. `function_declaration`, `arrow_function`, `method_definition`: Creates function scope.
2. `variable_declarator`: Handles `const x = ...`, `let y = ...`.
3. `assignment_expression`: Handles reassignments `x = y`.
4. `template_string`: Evaluates `${...}` substitution expressions for string interpolation.
5. `binary_expression`: Handles `+` string concatenation.
6. `call_expression`: Detects sink invocations (`eval`, `document.write`) and sanitizers (`DOMPurify.sanitize`).
7. `member_expression`: Tracks source access (`location.search`) and sink assignments (`element.innerHTML = ...`).

---

## 15. New Security Rules

### Rule Catalog Alignment
| Rule ID | Name | Detection Mode | Scope & Distinction |
| :--- | :--- | :--- | :--- |
| **`SEC-PY-009`** | SQL Injection via Data-Flow | `DETERMINISTIC` | `SEC-PY-005` flags string formatting happening *directly inside* `cursor.execute(...)`. `SEC-PY-009` tracks untrusted variables passed through assignments and multi-line constructions across the function into `cursor.execute`. |
| **`SEC-PY-010`** | Command Injection via Data-Flow | `DETERMINISTIC` | `SEC-PY-003` flags `shell=True` with dynamic strings. `SEC-PY-010` tracks user-controlled input propagating into subprocess arguments or `os.system` without shell quoting. |
| **`SEC-JS-007`** | DOM-Based XSS via Data-Flow | `DETERMINISTIC` | `SEC-JS-003` flags direct React `dangerouslySetInnerHTML`. `SEC-JS-007` tracks unvalidated URL parameters, cookies, or window properties flowing into `innerHTML` or `document.write`. |
| **`SEC-JS-008`** | Dynamic Code Execution via Data-Flow | `DETERMINISTIC` | `SEC-JS-001` flags direct literals in `eval()`. `SEC-JS-008` tracks user input flowing through variables into `eval()` or `new Function()`. |

> **Deferred Rules**: Path Traversal via Data-Flow (`SEC-PY-011`) is explicitly **deferred to Phase 14 / future milestone** to keep Phase 13 tightly bounded.

---

## 16. Architecture Centrality

Located in `analyzer/architecture/centrality.py`.

Phase 7 introduced package coupling metrics ($C_a, C_e, I$). Phase 13 complements this with **Graph Centrality Metrics** computed over the repository-local directed `ComponentGraph`:

### Selected Centrality Metrics:
1. **Betweenness Centrality ($C_{between}$)**:
   $$C_{between}(v) = \sum_{s \ne v \ne t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$
   Measures the fraction of all-pairs shortest paths between repository components that pass through component $v$. High betweenness identifies an **Architectural Mediation Hotspot / High-Centrality Bottleneck** where multiple independent subsystems communicate through a single component.
2. **In-Degree Centrality ($C_{in}$)**:
   $$C_{in}(v) = \frac{\text{deg}_{in}(v)}{|V| - 1}$$
   Normalized count of other repository components directly importing component $v$.
3. **Out-Degree Centrality ($C_{out}$)**:
   $$C_{out}(v) = \frac{\text{deg}_{out}(v)}{|V| - 1}$$
   Normalized count of other repository components imported by component $v$.

### Algorithmic Guarantees:
- **Local Components Only**: Calculated strictly on `ComponentGraph` containing repository packages. External dependencies, stdlib, and unresolved imports are excluded.
- **Deterministic Rounding**: All centrality floats are rounded to 4 decimal places (`round(val, 4)`).
- **Execution Target**: Initial implementation target is $< 50\text{ms}$ on graphs under 100 components; must be benchmarked against representative repositories during verification.

---

## 17. ARC-009 Design

Located in `analyzer/architecture/rules/arc_009_centrality.py`.

### Specification:
- **Rule ID**: `ARC-009`
- **Name**: `Architectural Bottleneck / High Centrality Component`
- **Category**: `ARCHITECTURE`
- **Severity**: `MEDIUM`
- **Confidence**: `HIGH`
- **Evidence Type**: `DETERMINISTIC`
- **Internal Classification**: `architectureRiskCategory: HIGH_CENTRALITY` (Conceptual alignment: `CWE-1061` Insufficient Encapsulation).

### Detection Condition:
A component is flagged by `ARC-009` if and only if:
1. $\text{Total Repository Components} \ge 5$ (prevents noise on small repositories).
2. $\text{Component File Count} \ge 2$ (excludes single-file utility leaves).
3. $\text{Betweenness Centrality} \ge \text{threshold}$ (Default: `0.35`, configurable via `AnalysisConfig.arc_009_centrality_threshold`).

### Deterministic Remediation & Factual Message:
*"Component '{component_id}' lies on a high proportion of repository-local dependency paths (Betweenness Centrality: {val:.4f} >= {threshold}). This creates a systemic architectural mediation hotspot. Consider decoupling high-traffic communication using dependency inversion, domain events, or facade interfaces."*

*(Note: Never claim that the component is guaranteed to cause a single point of failure; report strictly what the graph metric demonstrates).*

---

## 18. Evidence Model

Every Phase 13 finding embeds structured factual evidence inside `Finding.evidence`:

### Taint Flow Evidence Schema:
```json
{
  "flow_type": "INTRA_PROCEDURAL_TAINT",
  "source": {
    "file_path": "backend/app/api/views.py",
    "line": 14,
    "column": 12,
    "symbol_name": "user_id",
    "expression": "request.args['id']",
    "source_id": "FLASK_ARGS"
  },
  "propagation": [
    {
      "step": 1,
      "line": 15,
      "column": 4,
      "operation": "ASSIGNMENT",
      "from_symbol": "user_id",
      "to_symbol": "query",
      "expression": "'SELECT * FROM users WHERE id = ' + user_id"
    }
  ],
  "sanitizer": null,
  "sink": {
    "file_path": "backend/app/api/views.py",
    "line": 16,
    "column": 4,
    "callee": "cursor.execute",
    "sink_id": "SQL_EXECUTE",
    "argument_index": 0,
    "tainted_argument": "query"
  },
  "path_summary": "request.args['id'] -> user_id (L14) -> query (L15) -> cursor.execute(query) (L16)"
}
```

### Centrality Evidence Schema (ARC-009):
```json
{
  "component_id": "backend.app.services",
  "path": "backend/app/services",
  "betweenness_centrality": 0.4286,
  "threshold": 0.35,
  "in_degree_centrality": 0.6,
  "out_degree_centrality": 0.4,
  "participating_paths_count": 18
}
```

---

## 19. Pipeline Integration

Updated execution flow in `AnalysisPipeline` (`analyzer/engine/pipeline.py`):

```text
1. INGESTION (5%)          : Path validation & config verification
2. DISCOVERY (15%)         : File discovery with .gitignore & .sentinelignore
3. DETECTION (25%)         : Language & framework detection
4. PARSING (40%)           : AST & Tree-sitter parsing
5. DEPENDENCIES (55%)      : Module dependency resolution
6. ARCHITECTURE_GRAPH (65%): Graph construction & coupling metrics
7. CENTRALITY (75%)        : [NEW] Component centrality calculation
8. DATA_FLOW (82%)         : [NEW] Intraprocedural taint propagation
9. RULES (90%)             : Security & architecture rule evaluation
10. HEALTH_SCORING (95%)   : Codebase health score deduction calculation
11. COMPLETED (100%)       : Aggregation & canonical result construction
```

If data-flow is disabled via configuration or languages are unsupported, stages advance cleanly without emitting fabricated percentages.

---

## 20. Phase 11 Compatibility

1. **Celery Worker Execution**: The asynchronous Celery task `run_analysis_task` runs `pipeline.run(...)` synchronously in the worker process using `psycopg2-binary`. The new data-flow and centrality stages execute entirely within the standard task execution flow.
2. **Cooperative Cancellation**: Taint propagation periodically checks `is_cancelled()`:
   - Before analyzing each file.
   - Before analyzing each function within a file.
   - Every 25 statement evaluations inside large functions.
   - If cancelled, raises `AnalysisCancelledError`, setting job status to `CANCELLED` and cleaning up Redis keys.
3. **SSE Streaming**: Progress updates from stages `CENTRALITY` and `DATA_FLOW` stream automatically to the frontend over `GET /api/v1/jobs/{id}/stream`.

---

## 21. Phase 12 AI Compatibility

1. **Primary Location Alignment**:
   - For all data-flow findings, `Finding.location` points to the **sink statement** (e.g. line 16 for `cursor.execute(query)`).
2. **Bounded Context Envelope**:
   - `ContextBuilder` (`backend/app/services/ai/context_builder.py`) extracts the enclosing function scope for `location.line_start`.
   - If the enclosing function exceeds the 2,048-token limit, the context builder prioritizes the source line, propagation statements, and sink line, truncating unrelated middle statements. It does **not** dump the entire file.
3. **Pre-Prompt Secret Scrubbing**:
   - `SecretScrubber` sanitizes all code in the extracted scope, removing credentials before transmission to OpenRouter or Ollama.
4. **Advisory Remediation Diff**:
   - The LLM receives the candidate sink finding and surrounding function context. It produces a proposed unified diff parameterizing the query or quoting arguments.
   - Patches are displayed in `DiffPatchViewer.tsx` as advisory proposals and are never automatically applied.

---

## 22. Persistence Impact

1. **`FindingSnapshot` (No Migration Required)**:
   - The existing `finding_snapshots.evidence` column is already a `JSON` type.
   - The full structured taint evidence dictionary serializes cleanly into this column during `save_analysis_snapshot`.
2. **`ComponentSnapshot` (Alembic Migration 0004)**:
   - Migration `backend/alembic/versions/0004_phase13_component_centrality.py` adds:
     - `betweenness_centrality FLOAT DEFAULT 0.0`
     - `in_degree_centrality FLOAT DEFAULT 0.0`
     - `out_degree_centrality FLOAT DEFAULT 0.0`
   - Reversible `upgrade()` and `downgrade()` methods provided.

---

## 23. API Impact

1. **`backend/app/schemas/analysis.py`**:
   - Extend `ComponentCouplingDTO`:
     ```python
     betweenness_centrality: float = Field(default=0.0, description="Betweenness centrality in local component graph")
     in_degree_centrality: float = Field(default=0.0, description="In-degree centrality")
     out_degree_centrality: float = Field(default=0.0, description="Out-degree centrality")
     ```
   - In `FindingDTO`, expose `dataflow_evidence: Optional[dict[str, Any]] = None` derived directly from `FindingSnapshot.evidence`. Avoid competing duplicate evidence models.
2. **`backend/app/services/persistence.py`**:
   - In `reconstruct_analysis_dto`, populate `dataflow_evidence` and centrality metrics.

---

## 24. CLI Impact

1. **Rule Filtering**:
   - Existing `--enable-rule SEC-PY-009,ARC-009` and `--disable-rule` flags work automatically via `RuleRegistry`.
2. **Analysis Configuration Options**:
   - `AnalysisConfig` supports:
     - `max_taint_depth: int = Field(default=25, ge=1, le=100)`
     - `arc_009_centrality_threshold: float = Field(default=0.35, ge=0.0, le=1.0)`
3. **CLI Arguments Added to `analyzer/cli/main.py`**:
   - `--max-taint-depth`: Override max propagation depth.
   - `--centrality-threshold`: Override ARC-009 betweenness threshold.

---

## 25. SARIF Impact

In `analyzer/reporting/sarif.py`:
- Map taint findings to OASIS SARIF v2.1.0 `codeFlows` and `threadFlows`:
  ```json
  "codeFlows": [
    {
      "threadFlows": [
        {
          "locations": [
            {
              "location": { "physicalLocation": { "region": { "startLine": 14 } } },
              "importance": "essential",
              "message": { "text": "Source: request.args['id']" }
            },
            {
              "location": { "physicalLocation": { "region": { "startLine": 15 } } },
              "importance": "important",
              "message": { "text": "Propagation: query = ... + user_id" }
            },
            {
              "location": { "physicalLocation": { "region": { "startLine": 16 } } },
              "importance": "essential",
              "message": { "text": "Sink: cursor.execute(query)" }
            }
          ]
        }
      ]
    }
  ]
  ```
- Validated offline against pinned SARIF 2.1.0 JSON Schema (`analyzer/tests/fixtures/sarif-schema-2.1.0.json`) without external network access.

---

## 26. Baseline Comparison Impact

In `analyzer/comparison/diff.py`:
1. **Sink-Stabilized Matching**: Signature matching indexes `(rule_id, file_path, line_start, snippet)` where `line_start` is the sink location.
2. **Path Modification**: If the sink line remains identical but the propagation path changes, the finding transitions to `FindingTransition.MODIFIED`.
3. **Sanitization Gating**: When a developer inserts a valid category sanitizer or switches to parameterized query bindings, the data-flow rule stops flagging the sink. In differential comparison, the baseline finding transitions to `FindingTransition.RESOLVED`.
4. **New Taint Paths**: When an unvalidated input reaches a sink, it is flagged as `FindingTransition.NEW`.

---

## 27. Frontend Changes & Missing UI States

### 1. `FindingsExplorer.tsx` & `TaintTraceViewer.tsx`:
- When `finding.dataflow_evidence` is present, render an interactive **Taint Flow Trace** breadcrumb panel above the Monaco editor:
  - 🔴 **Source**: `views.py:14` (`request.args['id']`)
  - 🟡 **Propagation**: `views.py:15` (`query = 'SELECT...' + user_id`)
  - 🚨 **Sink**: `views.py:16` (`cursor.execute(query)`)
- Clicking any step in the trace moves the Monaco editor cursor directly to that line.

### 2. `ArchitectureGraph.tsx`:
- In the right-side component inspector drawer, add a **Graph Centrality** section:
  - Betweenness Centrality metric gauge ($0.00 - 1.00$).
  - In-Degree and Out-Degree indicators.
  - Alert banner if Betweenness $\ge$ threshold with badge: *"Architectural Bottleneck Component"*.

### 3. Explicit UI States Handled:
- **Loading State**: *"Running intraprocedural data-flow analysis..."* displayed during `DATA_FLOW` stage.
- **Empty State**: *"No supported source-to-sink data-flow paths detected."* (Explicitly **avoids** claiming *"No vulnerabilities found"*).
- **Partial/Unsupported State**: *"Data-flow analysis was limited because this language construct is outside the supported analysis scope."*
- **Error State**: Displays clear notifications for analysis failure, cancellation, or resource limits reached.

---

## 28. Performance & Resource Limits

| Safety Constraint | Default Limit | Purpose |
| :--- | :--- | :--- |
| **Max Propagation Depth** | 25 hops | Prevents unbounded recursion in complex assignments |
| **Max Paths per Finding** | 5 paths | Avoids combinatorial path explosion |
| **Max Tracked Symbols** | 100 per function | Restricts memory consumption per scope |
| **Max Statements Analyzed** | 500 per function | Skips monstrous machine-generated functions |
| **Max Evidence Steps** | 10 steps | Keeps finding payload concise and human-readable |
| **Loop Fixed-Point Iterations** | 2 iterations | Prevents infinite loops while calculating loop variable taint |
| **Cancellation Check Interval** | Every 25 statements | Ensures cancellation response times $< 200\text{ms}$ |
| **Centrality Graph Size** | Max 500 components | Betweenness calculation design target $< 50\text{ms}$ |

---

## 29. Determinism Guarantees

- **Stable AST Iteration**: AST nodes and symbol definitions are sorted by `(lineno, col_offset)`.
- **Finding ID Invariance**: Generated via `uuid.uuid5(NAMESPACE_DNS, f"{rule_id}:{file_path}:{sink_line}:{sink_col}")`.
- **Floating-Point Rounding**: All centrality values rounded to 4 decimal places.
- **Set Ordering**: All sets converted to sorted lists before comparison or persistence.

---

## 30. Security Model

1. **Zero Execution of Untrusted Code**: Uses static AST visitors only; never imports or runs user files.
2. **Resource Exhaustion Defense**: Strict statement, symbol, and depth limits prevent Denial of Service (DoS) via crafted syntax trees.
3. **Path Traversal Defense**: All file paths validated via `validate_repository_path()`.

---

## 31. File-by-File Implementation Plan

### `analyzer/` (Zero Backend/AI Imports)
1. **[NEW] `analyzer/dataflow/__init__.py`**: Module initialization.
2. **[NEW] `analyzer/dataflow/symbol.py`**: `Scope`, `ScopeKind`, `Definition`, `Reference`, deterministic scope table.
3. **[NEW] `analyzer/dataflow/taint/models.py`**: `TaintSource`, `TaintSink`, `TaintSanitizer`, `TaintState`, `TaintStep`, `TaintPath`.
4. **[NEW] `analyzer/dataflow/taint/registry.py`**: Declarative registry of standard Python and JS sources, sinks, sanitizers.
5. **[NEW] `analyzer/dataflow/taint/propagator.py`**: Core intraprocedural taint propagation evaluator.
6. **[NEW] `analyzer/dataflow/python_visitor.py`**: Python AST visitor executing data-flow tracking per function.
7. **[NEW] `analyzer/dataflow/js_visitor.py`**: Tree-sitter CST visitor executing JS/TS data-flow tracking.
8. **[NEW] `analyzer/security/python/sec_py_009_sql_dataflow.py`**: Rule implementation for SQL injection via data-flow.
9. **[NEW] `analyzer/security/python/sec_py_010_subprocess_dataflow.py`**: Rule implementation for Command injection via data-flow.
10. **[NEW] `analyzer/security/javascript/sec_js_007_dom_xss_dataflow.py`**: Rule implementation for DOM XSS via data-flow.
11. **[NEW] `analyzer/security/javascript/sec_js_008_eval_dataflow.py`**: Rule implementation for dynamic eval via data-flow.
12. **[NEW] `analyzer/architecture/centrality.py`**: `CentralityCalculator` computing betweenness, in-degree, out-degree.
13. **[NEW] `analyzer/architecture/rules/arc_009_centrality.py`**: Rule implementation for high-centrality architectural bottlenecks.
14. **[MODIFY] `analyzer/models/graph.py`**: Add centrality metrics to `PackageMetrics`.
15. **[MODIFY] `analyzer/rules/registry.py`**: Register `SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`, `ARC-009`.
16. **[MODIFY] `analyzer/engine/pipeline.py`**: Integrate centrality and data-flow analysis stages with progress reporting and cancellation.
17. **[MODIFY] `analyzer/reporting/sarif.py`**: Render `codeFlows` for findings with taint evidence.
18. **[MODIFY] `analyzer/cli/main.py`**: Add CLI flags for taint depth and centrality threshold.

### `backend/`
19. **[NEW] `backend/alembic/versions/0004_phase13_component_centrality.py`**: Migration adding centrality fields to `component_snapshots`.
20. **[MODIFY] `backend/app/models/component.py`**: Add `betweenness_centrality`, `in_degree_centrality`, `out_degree_centrality` to `ComponentSnapshot`.
21. **[MODIFY] `backend/app/schemas/analysis.py`**: Update `ComponentCouplingDTO` and `FindingDTO` with data-flow trace.
22. **[MODIFY] `backend/app/services/persistence.py`**: Persist and reconstruct centrality fields and data-flow trace.

### `frontend/`
23. **[NEW] `frontend/src/components/findings/TaintTraceViewer.tsx`**: Breadcrumb timeline component for source -> propagation -> sink navigation.
24. **[MODIFY] `frontend/src/types/api.ts`**: Add `DataFlowTraceDTO` and update `ComponentCouplingDTO`.
25. **[MODIFY] `frontend/src/components/findings/FindingsExplorer.tsx`**: Mount `TaintTraceViewer` above Monaco code editor.
26. **[MODIFY] `frontend/src/components/architecture/ArchitectureGraph.tsx`**: Add Centrality metrics block in inspector panel.

---

## 32. Database Migration Plan

- **File**: `backend/alembic/versions/0004_phase13_component_centrality.py`
- **Revision ID**: `0004_phase13`
- **Revises**: `0003_phase12`
- **Changes**:
  - `op.add_column('component_snapshots', sa.Column('betweenness_centrality', sa.Float(), nullable=True, server_default='0.0'))`
  - `op.add_column('component_snapshots', sa.Column('in_degree_centrality', sa.Float(), nullable=True, server_default='0.0'))`
  - `op.add_column('component_snapshots', sa.Column('out_degree_centrality', sa.Float(), nullable=True, server_default='0.0'))`
- **Downgrade**: Drops the three added columns cleanly.

---

## 33. Dependency Changes

**Zero New External Dependencies Required!**
- Data-flow analysis uses Python standard library `ast` and existing `tree_sitter_javascript` / `tree_sitter_typescript`.
- Centrality analysis uses existing `networkx`.
- Frontend uses existing `lucide-react`, `@xyflow/react`, and `@monaco-editor/react`.

---

## 34. Test Strategy

Create comprehensive test suite in `analyzer/tests/` and `backend/tests/`:

1. `test_phase13_boundary_independence.py`: AST inspection verifying `analyzer/` contains 0 imports of `backend`, `celery`, `redis`, `sqlalchemy`, `httpx`, or AI providers.
2. `test_phase13_symbol_scope.py`: Module scope, function scope, nested scope, class scope, parameter tracking, shadowing, deterministic scope identity.
3. `test_phase13_dataflow_engine.py`: Direct assignment, chained assignment, reassignment, expression propagation, attribute access, dictionary access, tuple unpacking, conditional branch merge, loops, try/except, early returns.
4. `test_phase13_taint_propagation.py`: Source -> sink, source -> variable -> sink, source -> multiple variables -> sink, source category mismatch, multiple sinks, multiple sources.
5. `test_phase13_sanitizers.py`: Context-specific sanitizers (`int()`, `shlex.quote()`, `DOMPurify.sanitize()`) vs. unknown functions; sanitizer category mismatch.
6. `test_phase13_security_rules.py`: SQL injection (`SEC-PY-009`), Command injection (`SEC-PY-010`), DOM XSS (`SEC-JS-007`), Dynamic eval (`SEC-JS-008`).
7. `test_phase13_centrality.py`: Deterministic centrality metrics, isolated nodes, cycles, repository-local graph filtering, external-node exclusion.
8. `test_phase13_arc_009.py`: High betweenness component threshold boundary, minimum component size gating.
9. `test_phase13_cancellation.py`: `is_cancelled` interrupts data-flow analysis safely.
10. `test_phase13_safety.py`: Malformed source, huge functions, huge symbol sets, propagation cycles, deep propagation, loop convergence.
11. `test_phase13_determinism.py`: Repeated runs produce identical finding IDs, taint traces, and centrality metrics.
12. `test_phase13_sarif.py`: Offline schema validation against pinned SARIF 2.1.0 JSON Schema.
13. `test_phase13_baseline.py`: Baseline transitions: NEW, MODIFIED, RESOLVED, UNCHANGED.
14. `test_phase13_ai_compatibility.py`: AI enrichment consumes Phase 13 findings with bounded context, source/sink evidence, and secret scrubbing.

---

## 35. End-to-End Scenarios

### Scenario 1 — Direct SQL Taint
```python
user_id = request.args["id"]
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)
```
- **Execution**: Engine detects source `request.args["id"]`, propagates taint to `user_id` -> `query` -> sink `cursor.execute(query)`.
- **Result**: Emits `SEC-PY-009` with structured taint trace in `evidence`.

### Scenario 2 — Parameterized SQL (Safe Sink Usage)
```python
user_id = request.args["id"]
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
- **Execution**: Engine recognizes static query string and safe parameter binding.
- **Result**: No SQL injection finding emitted.

### Scenario 3 — Numeric Constraint
```python
user_id = int(request.args["id"])
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)
```
- **Execution**: `int()` recognized as context-specific numeric constraint for `SQL_EXECUTE`. Taint cleared for SQL injection.
- **Result**: No `SEC-PY-009` finding emitted.

### Scenario 4 — Unknown Transformation
```python
value = request.args["id"]
value = normalize(value)
cursor.execute(value)
```
- **Execution**: `normalize()` is an unverified function; taint preserved.
- **Result**: Emits `SEC-PY-009` noting `normalize()` as an unverified intermediate propagation step.

### Scenario 5 — Shadowing
```python
value = request.args["id"]

def safe_function():
    value = "safe"
    cursor.execute(value)
```
- **Execution**: Inner `value` definition in `safe_function` shadows outer variable; does not inherit outer taint.
- **Result**: No finding emitted in `safe_function`.

### Scenario 6 — Sanitizer
```python
cmd = request.args["cmd"]
safe_cmd = shlex.quote(cmd)
subprocess.run(f"ls {safe_cmd}", shell=True)
```
- **Execution**: `shlex.quote()` recognized as shell argument sanitizer for `COMMAND_EXECUTE`. Taint cleared.
- **Result**: No `SEC-PY-010` finding emitted.

### Scenario 7 — Centrality Bottleneck
- An application has 8 components. Component `app.core` lies on 65% of all-pairs shortest dependency paths between UI, DB, and external service components.
- **Result**: Betweenness = `0.65` ($\ge 0.35$). Emits `ARC-009` noting an architectural mediation hotspot. No claim of system "single point of failure".

---

## 36. Documentation Changes

1. **`docs/ARCHITECTURE.md`**: Section 9 documenting the Intraprocedural Data-Flow Engine and Graph Centrality architecture.
2. **`docs/SECURITY_RULES.md`**: Formal specification for `SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`, `ARC-009`.
3. **`docs/ROADMAP.md`**: Mark Phase 13 COMPLETE upon implementation; update Phase 14 goals.
4. **`README.md`**: Update current status and feature highlights.

---

## 37. Verification Commands

Following implementation, Antigravity will execute:

```bash
# 1. Full Backend & Analyzer Test Suite
cd E:\AI-Workspace\projects\CodeSentinel
python -m pytest analyzer/tests backend/tests -v

# 2. Dedicated Phase 13 Test Verification
python -m pytest -k "phase13" -v

# 3. Focused Verification Commands
python -m pytest analyzer/tests/test_phase13_dataflow_engine.py -v
python -m pytest analyzer/tests/test_phase13_taint_propagation.py -v
python -m pytest analyzer/tests/test_phase13_centrality.py -v
python -m pytest analyzer/tests/test_phase13_arc_009.py -v
python -m pytest analyzer/tests/test_phase13_cancellation.py -v
python -m pytest analyzer/tests/test_phase13_determinism.py -v
python -m pytest analyzer/tests/test_phase13_sarif.py -v
python -m pytest analyzer/tests/test_phase13_baseline.py -v
python -m pytest backend/tests/test_phase13_ai_compatibility.py -v

# 4. Frontend Typecheck and Production Build
cd frontend
npm run typecheck
npm run build
```

---

## 38. Phase 13 Completion Gates

1. [ ] `analyzer/` contains strictly zero imports of `backend`, `celery`, `redis`, `sqlalchemy`, `httpx`, or AI providers.
2. [ ] Native Python AST visitor performs bounded intraprocedural symbol definition and reference tracking.
3. [ ] Tree-sitter visitor performs JS/TS scope and assignment tracking.
4. [ ] Variable shadowing is handled correctly; outer scope variables remain untainted.
5. [ ] Scope identifiers are strictly deterministic without runtime UUIDs.
6. [ ] Context-specific sanitizers (`int()`, `shlex.quote()`, `DOMPurify.sanitize()`) neutralize target category taint.
7. [ ] Parameterized SQL bindings are modeled as safe sink usage, distinct from string sanitizers.
8. [ ] Unknown functions preserve taint state conservatively.
9. [ ] `SEC-PY-009` detects multi-step raw SQL injection.
10. [ ] `SEC-PY-010` detects multi-step command injection.
11. [ ] `SEC-JS-007` detects multi-step DOM XSS.
12. [ ] `SEC-JS-008` detects multi-step dynamic code evaluation.
13. [ ] Betweenness, In-Degree, and Out-Degree centrality metrics are computed over repository-local `ComponentGraph`.
14. [ ] `ARC-009` flags components exceeding configurable betweenness threshold in codebases with $\ge 5$ components.
15. [ ] All finding IDs use deterministic UUIDv5 `f"{rule_id}:{file}:{sink_line}:{sink_col}"`.
16. [ ] Phase 11 cooperative cancellation (`is_cancelled`) is polled during data-flow traversal.
17. [ ] Phase 11 SSE progress streaming reports `CENTRALITY` and `DATA_FLOW` stages.
18. [ ] Phase 12 AI context builder extracts bounded scope without dumping full files.
19. [ ] Alembic migration `0004_phase13` successfully adds centrality columns to PostgreSQL.
20. [ ] Frontend `TaintTraceViewer` displays step-by-step breadcrumb timeline with line jump triggers.
21. [ ] Frontend `ArchitectureGraph` displays component centrality metrics.
22. [ ] 100% of existing 303 tests continue to pass without regression.

---

## 39. Risks & Mitigations

| Risk | Mitigation |
| :--- | :--- |
| **Explosion in Deep ASTs** | Enforce strict bounds: max 25 propagation steps, max 500 statements, max 100 symbols per function scope. |
| **Complex Assignment Syntax** | Graceful fallback to `UNTAINTED` on unsupported Python/JS edge constructs without crashing the pipeline. |
| **High Centrality False Positives** | Require $\ge 5$ total components and $\ge 2$ files in component before `ARC-009` can trigger. Make threshold configurable. |
| **Worker Task Latency** | Centrality computed on high-level component graph; intraprocedural data-flow bounded per function. Cancellation polled every 25 statements. |

---

## 40. Explicit Non-Goals

The following capabilities are **explicitly deferred to Phase 14 or future milestones**:
- **NO** interprocedural / cross-file whole-program taint analysis.
- **NO** dynamic execution, symbolic execution, or runtime tracing.
- **NO** automatic source-code modification or direct patch application.
- **NO** remote Git cloning, webhooks, or multi-tenant user authentication.
- **NO** centralized `.codesentinel.yml` repository configuration or pre-commit hooks (strictly Phase 14).
- **NO** multi-snapshot longitudinal health drift and vulnerability trend analytics (strictly Phase 14).
- **NO** standalone HTML executive report generator or GitLab SAST report formats (strictly Phase 14).

---

## 41. Correction Review Summary

In response to the architecture hardening review, the following 17 corrections and enhancements were made:

1. **Determinism Corrected**: Replaced absolute claims ("100% repeatable", "always identical") with qualified definition: *"Given identical repository contents, analyzer configuration, parser/runtime versions, rule definitions, and relevant environment assumptions, Phase 13 analysis produces semantically deterministic results."*
2. **Taint Lattice Corrected**: Replaced crude linear lattice with a category-aware state model (`UNTAINTED`, `TAINTED`, `SANITIZED`, `UNKNOWN`) and defined conservative merge rules ($\text{TAINTED} \sqcup \text{UNTAINTED} = \text{TAINTED}$).
3. **Sanitizer Semantics Corrected**: Reframed sanitizers as **context-specific** rather than universal (e.g. `int()` is a numeric constraint for SQL/shell, not a universal sanitizer).
4. **Parameterized SQL Modeled Separately**: Parameterized queries (e.g. `cursor.execute("SELECT ...", (id,))`) are classified as safe sink usage with parameter binding, distinct from string sanitizers.
5. **Scope/Shadowing Corrected**: Defined lexical scope lookup where local variables shadow outer scope definitions without polluting outer state.
6. **Scope IDs Made Deterministic**: Removed `uuid.uuid4()`; replaced with deterministic IDs based on file path, qualified name, and coordinates.
7. **Rule IDs Reconciled**: Formally registered `SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`, `ARC-009`. Explicitly marked path traversal (`SEC-PY-011`) as deferred.
8. **ARC-009 Terminology Corrected**: Replaced misleading "single point of failure" claims with "High-Centrality Architectural Bottleneck / Architectural Mediation Hotspot".
9. **Centrality Threshold Wording Corrected**: Reframed `0.35` as an initial heuristic threshold configurable via `AnalysisConfig.arc_009_centrality_threshold`.
10. **CWE Mapping Reviewed**: Clarified that `ARC-009` uses internal CodeSentinel classification `architectureRiskCategory: HIGH_CENTRALITY`, distinguishing it from security standard mappings.
11. **Performance Claims Corrected**: Replaced absolute latency claims with measurable design targets subject to benchmark verification.
12. **Evidence Model Simplified**: Consolidated structured data-flow evidence inside `Finding.evidence` to eliminate competing duplicate DTO representations.
13. **SARIF Validation Strengthened**: Required offline schema validation against pinned SARIF 2.1.0 JSON Schema.
14. **Phase 12 Compatibility Clarified**: Addressed context budgeting rules so large functions are truncated safely around source/propagation/sink statements without whole-file dumps.
15. **Missing Tests Added**: Added explicit test suites for nested conditions, try/except, loops, unknown functions, category mismatches, cancellation, and safety.
16. **Missing UI States Added**: Explicitly defined Loading, Empty (avoiding "No vulnerabilities found"), Partial/Unsupported, and Error states.
17. **Missing Resource/Cancellation Constraints Added**: Formalized limits on propagation depth, paths, statements, loop iterations, and cancellation check intervals.
