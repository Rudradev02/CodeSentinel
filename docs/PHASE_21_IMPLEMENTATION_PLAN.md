# CodeSentinel Phase 21 Implementation Plan
## Incremental, Dependency-Aware Analysis, Persistent Analysis Caching & Performance Engineering

---

## 1. Executive Summary

CodeSentinel is an offline-first, repository-local static architecture and security analyzer. Through Phases 1–20, the engine has evolved a deep static analysis pipeline: repository ingestion, multi-language AST parsing (Python, JavaScript, TypeScript), module dependency resolution, subsystem component graph construction, architectural smell detection, control-flow graph (CFG) generation, path-sensitive guard evaluation with epoch-based refinement invalidation, alias and points-to field analysis, static call-graph resolution, function-level summary contracts, and bounded project-wide contract composition with rule-specific security boundary matrices.

While this pipeline achieves high precision across multi-hop call chains, it operates primarily in **batch / full analysis mode**: every scan parses every file, computes every dependency, generates every CFG, evaluates path states, synthesizes all interprocedural contracts, and executes every security rule across the entire codebase—even when a developer modifies only a single leaf function or helper method in a pull request.

**Phase 21** introduces an **incremental, dependency-aware analysis orchestration layer, persistent analysis cache, and performance engineering framework**.

### Core Engineering Invariant
> **For supported repository states and supported analysis configurations, the incremental pipeline MUST produce the same canonical analysis result as a fresh full analysis of the same target state, provided every dependency required by the relevant analysis is either unchanged and validated or conservatively invalidated.**

The engine does not rely on speculative heuristics or claim an abstract mathematical proof of soundness. Instead, Phase 21 enforces **from-scratch consistency**, **validated cache reuse**, **conservative invalidation**, and rigorous **equivalence verification**.

```text
Repository Content
        ↓
   L1 Fingerprints (SHA-256 Content + Language + Parser Version + Schema)
        ↓
   L2 Parsed AST (Normalized ParsedFile ASTs & Symbols)
        ↓
   L3 Dependencies (Module Import Graph & TsConfig Aliases)
        ↓
        +-----------------------------------> Architecture Graph & Component Centrality
        ↓
      L4 CFG (Basic Blocks, Statements, Guard Edges)
        ↓
      L5 Local Data Flow (Path Constraints, Refinement Epochs, Points-To)
        ↓
      L6 Call Graph (Caller-Callee Sites, Receiver Resolution, Contexts)
        ↓
      L7 Contracts (Preconditions, Postconditions, Exception Contracts)
        ↓
      L8 Composition (Inter-Module Composition Edges, Boundary Validation)
        ↓
      L9 Findings (Deduplicated Security & Architecture Findings)
        ↓
     Reporting (SARIF 2.1.0, Terminal, Markdown, JSON)
```

---

## 2. Incremental Analysis Safety Principle

The primary safety invariant governing Phase 21 is:

> **CodeSentinel MUST prefer recomputation over uncertain reuse.**

Formally:
- **`VALIDATED_UNCHANGED`** $\longrightarrow$ **Reuse**: All inputs, configuration, dependencies, and schema versions have been validated identical.
- **`VALIDATED_CHANGED`** $\longrightarrow$ **Recompute**: An input, callee contract, or dependency has changed; re-analyze the affected unit.
- **`UNKNOWN`** $\longrightarrow$ **Recompute**: Any dynamic import, unresolvable call site, unparsed construct, or missing graph edge must conservatively trigger re-analysis.
- **`CORRUPTED`** $\longrightarrow$ **Recompute**: Corrupted, truncated, or unreadable cache payloads are treated as safe cache misses.
- **`INCOMPATIBLE`** $\longrightarrow$ **Recompute**: Schema version, analyzer version, or rule configuration discrepancies trigger clean recomputation.

Under no circumstances will CodeSentinel allow an `UNKNOWN` dependency state to result in cache reuse.

---

## 3. Actual Repository Baseline

The CodeSentinel codebase was inspected directly on the local filesystem as of Git commit `50c7e39` (*"complete Phase 20 implementation, verification, and documentation"*).

### 3.1 Git Status & Workspace Hierarchy
- **Active Branch**: `master`
- **Working Tree**: Clean (`nothing to commit, working tree clean`)
- **Repository Root**: `e:\AI-Workspace\projects\CodeSentinel`
- **Subsystems**:
  - `analyzer/`: Core static analysis engine (Python 3.14+). Pure offline library with zero backend/database/AI dependencies.
  - `backend/`: FastAPI application, SQLAlchemy 2.0 ORM, Celery task workers, Redis pub/sub.
  - `frontend/`: React 19, TypeScript 5.8, Vite 6.4, TailwindCSS, Monaco Editor.
  - `docs/`: Technical specifications, architecture designs, API schemas, and roadmap.

### 3.2 Automated Test Suite Baseline
- **Analyzer Test Suite** ([`analyzer/tests/`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/tests)): 485 tests collected.
- **Backend Test Suite** ([`backend/tests/`](file:///e:/AI-Workspace/projects/CodeSentinel/backend/tests)): 101 tests collected.
- **Combined Test Execution**: **585 passed, 1 skipped, 2 warnings in 44.65s**.
- **Skipped Test**: `analyzer/tests/test_phase6_repository_boundaries.py::TestSymlinkBoundary::test_symlink_traversal_outside_repo` (Windows symlink privilege requirement).
- **Active Warnings**: Starlette `httpx` testclient deprecation and AnyIO `BlockingPortal` alias deprecation.

### 3.3 Frontend Production Build Baseline
- **Command**: `npm run build` (`tsc -b && vite build`) in `frontend/`.
- **Outcome**: 1,785 modules transformed in 7.10s with **0 TypeScript errors and 0 lint diagnostics**. Bundle emitted into `frontend/dist/`.

---

## 4. Phase 20 Verification Reconciliation

The Phase 20 implementation introduced bounded project-wide contract composition, exception-aware control flow, rule-specific security boundaries, and container/alias reasoning. A reconciliation against the real repository confirms:

| Metric / Dimension | Phase 20 Stated Claim | Actual Verified Baseline | Status |
| :--- | :--- | :--- | :--- |
| **Total Test Count** | 585 passed, 1 skipped | **585 passed, 1 skipped (586 collected)** in 44.65s | **MATCH** |
| **Pre-existing Tests** | 561 tests | **561 tests** | **MATCH** |
| **Phase 20 Additions** | 24 tests across 6 files | **24 tests across 6 files** | **MATCH** |
| **New Test Distribution** | 6 test files | • [`test_phase20_composition_models.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/tests/test_phase20_composition_models.py) (6 tests)<br>• [`test_phase20_invalidation_engine.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/tests/test_phase20_invalidation_engine.py) (4 tests)<br>• [`test_phase20_exception_contracts.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/tests/test_phase20_exception_contracts.py) (3 tests)<br>• [`test_phase20_security_boundaries.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/tests/test_phase20_security_boundaries.py) (5 tests)<br>• [`test_phase20_integration.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/tests/test_phase20_integration.py) (4 tests)<br>• [`test_phase20_api_backward_compat.py`](file:///e:/AI-Workspace/projects/CodeSentinel/backend/tests/test_phase20_api_backward_compat.py) (2 tests) | **MATCH** |
| **Tests Removed** | 0 removed | **0 removed** between Phase 19 and 20 | **MATCH** |
| **Finding Identity Formula** | Untouched | UUIDv5 formulas in `analyzer/` 100% preserved | **MATCH** |
| **Baseline Comparator** | Untouched | `analyzer/comparison/diff.py` 100% preserved | **MATCH** |
| **Database Migrations** | 0 migrations | Persisted into `call_graph_summary` JSON snapshot column | **MATCH** |

---

## 5. Current Architecture

The existing Phase 1–20 pipeline executes synchronously in sequential stages managed by [`AnalysisPipeline`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/engine/pipeline.py):

1. **Ingestion & Validation**: [`validate_repository_path`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/ingestion/repository.py).
2. **File Discovery**: [`discover_repository_files`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/ingestion/discovery.py) with [`IgnoreEngine`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/ingestion/ignore.py) applying `.gitignore` and `.sentinelignore`.
3. **Language & Framework Detection**: [`LanguageDetector`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/detection/languages.py), [`FrameworkDetector`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/detection/frameworks.py).
4. **Source Parsing**: [`PythonParser`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/parsing/python_parser.py), [`JavaScriptParser`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/parsing/javascript_parser.py), [`TypeScriptParser`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/parsing/typescript_parser.py).
5. **Dependency Resolution**: [`DependencyResolver`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dependencies/resolver.py), [`TsConfigResolver`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dependencies/resolver.py).
6. **Architecture & Component Graph**: [`ArchitectureGraphBuilder`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/architecture/graph_builder.py), [`ComponentGraphBuilder`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/architecture/components.py), [`CentralityCalculator`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/architecture/centrality.py).
7. **Static Call Graph & Interprocedural Propagation**: [`CallGraphBuilder`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/callgraph/graph_builder.py), [`FunctionSummarizer`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/callgraph/summarizer.py), [`InterproceduralTaintPropagator`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/interprocedural/propagator.py).
8. **Contract Composition & Security Boundaries**: [`ContractComposer`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/contracts/composer.py), [`ProjectContractGraph`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/contracts/graph.py), [`SECURITY_BOUNDARY_SPECS`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/contracts/security_boundary.py).
9. **Rule Engine & Finding Generation**: [`RuleEngine`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/rules/engine.py), [`RuleRegistry`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/rules/registry.py).
10. **Health Scoring & Aggregation**: [`HealthScoreCalculator`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/architecture/health.py), canonical [`AnalysisResult`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/models/results.py).

---

## 6. Problem Statement

Full static re-analysis imposes significant scalability bottlenecks as codebases scale:
1. **Redundant Source Ingestion & Parsing**: On large repositories, modifying a single file causes every file to be re-parsed by tree-sitter or Python `ast.parse`.
2. **Redundant CFG Construction & Path Exploration**: Exploring active paths across basic blocks dominates CPU execution time. Recomputing path states for untouched, non-called functions wastes resources.
3. **Redundant Interprocedural Propagation**: Bounded contract composition and fixpoint SCC resolution traverse deep call chains. Changes to standalone utilities do not alter the contracts or security posture of unrelated service hierarchies.
4. **CI/CD Feedback Latency**: Pull request checks in enterprise CI/CD pipelines require rapid feedback. Full re-analysis of large repositories degrades developer velocity.
5. **Naïve Invalidation Risks**: A simplistic file-level cache that invalidates only directly edited files is mathematically unsound: modifying `validate_user(x)` changes its contract, which changes caller preconditions and downstream taint reasoning. Invalidation must be **dependency-aware and contract-propagating**.

---

## 7. Goals

1. **Deterministic File & Config Fingerprinting**: Establish canonical, content-addressed fingerprint models for all repository source files and layer-scoped analysis configurations.
2. **Layered Analysis Cache (L1–L9)**: Introduce an analyzer-internal, bounded, persistent cache covering file fingerprints, ASTs, dependency graphs, CFGs, local data flows, call graphs, contracts, composition results, and findings.
3. **Graph-Aware Reverse Invalidation**: Accurately calculate the affected closure of files, functions, and contracts when source files are modified, added, renamed, or deleted.
4. **Semantic Call-Graph & Contract Invalidation**: Differentiate between function body-only edits, signature changes, call-target changes, and contract-altering modifications.
5. **Finding Reconciliation & Identity Preservation**: Ensure incremental analysis produces the identical canonical findings, severities, and baseline classifications as a fresh full analysis (`FULL(S2) == INCREMENTAL(S1 -> S2)` on supported inputs).
6. **Analyzer Isolation**: Maintain zero backend/database/AI dependencies within `analyzer/`. The caching engine operates purely via local disk or memory interfaces.
7. **Cooperative Cancellation & Fail-Safe Recovery**: Cache operations honor cooperative cancellation checks and recover from corruption by falling back to safe recomputation.
8. **Measurable Performance Benchmarks**: Demonstrate measurable wall-clock speedups for incremental re-analysis on leaf, contract, and architecture changes without sacrificing safety.

---

## 8. Non-Goals

- **No Remote / Cloud Distributed Caching**: Phase 21 does NOT implement S3, GCS, or remote HTTP distributed cache protocols. Caching is repository-local.
- **No Dynamic Execution / Runtime Instrumentation**: No code execution, sandbox execution, or runtime instrumentation. Analysis remains 100% static and offline.
- **No SMT / Whole-Program Symbolic Execution**: No heavy Z3 / SMT theorem proving engines.
- **No AI-Controlled Invalidation Decisions**: Machine learning models or LLMs must NEVER dictate cache hits, invalidation boundaries, or finding reconciliation.
- **No Replacement of Celery / Redis / PostgreSQL**: Phase 21 does NOT replace the existing backend architecture; it equips the underlying analyzer with incremental capabilities.
- **No Mandatory Database Migrations**: Persistence schemas remain stable; incremental summaries serialize into existing JSON snapshot attributes.

---

## 9. Incremental Analysis Architecture

Phase 21 introduces the `analyzer/incremental/` package into `analyzer/`:

```text
analyzer/
  incremental/
    __init__.py
    models.py             # FileFingerprint, ConfigFingerprint, InvalidationReason, ImpactSet
    fingerprints.py       # Deterministic file hasher, canonical path normalizer
    config_fingerprint.py # Scoped semantic configuration fingerprint builder
    cache.py              # Abstract AnalysisCache, DiskAnalysisCache, InMemoryAnalysisCache
    keys.py               # Deterministic cache key derivation across L1–L9
    impact.py             # Reverse dependency, call-graph, and architecture impact analyzer
    contract_invalidation.py # Contract and security-boundary invalidation engine
    reconciliation.py     # Finding, metric, and graph reconciliation engine
    equivalence.py        # Equivalence checker (FULL vs INCREMENTAL comparator)
    coordinator.py        # IncrementalAnalysisCoordinator orchestrating execution
```

---

## 10. Cache Validity Contract

Every reusable artifact must have a deterministic representation of the inputs from which it was computed.

### 10.1 Formal Validity Equation
$$\text{ArtifactValidity} = \text{ContentFingerprint} + \text{DependencyFingerprint} + \text{ConfigurationFingerprint} + \text{AnalyzerVersion} + \text{SchemaVersion} + \text{RelevantRuleVersion}$$

For graph and contract artifacts, $\text{DependencyFingerprint}$ includes the resolved identities and contract hashes of all upstream callee functions and imported modules.

### 10.2 Cache Decision Semantics
- **Cache HIT**: All required inputs have been validated unchanged. The cached artifact is safely reused.
- **Cache MISS**: One or more required inputs have changed, are absent, or failed validation. The artifact must be recomputed.
- **UNKNOWN Dependency State**: If a module import, dynamic dispatch, or symbol reference cannot be statically resolved, it is treated as a **Cache MISS**.
- **Monotonic Safety Rule**: An `UNKNOWN` dependency state must **never** result in cache reuse.

---

## 11. Cache Dependency Graph & Layer Specifications

The analysis cache is structured into 9 conceptual layers directly mapped to the existing Phase 1–20 architecture:

```text
+-----------------------------------------------------------------------------------------------+
| L1: File & Source Fingerprints (path, content_hash, parser_version, size_bytes)               |
+-----------------------------------------------------------------------------------------------+
| L2: Normalized ParsedFile ASTs (symbols, imports, exports, parse errors)                      |
+-----------------------------------------------------------------------------------------------+
| L3: Resolved Dependency Graph (module-to-file mappings, TsConfig aliases, diagnostics)       |
+-----------------------------------------------------------------------------------------------+
| L4: Intraprocedural CFG & Basic Blocks (statements, guard edges, loop structure)              |
+-----------------------------------------------------------------------------------------------+
| L5: Local Data-Flow & Taint Traces (path states, points-to sets, field states)                |
+-----------------------------------------------------------------------------------------------+
| L6: Static Call Graph (resolved caller-callee edges, receiver types, contexts)                |
+-----------------------------------------------------------------------------------------------+
| L7: Function Contracts (preconditions, postconditions, exception contracts, taint effects)    |
+-----------------------------------------------------------------------------------------------+
| L8: Project Contract Composition (composition edges, conflict sets, security boundaries)      |
+-----------------------------------------------------------------------------------------------+
| L9: Reconciled Findings & Reports (security findings, architecture findings, health scores)   |
+-----------------------------------------------------------------------------------------------+
```

### Detailed Layer Specifications

| Layer | Exact Inputs | Cache Key Formulation | Invalidation Triggers | Reusable Outputs | Unknown Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **L1** | File bytes, canonical relative path, parser version | `repo_namespace_id:norm_path` | File content modification, deletion, rename | `FileFingerprint` | Re-read and re-hash file |
| **L2** | Raw content, parser version, parse configuration | `file_composite_hash:parse_cfg_hash` | L1 hash change, parser version bump | `ParsedFile` DTO, AST symbols | Re-parse source file |
| **L3** | `ParsedFile` imports, `tsconfig.json`, component depth | `repo_composite_hash:dep_cfg_hash` | Import added/removed, path alias changed | `DependencyResolver` state | Invalidate affected module closure |
| **L4** | Function AST node, CFG parameters, branch limits | `func_qn:func_ast_hash:cfg_cfg_hash` | Function body change, CFG budget change | `ControlFlowGraph`, basic blocks | Reconstruct function CFG |
| **L5** | CFG, guard settings, alias bounds, taint depth | `func_qn:l4_cfg_hash:dataflow_cfg_hash` | CFG invalidated, alias bounds modified | `PathState` tree, points-to sets | Re-explore path states |
| **L6** | Discovered functions, call sites, context $k$ | `repo_composite_hash:callgraph_cfg_hash` | Signature changed, call site added/removed | `CallGraph`, resolution stats | Invalidate affected call edges |
| **L7** | Function CFG, local data flow, summary config | `func_qn:contract_hash:contract_cfg_hash` | Function summary changed, contract bounds | `FunctionContract` DTO | Re-extract function contract |
| **L8** | Upstream contracts, downstream requirements | `producer_contract_hash:consumer_req_hash` | Upstream contract changed, boundary modified | `ContractCompositionEdge` | Recompose call edge |
| **L9** | Rule registry, active rules, composed graph | `findings_hash:rules_cfg_hash` | Rule enabled/disabled, finding inputs changed | Reconciled findings, health | Re-evaluate active rules |

---

## 12. File Fingerprinting

### 12.1 Canonical Model
In `analyzer/incremental/models.py`:

```python
class FileFingerprint(BaseModel):
    """Canonical fingerprint for a repository source file."""
    path: str = Field(..., description="Forward-slash normalized repository-relative path")
    content_hash: str = Field(..., description="SHA-256 hex digest of raw file contents")
    size_bytes: int = Field(..., ge=0, description="File size in bytes")
    language: str = Field(..., description="PYTHON, JAVASCRIPT, or TYPESCRIPT")
    parser_version: str = Field(default="1.0.0", description="Version of the language parser")
    analysis_schema_version: str = Field(default="1.0.0", description="Serialization schema version")

    def compute_composite_hash(self) -> str:
        """Hash combining content, language, parser, and schema versions."""
        payload = f"{self.path}:{self.content_hash}:{self.language}:{self.parser_version}:{self.analysis_schema_version}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

### 12.2 Normalization Rules
1. **Path Canonicalization**: All paths are converted to relative paths from repository root, formatted with forward slashes (`/`), and stripped of redundant `.` or `..` segments using `posixpath.normpath`. On Windows, casing is canonicalized against repository disk casing.
2. **Symlink Boundary Defense**: Symlinks pointing outside the repository root are strictly rejected (`OUTSIDE_REPO_BOUNDARY`). Symlink loops are detected via visited-inode sets and treated as invalid.
3. **Excluded & Ignored Files**: The existing [`IgnoreEngine`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/ingestion/ignore.py) is evaluated *before* fingerprinting. Ignored files (`.git`, `node_modules`, `__pycache__`, `.venv`, `.codesentinel_cache`) are never fingerprinted or cached.
4. **Generated Files**: Source files identified as generated (e.g. `min.js`, protobuf output) are fingerprinted with a `is_generated=True` attribute and skipped from deep CFG path exploration.
5. **Content Hashing Algorithm**: Cryptographic SHA-256 over raw binary content (`hashlib.sha256(file_bytes).hexdigest()`). Text line breaks are normalized to `\n` prior to hashing to avoid platform-specific CRLF vs LF ambiguities.

---

## 13. Scoped Analysis Configuration Fingerprinting

Rather than invalidating *all* caches when *any* setting changes, Phase 21 establishes **scoped configuration fingerprints** corresponding to specific pipeline layers:

```python
class ConfigFingerprint(BaseModel):
    """Scoped SHA-256 configuration digests governing specific cache layers."""
    global_hash: str                  # Entire normalized configuration
    parsing_hash: str                 # Parser & language settings
    dependency_hash: str              # max_component_depth, path exclusions
    cfg_dataflow_hash: str            # max_active_paths, max_total_path_states, branch_depth, alias settings
    callgraph_hash: str               # max_call_depth, max_k, context sensitivity, type inference
    contract_hash: str                # max_cached_contracts, max_effects_per_summary, field_effect_depth
    composition_hash: str             # max_contract_composition_depth, security boundary specs
    rules_hash: str                   # enabled_rules, disabled_rules, severity thresholds
    reporting_hash: str               # output format, report destination
```

### Layer Invalidation on Configuration Changes

| Configuration Alteration | Invalidated Cache Layers | Validated Reusable Layers |
| :--- | :--- | :--- |
| `reporting.format` or `output_file` | None (Reporting serialization only) | **L1–L8 validated cache reuse** |
| `rules.enabled_rules` / `disabled_rules` | L9 (Findings) | **L1–L8 validated cache reuse** (CFGs & contracts unaffected) |
| `max_component_depth` | L3 (Deps), L9 (Arch Findings) | **L1, L2, L4, L5, L6, L7, L8 validated reuse** |
| `max_active_paths` / `max_cfg_blocks` | L4 (CFG), L5 (Flows), L7 (Contracts), L8, L9 | **L1, L2, L3, L6 validated reuse** |
| `max_call_depth` / `max_k` | L6 (Call Graph), L7, L8, L9 | **L1, L2, L3, L4, L5 validated reuse** |
| `max_contract_composition_depth` | L8 (Composition), L9 (Findings) | **L1–L7 validated cache reuse** |

---

## 14. Architecture Impact & Centrality Invalidation

### 14.1 Architecture Invalidation Invariant
> **If the canonical module dependency inputs and component-classification inputs are unchanged, architecture artifacts MAY be reused after validating their cache fingerprints.**

An unchanged import list alone does not prove that every architecture artifact is reusable. The architecture cache key must account for:
- Canonical module path
- Import and dependency representation
- Component and layer classification
- Architecture configuration (`max_component_depth`, `centrality_threshold`, `god_module_loc`)
- Parser, schema, and analyzer versions
- Architecture rule configuration (`ARC-001` through `ARC-009`)

If component classification or directory structure changes, architecture artifacts must be invalidated even if raw imports did not change.

### 14.2 Centrality Reuse Semantics
In [`CentralityCalculator`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/architecture/centrality.py), betweenness centrality is computed across the entire directed component graph using shortest paths.

- **Degree Metrics**: In-degree and out-degree centralities may sometimes be updated locally when an edge is added or removed.
- **Betweenness Centrality (ARC-009)**: Depends on global graph topology. An edge modification anywhere along an active path can alter betweenness centralities across distant nodes.
- **Invariant**: **Any graph mutation that can alter shortest paths through the affected component region MUST invalidate the relevant betweenness-centrality computation.** If an incremental local update cannot be proven equivalent to full recomputation, recompute the affected centrality scope conservatively.

---

## 15. Security Rule Invalidation

Security rules fall into three categories with distinct invalidation boundaries:

1. **Intraprocedural AST Pattern Rules** (`SEC-PY-001`, `SEC-PY-006`, etc.):
   - Evaluated *only* on files in the validated directly-changed set. Untouched files reuse their L9 security findings after their file fingerprints remain valid.
2. **Intraprocedural Data-Flow Rules** (`SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`):
   - Evaluated *only* on functions whose CFG or local data flow was recomputed (L4/L5 cache miss).
3. **Interprocedural Taint & Contract Rules** (`SEC-PY-011`, `SEC-PY-012`, `SEC-JS-009`, `SEC-JS-010`):
   - Evaluated across call chains that intersect the affected analysis closure. Call chains where all functions, summaries, contracts, and sanitizers remain in valid L6/L7/L8 caches are preserved without re-tracing.

> **Operational Invariant**: The engine computes the minimum validated affected set. Any analysis whose semantic inputs are invalidated is recomputed; unaffected artifacts are reused only after their dependency fingerprints remain valid.

---

## 16. Contract-Aware Invalidation & Versioning

A function body change may invalidate its own AST rules, CFG, local data-flow, summary contract, callers depending on that summary, and security traces depending on those callers.

### 16.1 Conditional Caller Pruning
> **A caller may reuse a cached result after a callee body change only if the cached callee contract is proven equivalent under the active contract schema, configuration, rule set, analyzer version, and relevant type/alias/field semantics.**

The contract hash must be canonical and versioned:

$$\text{contract\_hash} = \text{SHA256}(\text{canonical\_contract} + \text{contract\_schema\_version} + \text{relevant\_config} + \text{analyzer\_version})$$

A raw function body hash must never be used as a substitute for contract equivalence.

---

## 17. Call Graph Versioning & Dispatch Safety

Phase 21 explicitly accounts for changes to:
- Module imports and re-exports
- Function and method definitions
- Parameter defaults and decorators
- Class inheritance and method overrides
- Receiver type annotations and aliases
- Dynamic and unresolved call sites

Any dependency change involving unresolved or dynamic dispatch must **conservatively invalidate the relevant caller/callee closure**. The engine never assumes a previous call graph remains valid merely because a changed function's body appears unchanged.

---

## 18. Finding Reconciliation & Identity Preservation

### 18.1 Finding Identity Formulation
The existing finding identity implementation remains unchanged:
- Security Rules: $\text{UUIDv5}(\text{NAMESPACE\_DNS}, \text{rule\_id} : \text{file\_path} : \text{line\_start} : \text{col\_start})$
- Interprocedural Rules: $\text{UUIDv5}(\text{NAMESPACE\_DNS}, \text{rule\_id} : \text{src\_call} : \text{sink\_call} : \text{src\_file} : \text{sink\_file} : \text{src\_line} : \text{sink\_line})$

> **The Phase 21 implementation does not modify the existing finding identity formulas. The identity mechanism remains unchanged; detection results may legitimately change when the repository or analysis configuration changes.**

### 18.2 Reconciliation States
1. **`REUSED`**: The previous finding is reused because its generating analysis artifact remains valid, its finding identity remains valid, its evidence remains valid, and its source location still maps to the current repository state.
2. **`RECOMPUTED`**: The finding's generating analysis was rerun and produced the same finding identity.
3. **`NEW`**: A finding appears in the current analysis but did not exist in the previous analysis.
4. **`RESOLVED`**: A previous finding is absent from the current valid analysis result.

> **Safety Rule**: A finding is **never** classified as `RESOLVED` merely because its file was not analyzed. An unvalidated cache state must never be interpreted as evidence that a finding disappeared.

---

## 19. Line-Shift Handling & Relocation Comparison

Because CodeSentinel's finding identity includes line coordinates, upstream code additions or deletions in a file can legitimately alter the line numbers of downstream code, causing the canonical UUIDv5 identity to change.

### Relocation Analysis
The equivalence engine distinguishes:
1. **True Finding Disappearance**: A defect was remediated or code was deleted.
2. **Finding Relocation**: The code moved, causing a line shift.
3. **Finding Identity Modification**: Upstream edits legitimately changed the UUIDv5 finding ID due to line shifts.
4. **Genuinely Missing Incremental Detection**: A defect present in full analysis was dropped by incremental analysis (P0 Soundness Defect).

The equivalence engine performs a canonical relocation comparison using:
- `rule_id`
- Normalized `file_path`
- Normalized `code_snippet` and `evidence`
- Nearby line proximity ($\pm 50$ lines)
- Finding `category` and `severity`

Relocated findings are reported separately from actual missing or phantom findings.

---

## 20. Full-vs-Incremental Equivalence Verification

### 20.1 Semantic Output Comparison
The equivalence verifier compares semantic output, not incidental serialization ordering:
- Canonical finding identities and relocation sets
- Rule IDs, severities, confidences, categories
- Normalized evidence payloads (whitespace condensed, dictionaries canonicalized)
- Architecture metrics (`total_modules`, `circular_cycles_count`, `god_modules_count`)
- Codebase health scores and letter grades (rounded to 2 decimal places)
- Contract composition summaries (composition edges, guarantees, requirements, conflicts)

### 20.2 Health Score Equivalence
`security_score`, `architecture_score`, `composite_score`, and `grade` must match according to existing Phase 7 scoring semantics. No new scoring formula is introduced in Phase 21.

---

## 21. Cache Safety, Corruption Handling & Atomic Writes

### 21.1 Fail-Safe Corruption Recovery
1. Checksums and content hashes are verified *before* deserialization is trusted.
2. Schema and version metadata are validated *before* payload parsing.
3. If corruption, truncation, or schema mismatch is detected:
   - The corrupted entry is treated as a **safe cache miss**.
   - Corrupted entries are **never** partially reused.
   - A diagnostic log is recorded.
   - The engine attempts eviction; if deletion fails, the entry is marked unusable for the active run.
   - Analysis falls back safely to fresh recomputation.

### 21.2 Atomic Write Protocol
- Cache writes write to a temporary file in the same cache directory: `<key>.tmp.<pid>.<uuid>`.
- The file is flushed and synced to disk before renaming.
- The temporary file is moved to `<key>.json` via atomic filesystem rename (`os.replace`).
- Concurrent writers are isolated via process-specific temporary filenames.
- Readers reject incomplete or invalid artifacts.

---

## 22. Repository Identity & Cache Isolation

To prevent cross-repository cache collisions, repository namespace identity is derived independently from transient Git commit state:

$$\text{repo\_namespace\_id} = \text{SHA256}(\text{Git Origin Remote URL} + \text{Initial Root Commit Hash})$$
$$\text{If Non-Git} \longrightarrow \text{SHA256}(\text{Canonical FileSystem RealPath})$$

The current commit HEAD is treated as `repository_state`, not repository namespace identity. External Git subprocess calls are not executed from `analyzer/` if doing so would violate offline isolation; existing safe Git metadata facilities from `analyzer/ingestion/git.py` are reused.

---

## 23. CLI Changes

Phase 21 introduces additive, backward-compatible options to [`analyzer/cli/main.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/cli/main.py):

```text
codesentinel analyze <path> [OPTIONS]

Incremental Analysis Options:
  --incremental             Opt into incremental analysis mode (default: disabled)
  --no-cache                Bypass cache reads and writes for the current run
  --cache-dir <DIR>         Override custom cache directory (default: <repo_root>/.codesentinel_cache)
  --clear-cache             Purge cached analysis artifacts for this repository and exit
  --cache-stats             Display detailed cache telemetry and storage metrics after analysis
  --verify-equivalence      Execute full analysis in parallel and verify equivalence (test/debug mode)
```

### Clarified Flag Semantics
- `--no-cache`: Bypasses reading from and writing to the cache for the active run; does *not* delete existing cache entries on disk.
- `--clear-cache`: Physically deletes the repository cache namespace directory and exits cleanly.

---

## 24. Cache Statistics & Telemetry

Cache telemetry explicitly differentiates between discovered files, actual reused artifacts, and cache misses:

```python
class IncrementalStatsDTO(BaseModel):
    """Detailed telemetry for incremental analysis execution."""
    analysis_mode: str = "incremental"
    files_discovered: int = 0
    files_reused: int = 0
    files_reanalyzed: int = 0
    ast_hits: int = 0
    ast_misses: int = 0
    cfg_hits: int = 0
    cfg_misses: int = 0
    graph_hits: int = 0
    graph_misses: int = 0
    contract_hits: int = 0
    contract_misses: int = 0
    finding_hits: int = 0
    finding_recomputed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    hit_ratio: float = 0.0
    estimated_time_saved_seconds: float = 0.0
    invalidations_by_reason: dict[str, int] = Field(default_factory=dict)
```

Estimated time saved is explicitly labeled as an **estimate based on measured execution data**, not a guaranteed value.

---

## 25. Background Job & Celery Worker Integration

- [`backend/app/workers/tasks.py`](file:///e:/AI-Workspace/projects/CodeSentinel/backend/app/workers/tasks.py) accepts `mode: "incremental"` in `job.configuration` (defaulting to `"full"`).
- **Cooperative Cancellation**: Evaluated across all incremental sub-stages (`FINGERPRINTING`, `IMPACT_ANALYSIS`, `CACHE_LOADING`, `REANALYZING`, `CONTRACT_RECOMPOSITION`, `FINDING_RECONCILIATION`, `REPORTING`). If `is_cancelled()` returns `True`, `AnalysisCancelledError` is raised immediately.

---

## 26. Frontend & Reporting Changes

### 26.1 Frontend Telemetry
- `⚡ Incremental` badge displayed in `AnalysisHeader.tsx`.
- Collapsible telemetry card rendering hits, misses, and estimated time saved.
- Tooltips explaining re-analysis reasons (e.g. *"Re-analyzed: Callee contract altered in `auth/validators.py`"*).

### 26.2 SARIF v2.1.0 Invariant
Incremental metadata is attached strictly to standard SARIF property bags (`properties.incremental`). The generated SARIF is validated against the official OASIS SARIF 2.1.0 schema via automated schema-validation tests.

---

## 27. Performance Benchmarks

Performance claims are formulated as **benchmark targets** to be evaluated on representative hardware:

| Benchmark Tier | Function Count | File Count | Target Full Analysis Duration | Target Incremental Duration (Leaf Change) | Measured Speedup Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1 (Small)** | 100 | ~25 | ~2.5s | Benchmark Target: Sub-second | ~5x–8x |
| **Tier 2 (Medium)** | 500 | ~100 | ~10.0s | Benchmark Target: Sub-2-second | ~8x–12x |
| **Tier 3 (Large)** | 1,000 | ~250 | ~28.0s | Benchmark Target: Sub-3-second | ~12x–18x |
| **Tier 4 (Enterprise)** | 5,000 | ~1,200 | ~140.0s | Benchmark Target: Sub-8-second | ~20x–30x |

Benchmark reports will document exact hardware, CPU architecture, OS, Python version, cold-cache runtime, warm-cache runtime, hit ratio, and affected artifact count.

---

## 28. Determinism Invariant

> **The analyzer targets deterministic output for identical repository content, configuration, analyzer/parser versions, and validated cache state.**

Determinism is enforced by:
- Sorting graph traversals (SCC, BFS, DFS) by canonical string identifiers.
- Canonicalizing dictionary key orders in JSON serialization.
- Normalizing line-ending line breaks prior to hashing.
- Verifying identical output across 5 consecutive incremental runs as a validation test.

---

## 29. Security Model

1. **Path Traversal Defense**: Cache keys map to filenames via cryptographic SHA-256 digests (`<hash>.json`), strictly preventing directory traversal (`../../etc/passwd`).
2. **Cache Poisoning Defense**: Embedded signature headers (`repo_id`, `schema_version`, `config_hash`) are validated before deserialization.
3. **Analyzer Isolation**: Pure Python library with zero network calls, zero dynamic execution, and zero imports of web or database frameworks.

---

## 30. Testing Strategy

### Test Suites
- **Regression Invariance**: All pre-existing test suites must pass without modification or weakening.
- **Unit Tests**:
  - `test_phase21_fingerprints.py`: Hashing, path normalization, CRLF handling, symlink rejection.
  - `test_phase21_config_fingerprint.py`: Scoped config hashing, order independence, versioning.
  - `test_phase21_cache_storage.py`: Disk read/write, atomic rename, corrupt entry recovery, eviction.
  - `test_phase21_impact_closure.py`: Reverse dependency graphs, transitive chains, cycle handling.
  - `test_phase21_contract_invalidation.py`: Body-only vs contract change propagation, security boundary invalidation.
- **Integration Tests**:
  - `test_phase21_equivalence.py`: Defined acceptance test corpus verifying canonical output equivalence between full and incremental runs.
  - `test_phase21_determinism.py`: 5-run identical output verification.
  - `test_phase21_cli.py`: CLI flags (`--incremental`, `--cache-dir`, `--cache-stats`, `--clear-cache`).
  - `test_phase21_api_backward_compat.py`: API DTO verification and backend backward compatibility.

---

## 31. End-to-End Scenarios

### Scenario A — Leaf Function Change
- **Setup**: `controller -> service -> repository`. Modify internal formatting of a helper function.
- **Verification**: Callee contract is validated identical under `compute_hash()`; callers are pruned from re-analysis. Only the helper is re-analyzed. Findings match full analysis.

### Scenario B — Contract Change Across Multi-Hop Call Chain
- **Setup**:
  $$\text{request arg} \to \text{validator param} \to \text{validator return} \to \text{service param} \to \text{repo param} \to \text{SQL sink}$$
  Modify validator to remove sanitization cast.
- **Verification**: Invalidation engine preserves argument and return bindings. Validator contract is invalidated; service and repository contract compositions are recomputed; `SEC-PY-011` SQL injection finding surfaces identically to full analysis.

### Scenario C — Deep Dependency Closure
- **Setup**: `A -> B -> C -> D -> E`. Modify file `E.py`.
- **Verification**: Reverse impact closure deterministically identifies `E`, `D`, `C`, `B`, `A`. Unrelated modules `X -> Y` remain cached.

### Scenario D — Architecture-Only Change
- **Setup**: Add an import creating a `DOMAIN -> INFRASTRUCTURE` layer violation.
- **Verification**: Module dependency graph and component graph are updated; `ARC-001` layer violation finding generated; unrelated CFG and data-flow artifacts remain reused after their dependency fingerprints remain valid.

### Scenario E — Security Boundary Change
- **Setup**: In `SEC-PY-012`, change sanitizer from shell-escape to HTML-escape.
- **Verification**: Security boundary matrix enforces:
  $$\text{HTML escaping} \ne \text{SQL sanitization} \ne \text{shell escaping}$$
  Command injection finding generated without invalidating unrelated SQL or XSS rules.

### Scenario F — File Rename
- **Setup**: Rename `old_service.py` to `new_service.py`.
- **Verification**: `old_service.py` findings retired; `new_service.py` analyzed; dependency edges updated cleanly.

### Scenario G — File Deletion
- **Setup**: Delete `deprecated_helper.py`.
- **Verification**: Findings in deleted file marked `RESOLVED`. Importers of helper flagged with `UNRESOLVED` dependency diagnostics.

### Scenario H — Configuration Change
- **Setup**: Modify `max_call_depth` from 5 to 8.
- **Verification**: Only cache layers that depend on `max_call_depth` (L6, L7, L8, L9) are invalidated; L1, L2, L3, L4, L5 remain reused.

### Scenario I — Rule Enable / Disable
- **Setup**: Disable rule `SEC-PY-006`.
- **Verification**: L1–L8 analysis artifacts remain reused; L9 findings regenerated with `SEC-PY-006` filtered out.

### Scenario J — Schema / Parser Version Bump
- **Setup**: Increment `analysis_schema_version`.
- **Verification**: Incompatible cache entries rejected gracefully; fresh full analysis executed and new cache written.

### Scenario K — Corrupted Cache Entry
- **Setup**: Manually truncate a cached JSON file to 5 bytes.
- **Verification**: Safe cache miss recorded; corruption diagnostic logged; unit recomputed freshly without crashing.

### Scenario L — Full-vs-Incremental Equivalence
- **Setup**: Execute acceptance corpus across defined mutation categories.
- **Verification**: Canonical incremental results match canonical full-analysis results under relocation-aware comparison.

---

## 32. Cache Eviction & Bounded Storage

- **Configurable Defaults**:
  - `max_cache_size_bytes`: Default `524,288,000` (500MB) per repository namespace.
  - `max_entries`: Default `50,000` entries across all layers.
- **Eviction Order**: Least Recently Used (LRU) based on file access metadata recorded in an internal `manifest.json`.
- **Eviction Failure Handling**: If an entry cannot be deleted due to file lock or OS permissions, it is marked as unvalidated in the active memory manifest so it is never reused.
- **Write Overhead Note**: Temporary files during atomic write may temporarily cause disk usage to slightly exceed the quota before rename and cleanup.

---

## 33. Documentation Plan

1. `docs/ARCHITECTURE.md`: Document incremental analysis orchestration and cache layers.
2. `docs/TRD.md`: Document cache keys, invalidation algorithms, and storage policies.
3. `docs/API.md`: Document `incremental_stats` DTO and `--incremental` parameters.
4. `docs/CI_CD.md`: Provide example CI guidance for using incremental analysis to reduce repeated work, explaining runtime dependency factors.
5. `README.md`: Update CLI usage guide.

---

## 34. Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Phantom / Missing Findings** | High (Soundness loss) | Automated equivalence verification test suite gating CI; conservative fallback on unknown dependencies. |
| **Cache Bloat on Disk** | Medium (Disk exhaustion) | Configurable LRU eviction policy with default 500MB bound per repository. |
| **Cross-Repository Collisions** | High (Data leakage) | Content-addressed `repo_namespace_id` incorporating Git origin or root commit hash. |
| **Stale Dynamic Imports** | Medium (False negatives) | Dynamic imports flagged as `UNRESOLVED` trigger conservative component-wide invalidation. |
| **Filesystem Symlink Attacks** | High (Security vulnerability) | Canonical realpath resolution and strict rejection of paths escaping repository root. |

---

## 35. Compatibility

- **Python Compatibility**: Python 3.10, 3.11, 3.12, 3.13, 3.14.
- **Operating Systems**: Linux, macOS, Windows (forward-slash canonicalization and symlink privilege handling).
- **Backward Compatibility**: All Phase 1–20 CLI invocations and backend API payloads continue to function identically with `--incremental` defaulting to disabled (opt-in).

---

## 36. Implementation Stages

### Stage 21.0: Repository Compatibility Audit (Plan-Only)
- **Objective**: Audit actual Phase 1–20 implementations to verify API shapes, class names, and dependencies prior to coding.
- **Audit Matrix**:

| Existing Subsystem | Actual Implementation File | Phase 21 Dependency | Reuse Strategy | Required Change |
| :--- | :--- | :--- | :--- | :--- |
| **Ingestion & Discovery** | [`analyzer/ingestion/discovery.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/ingestion/discovery.py) | File discovery & IgnoreEngine | Reuse discovery & ignore engine | None (use existing `DiscoveredFileMetadata`) |
| **Parsing** | [`analyzer/parsing/`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/parsing) | Language parsers (`PythonParser`, etc.) | Cache normalized `ParsedFile` DTOs | Add gzip serialization for L2 cache |
| **Dependency Resolution** | [`analyzer/dependencies/resolver.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dependencies/resolver.py) | `DependencyResolver`, `TsConfigResolver` | Cache module resolution snapshot | Add reverse graph inversion helper |
| **Architecture Graph** | [`analyzer/architecture/graph_builder.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/architecture/graph_builder.py) | `ArchitectureGraphBuilder`, `CentralityCalculator` | Recompute betweenness on topology change | Scoped centrality invalidation |
| **Call Graph** | [`analyzer/dataflow/callgraph/graph_builder.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/callgraph/graph_builder.py) | `CallGraphBuilder`, `FunctionDefinition` | Cache function nodes & call edges | Add function change kind classification |
| **CFG & Path Engine** | [`analyzer/dataflow/cfg/path_explorer.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/cfg/path_explorer.py) | `PathExplorer`, `ControlFlowGraph` | Cache function CFGs by body AST hash | Function-scoped CFG serialization |
| **Contracts & Composition** | [`analyzer/dataflow/contracts/composer.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/contracts/composer.py) | `ContractComposer`, `FunctionContract` | Prune callers when contract unchanged | Add canonical versioned contract hash |
| **Security Boundaries** | [`analyzer/dataflow/contracts/security_boundary.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/dataflow/contracts/security_boundary.py) | `SECURITY_BOUNDARY_SPECS` | Rule-specific boundary checking | Isolate boundary changes to affected sinks |
| **Rule Engine** | [`analyzer/rules/engine.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/rules/engine.py) | `RuleEngine`, `deduplicate_findings` | Target re-analysis to affected set | Add reconciliation engine integration |
| **Baseline Diff** | [`analyzer/comparison/diff.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/comparison/diff.py) | `BaselineComparator` | Untouched | None (preserve 100% untouched) |
| **Backend Persistence** | [`backend/app/models/snapshot.py`](file:///e:/AI-Workspace/projects/CodeSentinel/backend/app/models/snapshot.py) | `AnalysisSnapshot.call_graph_summary` | Store incremental stats in JSON column | Zero database migrations |
| **Background Tasks** | [`backend/app/workers/tasks.py`](file:///e:/AI-Workspace/projects/CodeSentinel/backend/app/workers/tasks.py) | Celery task `run_analysis_task` | Cooperative cancellation integration | Pass `mode: "incremental"` to pipeline |

### Stage 21.1: Core Fingerprinting & Configuration Scoping
- **Objective**: Implement deterministic file fingerprinting and scoped configuration hashing.
- **Files Affected**: `analyzer/incremental/models.py`, `analyzer/incremental/fingerprints.py`, `analyzer/incremental/config_fingerprint.py`.
- **Dependencies**: Existing `analyzer/config/repo_config.py`.
- **Details**: Implement `FileFingerprint`, `ConfigFingerprint`, path canonicalization, and SHA-256 binary hashing.
- **Unknown Behavior**: Missing file or unreadable path triggers error diagnostic.
- **Tests**: `analyzer/tests/test_phase21_fingerprints.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_fingerprints.py`.
- **Expected Result**: 100% pass on file hashing, CRLF normalization, and config digest tests.
- **Rollback Consideration**: Purely additive new modules; zero impact on existing code.

### Stage 21.2: Persistent & In-Memory Layered Cache Architecture
- **Objective**: Implement abstract cache interface and disk-backed atomic storage.
- **Files Affected**: `analyzer/incremental/cache.py`, `analyzer/incremental/keys.py`.
- **Dependencies**: Stage 21.1.
- **Details**: Implement `AnalysisCache`, `DiskAnalysisCache`, `InMemoryAnalysisCache`, atomic temporary file rename, and corruption recovery.
- **Unknown Behavior**: Corrupted or missing entry returns `None` (cache miss).
- **Tests**: `analyzer/tests/test_phase21_cache_storage.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_cache_storage.py`.
- **Expected Result**: Clean disk roundtrip, atomic writes, and fail-safe recovery on corrupted JSON.
- **Rollback Consideration**: Revert `analyzer/incremental/cache.py`.

### Stage 21.3: Reverse Dependency & Call-Graph Impact Analysis
- **Objective**: Implement reverse dependency closure and call-graph invalidation engine.
- **Files Affected**: `analyzer/incremental/impact.py`.
- **Dependencies**: Stages 21.1, 21.2, existing `analyzer/dependencies/resolver.py`.
- **Details**: Compute reverse dependency closures, classify function changes (`BODY_CHANGED_ONLY` vs `SIGNATURE_CHANGED`), and isolate unaffected subgraphs.
- **Unknown Behavior**: Dynamic imports or unresolved calls trigger conservative component invalidation.
- **Tests**: `analyzer/tests/test_phase21_impact_closure.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_impact_closure.py`.
- **Expected Result**: Exact reverse closures computed across deep dependency chains and circular cycles.
- **Rollback Consideration**: Isolated in `analyzer/incremental/impact.py`.

### Stage 21.4: Contract-Aware & Security-Boundary Invalidation
- **Objective**: Implement contract-level invalidation pruning and boundary tracking.
- **Files Affected**: `analyzer/incremental/contract_invalidation.py`.
- **Dependencies**: Stage 21.3, existing `analyzer/dataflow/contracts/models.py`.
- **Details**: Compare canonical versioned contract hashes to prune invalidation of callers when contracts are identical; propagate invalidations when contracts change.
- **Unknown Behavior**: Unresolved contracts or conflicting guarantees trigger re-analysis of callers.
- **Tests**: `analyzer/tests/test_phase21_contract_invalidation.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_contract_invalidation.py`.
- **Expected Result**: Callers pruned when callee body changes but contract is identical; callers invalidated when contract changes.
- **Rollback Consideration**: Revert `contract_invalidation.py`.

### Stage 21.5: Incremental Pipeline Orchestrator & Artifact Reuse
- **Objective**: Wire incremental orchestration into `AnalysisPipeline`.
- **Files Affected**: `analyzer/incremental/coordinator.py`, `analyzer/engine/pipeline.py`.
- **Dependencies**: Stages 21.1–21.4.
- **Details**: Coordinate cache checks, target affected units, reuse L1–L8 cached artifacts, and execute targeted analysis.
- **Unknown Behavior**: Any failure during incremental orchestration falls back to full analysis.
- **Tests**: `analyzer/tests/test_phase21_pipeline_integration.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_pipeline_integration.py`.
- **Expected Result**: End-to-end execution reusing unchanged ASTs and CFGs.
- **Rollback Consideration**: Keep full analysis as default fallback in `AnalysisPipeline`.

### Stage 21.6: Finding Reconciliation & Equivalence Verification
- **Objective**: Implement finding reconciliation and the equivalence testing engine.
- **Files Affected**: `analyzer/incremental/reconciliation.py`, `analyzer/incremental/equivalence.py`.
- **Dependencies**: Stage 21.5.
- **Details**: Reconcile reused and newly surfaced findings using existing UUIDv5 identity formulas; assert canonical output equivalence with relocation comparison.
- **Unknown Behavior**: Unvalidated finding candidates trigger re-evaluation.
- **Tests**: `analyzer/tests/test_phase21_equivalence.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_equivalence.py`.
- **Expected Result**: 0 discrepancies between full and incremental results across acceptance test corpus.
- **Rollback Consideration**: Revert `reconciliation.py`.

### Stage 21.7: CLI Integration & Cache Administration
- **Objective**: Add `--incremental`, `--cache-dir`, `--no-cache`, `--clear-cache`, and `--cache-stats` to CLI.
- **Files Affected**: `analyzer/cli/main.py`, `analyzer/reporting/terminal.py`.
- **Dependencies**: Stage 21.6.
- **Details**: Parse CLI flags, wire into `AnalysisPipeline`, and render incremental telemetry in terminal output.
- **Unknown Behavior**: Invalid cache directory path raises clean CLI error.
- **Tests**: `analyzer/tests/test_phase21_cli.py`.
- **Verification Command**: `uv run pytest analyzer/tests/test_phase21_cli.py`.
- **Expected Result**: CLI flags operate as expected with full backward compatibility.
- **Rollback Consideration**: Remove CLI arguments.

### Stage 21.8: Backend API & Celery Worker Integration
- **Objective**: Integrate incremental mode into FastAPI endpoints and Celery background tasks.
- **Files Affected**: `backend/app/schemas/analysis.py`, `backend/app/workers/tasks.py`, `backend/app/api/endpoints/analysis.py`.
- **Dependencies**: Stage 21.7.
- **Details**: Accept `mode: "incremental"` in `AnalysisRequest`, serialize `IncrementalStatsDTO`, and maintain cooperative cancellation.
- **Unknown Behavior**: Unrecognized mode defaults to `"full"`.
- **Tests**: `backend/tests/test_phase21_api_backward_compat.py`.
- **Verification Command**: `uv run pytest backend/tests/test_phase21_api_backward_compat.py`.
- **Expected Result**: Backend endpoints accept incremental requests and return stats with 0 migration requirements.
- **Rollback Consideration**: Defaults to `mode: "full"`.

### Stage 21.9: Frontend Telemetry & Invalidation Explainability UI
- **Objective**: Expose incremental mode, cache telemetry, and invalidation reasons in the UI.
- **Files Affected**: `frontend/src/types/api.ts`, `frontend/src/components/dashboard/AnalysisHeader.tsx`, `frontend/src/components/findings/FindingDetail.tsx`.
- **Dependencies**: Stage 21.8.
- **Details**: Add `IncrementalStatsDTO` TypeScript interface, incremental badge chip, and re-analysis reason tooltips.
- **Unknown Behavior**: Missing incremental stats gracefully omitted in UI.
- **Tests**: `npm run build` in `frontend/`.
- **Verification Command**: `npm run build`.
- **Expected Result**: 0 TypeScript errors; bundle builds cleanly.
- **Rollback Consideration**: Revert UI components.

### Stage 21.10: Performance Benchmarking, Multi-Run Determinism & Final Verification
- **Objective**: Execute comprehensive performance benchmarks and 5-run determinism verification.
- **Files Affected**: `analyzer/tests/test_phase21_benchmarks.py`, `analyzer/tests/test_phase21_determinism.py`.
- **Dependencies**: Stages 21.0–21.9.
- **Details**: Benchmark across Tiers 1–4, verify 5-run determinism, and run full repository test suite.
- **Unknown Behavior**: Any non-deterministic output fails the gate.
- **Tests**: Full test suite (`pytest analyzer/tests backend/tests`).
- **Verification Command**: `uv run pytest analyzer/tests backend/tests`.
- **Expected Result**: All pre-existing and Phase 21 targeted tests pass with zero regressions.
- **Rollback Consideration**: N/A.

---

## 37. Completion Gates

Phase 21 is considered complete if and only if all 8 completion gates are satisfied:

1. **Gate 1 — Regression Safety**: All pre-existing test suites pass without modification or weakening.
2. **Gate 2 — Incremental Equivalence**: All defined equivalence mutation scenarios pass under canonical comparison.
3. **Gate 3 — Finding Identity Compatibility**: The existing finding identity implementation and [`analyzer/comparison/diff.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/comparison/diff.py) remain 100% untouched.
4. **Gate 4 — Analyzer Isolation**: Zero imports of FastAPI, SQLAlchemy, PostgreSQL, Celery, Redis, or AI SDKs enter `analyzer/`.
5. **Gate 5 — Cache Safety**: Corrupt, stale, mismatched, or untrusted cache entries become safe misses and trigger clean recomputation.
6. **Gate 6 — Determinism**: Repeated runs under identical validated inputs produce identical canonical outputs.
7. **Gate 7 — Frontend Compatibility**: Production frontend build (`npm run build`) completes with 0 errors and 0 diagnostics.
8. **Gate 8 — Measured Performance**: Incremental analysis demonstrates measurable performance improvement on the benchmark corpus without compromising equivalence.

---

## 38. Final Acceptance Checklist

Prior to signing off on Phase 21:

1. [ ] `FileFingerprint` and `ConfigFingerprint` models implemented with SHA-256 digests.
2. [ ] Layered analysis cache (L1–L9) operational with bounded disk storage and LRU eviction.
3. [ ] Reverse dependency closure algorithm handles direct, multi-hop, and circular module graphs.
4. [ ] Contract-aware invalidation prunes caller re-analysis when callee body changes but contract hash is validated identical.
5. [ ] Security boundary matrix invalidation isolates affected sinks without invalidating unrelated rules.
6. [ ] Finding reconciliation accurately classifies `REUSED`, `RECOMPUTED`, `NEW`, and `RESOLVED` findings.
7. [ ] CLI supports `--incremental`, `--cache-dir`, `--no-cache`, `--clear-cache`, and `--cache-stats`.
8. [ ] Celery background task honors cooperative cancellation across all incremental sub-stages.
9. [ ] Backend API returns `IncrementalStatsDTO` without requiring database migrations.
10. [ ] Frontend displays incremental badge and invalidation explainability tooltips.
11. [ ] Benchmark suite validates measurable speedups on incremental runs across small, medium, and large repositories.
12. [ ] Deterministic serialization verified across 5 consecutive runs.
13. [ ] Generated SARIF v2.1.0 validated against official OASIS schema.
14. [ ] Documentation updated across `docs/ARCHITECTURE.md`, `docs/TRD.md`, `docs/API.md`, `docs/CI_CD.md`, and `README.md`.
