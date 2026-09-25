# CodeSentinel — Project Roadmap

## Phase 1: Foundation, Architecture & Core Interfaces (CURRENT)
- [x] Complete technical specifications and documentation suite (`PRD`, `TRD`, `ARCHITECTURE`, `DATABASE`, `API_SPEC`, `SECURITY_RULES`, `AI_PIPELINE`, `ROADMAP`, `README`).
- [x] Establish decoupled repository layout (`analyzer/`, `backend/`, `frontend/`, `docs/`).
- [x] Implement independent `analyzer` package with typed Pydantic models (`findings.py`, `graph.py`, `results.py`) and abstract rule interfaces.
- [x] Implement FastAPI backend configuration (`pydantic-settings`), structured logging, and health check endpoints (`/health`, `/api/v1/health`).
- [x] Implement buildable React 19 + TypeScript + Vite frontend scaffold with API client connection.
- [x] Configure infrastructure manifests (`docker-compose.yml`, `.env.example`, `.gitignore`).
- [x] Verify test suites and build checks for analyzer, backend, and frontend.

---

## Phase 2: Ingestion, Detection, AST Parsers & Dependency Graph (COMPLETE)
- [x] Implement file ingestion crawler with gitignore, sentinelignore, and binary filtering (`analyzer/ingestion/`).
- [x] Implement deterministic language and evidence-based framework detector for Python, JS, TS, Django, Flask, React (`analyzer/detection/`).
- [x] Implement Python AST parser and visitor for imports and symbol extraction (`analyzer/parsing/python_parser.py`).
- [x] Implement JavaScript & TypeScript syntax tree parser using Tree-sitter (`analyzer/parsing/javascript_parser.py`, `analyzer/parsing/typescript_parser.py`).
- [x] Implement dependency resolver for local and external module resolution (`analyzer/dependencies/resolver.py`).
- [x] Implement architecture graph builder using NetworkX (`analyzer/architecture/graph_builder.py`).
- [x] Implement cycle detection and coupling metric calculations (`analyzer/architecture/metrics.py`).
- [x] Implement unified AnalysisPipeline orchestrator and canonical AnalysisResult serialization (`analyzer/engine/pipeline.py`).
- [x] Create multi-language test fixture repository (`analyzer/tests/fixtures/sample_project/`).
- [x] Add comprehensive test suite for ingestion, detection, parsing, dependencies, graph, and pipeline.

---

## Phase 3: Deterministic & Heuristic Rule Catalog
- [x] Implement Python/Django/Flask security rules (`SEC-PY-001` through `SEC-PY-008`).
- [x] Implement JavaScript/TypeScript/React security rules (`SEC-JS-001` through `SEC-JS-006`).
- [x] Implement architecture anti-pattern rules:
  - `ARC-001`: Circular dependencies detection.
  - `ARC-002`: Excessive fan-out / unstable modules.
  - `ARC-003`: Oversized "god modules" / structural coupling smell.
  - `ARC-004`: Deeply nested dependency chains (via safe SCC condensation).
- [x] Implement central `RuleEngine` and `RuleRegistry` with language and framework applicability filters.
- [x] Create dedicated test fixtures and positive/negative test cases for every security and architecture rule (71 passing tests).
- [x] Integrate Rule Engine into `AnalysisPipeline` with deterministic UUIDv5 finding IDs and stable ordering.

---

## Phase 4: CLI, Reporting, Configuration & Analysis Quality (COMPLETE)
- [x] Implement standalone CLI entry point (`codesentinel`) using stdlib `argparse` with `analyze <path>` and ergonomic shortcuts.
- [x] Implement `AnalysisConfig` schema with whitelist (`--enable-rule`) and blacklist (`--disable-rule`) semantics, and conflict ambiguity rejection.
- [x] Implement separation of concerns between configuration model data validation and `RuleRegistry` boundary rule ID validation.
- [x] Implement dynamic architectural threshold overrides (`--god-module-loc`, fan-out, fan-in, depth).
- [x] Implement Terminal Reporter with KPI metrics, architecture graph metrics, detailed finding breakdowns, and circular dependency paths.
- [x] Implement JSON Reporter with canonical structure, deterministically pre-sorted collections, and normalized cyclic module rotations.
- [x] Implement policy threshold enforcement (`--fail-on`) with exit code 2 when any finding meets or exceeds severity threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- [x] Implement safe empty repository and unsupported-only repository handling (clean zero-file result, exit code 0).
- [x] Build comprehensive automated test suite (105 passing tests in 1.3s) covering configuration, CLI flags, exit codes, edge cases, and repeated-run determinism.

---

## Phase 5: Finding Quality, Explainability, Precision & CLI Rule Inspection (COMPLETE)
- [x] Extend `SourceLocation` to allow optional end coordinates (`line_end=None`, `col_end=None`) and coordinate aliases (`file`, `start_line`, `start_column`, `end_line`, `end_column`).
- [x] Extend `Finding` model with `message`, `explanation`, structured `evidence` dictionary, `file`, and `title` properties while preserving backward compatibility.
- [x] Decouple Severity (impact) and Confidence (static evidence strength; no ML/exploitability claims).
- [x] Extend `RuleDefinition` and `RuleRegistry` with authoritative metadata (`rationale`, `supported_languages`, CWE, OWASP, frameworks).
- [x] Implement structured evidence payloads across all 18 registered security and architecture rules.
- [x] Implement deterministic secret redaction helper (`redact_secret()`) for `SEC-PY-001` and `SEC-JS-004` (masking sensitive credentials in evidence, snippets, terminal, and JSON).
- [x] Implement deterministic finding deduplication in `RuleEngine` across `(rule_id, file_path, line_start, col_start, normalized_evidence)` while preserving distinct findings on same lines.
- [x] Implement CLI rule inspection subsystem (`codesentinel rules` list mode, `codesentinel rules <RULE_ID>` detail mode) with `--format terminal` and `--format json`, rejecting unknown rules with exit code 1.
- [x] Update Terminal and JSON reporters to output messages, explanations, locations, and structured evidence.
- [x] Verify dependency classification semantics (`LOCAL`, `EXTERNAL`, `STDLIB`, `UNRESOLVED`).
- [x] Document heuristic architectural limitations (especially `ARC-003`) and static analysis boundaries.
- [x] Add 26 new comprehensive Phase 5 tests (131 total analyzer tests passing in ~3.2s).

---

## Phase 6: Dependency Resolution, Architecture Intelligence & Analysis Coverage (COMPLETE)
- [x] Enhanced Python dependency resolution: `src/` layout auto-detection, `from foo import bar` submodule file resolution, accurate multi-level relative import traversal.
- [x] Strict `UNRESOLVED` enforcement: relative imports that fail resolution are never silently classified as `EXTERNAL`.
- [x] Enhanced JavaScript/TypeScript resolution: extended extension probing (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`), directory index file resolution, parent directory traversal.
- [x] Static path alias resolution via `tsconfig.json` / `jsconfig.json`: `compilerOptions.baseUrl` and `compilerOptions.paths` mapping (e.g., `"@/*": ["src/*"]`).
- [x] Re-export module specifier extraction in JS/TS parsers (`export { x } from './x'`, `export * from './module'`).
- [x] Strictly repository-local architecture graph: no fabricated external nodes. External/stdlib/unresolved deps preserved on `DependencyEdge` objects.
- [x] Enriched `CouplingMetrics`: `local_dependencies_count`, `stdlib_dependencies_count`, `external_dependencies_count`, `unresolved_dependencies_count`, `connected_components_count`, `strongly_connected_components_count`.
- [x] Structured `DependencyDiagnostic` model on `AnalysisResult.dependency_diagnostics` explaining resolution failures.
- [x] Explicit `followlinks=False` enforcement in `os.walk` for repository boundary isolation.
- [x] Terminal and JSON reporters updated for enriched metrics and diagnostics.
- [x] 50 new Phase 6 tests (181 total analyzer tests passing in ~3.7s).

---

## Phase 7: Component Layering, Architectural Boundary Enforcement & Codebase Health Scoring (COMPLETE)
- [x] Subsystem and package ComponentGraph abstraction (`ComponentGraph`, `ComponentNode`, `ComponentEdge`, `PackageMetrics`) with configurable depth collapsing (`--max-component-depth`, default: 2) and package boundary awareness (`__init__.py`, `index.ts`).
- [x] Robert C. Martin package coupling metrics: Afferent Coupling ($C_a$), Efferent Coupling ($C_e$), and Instability ($I = C_e / (C_a + C_e)$) strictly counting distinct other repository components.
- [x] Architectural tier classification: heuristic and explicit mapping of components to canonical layers (`PRESENTATION`, `APPLICATION`, `DOMAIN`, `INFRASTRUCTURE`, `UTILITY`).
- [x] New Architecture Rule `ARC-005`: Layer Boundary Inversion detecting prohibited downward-to-upward architectural flows (`INFRASTRUCTURE -> PRESENTATION`, `DOMAIN -> INFRASTRUCTURE`, etc.).
- [x] New Architecture Rule `ARC-006`: Component Circular Dependency Group detecting multi-component cycles via Strongly Connected Components (SCC) with canonical component sorting and deterministic UUIDv5 finding IDs.
- [x] New Architecture Rule `ARC-007`: Stable Dependencies Principle (SDP) violation detecting stable components ($I \le 0.30, C_a \ge 2$) depending on volatile components ($I \ge 0.70$).
- [x] New Architecture Rule `ARC-008`: Potentially Orphaned Export conservative dead-export scanner with entry-point exemptions and whole-module import suppression.
- [x] Deterministic Codebase Health Scoring engine (`HealthScoreCalculator`, `CodebaseHealth`, `SubScore`, `ScoreDeduction`):
  - Single-deduction architecture preventing double-counting.
  - Transparent point deduction audit logs allowing exact mathematical reconstruction ($100 - \sum \text{points} = \text{score}$).
  - Composite health score weighting (55% Security Posture + 45% Architecture Health) clamped to $[0.0, 100.0]$.
  - Letter grade thresholds (A: 90-100, B: 80-89, C: 70-79, D: 60-69, F: <60).
- [x] Terminal and JSON reporters updated with executive Codebase Health Grade badges, risk deduction breakdowns, and subsystem component graph summaries.
- [x] 25 new automated unit, integration, and determinism tests (206 total passing tests).

---

## Phase 8: Developer API Boundary & Interactive React Dashboard (COMPLETE)
- [x] Implement local developer FastAPI service (`POST /api/v1/analyze`, `GET /api/v1/rules`, `GET /api/v1/rules/{rule_id}`).
- [x] Implement local filesystem security boundary with canonical path resolution, directory validation, root drive rejection, and system directory protection.
- [x] Build interactive React 19 + TypeScript + Vite dashboard with Tailwind CSS.
- [x] Implement Health & Overview executive KPI cards and deduction breakdown table.
- [x] Implement Findings Explorer with cumulative severity filtering and Monaco Editor (`@monaco-editor/react`) code evidence viewer.
- [x] Implement interactive Component Architecture Graph canvas using React Flow (`@xyflow/react`) with circular cycle highlights.
- [x] Implement cumulative CLI filtering (`--severity`, `--category`, `--rule`).
- [x] Verify complete stack locally with zero database or background worker dependencies.

---

## Phase 9: CI/CD Automation, Baseline Differential Analysis & OASIS SARIF Standards (COMPLETE)
- [x] Implement safe Git provenance metadata extraction without network calls (`analyzer/ingestion/git.py`).
- [x] Implement native OASIS SARIF v2.1.0 reporting (`--format sarif`) compatible with GitHub Code Scanning, GitLab SAST, and Azure DevOps.
- [x] Implement deterministic baseline differential comparator (`BaselineComparator`) tracking `NEW`, `RESOLVED`, `UNCHANGED`, and `MODIFIED` findings, health deltas, and component graph changes.
- [x] Implement PR regression policy gating (`--fail-on-regression [SEVERITY]`) with exit code 2.
- [x] Implement differential CLI commands (`codesentinel compare`, `codesentinel analyze --baseline`).
- [x] Implement differential API endpoint (`POST /api/v1/compare`).
- [x] Build interactive "Baseline & Diff" explorer tab in React dashboard with drag-and-drop comparison.
- [x] Automated test suite expanded to 244 passed, 1 skipped (0 failures).

---

## Phase 10: Persistent Analysis Storage, Repository Catalog & Immutable Snapshots (COMPLETE)
- [x] Define relational schema using Async SQLAlchemy 2.0 (`Repository`, `AnalysisSnapshot`, `FindingSnapshot`, `HealthDeductionSnapshot`, `ComponentSnapshot`, `ComponentEdgeSnapshot`).
- [x] Version and execute schema migrations with Alembic (`0001_phase10_initial_schema.py`).
- [x] Implement `RepositoryStore` with path security verification and eager relationship loading.
- [x] Implement `PersistenceService` with secret redaction (`_sanitize_snippet`), atomic transaction snapshot persistence, and full-fidelity canonical reconstruction (`reconstruct_analysis_dto`).
- [x] Implement repository catalog REST API endpoints:
  - `POST /api/v1/repositories` (register repository)
  - `GET /api/v1/repositories` (list registered repositories)
  - `GET /api/v1/repositories/{id}` (repository details)
  - `DELETE /api/v1/repositories/{id}` (unregister & cascade delete)
  - `POST /api/v1/repositories/{id}/analyses` (run synchronous analysis & persist immutable snapshot)
  - `POST /api/v1/repositories/{id}/snapshots` (ingest snapshot from CLI)
  - `GET /api/v1/repositories/{id}/analyses` (list historical snapshot summaries)
  - `GET /api/v1/repositories/{id}/analyses/{analysis_id}` (get reconstructed historical snapshot enforcing repository isolation)
- [x] Extend CLI with `--save` and `--api-url` using stdlib `urllib` only; keep offline mode 100% database-free.
- [x] Build Frontend repository selector dropdown, repository registration modal, and paginated historical analysis timeline viewer.
- [x] Reconstruct historical snapshots into Monaco code viewer and React Flow canvas with read-only indicators.
- [x] Verify strict architectural decoupling: AST verification proves zero database/backend imports in `analyzer/`.
- [x] Automated test suite expanded to 259 passed, 1 skipped (0 regressions).

---

## Phase 11: Asynchronous Task Orchestration, Distributed Workers & Scalability (COMPLETE)
- [x] Celery worker application with Redis broker and result backend (`celery_app.py`, `celery_config.py`).
- [x] Asynchronous analysis endpoint `POST /api/v1/repositories/{id}/analyses` returning `202 Accepted` with `AnalysisJobDTO`.
- [x] Server-Sent Events (SSE) progress streaming (`GET /api/v1/jobs/{id}/stream`) with initial PostgreSQL state and live Redis pub/sub events.
- [x] Worker task execution using dedicated synchronous database sessions (`sync_session.py`, `psycopg2-binary`) without `asyncio.run()` event loop conflicts.
- [x] Cooperative cancellation protocol (`POST /api/v1/jobs/{id}/cancel`) using Redis flags and pipeline boundary checks.
- [x] Analyzer progress callback protocol (`on_progress`, `is_cancelled`) with zero infrastructure imports in `analyzer/`.
- [x] Redis analysis cache service with Git commit SHA and config hashing (`AnalysisCacheService`).
- [x] Real-time frontend progress bar, stage indicator, and interactive cancel button (`useJobProgress.ts`, `LoadingState.tsx`).
- [x] Automated test suite expanded to 279 passed, 1 skipped (0 regressions).

---

## Phase 12: Bounded Context AI Enrichment, Validation & Remediation Engine (COMPLETE)
- [x] Bounded AST context window extraction with strict 2,048-token budget and AST scope narrowing (`ContextBuilder`).
- [x] Zero-trust secret scrubber redacting cloud credentials, database URLs, auth headers, and private keys prior to AI transmission (`SecretScrubber`).
- [x] Pluggable LLM provider abstraction supporting OpenRouter (Claude, GPT-4o) and local Ollama instances (`BaseLLMProvider`, `OpenRouterProvider`, `OllamaProvider`).
- [x] Adversarial injection-quarantined prompt construction (`prompts.py`).
- [x] Post-generation semantic validator and diff security checker rejecting path traversal, malformed diffs, or leaked secrets (`SemanticValidator`).
- [x] Advisory-only false-positive triage validation and minimal unified diff remediation synthesis (`AIEnrichmentOrchestrator`).
- [x] Persistent database models (`AIEnrichmentRecord`) and Alembic migration (`0003_phase12_ai_enrichment.py`).
- [x] Asynchronous background enrichment queuing via Celery (`ai_tasks.py`, dedicated queue: `ai_enrichment`).
- [x] REST API endpoints (`POST /api/v1/repositories/{id}/analyses/{analysis_id}/findings/{finding_id}/enrich`, `GET /api/v1/repositories/{id}/analyses/{analysis_id}/findings/{finding_id}/enrichment`).
- [x] Interactive React triage slide-over drawer with true/false-positive verdicts, confidence meters, risk assessments, and side-by-side Monaco diff viewer (`FindingDetailDrawer.tsx`, `DiffPatchViewer.tsx`).
- [x] Automated test suite expanded to 303 passed, 1 skipped across all 304 tests (0 regressions).

---

## Phase 13: Advanced Static Analysis, Intraprocedural Data-Flow & Taint Tracking (COMPLETE)
- [x] Intraprocedural source-to-sink taint propagation engine with lattice merge (`analyzer/dataflow/taint/`).
- [x] Symbol scope tracking, lexical shadowing, and deterministic scope trees (`analyzer/dataflow/symbol.py`).
- [x] Native Python AST and Tree-sitter JS/TS intraprocedural data-flow visitors (`python_visitor.py`, `js_visitor.py`).
- [x] Advanced data-flow security rules (`SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`).
- [x] Component graph centrality calculation (Betweenness, In-degree, Out-degree) and `ARC-009` mediation hotspot rule.
- [x] SARIF v2.1.0 `codeFlows` and `threadFlows` execution path traces.
- [x] Backend snapshot centrality persistence and Alembic migration `0004_phase13`.
- [x] Frontend `TaintTraceViewer` step-by-step breadcrumb viewer and component centrality metrics visualization.

---

## Phase 14: Longitudinal Trend Intelligence, Developer Tooling & Reporting (COMPLETE)
- [x] Declarative repository configuration (`.codesentinel.yml` / `.codesentinel.json`) with Pydantic validation, safe directory scoping, and SHA-256 integrity hash tracking (`RepoConfig`, `load_repo_config`).
- [x] Three-tier configuration precedence engine (CLI Arguments > Repository Config > Built-in Defaults).
- [x] Pre-commit hook definition (`.pre-commit-hooks.yaml`) providing entrypoints for local scan gating and baseline differential checks.
- [x] Multi-target enterprise reporting formatters:
  - PR Review Markdown (`MarkdownReporter` / `--format markdown`) with findings tables, baseline comparison matrices, and collapsible rule details.
  - Standalone zero-external-CDN interactive HTML report (`HTMLReporter` / `--format html`) with embedded dark theme CSS, SVG visualizations, and instant client-side severity filtering.
  - Standard xUnit/JUnit XML (`JUnitReporter` / `--format junit`) for seamless CI/CD test suite integration.
  - GitLab Code Quality JSON (`GitLabReporter` / `--format gitlab`) matching `gl-code-quality-report.json` schema.
- [x] Database migration `0005_phase14_trend_indexes.py` establishing composite timeline indexes for rapid time-series analysis (`ix_snapshots_repo_created`, `ix_snapshots_repo_branch_created`).
- [x] Longitudinal Trend Service (`TrendService.get_repository_trends()`) computing historical health trajectory $H(t)$, defect churn/velocity (new vs. resolved), severity volume, and component instability drift $\Delta I(c)$.
- [x] Read-only REST API endpoint `GET /api/v1/repositories/{id}/trends` with branch filtering and strict repository isolation.
- [x] Frontend Longitudinal Trend Dashboard (`TrendsView.tsx`) with pure React SVG chart components (`HealthTrajectoryChart`, `DefectVelocityChart`, `SeverityVolumeChart`, `ComponentDriftCard`) mounted as a 5th navigation tab.
- [x] Automated test suite expanded to 359 passed, 1 skipped across repository (271 analyzer, 88 backend, 0 regressions).

---

## Phase 15: Interprocedural Data-Flow Analysis, Call Graph Intelligence & Cross-Function Taint Propagation (COMPLETE)
- [x] Deterministic static call graph models (`FunctionDefinition`, `CallEdge`, `CallGraph`, `FunctionSummary`, `InterproceduralTaintPath`).
- [x] Repository-wide function discovery with AST parsing for Python and Tree-sitter for JS/TS (`discovery.py`).
- [x] Multi-resolution call resolver for local functions, module imports, class methods, and dynamic calls (`resolver.py`).
- [x] Resource-bounded call graph builder with recursion detection and cycle resolution (`graph_builder.py`).
- [x] Bounded function summary generation with parameter taint transfer and sink/sanitizer tracking (`summarizer.py`).
- [x] Interprocedural taint propagator tracking multi-hop call chains with depth and complexity bounds (`propagator.py`).
- [x] Four new interprocedural security rules:
  - `SEC-PY-011`: Cross-Function SQL Injection (Python)
  - `SEC-PY-012`: Cross-Function Subprocess / Command Injection (Python)
  - `SEC-JS-009`: Cross-Function DOM-Based Cross-Site Scripting (JS/TS)
  - `SEC-JS-010`: Cross-Function Code Injection / Eval (JS/TS)
- [x] Pipeline integration (`CALL_GRAPH` and `INTER_PROCEDURAL` stages) and CLI flags (`--max-call-depth`, `--disable-interprocedural`).
- [x] Multi-file SARIF v2.1.0 `codeFlows` cross-function execution traces and comprehensive reporter extensions (Terminal, Markdown, HTML, JUnit).
- [x] Persistence & database migration `0006_phase15` (nullable `call_graph_summary` column on `analysis_snapshots`).
- [x] Read-only API endpoint `GET /api/v1/repositories/{id}/analyses/{analysis_id}/callgraph` with repository boundary isolation.
- [x] Frontend `InterproceduralTraceViewer.tsx` multi-file call chain timeline component integrated into `MonacoViewer.tsx`.
- [x] Zero regressions across entire test suite, expanding coverage to 405 passing tests, 1 skipped.

---

## Phase 16: Bounded Context-Sensitive & Type-Aware Static Analysis (COMPLETE)
- [x] Conservative type inference models (`TypeConfidence`, `TypeOrigin`, `ConstantBool`, `TypeBinding`, `CallContext`, `TypeEnvironment`) (`analyzer/dataflow/types/models.py`).
- [x] Local Python AST type extractor resolving constructors, annotations, parameters, aliases, and `self.db = db` field assignments with step caps (`analyzer/dataflow/types/python_type_extractor.py`).
- [x] Local JS/TS Tree-sitter type extractor resolving constructors, type annotations, and local bindings (`analyzer/dataflow/types/jsts_type_extractor.py`).
- [x] Type-aware receiver call resolver with candidate sorting and ambiguous receiver detection (`analyzer/dataflow/callgraph/type_resolver.py`).
- [x] Call-string context sensitivity manager with $k$-limiting ($k \le 2$), context widening, and constant-aware boolean branch condition evaluator (`analyzer/dataflow/callgraph/context_manager.py`).
- [x] Contextual function summarizer with branch pruning and SCC fixed-point iteration cap (`analyzer/dataflow/callgraph/context_summarizer.py`).
- [x] Integrated interprocedural taint propagator with receiver dispatch, context stack, recursion guards, and method parameter offset alignment (`analyzer/dataflow/interprocedural/propagator.py`).
- [x] Pipeline integration, configuration schema extension (`RepoConfig`, `AnalysisConfig`), and CLI flags (`--disable-type-inference`, `--disable-context-sensitivity`, `--max-k`, `--max-contexts-per-function`, `--max-summary-iterations`).
- [x] Multi-file SARIF v2.1.0 `codeFlows` enrichment with `properties.typeConfidence`, `properties.contextId`, and `properties.receiverType`.
- [x] Terminal and Markdown reporter enhancements with Type & Context Precision metrics and step badges.
- [x] Zero-migration backend schema extension (`TypeResolutionSummaryDTO`, `ContextSensitivitySummaryDTO`) and API snapshot backward compatibility.
- [x] Frontend `InterproceduralTraceViewer.tsx` receiver type and context badge visualization with graceful degradation.
- [x] Full test suite coverage across 11 end-to-end scenarios (A through K) and zero regressions across all Phase 1–15 tests.

---

## Phase 17: Bounded Alias, Points-To & Field-Sensitive Data-Flow Analysis (COMPLETE)
- [x] Bounded points-to set models (`AbstractObject`, `AllocationSite`, `FieldKey`, `AliasBinding`, `AliasEnvironment`, `PointsToSet`) with candidate cap ($k \le 4$), widening lattice, and deterministic allocation site hashing.
- [x] Flow-sensitive field tracking engine (`FieldStateMap`) with strong updates on singleton receivers, conservative weak updates on ambiguous receivers, and branch merge joins.
- [x] Python AST alias and field extractor resolving constructors, object copies, attribute assignments, and branch splits (`python_alias_extractor.py`).
- [x] JavaScript/TypeScript Tree-sitter alias and field extractor resolving `new` expressions, member assignments, and `else_clause` unwrapping (`jsts_alias_extractor.py`).
- [x] Integrated interprocedural taint propagator with receiver alias lookup, field-sensitive parameter transfer, and taint clearance on non-tainted overwrites (`propagator.py`).
- [x] Configuration & CLI options (`--disable-alias-analysis`, `--disable-field-sensitivity`, `--max-points-to-candidates`, `--max-fields-per-object`, `--max-objects-per-function`, `--max-alias-iterations`).
- [x] SARIF v2.1.0 evidence property bags (`aliasPath`, `fieldPath`, `allocationSite`) and enriched Terminal and Markdown report summaries.
- [x] Backend DTO backward compatibility (`AliasAnalysisSummaryDTO`) without requiring database migrations.
- [x] Frontend `InterproceduralTraceViewer.tsx` interactive badges (`Alias:`, `Field:`, `Alloc:`) and alias-resolved pills.
- [x] 33 new Phase 17 automated unit and integration tests; 100% test pass rate across complete test suite (474 tests passed).

---

## Phase 18: Bounded Path-Sensitive Control-Flow & Guard Analysis (COMPLETE)
- [x] Intraprocedural Control-Flow Graph (CFG) models with basic blocks, early exits (`return`, `raise`, `throw`, `assert`), loop edges (`LOOP_BACK`, `LOOP_EXIT`), and statement-level exception handling (`try/except/finally`) (`analyzer/dataflow/cfg/models.py`).
- [x] AST-driven Python CFG builder with leader detection, branch splitting, and cooperative cancellation checkpoints (`python_cfg_builder.py`).
- [x] Tree-sitter JS/TS CFG builder with statement block traversal, `else_clause` unwrapping, try/catch/finally routing, and loop exit edges (`jsts_cfg_builder.py`).
- [x] Propositional guard evaluator evaluating `isinstance`, `isdigit`, anchored regex, registered validators, nullity checks, and boolean `AND`/`OR`/`NOT` decompositions (`guard_evaluator.py`).
- [x] Rule-specific sink precondition reasoning via `RefinementFact`s (type, format, nullity, category sanitizers) decoupled from global taint states.
- [x] Bounded path explorer with active path bounding ($k \le 8$), state limits ($128$), contradiction pruning (`INFEASIBLE`), loop budget enforcement, and monotonic lattice state joins (`path_explorer.py`).
- [x] Integrated intraprocedural visitors (`python_visitor.py`, `js_visitor.py`) with statement-level early-exit pruning and branch-sensitive refinement intersection.
- [x] Interprocedural path propagation in `InterproceduralTaintPropagator` with path conditions, branch direction badges, and caller guard evaluation against callee sinks.
- [x] Configuration options (`AnalysisConfig`, `RepoConfig`) and CLI flags (`--disable-path-sensitivity`, `--disable-guard-analysis`, `--max-active-paths`, `--max-total-path-states`, `--max-branch-depth`, `--max-conditions-per-path`, `--max-cfg-blocks`).
- [x] SARIF v2.1.0 `codeFlows` enrichment (`pathCondition`, `branchTaken`, `guardPredicate`, `pathStatus`) and enhanced Terminal and Markdown reports.
- [x] Zero-migration backend DTO extension (`PathSensitivitySummaryDTO` on `CallGraphSummaryDTO`) with full backward compatibility.
- [x] Frontend `InterproceduralTraceViewer.tsx` guard badges, branch indicators, path conditions, and `Path-Guarded` chips.
- [x] 48 new automated Phase 18 unit, reporter, CLI, and end-to-end integration tests; 100% test pass rate across complete test suite (522 tests passed).

---

## Phase 19: Path-Sensitive Interprocedural Contracts, Function Summaries & Cross-Function Guard/Taint Reasoning (COMPLETE)
- [x] Path-sensitive function contract models (`FunctionContract`, `SummaryPrecondition`, `SummaryPostcondition`, `ConditionalTaintEffect`, `ContractVerificationStatus`, `PreconditionKind`, `PostconditionTrigger`, `EffectKind`) with deterministic SHA-256 contract hashing (`analyzer/dataflow/contracts/models.py`).
- [x] Intraprocedural contract extractor for Python AST and Tree-sitter JS/TS resolving return-correlated refinements (`if isinstance(x, int): return True`), conditional taint/sanitizer effects (`shlex.quote(x) if sanitize else x`), and field mutation contracts (`analyzer/dataflow/contracts/extractor.py`).
- [x] Contract evaluation engine with caller-side precondition verification, postcondition binding, and path-condition composition (`analyzer/dataflow/contracts/evaluator.py`).
- [x] Context-sensitive contract caching in `ContextSummaryManager` indexed by semantic signature, literal arguments, boolean flags, receiver type, and caller path conditions ($k \le 2$).
- [x] Deep interprocedural propagation in `InterproceduralTaintPropagator` with multi-hop contract application, callee precondition discharge, and conditional effect preservation.
- [x] Strict safety invariant preservation: `UNKNOWN != SAFE`, `WIDENED != SAFE`, `TRUNCATED != SAFE`, `UNRESOLVED != SAFE`.
- [x] Configuration options (`AnalysisConfig`, `RepoConfig`) and CLI flags (`--disable-interprocedural-contracts`, `--max-summary-iterations`, `--max-cached-contracts`, `--max-effects-per-summary`, `--max-field-effect-depth`).
- [x] Enriched SARIF v2.1.0 `codeFlows` reporting with contract property bags (`properties.contractStatus`, `properties.contractEffect`, `properties.preconditionKind`, `properties.contractId`).
- [x] Terminal and Markdown reporter enhancements with Contract Intelligence KPI tables, verification statistics, and step badges.
- [x] Zero-migration backend DTO extension (`ContractSummaryDTO` on `CallGraphSummaryDTO`) with full backward compatibility for historical snapshots.
- [x] Frontend `InterproceduralTraceViewer.tsx` contract badges (`Contract:`, `Effect:`, `Precond:`) and verified contract chips with graceful degradation.
- [x] 39 new Phase 19 automated unit, extraction, evaluation, integration, CLI, reporter, and API backward-compatibility tests; 100% test pass rate across complete test suite (561 tests passed).

---

## Phase 20: Enterprise Compliance & Governance Rule Packs (PLANNED)
- [ ] PCI-DSS v4.0, HIPAA, SOC 2, and NIST SP 800-53 automated compliance mapping and rule catalogs.
- [ ] Audit trail generation and cryptographically verifiable scan attestations.
- [ ] Automated regulatory compliance reporting in PDF, Excel, and CycloneDX formats.

