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

## Phase 14: Longitudinal Trend Intelligence, Developer Tooling & Reporting (PLANNED)
- [ ] Multi-snapshot longitudinal health drift and vulnerability trend analytics.
- [ ] Central repository configuration file (`.codesentinel.yml`).
- [ ] Pre-commit hook integration (`.pre-commit-hooks.yaml`).
- [ ] Standalone HTML executive report generator, JUnit XML, and GitLab SAST report formats.
