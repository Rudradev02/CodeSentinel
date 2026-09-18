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

## Phase 7: Backend Orchestration, PostgreSQL & Celery Workers
- [ ] Define async SQLAlchemy 2.0 ORM models corresponding to `docs/DATABASE.md`.
- [ ] Set up Alembic migration environment and baseline schema migration.
- [ ] Implement Celery worker application (`backend/app/workers/celery_app.py`) with Redis broker.
- [ ] Build analysis orchestration service to execute analyzer pipeline asynchronously and stream progress.
- [ ] Implement repository management endpoints (`POST /api/v1/repositories`, `POST /api/v1/analyses`).
- [ ] Implement finding and architecture query endpoints with filtering and pagination.

---

## Phase 8: AI Context & Remediation Pipeline
- [ ] Implement AST context window extractor (enclosing block, imports, callers) with token budgeting.
- [ ] Implement token and secret scrubber to redact sensitive tokens before external transmission.
- [ ] Implement `BaseLLMProvider` abstraction.
- [ ] Implement `OpenRouterProvider` for commercial frontier models (Claude, GPT-4o).
- [ ] Implement `OllamaProvider` for local/offline execution (DeepSeek Coder, Qwen).
- [ ] Build JSON schema validation and retry logic for LLM responses.

---

## Phase 9: Frontend Interactive Dashboard & Visualizations
- [ ] Build repository overview dashboard with risk scoring and language breakdown.
- [ ] Implement interactive Architecture Graph canvas using `@xyflow/react` (React Flow) with cycle highlights.
- [ ] Implement code viewer and diff inspector using `@monaco-editor/react`.
- [ ] Build finding details drawer with deterministic evidence display, AI explanations, and diff applicator.
- [ ] Implement real-time analysis progress tracker.

---

## Phase 10: Production Hardening & Release
- [ ] Dockerfile optimization with multi-stage production builds for backend and frontend.
- [ ] End-to-end integration tests on real-world open-source repositories.
- [ ] Performance benchmarking (sub-30s static analysis on 500+ file projects).
- [ ] Production security review, rate limiting, and RBAC authentication options.
- [ ] Official release documentation and CLI binary packaging.
