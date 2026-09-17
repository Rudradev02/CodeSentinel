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

## Phase 2: Ingestion, Detection, AST Parsers & Dependency Graph
- [ ] Implement file ingestion crawler with gitignore and binary filtering (`analyzer/ingestion/collector.py`).
- [ ] Implement language and framework detector for Python, JS, TS, Django, Flask, React (`analyzer/detection/detector.py`).
- [ ] Implement Python AST parser and visitor for imports and symbol extraction (`analyzer/parsers/python/parser.py`).
- [ ] Implement JavaScript & TypeScript AST parser using robust parser/visitor abstractions (`analyzer/parsers/javascript/`, `analyzer/parsers/typescript/`).
- [ ] Implement dependency graph builder using NetworkX (`analyzer/dependencies/graph.py`).
- [ ] Implement cycle detection (Tarjan SCC) and coupling metric calculations (fan-in, fan-out).
- [ ] Add comprehensive unit test suite for ingestion, parsing, and graph construction.

---

## Phase 3: Deterministic & Heuristic Rule Catalog
- [ ] Implement Python/Django/Flask security rules (`SEC-PY-001` through `SEC-PY-008`).
- [ ] Implement JavaScript/TypeScript/React security rules (`SEC-JS-001` through `SEC-JS-006`).
- [ ] Implement architecture anti-pattern rules:
  - Circular dependencies detection.
  - Excessive fan-out / unstable modules.
  - Oversized "god modules" / large component detection.
  - Deeply nested dependency chains.
- [ ] Create dedicated test fixtures and positive/negative test cases for every security and architecture rule.

---

## Phase 4: Backend Orchestration, PostgreSQL & Celery Workers
- [ ] Define async SQLAlchemy 2.0 ORM models corresponding to `docs/DATABASE.md`.
- [ ] Set up Alembic migration environment and baseline schema migration.
- [ ] Implement Celery worker application (`backend/app/workers/celery_app.py`) with Redis broker.
- [ ] Build analysis orchestration service to execute analyzer pipeline asynchronously and stream progress.
- [ ] Implement repository management endpoints (`POST /api/v1/repositories`, `POST /api/v1/analyses`).
- [ ] Implement finding and architecture query endpoints with filtering and pagination.

---

## Phase 5: AI Context & Remediation Pipeline
- [ ] Implement AST context window extractor (enclosing block, imports, callers) with token budgeting.
- [ ] Implement token and secret scrubber to redact sensitive tokens before external transmission.
- [ ] Implement `BaseLLMProvider` abstraction.
- [ ] Implement `OpenRouterProvider` for commercial frontier models (Claude, GPT-4o).
- [ ] Implement `OllamaProvider` for local/offline execution (DeepSeek Coder, Qwen).
- [ ] Build JSON schema validation and retry logic for LLM responses.

---

## Phase 6: Frontend Interactive Dashboard & Visualizations
- [ ] Build repository overview dashboard with risk scoring and language breakdown.
- [ ] Implement interactive Architecture Graph canvas using `@xyflow/react` (React Flow) with cycle highlights.
- [ ] Implement code viewer and diff inspector using `@monaco-editor/react`.
- [ ] Build finding details drawer with deterministic evidence display, AI explanations, and diff applicator.
- [ ] Implement real-time analysis progress tracker.

---

## Phase 7: Production Hardening & Release
- [ ] Dockerfile optimization with multi-stage production builds for backend and frontend.
- [ ] End-to-end integration tests on real-world open-source repositories.
- [ ] Performance benchmarking (sub-30s static analysis on 500+ file projects).
- [ ] Production security review, rate limiting, and RBAC authentication options.
- [ ] Official release documentation and CLI binary packaging.
