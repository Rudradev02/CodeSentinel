# CodeSentinel — System Architecture Document

## 1. High-Level Architecture Overview

CodeSentinel employs a decoupled, modular architecture designed for high determinism, clear boundary isolation, and explainable AI enrichment.

```mermaid
graph TB
    subgraph ClientLayer ["Client Layer"]
        ReactDashboard["React Dashboard (Vite + TypeScript)"]
        MonacoEditor["Monaco Code Viewer"]
        ReactFlowView["React Flow Architecture Canvas"]
    end

    subgraph APILayer ["Backend Orchestration Layer (FastAPI)"]
        APIRouter["API Router (/api/v1)"]
        HealthEndpoint["/health & /api/v1/health"]
        OrchestrationService["Analysis Orchestrator"]
        LLMOrchestrator["AI Context & Enrichment Service"]
        DBLayer["SQLAlchemy 2.0 Async ORM"]
    end

    subgraph WorkerLayer ["Asynchronous Job Workers (Celery)"]
        CeleryWorker["Celery Worker Pool"]
        JobScheduler["Task Queue & Status Manager"]
    end

    subgraph DataStorage ["Data & Message Infrastructure"]
        PostgreSQL[("PostgreSQL 16\n(Persisted Audits, Findings, Graphs)")]
        RedisQueue[("Redis 7\n(Broker & Result Backend)")]
    end

    subgraph StandaloneAnalyzer ["Independent Analyzer Engine (analyzer/)"]
        IngestionEngine["Ingestion & Discovery"]
        LangDetector["Language & Framework Detector"]
        ASTParsers["AST Parsers (Python, JS/TS)"]
        DepGraphEngine["Dependency Graph Engine (NetworkX)"]
        SecurityEngine["Deterministic & Heuristic Security Rules"]
        ArchEngine["Architecture Metric Engine"]
        PipelineAggregator["Pipeline Orchestrator -> AnalysisResult"]
    end

    subgraph AIProviders ["External / Local AI Providers"]
        OpenRouter["OpenRouter (Claude, GPT-4o)"]
        OllamaLocal["Ollama (Local Models)"]
    end

    %% Interactions
    ReactDashboard -->|HTTP / JSON| APIRouter
    APIRouter --> HealthEndpoint
    APIRouter --> OrchestrationService
    OrchestrationService --> DBLayer
    OrchestrationService -->|Enqueue Job| RedisQueue
    RedisQueue --> CeleryWorker
    CeleryWorker -->|Invoke Pipeline| StandaloneAnalyzer
    CeleryWorker -->|Store Result| DBLayer
    CeleryWorker -->|Request Enrichment| LLMOrchestrator
    LLMOrchestrator --> OpenRouter
    LLMOrchestrator --> OllamaLocal
    DBLayer --> PostgreSQL
```

---

## 2. Core Separation Principle

A primary design constraint is that **`analyzer/` is completely decoupled from `backend/`**:

```
                       ┌──────────────────────┐
                       │  Source Code Files   │
                       └──────────┬───────────┘
                                  │
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                        analyzer/ Package                         │
 │                                                                  │
 │   1. Ingestion: scan directory, filter ignored paths             │
 │   2. Detection: classify languages and frameworks                │
 │   3. Parsing: generate ASTs (Python `ast`, JS/TS AST)            │
 │   4. Graphing: extract imports, compute cycles, fan-in/fan-out   │
 │   5. Rules: run deterministic & heuristic rules                  │
 │   6. Aggregator: produce strongly typed `AnalysisResult`         │
 └────────────────────────────────┬─────────────────────────────────┘
                                  │ AnalysisResult (Pydantic)
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                        backend/ Package                          │
 │                                                                  │
 │   1. Orchestrator calls analyzer in background worker            │
 │   2. Persists entities into PostgreSQL relational tables         │
 │   3. Selectively extracts code snippets for flagged findings     │
 │   4. Calls AI provider with bounded context for validation/patch │
 │   5. Exposes REST API for React frontend                         │
 └──────────────────────────────────────────────────────────────────┘
```

The analyzer does not know about databases, HTTP requests, web frameworks, or workers. This guarantees:
- Analyzer can be unit tested without starting servers or mocking DB connections.
- Analyzer can be distributed as a standalone CLI tool or integrated into CI/CD pipelines directly.
- Backend API bugs cannot corrupt analysis pipeline logic.

---

## 3. Analysis Pipeline Stages & Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Dashboard
    participant API as FastAPI Backend
    participant Worker as Celery Task Worker
    participant Analyzer as Standalone Analyzer Engine
    participant AI as AI Provider (OpenRouter/Ollama)
    participant DB as PostgreSQL

    User->>API: POST /api/v1/analyses (target_path)
    API->>DB: Create Analysis Record (status=PENDING)
    API->>Worker: Enqueue analyze_repository_task
    API-->>User: 202 Accepted (analysis_id)

    Worker->>DB: Update status=IN_PROGRESS
    Worker->>Analyzer: Execute Pipeline(target_path)
    Analyzer->>Analyzer: Ingestion & File Discovery
    Analyzer->>Analyzer: Language & Framework Detection
    Analyzer->>Analyzer: AST Parsing & Symbol Extraction
    Analyzer->>Analyzer: Build Dependency Graph & Detect Cycles
    Analyzer->>Analyzer: Evaluate Security Rules
    Analyzer->>Analyzer: Evaluate Architecture Rules
    Analyzer-->>Worker: Return AnalysisResult

    Worker->>DB: Save Findings, Graph Topology, Metrics

    opt If AI Enrichment Enabled
        loop For Each Candidate Finding
            Worker->>AI: Send Bounded Context (AST snippet + Imports)
            AI-->>Worker: Return JSON Validation & Remediation Patch
            Worker->>DB: Save AIFindingEnrichment
        end
    end

    Worker->>DB: Update status=COMPLETED
    User->>API: GET /api/v1/analyses/{analysis_id}
    API->>DB: Query Analysis with Findings & Graph
    API-->>User: 200 OK (Enriched Analysis View)
```

---

## 4. Finding Classification Taxonomy

All findings generated by the system belong to one of three explicit evidence categories:

| Category | Description | Primary Evidence Source | Authority Level |
| :--- | :--- | :--- | :--- |
| **Deterministic** | Syntactically verified rule matches. Conditions are absolute (e.g. `shell=True` flag, `eval()` invocation). | AST node visitor match. | Authoritative; verified code defect or insecure configuration. |
| **Heuristic** | Contextual pattern matches where risk varies based on execution path or data source (e.g. potential raw SQL, high coupling). | AST pattern + lexical heuristic. | Advisory; flagged for developer review. |
| **AI-Assisted** | Contextual explanations, false-positive evaluations, and code remediation patches generated by LLM. | Bounded AST context + prompt. | Non-authoritative suggestion; requires developer approval. |

---

## 5. State Machine & Lifecycle of an Analysis Job

```mermaid
stateDiagram-v2
    [*] --> PENDING: Job Created via API
    PENDING --> IN_PROGRESS: Picked up by Worker
    IN_PROGRESS --> PARSING: Ingestion & AST Extraction
    PARSING --> GRAPHING: Dependency Graph Construction
    GRAPHING --> RULE_EVALUATION: Security & Architecture Rules
    RULE_EVALUATION --> AI_ENRICHING: (Optional) Contextual LLM Validation
    AI_ENRICHING --> COMPLETED: Persisted & Finalized
    RULE_EVALUATION --> COMPLETED: (If AI disabled) Finalized
    IN_PROGRESS --> FAILED: Unhandled Pipeline Exception
    PARSING --> FAILED: Ingestion Error
    RULE_EVALUATION --> FAILED: Worker Timeout / Crash
    COMPLETED --> [*]
    FAILED --> [*]
```

---

## 6. Implementation Status (Phase 1 vs Future)

- **Phase 1 (Current)**:
  - Repository structure and specification docs.
  - Analyzer core interfaces, typed models (`findings.py`, `graph.py`, `results.py`), and base rule classes.
  - Backend FastAPI initialization, configuration via `pydantic-settings`, structured logging, and `/health` + `/api/v1/health` endpoints.
  - Frontend Vite + React + TypeScript setup with API client and health connection.
  - Infrastructure templates (`docker-compose.yml`, `.env.example`, `.gitignore`).
- **Phase 2 (Next)**: Language detection, AST parsers for Python/JS/TS, and dependency graph construction.
- **Phase 3**: Implementation of initial security and architecture rule catalogs.
- **Phase 4**: Celery task workers, SQLAlchemy models, and PostgreSQL persistence.
- **Phase 5**: AI context extraction pipeline and OpenRouter/Ollama providers.
- **Phase 6**: React Flow dependency visualization, Monaco code viewer, and full interactive dashboard.
