# CodeSentinel Local Developer API Reference (Phase 10)

> **Important Deployment Notice**:  
> The CodeSentinel API is designed and intended strictly for **local development and local workstation execution**.  
> The API binds by default to `127.0.0.1` and accepts local filesystem paths. It **MUST NOT** be exposed directly to the public internet or deployed as an unauthenticated multi-user public service.

---

## 1. Overview & Guarantees

CodeSentinel is an offline, deterministic static analysis engine auditing codebases for architectural smells and security vulnerabilities.

### Phase 10 Architectural Invariants & Guarantees
- **Localhost Developer Scope**: Operates in local workstation environments.
- **Strictly Offline & Static**: Zero runtime execution of analyzed code, zero dynamic imports, zero external network queries, zero subprocesses in the analyzer.
- **Persistent Storage & Repository Catalog**: Relational persistence in PostgreSQL 16 (or local SQLite during lightweight/testing runs) via Async SQLAlchemy 2.0 and Alembic migrations.
- **Immutable Historical Snapshots**: Every persisted analysis is recorded as an immutable snapshot. Analyses are never mutated or overwritten in place; historical runs remain accessible permanently.
- **Repository Isolation**: All snapshot and analysis queries enforce strict repository ownership boundaries (`repository_id` scoping).
- **Deterministic**: Semantically identical canonical analysis results for identical repository contents and configuration.
- **Standard HTTP Error Statuses**: Uses HTTP 200, 201, 204, 400, 403, 404, 422, and 500 with a structured error envelope.

---

## 2. Base URLs & Service Discovery

| Service | Address | Description |
| :--- | :--- | :--- |
| **Backend API** | `http://127.0.0.1:8000` | FastAPI developer & persistence service |
| **Interactive UI** | `http://localhost:5173` | React + Vite + Monaco + React Flow dashboard |
| **OpenAPI Documentation** | `http://127.0.0.1:8000/docs` | Interactive Swagger UI |
| **OpenAPI Schema** | `http://127.0.0.1:8000/openapi.json` | Raw OpenAPI 3.1 JSON schema |

---

## 3. Endpoints

### 3.1 Execute Static Analysis
`POST /api/v1/analyze`

Executes an end-to-end static audit on a local directory path synchronously in the worker thread pool.

#### Request Body (`application/json`)
```json
{
  "path": "analyzer/tests/fixtures/sample_project",
  "fail_on": "HIGH",
  "enabled_rules": ["ARC-001", "SEC-PY-001"],
  "disabled_rules": ["ARC-004"],
  "max_component_depth": 2
}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `path` | `string` | **Yes** | Local directory path to analyze (absolute or relative to current working directory). |
| `fail_on` | `string` | No | Optional severity threshold: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `enabled_rules` | `list[str]` | No | Optional whitelist of rule IDs to evaluate. |
| `disabled_rules`| `list[str]` | No | Optional blacklist of rule IDs to skip. |
| `max_component_depth` | `int` | No | Maximum directory depth for subsystem component aggregation (default: 2). |

#### Response (`200 OK`)
```json
{
  "id": "7ec928f6-2fa5-4505-8977-96a6042db62b",
  "status": "COMPLETED",
  "repository_path": "E:\\AI-Workspace\\projects\\CodeSentinel\\analyzer\\tests\\fixtures\\sample_project",
  "repository_name": "sample_project",
  "summary": {
    "total_findings": 4,
    "critical": 0,
    "high": 4,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total_modules": 7,
    "circular_dependencies_count": 1,
    "total_files": 7,
    "total_loc": 68,
    "duration_seconds": 0.035
  },
  "health": {
    "overall_score": 84.7,
    "overall_grade": "B",
    "architecture_health": {
      "score": 66.0,
      "grade": "D",
      "deductions": [
        {
          "category": "ARCHITECTURE",
          "rule_id": "ARC-001",
          "points_deducted": 15.0,
          "reason": "Circular file-level dependency detected",
          "finding_id": null,
          "item_count": 1
        }
      ]
    },
    "security_posture": {
      "score": 100.0,
      "grade": "A",
      "deductions": []
    },
    "total_deductions_count": 2,
    "summary": "Moderate structural risks detected. Architecture requires decoupling."
  },
  "findings": [
    {
      "id": "e44d326f-40e9-4468-b71a-289ec0a3bece",
      "rule_id": "ARC-001",
      "rule_name": "Circular Dependency",
      "message": "Circular dependency detected between backend/core/engine.py and backend/services/auth.py",
      "category": "ARCHITECTURE",
      "severity": "HIGH",
      "confidence": "HIGH",
      "description": "Modules participate in a circular dependency chain.",
      "remediation": "Refactor common interfaces into a shared contract module.",
      "location": {
        "file_path": "backend/core/engine.py",
        "line_start": 4,
        "line_end": 4,
        "column_start": 0,
        "column_end": null
      },
      "evidence": {
        "snippet": "from backend.services.auth import verify_token\n",
        "language": "python",
        "highlight_lines": [4]
      },
      "cwe_id": null,
      "owasp_category": null
    }
  ],
  "component_graph": {
    "nodes": [
      {
        "id": "backend.core",
        "name": "core",
        "path": "backend/core",
        "layer": "APPLICATION",
        "coupling": {
          "afferent": 2,
          "efferent": 1,
          "instability": 0.33,
          "total_loc": 24,
          "file_count": 2
        },
        "files": ["backend/core/engine.py", "backend/core/config.py"]
      }
    ],
    "edges": [
      {
        "id": "673cfc82-b7e8-5b4d-9ea8-228741369796",
        "source": "backend.core",
        "target": "backend.services",
        "weight": 1,
        "is_cycle": true
      }
    ],
    "circular_components_count": 1,
    "cycles": [["backend.core", "backend.services"]]
  },
  "diagnostics": []
}
```

---

---

### 3.2 Compare Baseline Differential Analysis (Phase 9)
`POST /api/v1/compare`

Evaluates regressions, resolved issues, and health deltas between a baseline analysis report and a current report/path synchronously.

#### Request Body (`application/json`)
```json
{
  "baseline_report": { /* AnalysisResult JSON payload */ },
  "current_path": "analyzer/tests/fixtures/sample_project",
  "fail_on_regression": "HIGH"
}
```

---

### 3.3 Register a Repository (Phase 10)
`POST /api/v1/repositories`

Registers a local repository for persistent snapshot tracking and analysis history. Validates filesystem path security boundaries.

#### Request Body (`application/json`)
```json
{
  "path": "e:/AI-Workspace/projects/CodeSentinel",
  "name": "CodeSentinel"
}
```

#### Response (`201 Created`)
```json
{
  "id": "e838e555-d36a-4933-911e-ec95a9757f59",
  "name": "CodeSentinel",
  "path": "E:\\AI-Workspace\\projects\\CodeSentinel",
  "created_at": "2026-09-22T17:30:00Z",
  "updated_at": "2026-09-22T17:30:00Z",
  "analysis_count": 0
}
```

---

### 3.4 List Registered Repositories (Phase 10)
`GET /api/v1/repositories`

Retrieves a paginated list of all registered repositories.

#### Query Parameters
- `skip` (`int`, default: `0`): Pagination offset.
- `limit` (`int`, default: `50`, max: `100`): Maximum records to return.

#### Response (`200 OK`)
```json
{
  "items": [
    {
      "id": "e838e555-d36a-4933-911e-ec95a9757f59",
      "name": "CodeSentinel",
      "path": "E:\\AI-Workspace\\projects\\CodeSentinel",
      "created_at": "2026-09-22T17:30:00Z",
      "updated_at": "2026-09-22T17:30:00Z",
      "analysis_count": 3
    }
  ],
  "total": 1,
  "skip": 0,
  "limit": 50
}
```

---

### 3.5 Get Repository Details (Phase 10)
`GET /api/v1/repositories/{repository_id}`

Retrieves details for an individual registered repository. Returns `404 Not Found` if the ID does not exist.

---

### 3.6 Unregister / Delete Repository (Phase 10)
`DELETE /api/v1/repositories/{repository_id}`

Removes a repository from the catalog. Cascades deletion to all associated analysis snapshots, findings, health deductions, and component graphs. Returns `204 No Content`.

---

### 3.7 Run Analysis and Persist Immutable Snapshot (Phase 10)
`POST /api/v1/repositories/{repository_id}/analyses`

Executes static analysis synchronously on the registered repository filesystem path, records Git provenance, secret-redacts finding snippets, atomically saves an immutable snapshot in the database, and returns the reconstructed canonical `AnalysisResultDTO`.

#### Request Body (`application/json`, Optional)
```json
{
  "fail_on": "HIGH",
  "enabled_rules": ["ARC-001", "SEC-PY-001"],
  "disabled_rules": ["ARC-004"],
  "max_component_depth": 2
}
```

#### Response (`201 Created`)
Returns the full canonical `AnalysisResultDTO` matching Section 3.1.

---

### 3.8 Ingest Completed Snapshot from CLI (Phase 10)
`POST /api/v1/repositories/{repository_id}/snapshots`

Accepts a completed canonical `AnalysisResult` JSON payload (e.g. from `codesentinel analyze <path> --save`) and saves it as an immutable snapshot associated with the repository.

#### Response (`201 Created`)
```json
{
  "id": "5f134bd9-d4c3-4d6d-8e42-1279a0ce8e84",
  "repository_id": "e838e555-d36a-4933-911e-ec95a9757f59",
  "created_at": "2026-09-22T17:35:00Z",
  "commit_hash": "a1b2c3d4e5f67890",
  "branch": "main",
  "is_dirty": false,
  "analyzer_version": "0.1.0",
  "status": "COMPLETED",
  "duration_seconds": 0.045,
  "overall_score": 92.5,
  "overall_grade": "A",
  "architecture_score": 88.0,
  "architecture_grade": "B",
  "security_score": 100.0,
  "security_grade": "A",
  "total_findings": 2,
  "critical_count": 0,
  "high_count": 2,
  "medium_count": 0,
  "low_count": 0,
  "info_count": 0
}
```

---

### 3.9 List Historical Analysis Snapshots (Phase 10)
`GET /api/v1/repositories/{repository_id}/analyses`

Retrieves a chronologically ordered (newest first) paginated collection of lightweight historical analysis snapshot summaries for the given repository. Enforces strict repository isolation.

#### Query Parameters
- `skip` (`int`, default: `0`): Offset.
- `limit` (`int`, default: `20`, max: `100`): Limit.

#### Response (`200 OK`)
```json
{
  "items": [
    {
      "id": "5f134bd9-d4c3-4d6d-8e42-1279a0ce8e84",
      "repository_id": "e838e555-d36a-4933-911e-ec95a9757f59",
      "created_at": "2026-09-22T17:35:00Z",
      "commit_hash": "a1b2c3d4e5f67890",
      "branch": "main",
      "is_dirty": false,
      "analyzer_version": "0.1.0",
      "status": "COMPLETED",
      "duration_seconds": 0.045,
      "overall_score": 92.5,
      "overall_grade": "A",
      "architecture_score": 88.0,
      "architecture_grade": "B",
      "security_score": 100.0,
      "security_grade": "A",
      "total_findings": 2,
      "critical_count": 0,
      "high_count": 2,
      "medium_count": 0,
      "low_count": 0,
      "info_count": 0
    }
  ],
  "total": 1,
  "skip": 0,
  "limit": 20
}
```

---

### 3.10 Get Reconstructed Historical Analysis Snapshot (Phase 10)
`GET /api/v1/repositories/{repository_id}/analyses/{analysis_id}`

Retrieves an individual historical analysis snapshot and reconstructs the full-fidelity canonical `AnalysisResultDTO` (including all findings, health deduction logs, component graph topology, and dependency diagnostics).
Enforces repository isolation: if `analysis_id` does not belong to `repository_id`, returns `404 Not Found`.

#### Response (`200 OK`)
Returns the complete canonical `AnalysisResultDTO` matching Section 3.1.

---

### 3.11 List Registered Analysis Rules
`GET /api/v1/rules`

Returns the complete catalog of registered static analysis rules sorted deterministically by `rule_id`.

#### Response (`200 OK`)
```json
{
  "total_rules": 22,
  "rules": [
    {
      "rule_id": "ARC-001",
      "name": "Circular Dependency",
      "category": "ARCHITECTURE",
      "evidence_type": "DETERMINISTIC",
      "severity": "HIGH",
      "confidence": "HIGH",
      "description": "Detects mutual and transitive import cycles between source modules.",
      "remediation": "Extract shared types or introduce dependency inversion.",
      "supported_languages": ["python", "javascript", "typescript"],
      "frameworks": [],
      "cwe_id": null,
      "owasp_category": null,
      "rationale": "Circular dependencies cause initialization deadlocks and impede refactoring."
    }
  ]
}
```

---

### 3.12 Inspect Single Rule Details
`GET /api/v1/rules/{rule_id}`

Retrieves complete metadata for an individual rule. Lookup is case-insensitive.

#### Example: `GET /api/v1/rules/ARC-005`
```json
{
  "rule_id": "ARC-005",
  "name": "Layer Boundary Inversion",
  "category": "ARCHITECTURE",
  "evidence_type": "HEURISTIC",
  "severity": "HIGH",
  "confidence": "MEDIUM",
  "description": "Prohibited upward dependency from lower infrastructure or utility layer to higher presentation or domain layer.",
  "remediation": "Invert dependency using interfaces or abstract base classes.",
  "supported_languages": ["python", "javascript", "typescript"],
  "frameworks": [],
  "cwe_id": null,
  "owasp_category": null,
  "rationale": "Violates Clean Architecture boundary rules."
}
```

---

### 3.13 Service Health Checks
- `GET /health`: Root service health check returning uptime and backend component readiness.
- `GET /api/v1/health`: API v1 health check.

---

### 3.14 Get Repository Longitudinal Trends (Phase 14)
`GET /api/v1/repositories/{repository_id}/trends`

Computes longitudinal quality trajectories, defect churn/velocity, severity volume over time, and component instability drift $\Delta I(c)$ across stored immutable snapshots in PostgreSQL.

#### Query Parameters:
- `branch` (string, optional): Filter snapshots to a specific Git branch (e.g. `main`).
- `limit` (integer, optional, default: 50, ge: 2, le: 500): Maximum number of historical points to analyze.
- `since` (ISO-8601 string, optional): Filter snapshots created on or after this timestamp.
- `until` (ISO-8601 string, optional): Filter snapshots created on or before this timestamp.

#### Response (`200 OK`)
```json
{
  "repository_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "repository_name": "CodeSentinel",
  "branch_filter": "main",
  "timeline": [
    {
      "snapshot_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "created_at": "2026-09-20T10:00:00Z",
      "commit_hash": "a1b2c3d4e5f6...",
      "branch": "main",
      "health_score": 92.5,
      "health_grade": "A",
      "findings_count": 4,
      "critical_count": 0,
      "high_count": 1,
      "medium_count": 2,
      "low_count": 1,
      "info_count": 0,
      "config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ],
  "defect_velocity": [
    {
      "snapshot_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "created_at": "2026-09-20T10:00:00Z",
      "commit_hash": "a1b2c3d4e5f6...",
      "new_findings": 0,
      "resolved_findings": 0,
      "net_change": 0
    }
  ],
  "component_drift": [
    {
      "component_name": "analyzer.dataflow",
      "initial_instability": 0.40,
      "latest_instability": 0.35,
      "instability_delta": -0.05,
      "is_destabilizing": false
    }
  ],
  "has_config_drift": false,
  "config_hashes_present": [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ]
}
```

#### Status Codes:
- `200 OK`: Successful trend computation.
- `404 Not Found`: Repository with `repository_id` does not exist.

---

### 3.15 Get Call Graph Summary (Phase 15)
`GET /api/v1/repositories/{repository_id}/analyses/{analysis_id}/callgraph`

Retrieves static call graph intelligence metrics, edge resolution rates, and interprocedural finding counters for an immutable analysis snapshot.

#### Response (`200 OK`)
```json
{
  "analysis_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "total_functions": 142,
  "total_call_edges": 287,
  "resolved_local": 198,
  "resolved_import": 52,
  "unresolved": 37,
  "resolution_rate": 0.871,
  "summarized_functions": 135,
  "unsummarized_functions": 7,
  "interprocedural_findings_count": 3,
  "max_call_depth_reached": 3
}
```

#### Status Codes:
- `200 OK`: Successful call graph summary retrieval.
- `404 Not Found`: Repository or analysis snapshot does not exist, cross-repository boundary violation, or snapshot predates Phase 15.

---

## 4. Error Handling & Status Codes

All API errors return standard HTTP status codes with a structured error envelope:

```json
{
  "code": "NOT_FOUND",
  "message": "Repository path does not exist: 'nonexistent_directory'",
  "details": {
    "path": "nonexistent_directory"
  }
}
```

| HTTP Status | Error Code | Description |
| :--- | :--- | :--- |
| **400 Bad Request** | `INVALID_PATH` | Path is empty, syntax is invalid, or points to a file instead of a directory. |
| **403 Forbidden** | `SECURITY_POLICY_VIOLATION` | Path violates local filesystem security policy (e.g. drive root or protected system directory). |
| **404 Not Found** | `NOT_FOUND` / `RULE_NOT_FOUND` | Repository path does not exist, or requested `rule_id` is unknown. |
| **422 Unprocessable** | `VALIDATION_ERROR` | Request body failed Pydantic schema validation. |
| **500 Internal Error** | `INTERNAL_ANALYSIS_ERROR` | Unexpected unhandled engine failure (stack traces are logged internally, not leaked). |

---

## 5. Filesystem Security Boundary

CodeSentinel implements explicit security controls for local filesystem access:
1. **Canonical Path Resolution**: All inputs are resolved via `Path.resolve()`.
2. **Directory Verification**: The path must exist and must be a directory (`is_dir() == True`).
3. **Drive Root Rejection**: Analysis cannot target drive roots (`C:\`, `/`).
4. **Protected System Directory Rejection**: Analysis cannot target `C:\Windows`, `C:\Program Files`, `/etc`, `/usr`, `/bin`, `/proc`, or `/sys`.
5. **Safe Ingestion**: Directory traversal ignores symlink chains (`followlinks=False`), skipping `.git`, `node_modules`, `venv`, and `__pycache__`.
6. **Zero Code Execution**: Analyzed files are parsed strictly as AST data tokens; no code is imported or executed, and no external commands are spawned.
7. **Bounded Evidence Snippets**: The API only transmits bounded finding snippets; no open file browser endpoint is provided.

---

## 6. CLI Usability & Filtering

The CLI (`codesentinel`) provides cumulative severity and category filtering, baseline diffing, and backend snapshot persistence:

```bash
# Analyze target repository
codesentinel analyze path/to/repo

# Persist analysis snapshot to backend database (Phase 10)
codesentinel analyze path/to/repo --save
codesentinel analyze path/to/repo --save --api-url http://127.0.0.1:8000

# Filter by severity (HIGH includes CRITICAL and HIGH)
codesentinel analyze path/to/repo --severity HIGH

# Filter by category
codesentinel analyze path/to/repo --category SECURITY
codesentinel analyze path/to/repo --category ARCHITECTURE

# Filter by specific rule ID
codesentinel analyze path/to/repo --rule ARC-001

# Combine filters with JSON output
codesentinel analyze path/to/repo --category ARCHITECTURE --severity HIGH --format json

# Baseline differential analysis (Phase 9)
codesentinel analyze path/to/repo --baseline baseline.json --fail-on-regression HIGH

# Generate SARIF report for GitHub Code Scanning / GitLab SAST (Phase 9)
codesentinel analyze path/to/repo --format sarif -o report.sarif
```

---

## 7. Running the Developer UI

Start the backend and frontend in separate terminals:

```bash
# Terminal 1: Backend (with PostgreSQL 16 or SQLite configured)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.
1. Select an existing registered repository from the **Catalog** dropdown or click **+ Register** to add a new local repository.
2. Click **Run Analysis** to execute a static scan and save an immutable snapshot to the database.
3. Click the **History** button to inspect the paginated historical snapshot timeline, comparing score progressions and loading any historical analysis snapshot in full fidelity into the Monaco code viewer and React Flow architecture graph.

