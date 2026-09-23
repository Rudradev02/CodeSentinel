# Phase 14 — Longitudinal Trend Intelligence, Developer Tooling & Reporting

> **Phase 14 Master Architecture & Implementation Plan**  
> **Status**: APPROVED FOR IMPLEMENTATION PLANNING  
> **Repository**: `E:\AI-Workspace\projects\CodeSentinel`  
> **Target Baseline**: Post-Phase 13 (329 automated tests passing, 1 skipped)  
> **Scope**: Developer Configuration (`.codesentinel.yml`), CLI Precedence & Exit Semantics, Historical Longitudinal Trend Intelligence, Read-Only Trend API, Frontend Trend Visualizations, Multi-Target Enterprise Reporting (Markdown, Standalone HTML, JUnit XML, GitLab Code Quality), Pre-Commit Gating, and CI/CD Integrations.

---

## 1. Executive Summary

Phase 14 elevates CodeSentinel from a local, point-in-time security and architecture auditing tool into an **enterprise-grade longitudinal quality and CI intelligence platform**.

Prior to Phase 14, CodeSentinel provided point-in-time scans (Phase 1–8), pairwise baseline comparisons (Phase 9), immutable snapshot persistence in PostgreSQL (Phase 10), asynchronous worker task orchestration (Phase 11), bounded AI context enrichment (Phase 12), and intraprocedural data-flow tracking with component centrality (Phase 13). However, developers and CI systems lacked:
1. A standard repository-local configuration file (`.codesentinel.yml`) to declaratively manage active rules, architectural thresholds, and ignore paths without repetitively passing complex CLI flags.
2. A longitudinal trend engine to track codebase health trajectories ($H(t)$), defect velocity (new regressions vs. resolved findings), technical debt burn-down, and architectural stability shifts across historical commits and branches.
3. Multi-target enterprise reporting formats beyond terminal, JSON, and SARIF—specifically standalone interactive HTML reports, GitHub/GitLab Pull Request Markdown summaries, standard JUnit XML test results, and GitLab Code Quality JSON.
4. Native pre-commit hook gating (`.pre-commit-hooks.yaml`) to prevent defect injection locally before code enters source control.

Phase 14 delivers these capabilities while strictly preserving CodeSentinel's foundational invariants: **100% offline analyzer operation**, **zero database/backend imports in `analyzer/`**, **deterministic analysis reproducibility**, **bounded memory and execution limits**, and **complete isolation between deterministic static truth and advisory reporting**.

---

## 2. Current Repository Baseline (Post-Phase 13)

The actual repository state on disk following Phase 13 verification forms the authoritative foundation:

| Subsystem | Current State on Disk | Verification Status |
| :--- | :--- | :--- |
| **Analyzer Core** | Bounded intraprocedural data-flow engine (`analyzer/dataflow/`), symbol scoping (`symbol.py`), 4-point join lattice taint propagator (`propagator.py`), Brandes centrality calculator (`analyzer/architecture/centrality.py`), 27 registered rules (10 Python security, 8 JS/TS security, 9 Architecture rules), SARIF v2.1.0 `codeFlows` / `threadFlows` generator. | **248 passed, 1 skipped** (symlinks on Windows) |
| **Backend API & DB** | Async SQLAlchemy 2.0 with Alembic revisions (`0001_phase10` through `0004_phase13`), immutable snapshot models (`AnalysisSnapshot`, `FindingSnapshot`, `HealthDeductionSnapshot`, `ComponentSnapshot`, `ComponentEdgeSnapshot`), Celery 5.4 worker dispatch with cooperative cancellation, Redis cache & SSE event bus, bounded AI enrichment orchestrator. | **81 passed** |
| **Frontend UI** | React 18 + Vite + Tailwind CSS + Lucide React + Monaco Editor + React Flow. Views: Overview (`HealthCard`, `MetricSummary`, `DeductionsTable`), Findings (`FindingsExplorer`, `MonacoViewer`, `TaintTraceViewer`), Architecture (`ArchitectureGraph`), Differential (`DifferentialView`), Rules (`RuleCatalogModal`), History (`AnalysisHistoryModal`). | **TypeScript clean (`tsc --noEmit`), Vite production build clean (0 errors)** |
| **Total Automated Tests** | **329 passed**, 1 skipped, 0 failures. | All test suites green across repository. |

---

## 3. Phase 14 Goals

1. **Repository Configuration (`.codesentinel.yml`)**:
   - Provide a declarative, versioned YAML configuration format (`version: 1`) allowing developers to customize enabled/disabled rules, architectural thresholds, path exclusions, reporting defaults, and regression failure gates in source control.
   - Support zero-dependency JSON fallback (`.codesentinel.json`) when PyYAML is unavailable.
   - Enforce deterministic configuration hashing (`config_hash`) to track configuration drift across historical runs.

2. **CLI Precedence & Configuration Integration**:
   - Unify CLI argument parsing with repository configuration under strict precedence: **CLI Arguments > `.codesentinel.yml` > Built-in Defaults**.
   - Preserve existing CLI flags and strict POSIX exit code semantics (`0` = success, `1` = operational/config error, `2` = policy violation/regression failure).

3. **Longitudinal Trend Intelligence**:
   - Compute historical health trajectories, defect velocity (new vs. resolved), severity volume, and component stability drift across stored immutable snapshots in PostgreSQL.
   - Formulate strict comparability semantics to prevent invalid comparisons across differing branches or divergent configurations.

4. **Read-Only Trend API**:
   - Expose `GET /api/v1/repositories/{id}/trends` returning structured time-series DTOs with branch filtering, date range boundaries, and pagination/limits.
   - Preserve repository isolation boundaries (cross-repository lookups return HTTP 404).

5. **Frontend Longitudinal Trend Dashboard**:
   - Mount a new `Trends` navigation tab in `Header.tsx` and `App.tsx`.
   - Render responsive, deterministic SVG charts (Health Trajectory, Severity Stack, Defect Velocity, Component Centrality Drift) using pure React and Tailwind CSS without heavy third-party charting libraries.
   - Handle all UX states: `loading`, `empty`, `error`, `configuration_drift`, and `partial`.

6. **Multi-Target Reporting Architecture**:
   - Extend `BaseReporter` to produce:
     - **Standalone HTML Report** (`--format html`): 100% self-contained single-file report with embedded CSS, SVG KPI visualizers, collapsible taint traces, and safe HTML escaping.
     - **PR Comment Markdown Report** (`--format markdown`): Compact, bounded markdown summary optimized for GitHub PR comments and GitLab MR notes.
     - **JUnit XML Report** (`--format junit`): Standard xUnit testcase XML enabling CI test dashboards to display findings as test failures.
     - **GitLab Code Quality Report** (`--format gitlab`): Conforms to GitLab's `gl-code-quality-report.json` schema for GitLab CI Code Quality widget integration.

7. **Developer Workflow & Pre-Commit Gating**:
   - Provide `.pre-commit-hooks.yaml` enabling local `git commit` gating.
   - Ensure local pre-commit execution is 100% offline, requires zero background services (no PostgreSQL, no Redis, no Celery), and executes in sub-second to single-digit second timeframes.

---

## 4. Architectural Invariants

Phase 14 must rigorously adhere to the following architectural boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Strict Architectural Invariants                      │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Analyzer Independence:                                              │
│    analyzer/ contains ZERO imports of FastAPI, SQLAlchemy, Alembic,    │
│    PostgreSQL, asyncpg, Redis, Celery, OpenRouter, Ollama, or frontend.│
│                                                                        │
│ 2. Offline Analyzer Truth:                                             │
│    The static analyzer remains fully functional in local CLI and       │
│    pre-commit modes without network connectivity or backend databases. │
│                                                                        │
│ 3. Single Persistence Layer:                                           │
│    Phase 14 does NOT create a second database or snapshot store.       │
│    Historical trends are computed exclusively from Phase 10            │
│    AnalysisSnapshot records in PostgreSQL.                             │
│                                                                        │
│ 4. Read-Only Trend Queries:                                            │
│    Trend calculation endpoints never mutate database state, never      │
│    trigger background analyses, and never alter historical snapshots.  │
│                                                                        │
│ 5. Safe Configuration Sandboxing:                                      │
│    .codesentinel.yml is strictly declarative data. No shell execution, │
│    no eval(), no arbitrary Python object instantiation, no plugins.   │
│                                                                        │
│ 6. Report Escaping & Sanitization:                                     │
│    All user/repository strings rendered into HTML/Markdown/JUnit       │
│    reports undergo strict HTML/XML escaping and credential masking.    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Configuration Architecture (`.codesentinel.yml`)

### 5.1 Schema Specification

The repository configuration file resides at the target repository root: `.codesentinel.yml` (or `.codesentinel.yaml` / `.codesentinel.json`).

```yaml
version: 1

analysis:
  # Explicit whitelist of active rules (null enables all registered rules)
  enabled_rules: null
  # Explicit blacklist of deactivated rules
  disabled_rules:
    - ARC-004

  # Severity threshold to fail analysis (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  fail_on_severity: HIGH

  # Architectural threshold overrides
  max_component_depth: 2
  centrality_threshold: 0.35
  max_taint_depth: 25
  coupling_threshold: 10
  god_module_loc: 500

paths:
  # Additional directory or file patterns to exclude from analysis
  exclude:
    - "legacy/**"
    - "tests/fixtures/**"
    - "scripts/scratch/**"

comparison:
  # Path to default baseline JSON report for differential comparison
  baseline: ".codesentinel/baseline.json"
  # Severity threshold to trigger failure on newly introduced findings
  fail_on_regression: HIGH

reporting:
  # Default output formats when running CLI
  format: terminal
  # Optional default report output file
  output_file: null
```

### 5.2 Schema Data Types & Validation Rules

A new Pydantic schema [`analyzer/config/repo_config.py`](file:///e:/AI-Workspace/projects/CodeSentinel/analyzer/config/repo_config.py) validates the configuration file:

| Section | Field | Type | Default | Constraints & Validation |
| :--- | :--- | :--- | :--- | :--- |
| **Root** | `version` | `int` | `1` | Must equal `1`. Unsupported versions raise actionable error. |
| **`analysis`** | `enabled_rules` | `list[str] \| null` | `null` | Rule IDs must match `SEC-[A-Z]+-[0-9]{3}` or `ARC-[0-9]{3}`. Cannot overlap with `disabled_rules`. |
| | `disabled_rules` | `list[str]` | `[]` | Must be valid registered rule IDs. |
| | `fail_on_severity` | `str \| null` | `null` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (case-insensitive). |
| | `max_component_depth` | `int` | `2` | $1 \le x \le 10$. |
| | `centrality_threshold` | `float` | `0.35` | $0.0 \le x \le 1.0$. |
| | `max_taint_depth` | `int` | `25` | $1 \le x \le 100$. |
| | `coupling_threshold` | `int` | `10` | $x \ge 1$. |
| | `god_module_loc` | `int` | `500` | $x \ge 50$. |
| **`paths`** | `exclude` | `list[str]` | `[]` | Glob patterns normalized to POSIX forward slashes. Path traversal (`../`) rejected. |
| **`comparison`**| `baseline` | `str \| null` | `null` | Relative path to baseline report file within repository bounds. |
| | `fail_on_regression` | `str \| null` | `null` | Valid severity enum value. |
| **`reporting`** | `format` | `str` | `"terminal"`| `terminal`, `json`, `sarif`, `html`, `markdown`, `junit`, `gitlab`. |
| | `output_file` | `str \| null` | `null` | Relative or absolute path. |

### 5.3 Configuration Loader (`analyzer/config/file_loader.py`)

The loader implements the following deterministic discovery sequence:
1. If `--config <path>` is explicitly passed on the CLI, verify the path exists; if missing or invalid, fail immediately with exit code `1`.
2. Otherwise, check for `.codesentinel.yml`, `.codesentinel.yaml`, and `.codesentinel.json` in the target repository root in that exact order.
3. If found, read with UTF-8 encoding.
   - For `.yml` / `.yaml`: parse with `yaml.safe_load(content)` if PyYAML is installed. If PyYAML is not installed and a YAML config is present, raise a helpful error instructing the developer to install `pyyaml` or rename/convert to `.codesentinel.json`.
   - For `.json`: parse with Python standard library `json.loads(content)`.
4. If no configuration file exists, return the default `RepoConfig()`.
5. Reject unknown top-level keys (`extra="forbid"` in Pydantic) to catch typos immediately (e.g., `analysys` instead of `analysis`).

### 5.4 Deterministic Configuration Hash (`config_hash`)

To ensure reproducibility across time and detect configuration drift:
- The validated configuration is serialized into canonical JSON with sorted keys, stripped whitespace, and excluded paths.
- A SHA-256 digest is generated: `config_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()[:16]`.
- This `config_hash` is recorded in `AnalysisResult.diagnostics`, stored in PostgreSQL `AnalysisSnapshot.configuration["config_hash"]`, and used during trend calculation to verify comparability.

---

## 6. CLI Integration & Precedence Architecture

### 6.1 Precedence Hierarchy

Configuration values resolve according to a strict three-tier precedence hierarchy:

```
┌─────────────────────────────────────────────────────────────┐
│                    1. CLI Explicit Arguments                │
│    (--severity, --rule, --max-component-depth, --fail-on)   │
└──────────────────────────────┬──────────────────────────────┘
                               │ Overrides
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              2. Repository Config (.codesentinel.yml)       │
│           (analysis.*, paths.exclude, comparison.*)         │
└──────────────────────────────┬──────────────────────────────┘
                               │ Overrides
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 3. Engine Built-in Defaults                 │
│      (max_depth=2, centrality=0.35, taint_depth=25)         │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 CLI Overrides Matrix

| Configuration Field | CLI Argument | Override Behavior |
| :--- | :--- | :--- |
| `analysis.enabled_rules` | `--enable-rule <id>` | If passed on CLI, replaces or extends YAML `enabled_rules`. |
| `analysis.disabled_rules` | `--disable-rule <id>`| Merged with YAML `disabled_rules`. |
| `analysis.fail_on_severity` | `--fail-on <SEV>` | CLI value takes precedence over YAML. |
| `analysis.max_component_depth` | `--max-component-depth <N>`| CLI value takes precedence over YAML. |
| `analysis.centrality_threshold`| `--centrality-threshold <F>`| CLI value takes precedence over YAML. |
| `analysis.max_taint_depth` | `--max-taint-depth <N>` | CLI value takes precedence over YAML. |
| `comparison.baseline` | `--baseline <path>` | CLI argument overrides YAML baseline path. |
| `comparison.fail_on_regression`| `--fail-on-regression <SEV>`| CLI argument overrides YAML regression threshold. |
| `reporting.format` | `--format <fmt>` | CLI argument overrides YAML format. |
| `reporting.output_file` | `--output <file>` | CLI argument overrides YAML output file. |
| `paths.exclude` | *(CLI internal)* | YAML exclude globs are passed directly to `IgnoreEngine.custom_patterns`. |

### 6.3 Exit Code Semantics

CodeSentinel adheres strictly to standard POSIX exit codes across all commands (`analyze`, `compare`, `rules`):

| Exit Code | Meaning | Triggers |
| :--- | :--- | :--- |
| `0` | **Success** | Analysis completed cleanly; no findings met `--fail-on`; no regressions met `--fail-on-regression`. |
| `1` | **Operational / Config Error** | Non-existent target directory, invalid `.codesentinel.yml` schema, unparseable baseline JSON, or I/O failure. |
| `2` | **Policy Threshold Violation** | One or more findings met or exceeded `--fail-on`, OR newly introduced regressions met or exceeded `--fail-on-regression`. |
| `130`| **User Cancellation** | SIGINT (Ctrl+C) received during execution; cooperative cancellation halted analysis cleanly. |

---

## 7. Longitudinal Trend Architecture

### 7.1 Data Flow Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│                    PostgreSQL Immutable Snapshots                         │
│                    (Persisted across historical runs)                     │
│                                                                           │
│   Snapshot #1 (t1, c1)  ──►  Snapshot #2 (t2, c2)  ──►  Snapshot #3 (t3) │
│   Health: 88, Vulns: 12      Health: 85, Vulns: 14      Health: 92, Vulns: 8│
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                       backend/app/services/trend_service.py               │
│                                                                           │
│   1. Fetch ordered snapshots for repository (filtered by branch/date)     │
│   2. Verify comparability (config_hash, analyzer version)                │
│   3. Compute delta vectors:                                               │
│      • ΔHealth = H(t) - H(t-1)                                            │
│      • Defect velocity = New Regressions vs. Resolved Findings            │
│      • Severity trajectory = [Crit(t), High(t), Med(t), Low(t)]           │
│      • Component stability drift = ΔCycles, ΔHotspots                     │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                      GET /api/v1/repositories/{id}/trends                 │
│                      (Read-Only FastAPI Endpoint)                         │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                      Frontend TrendsView.tsx                              │
│                      (Pure React SVG Charts & Drift Badges)               │
└───────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Core Trend Metrics

The trend engine calculates four primary longitudinal dimensions from persisted records:

1. **Codebase Health Trajectory**:
   - Composite Health Score ($0.0 - 100.0$) and Letter Grade ($A, B, C, D, F$).
   - Security Posture Sub-Score ($0.0 - 100.0$) and Architecture Health Sub-Score ($0.0 - 100.0$).
   - Health delta relative to initial baseline snapshot and relative to immediately preceding snapshot ($\Delta H$).

2. **Finding Severity Distribution**:
   - Counts over time: `critical`, `high`, `medium`, `low`, `info`.
   - Security vs. Architecture breakdown over time.
   - Intraprocedural Taint Findings count over time (`SEC-PY-009`, `SEC-PY-010`, `SEC-JS-007`, `SEC-JS-008`).

3. **Defect Velocity & Burn-Down**:
   - `new_findings_count`: Findings introduced in snapshot $S_k$ that were absent in comparable snapshot $S_{k-1}$.
   - `resolved_findings_count`: Findings present in $S_{k-1}$ that are absent in $S_k$.
   - `net_defect_delta`: $\text{New} - \text{Resolved}$.
   - `legacy_findings_count`: Pre-existing findings remaining open across consecutive runs.

4. **Component Stability & Centrality Drift**:
   - Total component count.
   - Cyclic component group count (participating in `ARC-006` circular groups).
   - High-Centrality Bottleneck count (components exceeding `arc_009_centrality_threshold`).

---

## 8. Historical Comparison Semantics & Comparability

Historical trends cannot blindly compare arbitrary analysis runs. The trend engine enforces strict comparability tiers:

### 8.1 Comparability States

| State | Criteria | Engine Behavior |
| :--- | :--- | :--- |
| **Fully Comparable** | Same `repository_id`, same `branch`, identical `config_hash`, matching analyzer major version. | Full delta metrics computed (Health $\Delta$, New, Resolved, Severity drift). |
| **Partially Comparable** | Same `repository_id`, same `branch`, but `config_hash` differs (e.g. rules enabled/disabled or thresholds tuned). | Metrics calculated but marked with `config_drift: true`. UI displays a configuration drift indicator on the timeline. |
| **Non-Comparable** | Cross-branch comparison requested without explicit branch mapping, or major analyzer version incompatibility. | Snapshots plotted on timeline as discrete points, but differential regression/resolution vectors between them are suppressed. |

### 8.2 Defect Transition Matching Algorithm

When computing New vs. Resolved findings between consecutive snapshots $S_{k-1}$ and $S_k$, the trend engine reuses Phase 9's multi-tier deterministic matching algorithm:
1. **Deterministic Finding ID match**: Compares `finding_uuid`.
2. **Exact Signature match**: Compares `(rule_id, normalized_path, line_start, normalized_snippet)`.
3. **Fuzzy Snippet match**: Compares `(rule_id, normalized_path, normalized_snippet)` across line shifts.
4. **Fuzzy Location match**: Compares `(rule_id, normalized_path, line_start)` across minor whitespace/token edits.

---

## 9. Trend API Specification

### 9.1 Endpoint

```http
GET /api/v1/repositories/{repository_id}/trends
```

### 9.2 Query Parameters

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `branch` | `string` | No | `null` | Filter timeline to a specific Git branch (e.g. `main`). If omitted, includes all repository runs. |
| `since` | `datetime`| No | `null` | ISO 8601 UTC timestamp filtering out snapshots older than this date. |
| `limit` | `int` | No | `50` | Maximum snapshot points to return ($1 \le \text{limit} \le 200$). |

### 9.3 Response Schema (`LongitudinalTrendDTO`)

```json
{
  "repository_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "repository_name": "sample_project",
  "summary": {
    "total_snapshots": 12,
    "earliest_date": "2026-08-01T10:00:00Z",
    "latest_date": "2026-09-23T20:00:00Z",
    "initial_health_score": 78.5,
    "latest_health_score": 92.0,
    "net_health_delta": 13.5,
    "total_new_regressions_detected": 6,
    "total_findings_resolved": 14,
    "active_branches": ["main", "feature/dataflow"]
  },
  "points": [
    {
      "snapshot_id": "a1b2c3d4-...",
      "created_at": "2026-09-01T12:00:00Z",
      "commit_hash": "c0ffee1",
      "branch": "main",
      "is_dirty": false,
      "config_hash": "e3b0c442",
      "config_drift": false,
      "health": {
        "overall_score": 85.0,
        "overall_grade": "B",
        "security_score": 80.0,
        "security_grade": "B",
        "architecture_score": 90.0,
        "architecture_grade": "A",
        "score_delta": 0.0
      },
      "findings_summary": {
        "total": 15,
        "critical": 1,
        "high": 4,
        "medium": 7,
        "low": 3,
        "info": 0,
        "security_count": 8,
        "architecture_count": 7,
        "taint_count": 3
      },
      "transitions": {
        "new_count": 0,
        "resolved_count": 0,
        "unchanged_count": 15,
        "modified_count": 0
      },
      "components_summary": {
        "total_components": 8,
        "circular_components_count": 0,
        "high_centrality_count": 1
      }
    }
  ]
}
```

---

## 10. Frontend Trend Dashboard (`TrendsView.tsx`)

### 10.1 UI Component Architecture

A dedicated component hierarchy is created in `frontend/src/components/trends/`:
- [`TrendsView.tsx`](file:///e:/AI-Workspace/projects/CodeSentinel/frontend/src/components/trends/TrendsView.tsx): Main dashboard container with header filters (branch selector, time range).
- [`HealthTrajectoryChart.tsx`](file:///e:/AI-Workspace/projects/CodeSentinel/frontend/src/components/trends/HealthTrajectoryChart.tsx): Multi-line SVG chart plotting Overall Health, Security Score, and Architecture Score across time.
- [`SeverityVolumeChart.tsx`](file:///e:/AI-Workspace/projects/CodeSentinel/frontend/src/components/trends/SeverityVolumeChart.tsx): Stacked SVG area chart illustrating Critical, High, Medium, and Low defect volume.
- [`DefectVelocityChart.tsx`](file:///e:/AI-Workspace/projects/CodeSentinel/frontend/src/components/trends/DefectVelocityChart.tsx): Dual-bar SVG chart illustrating New Regressions (red) vs. Resolved Findings (green) per snapshot.
- [`ComponentDriftCard.tsx`](file:///e:/AI-Workspace/projects/CodeSentinel/frontend/src/components/trends/ComponentDriftCard.tsx): Metric tiles displaying circular dependency evolution and high-centrality bottleneck trends.

### 10.2 Pure SVG Charting Strategy

To guarantee bundle lightness, deterministic rendering, and zero runtime dependencies:
- Charts are implemented using **pure React SVG elements** (`<svg>`, `<path>`, `<polyline>`, `<circle>`, `<rect>`).
- Scales are calculated linearly with pure TypeScript helpers:
  $$x = \text{padding} + \frac{i}{N - 1} \cdot (\text{width} - 2 \cdot \text{padding})$$
  $$y = \text{height} - \text{padding} - \frac{\text{val} - \text{min}}{\text{max} - \text{min}} \cdot (\text{height} - 2 \cdot \text{padding})$$
- Interactive SVG `<g>` elements display tooltips on hover with coordinates, commit hashes, and score values.

### 10.3 State Machine & UX Feedback

The component strictly implements five distinct states:
1. **Loading**: Renders animated skeleton cards with message: *"Loading historical trend intelligence..."*.
2. **Empty**: If the repository has $< 2$ snapshots: *"At least two completed analysis runs are required to compute longitudinal trends. Run an analysis to begin tracking."*.
3. **Error**: Displays an alert banner with retry button if API fails: *"Unable to load historical trend data. Check backend connectivity."*.
4. **Configuration Drift**: Displays an informational badge on timeline points where `config_drift == true`: *"Configuration changed at commit [hash]; score trajectory reflects adjusted rules/thresholds."*.
5. **Success**: Fully rendered interactive trend timeline with snapshot detail inspection.

---

## 11. Multi-Target Reporting Architecture

### 11.1 Shared Reporter Interface

All reporters inherit from the canonical contract in `analyzer/reporting/base.py`:

```python
class BaseReporter(ABC):
    """Abstract interface for formatting analysis results."""

    @abstractmethod
    def render(self, result: AnalysisResult) -> str:
        """Render an AnalysisResult into a formatted string report."""
        pass

    def render_comparison(self, comparison: ComparisonResult) -> str:
        """Render a differential ComparisonResult into a formatted report."""
        raise NotImplementedError("This reporter does not support differential comparison rendering.")
```

---

## 12. Markdown Reporting (`analyzer/reporting/markdown_reporter.py`)

### 12.1 Objective & Target Use Case
Formatted specifically for automated GitHub Pull Request comments and GitLab Merge Request notes.

### 12.2 Report Content & Structure
1. **Header & Badges**: Composite Health Score badge, Grade badge, Findings count badge.
2. **Executive Summary Table**: Total Files, Lines of Code Scanned, Execution Duration, Scan Timestamp.
3. **Health Breakdown Table**:
   - Architecture Health Score & Grade
   - Security Posture Score & Grade
   - Deductions summary
4. **Differential Regression Summary** (if rendering a `ComparisonResult`):
   - Table of New Findings (Regressions)
   - Table of Resolved Findings
5. **Top Findings Table** (bounded to the first 25 findings to prevent PR comment bloat):
   - Severity | Rule ID | Location | Summary
   - Truncation note if total findings $> 25$: *"Showing top 25 of N findings. Run `codesentinel analyze` locally for full results."*
6. **Data-Flow Taint Traces** (collapsible `<details>` tags for intraprocedural taint flows).

---

## 13. Standalone HTML Reporting (`analyzer/reporting/html_reporter.py`)

### 13.1 Objective & Target Use Case
Generates a 100% self-contained, interactive single-file HTML report (`codesentinel_report.html`) that can be saved as a CI build artifact, shared via email, or viewed offline in any browser without an HTTP server or internet connection.

### 13.2 Architecture & Security Guarantees
- **Zero External Assets**: No external Google Fonts, no external CDN stylesheets, no external JavaScript libraries. All CSS and JavaScript are strictly inlined.
- **Strict HTML Escaping**: Every single user-controlled string (file paths, code snippets, rule descriptions, messages, Git commit messages) is filtered through `html.escape(s, quote=True)` before injection into the template.
- **Content Security Policy**: Emits `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">` to block all outgoing network requests.
- **Interactive Tab Navigation**: Inline vanilla JavaScript provides instant client-side tab switching between *Overview*, *Findings*, *Architecture & Centrality*, and *Taint Traces*.

---

## 14. JUnit XML Reporting (`analyzer/reporting/junit_reporter.py`)

### 14.1 Objective & Target Use Case
Standard xUnit/JUnit XML format for continuous integration dashboards (Jenkins, Azure DevOps Test Plans, GitLab CI `artifacts:reports:junit`, Bitbucket Pipelines).

### 14.2 Mapping Specification
- `<testsuites name="CodeSentinel Static Analysis" tests="{total}" failures="{violations}">`
- Each evaluated rule or finding maps to a `<testcase>`:
  - `classname`: `codesentinel.{category.lower()}` (e.g. `codesentinel.security`)
  - `name`: `{rule_id}: {file_path}:{line}`
  - `file`: `{file_path}`
  - `line`: `{line_start}`
- Findings that meet or exceed `--fail-on` or `--fail-on-regression` emit `<failure>`:
  - `message`: `{rule_name} - {message}`
  - `type`: `{rule_id}`
  - Text body: Sanitized code snippet, remediation advice, and CWE/OWASP identifiers.
- Clean rules emit empty `<testcase>` elements (representing passed checks).

---

## 15. GitLab Code Quality Reporting (`analyzer/reporting/gitlab_reporter.py`)

### 15.1 Objective & Target Use Case
Conforms precisely to GitLab's Code Quality JSON schema (`gl-code-quality-report.json`), enabling GitLab Merge Requests to display code quality degradation widgets natively.

### 15.2 Schema Mapping

| GitLab Attribute | CodeSentinel Source | Description |
| :--- | :--- | :--- |
| `description` | `f.message` | Factual description of the defect. |
| `check_name` | `f.rule_id` | e.g. `SEC-PY-009`, `ARC-001`. |
| `fingerprint` | `f.id` | Deterministic UUIDv5 finding identifier. |
| `severity` | Mapped severity | `CRITICAL` $\rightarrow$ `critical`, `HIGH` $\rightarrow$ `major`, `MEDIUM` $\rightarrow$ `minor`, `LOW` / `INFO` $\rightarrow$ `info`. |
| `location.path` | `f.location.file_path` | Relative path normalized to POSIX slashes. |
| `location.lines.begin`| `f.location.line_start` | Starting line number (1-indexed). |
| `categories` | `[f.category.value]` | `["SECURITY"]` or `["ARCHITECTURE"]`. |

---

## 16. Developer Workflow & Pre-Commit Integration

### 16.1 `.pre-commit-hooks.yaml`

Located in the repository root for integration with the standard Python `pre-commit` framework:

```yaml
- id: codesentinel
  name: CodeSentinel Static Auditor
  description: Fast deterministic static analysis for security vulnerabilities and architectural smells
  entry: codesentinel analyze .
  language: system
  pass_filenames: false
  always_run: true

- id: codesentinel-diff
  name: CodeSentinel Regression Gate
  description: Differential regression gate checking against baseline report
  entry: codesentinel analyze . --baseline .codesentinel/baseline.json --fail-on-regression HIGH
  language: system
  pass_filenames: false
  always_run: true
```

### 16.2 Developer Installation & Setup

Developers configure pre-commit in their local repositories with:

```bash
# Install pre-commit framework
pip install pre-commit

# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: codesentinel
```

### 16.3 Performance & Safety Invariants
- Pre-commit execution runs **strictly local** and **offline**.
- Bypasses Celery, Redis, PostgreSQL, and LLM calls.
- Completes static analysis in under 2 seconds for typical codebases ($< 10,000$ LOC).

---

## 17. CI/CD Integration & Pipeline Workflows

### 17.1 GitHub Actions Complete Workflow

```yaml
name: CodeSentinel Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install CodeSentinel
        run: pip install -e ./analyzer

      - name: Run Static Analysis & Generate Artifacts
        run: |
          codesentinel analyze . --format sarif --output codesentinel.sarif
          codesentinel analyze . --format markdown --output codesentinel_summary.md
          codesentinel analyze . --format html --output codesentinel_report.html

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: codesentinel.sarif

      - name: Upload HTML Report Artifact
        uses: actions/upload-artifact@v4
        with:
          name: codesentinel-html-report
          path: codesentinel_report.html
```

### 17.2 GitLab CI Complete Pipeline

```yaml
stages:
  - test
  - quality

codesentinel_scan:
  stage: quality
  image: python:3.11-slim
  script:
    - pip install -e ./analyzer
    - codesentinel analyze . --format gitlab --output gl-code-quality-report.json
    - codesentinel analyze . --format junit --output junit.xml
    - codesentinel analyze . --fail-on HIGH
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
      junit: junit.xml
    when: always
```

---

## 18. Security Hardening

1. **Declarative Configuration Hardening**:
   - `.codesentinel.yml` uses `yaml.safe_load()`. Custom tags (e.g. `!!python/object/apply`) are rejected with an explicit error.
   - File path exclusions in `paths.exclude` are verified using `Path.resolve()` to ensure they do not traverse outside the target repository root.
2. **Report Injection Defense**:
   - Every string injected into HTML templates is sanitized via `html.escape(quote=True)`.
   - Markdown output escapes pipe characters (`|`) in table cells to prevent Markdown table formatting breaks.
   - JUnit XML escapes `&`, `<`, `>`, `"`, and `'`.
3. **Secret Masking Guarantee**:
   - Snippets containing credentials (`SEC-PY-001`, `SEC-JS-004`) remain strictly masked (`***` or `AKI...12`) across all reporter outputs, trend APIs, and frontend views.

---

## 19. Performance & Scalability Safeguards

1. **Database Query Optimization**:
   - Trend queries only select aggregate numerical columns (`overall_score`, `security_score`, `architecture_score`, severity counters) rather than loading heavy foreign key trees (findings/evidence) for the entire timeline.
   - Detailed finding snapshots are only loaded on-demand when inspecting a specific historical snapshot.
2. **Timeline Pagination & Limits**:
   - `limit` parameter clamped between 1 and 200 (default 50).
   - Prevents memory exhaustion on repositories with thousands of historical CI runs.
3. **SVG Rendering Efficiency**:
   - Trend graphs render bounded point arrays (maximum 200 points). Polyline simplification is applied if points exceed screen pixel width.

---

## 20. Database Migration: `0005_phase14_trend_indexes`

To optimize longitudinal trend queries filtering by `repository_id` and `branch` ordered by `created_at`, a new Alembic migration is planned:

- **Revision ID**: `0005_phase14`
- **Revises**: `0004_phase13`
- **Operations**:
  ```python
  def upgrade() -> None:
      # Composite index for repository trend queries
      op.create_index(
          'ix_analysis_snapshots_repo_created',
          'analysis_snapshots',
          ['repository_id', 'created_at'],
          unique=False,
      )
      op.create_index(
          'ix_analysis_snapshots_repo_branch_created',
          'analysis_snapshots',
          ['repository_id', 'branch', 'created_at'],
          unique=False,
      )
      # Index for finding severity aggregation
      op.create_index(
          'ix_finding_snapshots_snapshot_severity',
          'finding_snapshots',
          ['snapshot_id', 'severity'],
          unique=False,
      )
  ```

---

## 21. Testing Strategy

Phase 14 introduces dedicated, isolated test suites covering every component:

### 21.1 Analyzer Test Suites (`analyzer/tests/`)
1. `test_phase14_config_loader.py`:
   - Valid `.codesentinel.yml` parsing and schema validation.
   - Missing configuration fallback to default settings.
   - Invalid YAML syntax handling (returns actionable error).
   - Unknown field rejection (`extra="forbid"`).
   - Path exclusion globs passed to `IgnoreEngine`.
   - `.codesentinel.json` fallback parsing.
   - Deterministic `config_hash` calculation.
2. `test_phase14_cli_precedence.py`:
   - CLI flags override YAML settings.
   - YAML settings override built-in defaults.
   - Exit code validation (`0`, `1`, `2`).
   - `--config <path>` flag handling.
3. `test_phase14_markdown_reporter.py`:
   - Renders Markdown table correctly.
   - Bounded finding limit (truncates past 25 with note).
   - Escapes table pipes safely.
4. `test_phase14_html_reporter.py`:
   - Produces standalone valid HTML.
   - Verifies zero external CDN links.
   - Tests strict HTML escaping of malicious snippets (`<script>alert(1)</script>`).
5. `test_phase14_junit_reporter.py`:
   - XML schema validation.
   - Failure emission only for findings matching `--fail-on`.
6. `test_phase14_gitlab_reporter.py`:
   - Validates GitLab Code Quality JSON schema.
   - Verifies severity mappings.
7. `test_phase14_precommit.py`:
   - Simulates pre-commit hook invocation.
   - Verifies zero network / zero database calls.

### 21.2 Backend Test Suites (`backend/tests/`)
1. `test_phase14_trend_service.py`:
   - Historical snapshot aggregation.
   - Comparability calculation (fully comparable, partially comparable with config drift, non-comparable).
   - Defect velocity calculation (new vs. resolved).
   - Branch filtering.
2. `test_phase14_trend_api.py`:
   - `GET /api/v1/repositories/{id}/trends` returns HTTP 200.
   - Unknown repository returns HTTP 404.
   - Query filters (`branch`, `since`, `limit`).
   - Empty history returns empty trend DTO gracefully.
3. `test_phase14_boundary_independence.py`:
   - Verifies that new Phase 14 analyzer modules (`repo_config.py`, `file_loader.py`, `html_reporter.py`, `markdown_reporter.py`, `junit_reporter.py`, `gitlab_reporter.py`) have **strictly zero** imports of backend, database, Celery, or Redis.

### 21.3 Frontend Verification
- TypeScript strict typecheck: `npm.cmd run typecheck` (0 errors).
- Vite production build: `npm.cmd run build` (0 errors).

---

## 22. End-to-End Scenarios

### E2E Scenario 1: Developer Configuration & CLI Analysis
```text
Target Project Root
    ├── .codesentinel.yml (declares fail_on_severity: HIGH, disables ARC-004)
    └── src/
         └── main.py (contains SQL injection)

Command: codesentinel analyze .
1. Engine auto-discovers .codesentinel.yml.
2. Validates schema and computes config_hash.
3. Deactivates ARC-004; evaluates remaining 26 rules.
4. Detects SEC-PY-009 (SQL Injection, HIGH).
5. Triggers fail_on_severity policy.
6. Exits with code 2.
```

### E2E Scenario 2: Local Pre-Commit Hook Execution
```text
Developer stages code: git add src/api.py
Developer runs: git commit -m "update api"
1. Git pre-commit framework triggers `codesentinel analyze .`.
2. Analysis executes locally in 450ms. Zero network/database access.
3. Output reports 0 critical/high findings.
4. Hook exits with code 0; git commit completes successfully.
```

### E2E Scenario 3: Longitudinal Trend Tracking
```text
Day 1: Analysis #1 stored in PostgreSQL (Score: 78, 12 findings).
Day 2: Developer fixes 4 findings, adds new code.
Day 3: Analysis #2 stored in PostgreSQL (Score: 86, 9 findings: 1 new regression, 4 resolved).
API Request: GET /api/v1/repositories/{id}/trends
Response:
  • Health Delta: +8.0
  • Net Defect Velocity: -3 findings
  • Timeline: 2 points with full score and severity trajectories.
Frontend Dashboard: Trends tab renders interactive SVG line charts.
```

### E2E Scenario 4: CI/CD Multi-Target Artifact Generation
```text
GitHub Actions Runner executes:
  codesentinel analyze . --format sarif --output results.sarif
  codesentinel analyze . --format markdown --output summary.md
  codesentinel analyze . --format html --output report.html
1. All three formats generated from the identical canonical AnalysisResult.
2. SARIF uploaded to GitHub Security tab.
3. Markdown posted as Pull Request review comment.
4. HTML preserved as downloadable build artifact.
```

### E2E Scenario 5: Phase 13 Taint & Centrality in Longitudinal Trends
```text
Snapshot #1 contains ARC-009 (betweenness = 0.42) and SEC-PY-009 taint finding.
Developer refactors component into decoupled modules.
Snapshot #2: ARC-009 resolved (betweenness = 0.18); SEC-PY-009 parameterized.
Trend Service:
  • Flags ARC-009 as resolved component bottleneck.
  • Flags SEC-PY-009 as resolved taint finding.
  • Health Score increases by 10 points.
```

---

## 23. Documentation Updates

Upon Phase 14 implementation, the following documentation will be updated:
1. **`docs/ROADMAP.md`**: Mark Phase 14 as COMPLETE. Update overall project completion status.
2. **`docs/ARCHITECTURE.md`**: Document `.codesentinel.yml` configuration precedence and the longitudinal trend service architecture.
3. **`docs/CI_CD.md`**: Add pre-commit integration guides, GitLab CI Code Quality configuration, and GitHub Actions PR Markdown comment workflow.
4. **`docs/API.md`**: Document the `GET /api/v1/repositories/{id}/trends` endpoint, request parameters, and response schemas.
5. **`docs/README.md`**: Update getting started guide with `.codesentinel.yml` sample and pre-commit setup commands.

---

## 24. Work Breakdown Structure

The Phase 14 implementation is divided into 14 focused, sequential workstreams:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Phase 14 Work Breakdown                         │
├────────────────────────────────────────────────────────────────────────┤
│ Phase 14.1 : Repository Configuration Schema & Parser                  │
│              (analyzer/config/repo_config.py, file_loader.py)          │
│ Phase 14.2 : CLI Precedence & Config Integration                      │
│              (analyzer/cli/main.py, config resolution)                 │
│ Phase 14.3 : Database Migration for Trend Indexes                      │
│              (backend/alembic/versions/0005_phase14_trend_indexes.py)  │
│ Phase 14.4 : Longitudinal Trend Service                                │
│              (backend/app/services/trend_service.py)                   │
│ Phase 14.5 : Read-Only Trend API Endpoint                             │
│              (backend/app/api/v1/endpoints/trends.py, schemas)         │
│ Phase 14.6 : Markdown Reporter                                         │
│              (analyzer/reporting/markdown_reporter.py)                 │
│ Phase 14.7 : Standalone Interactive HTML Reporter                      │
│              (analyzer/reporting/html_reporter.py)                     │
│ Phase 14.8 : JUnit XML Reporter                                        │
│              (analyzer/reporting/junit_reporter.py)                    │
│ Phase 14.9 : GitLab Code Quality Reporter                              │
│              (analyzer/reporting/gitlab_reporter.py)                   │
│ Phase 14.10: Reporter Abstraction & CLI Output Formatting Extension   │
│              (analyzer/reporting/base.py, main.py --format choices)    │
│ Phase 14.11: Pre-Commit Integration                                    │
│              (.pre-commit-hooks.yaml, pre-commit tests)                │
│ Phase 14.12: Frontend Trend DTOs & API Client                          │
│              (frontend/src/types/api.ts, client.ts)                    │
│ Phase 14.13: Frontend Trend Dashboard & Pure SVG Charts                │
│              (frontend/src/components/trends/, App.tsx tab)            │
│ Phase 14.14: Full Verification, Documentation & Verification Report    │
│              (Pytest suites, Typecheck, Build, Docs updates)           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 25. Dependency Order

```
[Phase 14.1: Config Schema & Loader]
               │
               ▼
[Phase 14.2: CLI Config Precedence] ──────► [Phase 14.11: Pre-Commit Hooks]
               │
               ├──────────────────────────┐
               ▼                          ▼
[Phase 14.6 - 14.10: Reporters]   [Phase 14.3: DB Migration 0005]
(Markdown, HTML, JUnit, GitLab)           │
                                          ▼
                                  [Phase 14.4: Trend Service]
                                          │
                                          ▼
                                  [Phase 14.5: Trend API Endpoint]
                                          │
                                          ▼
                                  [Phase 14.12: Frontend API/DTOs]
                                          │
                                          ▼
                                  [Phase 14.13: Frontend Trend UI]
                                          │
                                          ▼
                                  [Phase 14.14: E2E Verification]
```

---

## 26. Non-Goals

To maintain strict architectural focus and prevent scope creep:
1. **No Remote GitHub/GitLab Cloning**: CodeSentinel operates strictly on local or CI-mounted filesystems. Remote API cloning and webhook daemons remain out of scope.
2. **No User Accounts, Authentication, or RBAC**: CodeSentinel is a local workstation and CI intelligence tool. Multi-tenant user login systems are not implemented.
3. **No Autonomous Patching or Auto-Remediation**: The engine identifies defects, generates reports, and suggests remediations; it never modifies repository source files automatically.
4. **No Heavy Third-Party Charting Bloat**: Frontend visualizations use pure React SVG instead of heavy external charting packages.
5. **No Second Database**: Historical trends rely 100% on Phase 10 PostgreSQL snapshot persistence.

---

## 27. Final Verification Matrix

| Subsystem | Test Command | Target / Success Criteria | Regression Risk |
| :--- | :--- | :--- | :--- |
| **Analyzer Config** | `pytest analyzer/tests/test_phase14_config*.py -v` | Validates YAML/JSON parsing, schema rules, hash computation. | Low |
| **CLI & Precedence** | `pytest analyzer/tests/test_phase14_cli*.py -v` | Validates CLI overrides YAML, exit codes 0/1/2 intact. | Medium (CLI flags) |
| **Reporters** | `pytest analyzer/tests/test_phase14_*reporter*.py -v`| Markdown, HTML, JUnit XML, GitLab JSON schema validity. | Low |
| **Pre-Commit** | `pytest analyzer/tests/test_phase14_precommit.py -v` | Validates offline execution, zero DB/network calls. | Low |
| **Analyzer Independence** | `pytest backend/tests/test_phase14_boundary*.py -v` | Proves 0 backend/DB/queue imports in `analyzer/`. | Critical |
| **Database Migration** | `alembic -c backend/alembic.ini upgrade head` | Revision `0005_phase14` applies cleanly to PostgreSQL. | Medium (Schema) |
| **Trend Service & API** | `pytest backend/tests/test_phase14_trend*.py -v` | Verifies comparability logic, trend deltas, 404 handling. | Low |
| **Full Analyzer Suite** | `pytest analyzer/tests -v` | All ~260+ tests pass with zero regressions. | High |
| **Full Backend Suite** | `pytest backend/tests -v` | All ~85+ tests pass with zero regressions. | High |
| **Frontend Typecheck** | `npm.cmd run typecheck` | Clean, 0 TypeScript errors. | Low |
| **Frontend Production Build** | `npm.cmd run build` | Vite builds production bundle in $< 5$s. | Low |

---

## 28. Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **PyYAML Missing in Environment** | Configuration file loader fails if developer provides `.codesentinel.yml` but PyYAML is not installed. | Support `.codesentinel.json` out-of-the-box via Python standard library `json`. Add `pyyaml>=6.0` to `analyzer/pyproject.toml`. Catch `ModuleNotFoundError` with a clear, actionable instruction. |
| **Large Report File Bloat** | Repositories with thousands of findings produce massive HTML/Markdown files. | Enforce finding truncation limits (top 25 in Markdown, collapsible virtualized DOM in HTML). Group findings by rule ID. |
| **Stored XSS in HTML Reports** | Malicious code in analyzed repository executes inside browser when viewing HTML report. | Enforce `html.escape(s, quote=True)` on every dynamic string and embed a strict `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';`. |
| **Slow Trend API on Large Histories** | Calculating trends across hundreds of snapshots causes latency. | Add database indexes (`ix_analysis_snapshots_repo_created`). Select only aggregate counter columns for the timeline. Clamp query `limit` to 200. |
| **Configuration Drift Obscuring Trends** | A developer disables rules or changes thresholds, creating artificial score improvements. | Track `config_hash`. Mark drifted snapshots with `config_drift: true` in the API and display clear UI warning badges. |

---

## 29. Implementation Checklist

- [ ] **Phase 14.1**: Create `analyzer/config/repo_config.py` and `analyzer/config/file_loader.py`.
- [ ] **Phase 14.2**: Update `analyzer/cli/main.py` with configuration loader and precedence resolution.
- [ ] **Phase 14.3**: Create Alembic migration `0005_phase14_trend_indexes.py` and execute upgrade.
- [ ] **Phase 14.4**: Implement `backend/app/services/trend_service.py` with comparability checks and delta calculations.
- [ ] **Phase 14.5**: Add endpoint `GET /api/v1/repositories/{repository_id}/trends` in `backend/app/api/v1/endpoints/trends.py`.
- [ ] **Phase 14.6**: Implement `analyzer/reporting/markdown_reporter.py` (PR comment summary).
- [ ] **Phase 14.7**: Implement `analyzer/reporting/html_reporter.py` (self-contained interactive HTML).
- [ ] **Phase 14.8**: Implement `analyzer/reporting/junit_reporter.py` (JUnit XML).
- [ ] **Phase 14.9**: Implement `analyzer/reporting/gitlab_reporter.py` (GitLab Code Quality JSON).
- [ ] **Phase 14.10**: Extend `analyzer/reporting/base.py` and register new formats in CLI `--format`.
- [ ] **Phase 14.11**: Create `.pre-commit-hooks.yaml` in repository root and add verification test.
- [ ] **Phase 14.12**: Define `LongitudinalTrendDTO` in `frontend/src/types/api.ts` and add API client method in `client.ts`.
- [ ] **Phase 14.13**: Create `TrendsView.tsx` with pure SVG charts and mount as 5th tab in `App.tsx`.
- [ ] **Phase 14.14**: Run full test suites, verify zero analyzer boundary leaks, update documentation, and verify build.
