# CodeSentinel — Database Architecture & Schema Specification

## 1. Overview & Strategy

CodeSentinel uses **PostgreSQL 16** (with async SQLAlchemy 2.0 and Alembic) as its primary backend datastore for persisting completed analysis snapshots, repository catalogs, and historical audit records.

> [!IMPORTANT]
> **Core Architectural Invariant**: The analyzer engine (`analyzer/`) is strictly **database-independent, network-independent, and offline**. The analyzer executes static analysis and produces an immutable, strongly-typed `AnalysisResult`.
>
> The backend service (`backend/`) orchestrates persistence, converting canonical `AnalysisResult` instances into relational database snapshots and storing them within PostgreSQL. The analyzer can always be executed independently without any database running (`codesentinel analyze .`).

---

## 2. Entity-Relationship Diagram (ERD)

```mermaid
erDiagram
    REPOSITORIES ||--o{ ANALYSIS_SNAPSHOTS : has
    ANALYSIS_SNAPSHOTS ||--o{ FINDING_SNAPSHOTS : contains
    ANALYSIS_SNAPSHOTS ||--o{ HEALTH_DEDUCTION_SNAPSHOTS : records
    ANALYSIS_SNAPSHOTS ||--o{ COMPONENT_SNAPSHOTS : aggregates
    ANALYSIS_SNAPSHOTS ||--o{ COMPONENT_EDGE_SNAPSHOTS : interconnects

    REPOSITORIES {
        string id PK "UUID"
        string name "Repository display name"
        string path UK "Canonical absolute path"
        timestamp created_at "Registration time (UTC)"
        timestamp updated_at "Last update time (UTC)"
    }

    ANALYSIS_SNAPSHOTS {
        string id PK "Matches AnalysisResult.id"
        string repository_id FK "References repositories.id"
        timestamp created_at "Run completion time (UTC)"
        string commit_hash "Git commit SHA"
        string branch "Git branch"
        boolean is_dirty "Uncommitted changes"
        string analyzer_version "Engine version (0.1.0)"
        string status "COMPLETED"
        float duration_seconds "Execution time"
        integer total_files "Scanned files"
        integer total_loc "Total LOC"
        json configuration "Serialized AnalysisConfig"
        float overall_score "Health score (0-100)"
        string overall_grade "Grade (A, B, C, D, F)"
        float architecture_score "Architecture health"
        string architecture_grade "Architecture grade"
        float security_score "Security posture"
        string security_grade "Security grade"
        integer total_deductions_count "Deductions count"
        text health_summary "Human readable summary"
        integer total_findings "Findings count"
        integer critical_count "Critical findings"
        integer high_count "High findings"
        integer medium_count "Medium findings"
        integer low_count "Low findings"
        integer info_count "Info findings"
        integer circular_dependencies_count "Module cycles"
        integer circular_components_count "Component cycles"
        json diagnostics_payload "Resolution diagnostics"
    }

    FINDING_SNAPSHOTS {
        string id PK "Row UUID"
        string snapshot_id FK "References analysis_snapshots.id"
        string finding_uuid "Deterministic finding UUID"
        string rule_id "SEC-PY-001, ARC-001..."
        string rule_name "Rule display title"
        string category "SECURITY | ARCHITECTURE"
        string severity "CRITICAL | HIGH | MEDIUM | LOW | INFO"
        string confidence "HIGH | MEDIUM | LOW"
        text message "Finding message"
        text description "Detailed explanation"
        text remediation "Remediation guidance"
        string file_path "Repo-relative file path"
        integer line_start "Starting line"
        integer line_end "Ending line"
        integer column_start "Starting column"
        integer column_end "Ending column"
        text snippet "Code extract (redacted for secrets)"
        string language "Syntax highlight mode"
        json evidence "Structured evidence dictionary"
        string cwe_id "CWE classification"
        string owasp_category "OWASP classification"
    }

    HEALTH_DEDUCTION_SNAPSHOTS {
        string id PK "Row UUID"
        string snapshot_id FK "References analysis_snapshots.id"
        string category "SECURITY | ARCHITECTURE"
        string rule_id "Rule ID causing deduction"
        float points_deducted "Point penalty"
        text reason "Explanation of deduction"
        string finding_id "Associated finding UUID"
        integer item_count "Count of occurrences"
    }

    COMPONENT_SNAPSHOTS {
        string id PK "Row UUID"
        string snapshot_id FK "References analysis_snapshots.id"
        string component_id "Dot-separated component ID"
        string name "Component display name"
        string path "Directory path"
        string layer "Inferred layer"
        integer afferent_coupling "Ca"
        integer efferent_coupling "Ce"
        float instability "I = Ce / (Ca + Ce)"
        integer total_loc "Component LOC"
        integer file_count "Component file count"
        json files "List of file paths"
    }

    COMPONENT_EDGE_SNAPSHOTS {
        string id PK "Row UUID"
        string snapshot_id FK "References analysis_snapshots.id"
        string edge_id "Unique edge ID"
        string source_component_id "Source component ID"
        string target_component_id "Target component ID"
        integer weight "File dependency count"
        boolean is_circular "Cycle member flag"
    }
```

---

## 3. Immutability & Snapshot Principles

1. **Append-Only History**: Analysis snapshots represent historical points in time. Once an `AnalysisSnapshot` and its child records are written to PostgreSQL, they are **never mutated**.
2. **No Mutable "Latest" Pointer**: The repository does not store a mutable `latest_analysis_id` column as the source of truth. Historical queries order snapshots by `created_at DESC` and address snapshots by their explicit run ID.
3. **Repository Updates**: Modifying a repository's display name or updating registration details does not alter historical analysis snapshots.
4. **Cascade Deletion**: When an operator unregisters a repository (`DELETE /api/v1/repositories/{id}`), PostgreSQL foreign key constraints (`ON DELETE CASCADE`) remove all associated historical snapshots and child tables atomically.
5. **Secret Redaction**: Finding snippets that originate from secret-detection rules (such as `SEC-PY-001` or `SEC-JS-004`) are automatically sanitized before persistence so credentials are not permanently committed to database tables.

---

## 4. Alembic Migration Strategy

Database migrations are managed by **Alembic** under `backend/alembic/`.

### Migration Commands

Run migrations to update schema to latest version:
```bash
alembic -c backend/alembic.ini upgrade head
```

Revert migration to initial empty state:
```bash
alembic -c backend/alembic.ini downgrade base
```

Create a new schema revision:
```bash
alembic -c backend/alembic.ini revision -m "description_of_change"
```

---

## 5. Local Development & Configuration

Configure the database connection via `.env` or environment variables:

```env
DATABASE_URL=postgresql+asyncpg://codesentinel:codesentinel@localhost:5432/codesentinel
DATABASE_ECHO=false
```

For zero-dependency unit and integration testing, SQLAlchemy seamlessly supports SQLite:
```env
DATABASE_URL=sqlite+aiosqlite:///:memory:
```
All tables use standard SQLAlchemy `JSON` types which serialize transparently to PostgreSQL `JSONB` in production and SQLite JSON text in local tests.
