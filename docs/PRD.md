# CodeSentinel — Product Requirements Document (PRD)

## 1. Executive Summary

**CodeSentinel** is an AI-assisted codebase architecture and security auditor. It evaluates source code using deterministic static analysis, Abstract Syntax Tree (AST) parsing, and dependency graph generation to identify security vulnerabilities, architectural anti-patterns, and code-quality issues. 

Unlike generic "AI-wrapper" tools that blindly pass raw source code to large language models, CodeSentinel establishes an evidence-first pipeline:
1. Deterministic and heuristic static analysis rules identify candidate findings with precise source code locations.
2. An architecture engine models dependency structures and flags structural anomalies (e.g., circular dependencies, tight coupling).
3. An LLM is utilized strictly for contextual validation, explanation, risk prioritization, and minimal remediation diff generation.

The LLM is **never** the primary or sole vulnerability detector.

---

## 2. Problem Statement & Value Proposition

### 2.1 The Problem
- **Traditional Static Analysis (SAST)** tools often generate high volumes of false positives, lack contextual architectural awareness, and present cryptic error outputs without actionable remediations.
- **Blind LLM Review Tools** suffer from hallucinations, non-deterministic audit results, severe context window exhaustion on large codebases, and significant privacy/confidentiality risks.
- **Architectural Erosion** (circular imports, god modules, hidden dependency chains) often goes unnoticed until runtime failures, testing bottlenecks, or security isolation breaches occur.

### 2.2 The Solution
CodeSentinel bridges deterministic rigor with targeted LLM assistance:
- **Reproducible Findings**: Candidate findings are grounded in AST and structural dependency evidence.
- **Context-Budgeted AI**: Only relevant code context (enclosing AST node, local imports, caller chain) is provided to the LLM for validation and remediation.
- **Clear Finding Classification**: All issues are strictly classified as **Deterministic**, **Heuristic**, or **AI-assisted**.
- **Interactive Developer Experience**: Integrated web dashboard providing dependency graph visualization, Monaco-based code inspection, and diff-ready remediation patches.

---

## 3. Target Personas

| Persona | Primary Goal | Pain Point Addressed |
| :--- | :--- | :--- |
| **Security Engineer** | Audit repositories for high-risk vulnerabilities (secrets, injection, CSRF, insecure configs). | Reduces triage time by filtering noise with deterministic AST rules and contextual AI explanations. |
| **Lead Software Architect** | Detect structural rot, circular dependencies, and monolithic component bloat. | Generates clear dependency graphs and architectural metrics without manual tracing. |
| **Full-Stack Developer** | Receive actionable, low-friction security feedback during code review and development. | Provides precise line references and verified minimal diff remediations rather than vague warnings. |

---

## 4. MVP Scope & Boundaries

### 4.1 In-Scope Languages & Frameworks (MVP)
The MVP targets modern full-stack web application codebases:
- **Languages**: Python, JavaScript, TypeScript
- **Backend Frameworks**: Django, Flask
- **Frontend Frameworks**: React

### 4.2 Non-Goals (MVP)
- Full polyglot coverage (e.g., C/C++, Java, Go, Rust are deferred to post-MVP).
- Dynamic Application Security Testing (DAST) or runtime fuzzing.
- Complete OWASP Top 10 coverage claims without empirical AST rule backing.
- Whole-repository indiscriminate LLM ingestion.
- Fully automated, unreviewed code mutation or auto-merging pull requests.

---

## 5. Core Functional Requirements

### 5.1 Ingestion & Discovery
- Accept local directory path or repository archive.
- Discover files while respecting `.gitignore`, `.sentinelignore`, and binary exclusions.
- Calculate basic repository metrics: file count, detected languages, lines of code (LOC).

### 5.2 Language & Framework Detection
- Detect primary and auxiliary languages based on file extensions, manifest files (`package.json`, `requirements.txt`, `pyproject.toml`), and syntax inspection.
- Detect frameworks: Django (`settings.py`, `manage.py`), Flask (`Flask(__name__)`), React (`react`, `react-dom` in manifests or JSX imports).

### 5.3 Deterministic & Heuristic Parsing
- Parse Python source into AST trees using native Python AST libraries.
- Parse JavaScript/TypeScript into structured AST representations.
- Extract file-level and module-level imports and exports.

### 5.4 Architecture & Dependency Graph
- Build directed dependency graph where nodes are modules/files and edges are import relationships.
- Detect circular dependency cycles.
- Identify module coupling, fan-in, and fan-out metrics.
- Detect architectural anti-patterns: circular dependencies, excessive fan-out, oversized modules, and React "god components".

### 5.5 Finding Classification Framework
All audit findings must declare their evidence source:
1. **Deterministic**: AST/rule-based evidence with explicit syntax match conditions (e.g., `shell=True` in `subprocess.call`, explicit `DEBUG = True` assignment).
2. **Heuristic**: Pattern/context-based analysis where confidence depends on available evidence (e.g., sensitive keys stored in `localStorage`, suspected raw SQL string concatenations).
3. **AI-assisted**: Contextual validation, false-positive reduction, natural-language explanation, and remediation patches generated by an LLM based on bounded AST context.

### 5.6 AI Enrichment Pipeline
- Extract minimal bounded context for each deterministic/heuristic candidate finding.
- Forward structured prompt to configured provider (OpenRouter or local Ollama).
- Enforce strict JSON output schema validation (Pydantic).
- Attach AI explanation, verification status (`CONFIRMED`, `PROBABLE_FALSE_POSITIVE`, `NEEDS_REVIEW`), and remediation patch to the finding.

### 5.7 User Interface & Dashboards
- **Dashboard**: Repository summary, risk score, severity distributions, and architecture metrics.
- **Finding Details**: Source location, rule ID, classification, severity, confidence, explanation, and diff remediation.
- **Architecture View**: Interactive dependency graph powered by React Flow with cycle highlighting.
- **Code Viewer**: Read-only Monaco code viewer displaying highlighted finding lines.

---

## 6. Non-Functional Requirements

- **Engine Decoupling**: The core analyzer package (`analyzer/`) must remain independent of any web framework (FastAPI) or database. It must be executable via Python scripts, worker tasks, or CLI tools.
- **Performance**: Analysis of a 500-file repository should complete deterministic static analysis and graph construction in under 30 seconds (excluding external LLM call latency).
- **Explainability**: Every finding must cite the exact rule ID, file, line number, source snippet, and evidence category.
- **Confidentiality**: Zero external data transmission unless AI enrichment is explicitly enabled. When enabled, only bounded AST snippets are transmitted—never the entire repository.

---

## 7. Success Metrics & KPIs

1. **Deterministic Accuracy**: Zero syntactic false positives for deterministic rules.
2. **Context Window Efficiency**: Average prompt token size under 2,000 tokens per finding.
3. **Actionability**: Over 80% of generated remediation diffs syntactically valid and targeted to the relevant block.
4. **Analysis Reliability**: Complete analysis execution without unhandled pipeline crashes on malformed source files.
