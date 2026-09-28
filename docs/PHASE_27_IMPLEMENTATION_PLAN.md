# PHASE 27 IMPLEMENTATION PLAN — Compliance Assurance, Standards Validation & Governance Hardening

## 1. Executive Summary

Phase 26 introduced the architectural foundations of regulatory compliance mapping (PCI-DSS v4.0, HIPAA Security Rule, SOC 2 TSC, NIST SP 800-53 Rev 5), in-toto / DSSE scan attestations, hash-chained audit trails, multi-format regulatory reporting (CycloneDX, OpenXML Excel, PDF), and hierarchical rule pack resolution.

However, a rigorous technical inspection of the repository reveals critical semantic, standards-conformance, and cryptographic gaps between the Phase 26 initial implementation and enterprise audit-grade reality:
1. **Semantic Conflation of "No Findings" with "Compliance"**: In `analyzer/compliance/evaluator.py`, any compliance control with zero detected findings is automatically marked `COMPLIANT` with a score of `1.0`. In static application security testing (SAST), **absence of a detected violation is not proof of requirement satisfaction**, particularly when static analysis covers only a tiny subset of an enterprise control or when target code lacks relevant entry points.
2. **Conflation of Finding Suppression with Partial Compliance**: Findings suppressed via inline annotations or config exclusions automatically transition controls to `PARTIALLY_COMPLIANT` with an arbitrary hardcoded score of `0.8`. Suppressions are developer triage dispositions; they do not equate to authorized regulatory compensating controls.
3. **Cryptographic & Standards Discrepancies**:
   - The attestation claims **RFC 8785** canonical JSON, but actually uses standard Python `json.dumps(sort_keys=True)`.
   - The Merkle root calculation concatenates hex strings instead of raw binary digests with domain separation prefixes, leaving it exposed to structural ambiguities.
   - The DSSE envelope uses symmetric HMAC-SHA256 with a default hardcoded secret in the CLI (`"default-enterprise-secret"`), providing tamper detection but **zero non-repudiation**.
   - The audit ledger uses random `uuid4()` identifiers that are omitted from the cryptographic hash preimage, and lacks ledger identity (`chain_id`), genesis binding, and truncation detection.
4. **Report Vulnerabilities & Inaccuracies**:
   - The OpenXML Excel reporter escapes XML entities but does **not** protect against Spreadsheet Formula Injection (CWE-1236) on user-controlled finding text starting with `=`, `+`, `-`, or `@`.
   - The CycloneDX reporter outputs a hybrid VEX document with only vulnerable files under `components`, lacking schema validation and full SBOM inventory.
   - The PDF generator forces `latin-1` encoding with character replacement, discarding non-ASCII Unicode and lacking word-wrapping for long paths or descriptions.
5. **Architectural & Persistence Disconnect**:
   - `AnalysisSnapshot` in the backend database does not persist `compliance` or `attestation` structures, causing all compliance data to be lost upon persistence.
   - Incremental config fingerprinting does not hash rule pack contents or compliance catalog versions.

Phase 27 is **not** designed to add another sprawling feature layer. The objective of Phase 27 is **assurance, validation, and governance hardening**: establishing semantic precision, standards compliance, historical reproducibility, cryptographic integrity, and absolute honesty regarding what static analysis can and cannot establish.

---

## 2. Current Phase 26 Findings & Reconciliation

The table below reconciles the claims made in the Phase 26 documentation with the actual code in the repository.

| Architectural Component | Phase 26 Claim | Actual Repository Implementation | Classification | Technical Impact / Risk |
| :--- | :--- | :--- | :--- | :--- |
| **Control Compliance Semantics** | Evaluates controls as `COMPLIANT`, `PARTIAL`, `NON_COMPLIANT`. | Evaluates status strictly by finding count: 0 findings = `COMPLIANT` (1.0); suppressed findings = `PARTIAL` (0.8); active findings = `NON_COMPLIANT` (degraded by 0.2/viol). | **PARTIALLY_IMPLEMENTED** | Falsely certifies unassessed or non-applicable code as compliant. Conflates suppression with regulatory exception. |
| **Proof-Obligation Integration** | Integrates Phase 24 proof obligations into control scoring. | Reads `proof_obligations` list in finding evidence and tallies states, but does not use them to establish `PROVEN_SAFE` compliance. | **PARTIALLY_IMPLEMENTED** | Fails to leverage Phase 24 semantic proofs to verify compliance invariants. |
| **Catalog Metadata & Limitations** | Full regulatory catalogs for PCI-DSS, HIPAA, SOC 2, NIST. | 16 controls across 4 frameworks with hardcoded titles, sections, descriptions, and rule mappings. Missing framework versions, mapping types, and static limitations. | **PARTIALLY_IMPLEMENTED** | Overclaims regulatory compliance; does not explain that source analysis cannot assess administrative or operational controls. |
| **in-toto v1.0 Statement** | Conforms to in-toto v1.0 Statement envelope. | Defines `_type`, `subject`, `predicateType`, `predicate`. In Pydantic v2, `_type` is excluded by default in `model_dump()`, causing invalid in-toto serialization. | **PARTIALLY_IMPLEMENTED** | Generated JSON may omit the mandatory `_type` field when serialized to canonical bytes. |
| **DSSE Envelope** | Dead Simple Signing Envelope specification. | Implements PAE pre-image string formatting and base64 payload/signature wrapping. | **IMPLEMENTED** | Functionally wraps payload, but uses symmetric HMAC rather than asymmetric public-key cryptography. |
| **RFC 8785 Canonical JSON** | Serializes objects to canonical RFC 8785 JSON bytes. | Uses `json.dumps(data_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")`. | **PARTIALLY_IMPLEMENTED** | Fails RFC 8785 ECMAScript float formatting, Unicode normalization (NFC), and surrogate handling. |
| **Merkle Tree Root** | Deterministic SHA-256 binary Merkle root over findings. | Computes leaf hashes, sorts them alphabetically, and recursively pairwise hashes concatenated hex strings. | **PARTIALLY_IMPLEMENTED** | Pairwise reduction exists, but string concatenation without domain separation leaves Merkle proofs vulnerable to collision/second-preimage attacks. |
| **HMAC Trust Model** | Cryptographically verifiable scan attestation. | Uses symmetric HMAC-SHA256 with hardcoded CLI default key `"default-enterprise-secret"`. | **IMPLEMENTED** | Provides integrity against external tampering if key is secret, but zero non-repudiation. Insecure default key. |
| **Audit Ledger Hash Chain** | Tamper-evident hash-chained audit ledger. | Links `AuditEvent` via SHA-256 hash of `seq|ts|evt_type|actor|details|prev_hash`. | **IMPLEMENTED** | Hash chaining works, but `event_id` (random `uuid4`) is omitted from hash preimage; no ledger root commit; vulnerable to truncation and replay. |
| **CycloneDX 1.6 Reporter** | CycloneDX 1.6 VEX and SBOM reporter. | Generates JSON with components and vulnerabilities with VEX analysis states. | **PARTIALLY_IMPLEMENTED** | Only lists files with findings under `components` (not an SBOM). Nondeterministic `uuid4` serialNumber. No schema validation. |
| **OpenXML Excel Reporter** | Valid OpenXML (.xlsx) multi-tab workbook. | Builds ZIP archive containing `[Content_Types].xml`, `workbook.xml`, `styles.xml`, and sheet XMLs using Python `zipfile`. | **IMPLEMENTED** | Generates valid workbooks, but vulnerable to formula injection (CWE-1236) and XML 1.0 invalid control character crashes. |
| **Executive PDF Reporter** | Deterministic pure-Python PDF 1.4 compiler. | Emits PDF 1.4 binary objects, cross-reference table, and text streams with Type 1 Helvetica font. | **IMPLEMENTED** | Valid minimal PDF, but forces Latin-1 replacement (breaks Unicode) and lacks text wrapping / robust pagination. |
| **Rule Pack Inheritance & DAG** | Multi-parent DAG resolution with cycle detection. | Implements DFS traversal, cycle detection, and monotonic check for `enabled` and `severity_override`. | **IMPLEMENTED** | DAG resolution works, but `ResolvedRulePackConfig` has no canonical hash. Parameter overrides and gate policies can be relaxed by children. |
| **Database Persistence** | Integrated with CodeSentinel backend. | Endpoints `/frameworks`, `/controls`, `/packs`, `/verify-attestation` implemented. | **PARTIALLY_IMPLEMENTED** | Endpoints are stateless query endpoints. `AnalysisSnapshot` entity does not store compliance results or attestations. |
| **Frontend UI** | Visual compliance cards and dashboards. | No compliance UI exists in `frontend/src/`. | **NOT_IMPLEMENTED** | Compliance results cannot be viewed in the web interface. |

---

## 3. Repository Inspection Results

### 3.1 Compliance Engine (`analyzer/compliance/`)
- `models.py`:
  - `ComplianceFramework`: String enum (`PCI_DSS_V4_0`, `HIPAA_SECURITY`, `SOC2_TSC`, `NIST_SP_800_53_R5`).
  - `ComplianceStatus`: 4 enum values (`COMPLIANT`, `NON_COMPLIANT`, `PARTIALLY_COMPLIANT` / `PARTIAL`, `NOT_APPLICABLE`). Missing `PROVEN`, `VIOLATED`, `UNKNOWN`, `NOT_ASSESSED`.
  - `ComplianceControl`: Lacks `framework_version`, `mapping_type`, `assessment_scope`, and `limitations`.
- `evaluator.py`:
  - Line 93: `if active_viols == 0 and supp_viols == 0: status = ComplianceStatus.COMPLIANT; score = 1.0`. This is the fundamental defect: a repository with zero lines of code or zero relevant endpoints is declared 100% compliant with PCI-DSS Requirement 6.
  - Line 102: `score = max(0.0, 1.0 - (0.2 * active_viols))` is an uncalibrated heuristic.
  - Framework score: `overall_pct = round((total_score_acc / total_ctrls) * 100.0, 1)`. Unweighted arithmetic mean treats a low-priority documentation hygiene control identically to a critical injection vulnerability.

### 3.2 Attestation & Audit Trail (`analyzer/compliance/attestation.py`, `audit_trail.py`)
- `attestation.py`:
  - `canonical_json_bytes()`: Calls `data.model_dump(exclude_none=True)` then `json.dumps(..., sort_keys=True)`. In Pydantic, private fields starting with `_` (such as `_type`) are skipped by default.
  - `compute_findings_merkle_root()`: Pairwise hashes hex strings: `hashlib.sha256((left + right).encode("utf-8")).hexdigest()`. Odd-length levels duplicate the left node: `right = current_level[i + 1] if i + 1 < len(current_level) else left`. This is susceptible to CVE-2012-2459 style duplicate-leaf denial-of-service/malleability without length padding or tree height tagging.
  - `sign_attestation()` / `verify_attestation()`: Correctly implements DSSE PAE format, but relies exclusively on symmetric HMAC.
- `audit_trail.py`:
  - `AuditEvent.event_id`: Initialized via `str(uuid.uuid4())`. This creates nondeterministic events and prevents reproducible audit verification across re-scans.
  - `_compute_event_hash()`: Omits `event_id` from the preimage string `f"{seq}|{ts}|{evt_type}|{actor}|{serialized_details}|{prev_hash}"`.

### 3.3 Rule Pack Composition (`analyzer/rules/rule_pack.py`, `pack_resolver.py`)
- `pack_resolver.py`:
  - Monotonicity only checks `enabled=False` and demotion of `severity_override`.
  - If a parent pack defines `max_taint_depth: 25`, a child pack can specify `max_taint_depth: 5` (weakening analysis) without triggering `MonotonicPolicyViolationError`.
  - If a parent pack defines `gate_policy: {"fail_on_severity": "HIGH"}`, line 154 overrides it entirely with child's `gate_policy`.

### 3.4 Reporters (`analyzer/reporting/`)
- `cyclonedx_reporter.py`: Produces `urn:uuid:{uuid.uuid4()}` for `serialNumber`, breaking reproducible build and byte determinism requirements.
- `excel_reporter.py`: Directly writes strings to `<t>{escaped_str}</t>` without formula character checking (`=`, `+`, `-`, `@`).
- `pdf_reporter.py`: Does not wrap text; strings exceeding page boundaries are clipped invisibly. Non-Latin-1 characters are replaced with `?`.

### 3.5 Persistence & Incremental Cache
- `backend/app/models/snapshot.py`: `AnalysisSnapshot` schema has columns for scores, grades, and diagnostics, but zero columns or relationships for compliance results.
- `analyzer/incremental/config_fingerprint.py`:
  - `rule_pack_hash`: Only hashes pack IDs (`["pci-dss-v4"]`), not the actual pack YAML definitions or resolved overrides.
  - `compliance_hash`: Only hashes requested framework names and minimum score threshold, not catalog contents or mapping versions.
  - `global_hash`: Does **not** include `rule_pack_hash` or `compliance_hash`.

---

## 4. Goals

1. **Conservative Compliance Semantics**: Establish a 5-state control assessment model (`PROVEN`, `VIOLATED`, `PARTIAL`, `UNKNOWN`, `NOT_ASSESSED`) that strictly separates static proof, detected violations, missing coverage, and suppression exceptions.
2. **Explicit Regulatory Scope & Limitations**: Enrich every framework and control mapping with precise metadata documenting what static analysis assesses, what it cannot assess, and its exact mapping classification (`DIRECT`, `SUPPORTING`, `PARTIAL`, `INFERRED`, `NOT_ASSESSABLE`).
3. **Rigorous Standards Conformance**:
   - Validate in-toto v1.0 Statement serialization (ensuring `_type` is correctly emitted).
   - Implement RFC 8785 compliant canonical JSON serialization.
   - Refactor Merkle tree digest computation with binary pairwise hashing and domain separation prefixes (`\x00` leaf, `\x01` interior node).
   - Harden DSSE envelope signing with key metadata, rotation support, and strict elimination of hardcoded default secrets.
4. **Tamper-Evident Audit Trail Hardening**: Bind audit ledgers to a unique `chain_id` / repository root, eliminate nondeterministic `uuid4` IDs, include all fields in event hash preimages, and detect truncation, reordering, and event insertion.
5. **Immutable Historical Evaluations**: Ensure compliance evaluations are permanently bound to historical analysis snapshots and cannot be retroactively mutated when suppressions expire or catalogs evolve.
6. **Robust Rule Pack Governance**: Implement canonical `resolved_pack_hash` computation and exhaustive field-by-field monotonic strictness enforcement.
7. **Secure Multi-Format Reporting**: Implement CWE-1236 formula sanitization in Excel, JSON schema validation and true SBOM component inventory in CycloneDX, and robust text-wrapping/Unicode handling in PDF.
8. **Incremental Cache Integrity**: Incorporate resolved rule pack hashes, catalog versions, and mapping digests into scoped incremental cache invalidation.
9. **Zero-Migration Snapshot Persistence**: Store compliance suites and attestations cleanly in existing backend analysis structures without breaking migrations.

---

## 5. Non-Goals

- **No Automated Regulatory Certification**: CodeSentinel will not generate certificates claiming "PCI-DSS Compliant" or "SOC 2 Type II Certified".
- **No Replacement for Human Auditors**: The tool produces technical audit evidence and gap analysis, not an independent auditor's report.
- **No Assessment of Non-Technical Safeguards**: CodeSentinel will not attempt to assess administrative policies, background checks, disaster recovery plans, or physical facility security.
- **No Public-Key Infrastructure (PKI) Engine**: Phase 27 will harden symmetric HMAC and prepare DSSE for asymmetric keys, but will not implement an internal CA, X.509 certificate chain validator, or Key Management Service (KMS).
- **No Arbitrary Remote Rule Pack Loading**: Rule packs must be loaded from local files or verified built-in catalogs; no dynamic unauthenticated downloading from remote URLs.
- **No AI / LLM Evaluation**: All compliance mapping, evaluation, scoring, and attestation remains 100% offline, deterministic, and rule-based.

---

## 6. Compliance Assessment Semantic Model

### 6.1 The Core Principle

$$\text{No Detected Violation} \neq \text{Static Evidence Supports Requirement} \neq \text{Control Fully Assessed} \neq \text{Regulatory Compliance Established}$$

CodeSentinel must explicitly distinguish between:
1. **Finding Status** (the lifecycle state of an individual finding).
2. **Proof Obligation State** (the formal verification outcome of a security invariant).
3. **Control Assessment Status** (the technical posture of a specific regulatory requirement).
4. **Regulatory Certification** (an organizational determination outside the scope of SAST).

### 6.2 State Machine & Taxonomies

#### A. Technical Finding Status (`FindingLifecycleState` - Phase 25)
- `ACTIVE`: Detected violation present in current codebase, unsuppressed.
- `SUPPRESSED`: Finding matched by an active, unexpired developer suppression.
- `RESOLVED`: Finding previously detected but absent in current code.
- `EXPIRED_SUPPRESSION`: Finding formerly suppressed whose expiration date has passed (`now > expires_at`), reverting to `ACTIVE`.

#### B. Proof Obligation State (`ObligationEvaluationState` - Phase 24)
- `PROVEN_SAFE`: Mathematical dataflow/boundary proof establishes the invariant holds across all paths.
- `PROVEN_VIOLATION`: Counter-example path discovered reaching sink without required property.
- `UNKNOWN`: Path explosion, dynamic dispatch, or external library call prevented conclusive proof.

#### C. Control Assessment Status (`ControlAssessmentStatus` - New in Phase 27)

```
                                  ┌────────────────────────┐
                                  │      NOT_ASSESSED      │ (No rules mapped or tech stack unhandled)
                                  └────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │ Check Mapped Rules & Obligations │
                              └──────────────────────────────────┘
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
     [ Active Violations > 0 ]      [ Active = 0, Suppressed > 0 ]   [ Active = 0, Suppressed = 0 ]
               │                               │                               │
               ▼                               ▼                               ▼
        ┌──────────────┐               ┌───────────────┐              ┌──────────────────┐
        │   VIOLATED   │               │    PARTIAL    │              │ Are Obligations  │
        └──────────────┘               │ (Under Triage)│              │  PROVEN_SAFE?    │
                                       └───────────────┘              └────────┬─────────┘
                                                                               │
                                                       ┌───────────────────────┴───────────────────────┐
                                                       ▼                                               ▼
                                              [ All PROVEN_SAFE ]                            [ Insufficient Proof ]
                                                       │                                               │
                                                       ▼                                               ▼
                                                ┌──────────────┐                               ┌───────────────┐
                                                │    PROVEN    │                               │    UNKNOWN    │
                                                │ (Compliant)  │                               │(Inconclusive) │
                                                └──────────────┘                               └───────────────┘
```

1. **`PROVEN`**:
   - Active violations: 0.
   - Suppressed violations: 0.
   - Required proof obligations: At least one mapped policy proof obligation exists and **100% of evaluated obligations are `PROVEN_SAFE`**.
2. **`VIOLATED`**:
   - One or more unsuppressed findings directly violate the mapped rules or policies.
3. **`PARTIAL`**:
   - Active unsuppressed violations: 0.
   - Suppressed violations: $\ge 1$.
   - The codebase contains known violations that have been suppressed or deferred. The control is **not** compliant, but under acknowledged operational exception.
4. **`UNKNOWN`**:
   - Active violations: 0.
   - Suppressed violations: 0.
   - No active violations were detected, but **no formal static proof (`PROVEN_SAFE`) was established** (e.g., negative heuristic only, or taint analysis encountered an unresolved boundary).
5. **`NOT_ASSESSED`**:
   - The scanned repository does not use the framework or language relevant to the control (e.g., assessing Flask SQL controls on a pure React frontend), or the control requires manual/organizational verification.

### 6.3 Decoupling Suppressions from Control Compliance

Under no circumstances should a suppression automatically grant "80% compliance":
- A suppression is an **exception ticket**, not a security control.
- In reports, `PARTIAL` controls must display:
  - Number of suppressed findings.
  - Justification and expiration date.
  - Explicit warning: *"Control contains active exceptions. Authorized auditor review required."*

---

## 7. Regulatory Mapping Provenance

### 7.1 Mapping Provenance Schema

To answer an auditor's question (*"Why does CodeSentinel claim this rule maps to this control?"*), every control definition must include immutable provenance:

```python
class MappingType(str, Enum):
    DIRECT = "DIRECT"                # Rule detects exact vulnerability prohibited by control (e.g., SQLi -> PCI 6.2.4)
    SUPPORTING = "SUPPORTING"        # Rule provides hygiene evidence (e.g., circular dep -> PCI 6.3.2 architecture)
    PARTIAL = "PARTIAL"              # Rule covers only one specific clause of a compound regulatory requirement
    INFERRED = "INFERRED"            # Rule infers requirement satisfaction via framework defaults
    NOT_ASSESSABLE = "NOT_ASSESSABLE"# Control cannot be verified via static code analysis

class ControlProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)
    catalog_version: str = "2026.1"
    source_standard: str             # e.g., "PCI-DSS v4.0", "NIST SP 800-53 Rev 5"
    official_reference: str          # e.g., "Section 6.2.4, Page 58"
    requirement_summary: str
    mapping_type: MappingType
    static_analysis_scope: str       # Exact scope of what the AST/taint engine analyzes
    static_limitations: list[str]    # Explicit list of what static analysis CANNOT verify
    auditor_notes: str
```

### 7.2 Framework-Specific Boundaries

#### 1. PCI-DSS v4.0
- **What CodeSentinel Evaluates**: Technical code vulnerabilities prohibited under Requirement 6 (injection, XSS, insecure dependencies, CORS misconfigurations) and Requirement 3 (hardcoded credentials, weak cryptographic hashes).
- **Explicit Limitations**: Cannot verify Requirement 8 password complexity policies, multi-factor hardware keys, quarterly external ASV network scans, penetration tests, or physical access controls to cardholder data environments (CDE).

#### 2. HIPAA Security Rule (45 CFR Part 164 Subpart C)
- **What CodeSentinel Evaluates**: Technical safeguards under § 164.312 (transmission security encryption algorithms, access control authorization decorators on patient data mutation endpoints, integrity validation).
- **Explicit Limitations**: Cannot verify § 164.308 administrative safeguards (Business Associate Agreements, security management process, workforce training) or § 164.310 physical safeguards (workstation use, device media controls).

#### 3. SOC 2 Type II (Trust Services Criteria)
- **What CodeSentinel Evaluates**: Technical evidence supporting CC6.1 (logical access controls), CC6.6 (boundary protection and logical segmentation), CC6.8 (unauthorized mobile code/command execution prevention), and CC7.1 (vulnerability identification).
- **Explicit Limitations**: CodeSentinel provides technical evidence artifacts; it **does not** replace an independent AICPA SOC 2 Type II examination, which audits operational effectiveness over a 6-to-12 month evaluation window.

#### 4. NIST SP 800-53 Rev. 5
- **What CodeSentinel Evaluates**: Software-level implementation of AC-3 (Access Enforcement), IA-5 (Authenticator Management), SC-8 (Transmission Confidentiality), SC-13 (Cryptographic Protection), and SI-10 (Information Input Validation).
- **Explicit Limitations**: Does not assess organizational policies, contingency planning (CP), incident response (IR), physical protection (PE), or personnel security (PS).

---

## 8. Attestation Standards Validation

### 8.1 in-toto v1.0 Statement Conformance

The attestation statement structure must strictly conform to [in-toto Statement Specification v1.0](https://github.com/in-toto/attestation/blob/main/spec/v1.0/statement.md):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "repository-name",
      "digest": {
        "gitCommit": "a1b2c3d4e5f6..."
      }
    }
  ],
  "predicateType": "https://codesentinel.dev/attestation/compliance/v1",
  "predicate": { ... }
}
```

- **Fix Required**: In Pydantic v2, fields with a leading underscore are treated as private attributes and omitted from `model_dump()`.
- **Solution**: Define the field using an alias:
  ```python
  class ScanAttestationStatement(BaseModel):
      model_config = ConfigDict(frozen=True, populate_by_name=True)
      type_: str = Field(default="https://in-toto.io/Statement/v1", alias="_type")
      subject: list[SubjectEntry]
      predicateType: str
      predicate: AttestationPredicate
  ```

### 8.2 DSSE (Dead Simple Signing Envelope) Specification

Conform strictly to the [DSSE Envelope Spec](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md):
- **Envelope Structure**:
  ```json
  {
    "payload": "<base64-encoded canonical in-toto statement>",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": [
      {
        "keyid": "codesentinel-key-2026-01",
        "sig": "<base64-encoded signature>"
      }
    ]
  }
  ```
- **Pre-Authentication Encoding (PAE)**:
  $$\text{PAE}(type, payload) = \text{"DSSEv1 "} + \text{len}(type) + \text{" "} + type + \text{" "} + \text{len}(payload) + \text{" "} + payload$$
- Verification must ensure byte-length fields in PAE match UTF-8 byte lengths, not string character counts.

### 8.3 True RFC 8785 Canonical JSON Serialization

Standard `json.dumps(sort_keys=True)` does not satisfy [RFC 8785 (JSON Canonicalization Scheme - JCS)](https://datatracker.ietf.org/doc/html/rfc8785).
Phase 27 will implement a deterministic JCS serializer:
1. **Object Key Sorting**: Sort keys by UTF-16 code units (or lexicographical byte sequence of UTF-8 representation).
2. **Whitespace**: No whitespace outside of string literals (separators `,` and `:` without spaces).
3. **Number Formatting**:
   - Integers: No leading zeros, no trailing `.0`.
   - IEEE 754 64-bit binary floating-point numbers formatted according to ECMAScript canonical representation (no `+` in exponent, shortest representation).
4. **String Escaping**: Only escape quotation mark (`\"`), reverse solidus (`\\`), and control characters (`\u0000` through `\u001f`). Do not escape solidus (`/`).
5. **Unicode Normalization**: Canonicalize string representations to Unicode Normalization Form C (NFC) prior to hashing.

### 8.4 Cryptographically Sound Merkle Root Algorithm

Replace the insecure string-concatenation Merkle reduction with RFC 6962 / Certificate Transparency standard domain-separated hashing:
1. **Leaf Hash**:
   $$\text{LeafHash}(f) = \text{SHA-256}(\mathtt{0x00} \parallel \text{CanonicalJCS}(f.\text{fingerprint}))$$
2. **Interior Node Hash**:
   $$\text{NodeHash}(L, R) = \text{SHA-256}(\mathtt{0x01} \parallel L \parallel R)$$
   *(where $L$ and $R$ are raw 32-byte binary digests, not hex strings)*.
3. **Odd-Node Handling**: When a level has an odd number of nodes, do **not** duplicate the node (which creates second-preimage vulnerabilities). Carry the solitary node up to the next level unchanged or apply length-prefixed tree balancing.

### 8.5 HMAC Security & Trust Model

1. **Symmetric Cryptography Limitations**:
   - HMAC-SHA256 provides **tamper evidence** against untrusted third parties as long as the secret is confidential.
   - HMAC **cannot provide non-repudiation**; anyone possessing the secret key can forge an attestation.
   - Phase 27 will document this explicitly in attestation output metadata:
     `"cryptographic_assurance": "SYMMETRIC_AUTHENTICATION_ONLY"`
2. **Secret Management & Hardening**:
   - **Remove Hardcoded Default Key**: Prohibit `"default-enterprise-secret"`. If `--key` or `CODESENTINEL_SIGNING_KEY` is not provided, attestation generation must fail with exit code 1.
   - **Key Metadata**: Require `--key-id` (e.g., `prod-ci-2026-q3`).
   - **Redaction**: Zeroize keys in memory where practical; ensure secret keys are excluded from logs, error messages, and debug dumps.

---

## 9. Audit Trail Hardening

### 9.1 Root of Trust & Chain Identity

The current audit ledger cannot detect if an entire ledger from `repo-A` is substituted for `repo-B`. Phase 27 introduces a cryptographically bound Genesis Header:

```json
{
  "genesis": {
    "chain_id": "sha256-digest-of(repo_id + analysis_id + start_timestamp)",
    "chain_version": "1.0",
    "repository_id": "org/repo-name",
    "commit_hash": "a1b2c3d...",
    "tool_version": "0.1.0"
  }
}
```

- **Genesis Hash**: $\text{Hash}_0 = \text{SHA-256}(\mathtt{0x02} \parallel \text{CanonicalJCS}(\text{genesis}))$.
- **Chain Continuity**: Every subsequent event must embed `chain_id`.

### 9.2 Complete Preimage Hashing & Determinism

1. **Eliminate `uuid4()`**: Replace random event IDs with deterministic sequential hashes:
   $$\text{event\_id} = \text{SHA-256}(\text{chain\_id} \parallel \text{seq\_number})[:16]$$
2. **Preimage Invariant**:
   $$\text{event\_hash} = \text{SHA-256}(\text{seq} \parallel \text{timestamp} \parallel \text{event\_type} \parallel \text{actor} \parallel \text{details\_digest} \parallel \text{prev\_hash})$$
3. **Truncation & Deletion Detection**:
   - The ledger must emit a sealed terminal event: `SCAN_TERMINATED` containing `final_event_count`, `total_findings_digest`, and `ledger_root_hash`.
   - Any attempt to truncate events from the end breaks the terminal event seal.

---

## 10. Immutable Historical Compliance Evaluations

### 10.1 Temporal Decoupling

A critical governance requirement: **yesterday's compliance report must never change because a suppression expired today or a rule pack was updated tomorrow.**

```
                                  Time T0 (Scan Execution)
                                             │
             ┌───────────────────────────────┴───────────────────────────────┐
             ▼                                                               ▼
   [ Analysis Snapshot ]                                           [ Compliance Suite ]
   - Commit: c1                                                    - Framework: PCI-DSS v4
   - Finding F1 (active)                                           - Control: PCI-6.2.4
   - Suppression S1 (expires T2)                                   - Status: PARTIAL
                                                                   - Catalog Version: 2026.1
                                                                             │
                                                                             ▼
                                                                [ Sealed in Attestation ]
                                                                             │
                                                                             │
                                  Time T1 (Later Review)                     │
                                             │                               │
                                             ▼                               ▼
                              Fetch Snapshot c1 at T1 ────────────────► Unchanged (PARTIAL)
                              (Immutable Audit View)
                                             │
                                             │
                                  Time T2 (Suppression S1 Expires)
                                             │
                                             │
                                  Time T3 (New Scan on c1)
                                             │
                                             ▼
                              Re-evaluate Compliance at T3
                              - Finding F1 now ACTIVE (expired)
                              - Status: VIOLATED
                              - New Snapshot & New Attestation Generated
```

1. **Immutable Snapshot Linkage**:
   - Compliance evaluations are serialized and stored directly inside the snapshot record (`AnalysisSnapshot.compliance_suite_payload`).
   - Historical CLI and API queries retrieve the immutable stored JSON payload rather than recalculating on the fly.
2. **Live Recalculation Mode**:
   - If an auditor explicitly requests a recalculation (*"What would snapshot c1 look like under today's rules?"*), the system must flag it:
     `"evaluation_mode": "RETROSPECTIVE_RECALCULATION"`
     `"original_evaluation_timestamp": "2026-09-28T12:00:00Z"`

---

## 11. Rule-Pack Governance Hardening

### 11.1 Canonical Resolved Identity

A resolved rule pack configuration must have a deterministic cryptographic fingerprint:
$$\text{resolved\_pack\_hash} = \text{SHA-256}(\text{CanonicalJCS}(\{ \text{pack\_hierarchy}, \text{rules}, \text{severities}, \text{parameters}, \text{policies} \}))$$
This hash is embedded into the scan metadata and attestation predicate.

### 11.2 Field-by-Field Monotonic Strictness Matrix

The table below defines strict monotonicity rules across inheritance levels. Any child violation raises `MonotonicPolicyViolationError`.

| Configuration Field | Parent Value | Permitted Child Operation | Forbidden Child Operation | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `rule.enabled` | `True` (locked) | Remain `True` | Set `False` | Mandated security rules cannot be disabled. |
| `rule.enabled` | `False` | Set `True` | None | Enabling dormant rules tightens posture. |
| `rule.severity` | e.g. `HIGH` | Upgrade to `CRITICAL` | Downgrade to `MEDIUM`, `LOW`, `INFO` | Threat severity cannot be trivialized. |
| `disallow_inline_suppressions` | `True` | Remain `True` | Set `False` | Enterprise exception policy cannot be relaxed. |
| `max_taint_depth` | `25` | Increase $\ge 25$ | Decrease $< 25$ | Reducing depth drops path exploration. |
| `max_call_depth` | `5` | Increase $\ge 5$ | Decrease $< 5$ | Reducing depth truncates interprocedural analysis. |
| `centrality_threshold` | `0.35` | Decrease $\le 0.35$ | Increase $> 0.35$ | Lowering threshold tightens bottleneck detection. |
| `god_module_loc` | `500` | Decrease $\le 500$ | Increase $> 500$ | Lowering threshold tightens module size limits. |
| `gate_policy.fail_on` | `HIGH` | Upgrade to `MEDIUM` / `LOW` | Downgrade to `CRITICAL` or `None` | CI/CD breaking threshold cannot be relaxed. |
| `gate_policy.max_new_findings` | `0` | Remain `0` | Increase $> 0$ | Cannot permit introducing new regressions. |

---

## 12. Reporting Validation & Security

### 12.1 CycloneDX 1.6: SBOM vs VEX Separation

The current generator labels a vulnerability list as an SBOM. Phase 27 will strictly conform to CycloneDX 1.6 taxonomy:
1. **Full Component Inventory**:
   - Enumerate all scanned files and discovered dependencies (via Phase 6 dependency graph) under `components`, not just files with vulnerabilities.
   - For repositories, generate an accurate `root-application` component.
2. **VEX (Vulnerability Exploitability eXchange)**:
   - Map findings cleanly to CycloneDX `vulnerabilities` with standardized `analysis.state`:
     - Active finding: `exploitable` or `in_triage`.
     - Suppressed finding: `not_affected` with `justification: code_not_reachable` or `protected_by_mitigating_control`.
3. **Schema Validation**:
   - Provide an offline JSON Schema validator for CycloneDX 1.6 to ensure output passes `cyclonedx-cli validate`.

### 12.2 OpenXML Excel: Spreadsheet Formula Injection Mitigation

Excel interprets cells starting with `=`, `+`, `-`, or `@` as dynamic formulas (CWE-1236). If a repository contains a finding with a snippet like `=cmd|' /C calc'!A0`, opening the audit report executes arbitrary commands:
- **Sanitization Invariant**:
  ```python
  def sanitize_excel_cell(value: Any) -> str:
      s = str(value)
      if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
          # Prepend single quote escape character
          return "'" + s
      return s
  ```
- **XML 1.0 Invalid Control Character Stripping**:
  Remove all characters in range `\x00`–`\x08`, `\x0b`–`\x0c`, `\x0e`–`\x1f` which violate the XML 1.0 specification and crash Excel.

### 12.3 PDF 1.4 Robustness & Typography

- **Word Wrapping & Layout Engine**:
  - Implement a pure-Python greedy line-wrapping algorithm based on character bounding widths for Helvetica.
  - Automatically wrap long file paths and rule explanations across multiple lines without overflowing the printable margin (50pt to 562pt).
- **Unicode Transcoding**:
  - When compiling to Latin-1 Type 1 Helvetica, use standard Unicode transliteration (unidecode / NFKD decomposition) rather than raw `"replace"`, preserving readable character equivalents for non-ASCII text.
- **Visual Compliance Badging**:
  - Standardize vector seal drawing coordinates and page numbering footer (`Page X of Y`).

---

## 13. Sensitive Information and Report Security

Reusing Phase 12 Secret-Scrubbing principles:
1. **Snippet Redaction**:
   - When findings involve `SEC-PY-001` (hardcoded secrets) or `SEC-JS-004`, finding snippets must be masked before embedding into Excel, PDF, CycloneDX, or Attestation envelopes:
     `api_key = "sk_live_********************"`
2. **File Path Anonymization Option**:
   - CLI flag `--sanitize-paths` to strip local absolute workspace prefixes (e.g., `E:/AI-Workspace/projects/...`) to relative repository paths (`src/auth/service.py`) in public attestations.
3. **HMAC Key Exposure Prevention**:
   - Ensure CLI arguments passing keys are masked in process tables (`setproctitle` or argv scrubbing) and never printed to stdout/stderr.

---

## 14. Incremental Analysis Integration

### 14.1 Cache Scoping & Invalidation

A change to a compliance mapping or rule pack must **not** invalidate expensive lower-level caches:
- **L1–L5 Caches (Parsing, CFG, Taint Graph, Call Graph, Contracts)**: Reused unconditionally.
- **L6 Cache (Finding Generation)**: Reused unless rule pack adds/enables rules.
- **L7 Cache (Compliance & Attestation)**: Invalidated if any component of `compliance_fingerprint` changes.

### 14.2 Compliance Fingerprint Definition

```python
compliance_fingerprint = canonical_json_digest({
    "analysis_snapshot_id": snapshot_id,
    "findings_semantic_digest": compute_findings_merkle_root(findings),
    "suppression_state_digest": suppression_hash,
    "frameworks": sorted([fw.value for fw in requested_frameworks]),
    "catalogs_version": "2026.1",
    "mappings_version": "2026.1",
    "resolved_pack_hash": resolved_pack_hash,
    "evaluator_version": "1.1.0",
    "min_compliance_score": min_score,
})
```

---

## 15. CLI, API & UI Requirements

### 15.1 CLI Hardening

- `codesentinel compliance check <path>`:
  - Add `--require-proven`: Requires 100% of assessed controls to be `PROVEN` (fails on `UNKNOWN` or `PARTIAL`).
  - Redesign `--min-compliance-score`: Provide clear summary table showing `PROVEN`, `VIOLATED`, `PARTIAL`, `UNKNOWN`, and `NOT_ASSESSED` counts before checking numerical threshold.
- `codesentinel compliance attest <path>`:
  - Mandate `--key` or environment variable `CODESENTINEL_SIGNING_KEY`.
  - Abort if default key is detected.
- `codesentinel compliance verify-attestation <file>`:
  - Add `--dump-statement`: Output decoded in-toto Statement JSON if verification succeeds.

### 15.2 Backend API DTOs

Enrich `/api/v1/compliance/controls` and analysis responses:
- Include `provenance`, `static_limitations`, and `mapping_type` in `ComplianceControlDTO`.
- Support query parameter `?include_limitations=true`.

---

## 16. Persistence Requirements

To avoid database migrations while achieving full historical compliance persistence:
1. **JSON Snapshot Storage**:
   - Utilize existing `configuration` JSON column or add structured `compliance_suite` and `attestation` payloads directly into the analysis snapshot serializer in `backend/app/services/persistence.py`.
2. **Repository Isolation**:
   - Ensure all compliance lookups verify that `snapshot.repository_id == current_repo_id`, preventing cross-tenant information disclosure.

---

## 17. Determinism Specification

| Component | Potential Source of Nondeterminism | Phase 27 Canonical Mitigation |
| :--- | :--- | :--- |
| **Attestation Predicate** | Current system clock timestamp | Accept explicit `--analysis-timestamp` (defaulting to Git commit timestamp or pipeline start time). |
| **Audit Ledger** | `uuid.uuid4()` event identifiers | Derive `event_id` deterministically from `SHA-256(chain_id + seq_number)`. |
| **CycloneDX** | `urn:uuid:{uuid.uuid4()}` serial number | Derive serial number as UUID v5 from `(namespace_dns, repository_name + commit_hash)`. |
| **OpenXML Excel** | ZIP archive file timestamps & entry ordering | Set ZIP entry `date_time` to constant epoch (1980-01-01 00:00:00) and sort filenames alphabetically. |
| **PDF 1.4** | PDF `/CreationDate` and object ordering | Sort PDF dictionary keys; set creation timestamp to scan timestamp; sort object IDs sequentially. |
| **Merkle Tree** | Unordered finding arrays | Sort finding fingerprints lexicographically by `primary_hash` before leaf reduction. |

---

## 18. Comprehensive Test Strategy

The Phase 27 test suite will cover the following dedicated test domains:

### 1. Compliance Semantics & Proofs
- `test_empty_repository_is_unknown_not_compliant`: Verifies empty repository evaluates to `UNKNOWN` or `NOT_ASSESSED`, never `PROVEN`.
- `test_policy_proof_obligation_elevates_to_proven`: Verifies control with verified `PROVEN_SAFE` obligation reaches `PROVEN`.
- `test_active_finding_causes_violation`: Verifies violation triggers `VIOLATED`.
- `test_suppression_causes_partial_not_compliant`: Verifies suppressed finding yields `PARTIAL` with zero `PROVEN` inflation.
- `test_expired_suppression_reverts_to_violated`: Verifies expired timed deferral causes immediate transition to `VIOLATED`.

### 2. Attestation & Cryptographic Standards
- `test_intoto_statement_serializes_type_attribute`: Verifies serialized JSON contains `_type: https://in-toto.io/Statement/v1`.
- `test_rfc8785_canonical_json_ordering_and_floats`: Tests ECMAScript float formatting, key sorting, and UTF-8 NFC normalization.
- `test_merkle_tree_domain_separation`: Verifies leaf (`0x00`) and internal node (`0x01`) domain prefixes prevent second-preimage attacks.
- `test_odd_node_merkle_reduction`: Verifies tree with odd leaves does not duplicate nodes.
- `test_attestation_verification_fails_tampered_pae`: Tampering with payload type or base64 length in PAE fails verification.
- `test_cli_attest_rejects_default_secret`: Verifies CLI refuses to sign with unconfigured default key.

### 3. Audit Trail Integrity
- `test_audit_ledger_detects_deletion`: Removing an event from the middle breaks hash chain.
- `test_audit_ledger_detects_reordering`: Swapping two events breaks sequence and hash chain.
- `test_audit_ledger_detects_truncation`: Truncating last 3 events fails terminal seal verification.
- `test_audit_ledger_detects_chain_replay`: Replaying events from another repository fails `chain_id` validation.

### 4. Rule Pack Monotonicity & Governance
- `test_pack_resolution_forbids_relaxing_max_taint_depth`: Child lowering analysis depth fails.
- `test_pack_resolution_forbids_relaxing_gate_policy`: Child loosening `fail_on` fails.
- `test_pack_canonical_hash_changes_on_yaml_edit`: Modifying a rule pack parameter updates `resolved_pack_hash`.

### 5. Secure Reporting
- `test_excel_formula_injection_sanitization`: Value `=CMD|'...'` is safely escaped with leading `'`.
- `test_excel_xml_control_character_stripping`: Bytes `\x00`–`\x08` are stripped without crashing workbook.
- `test_cyclonedx_schema_conformance`: Output validates against CycloneDX 1.6 JSON Schema.
- `test_pdf_greedy_word_wrapping`: 200-character line wraps cleanly without margin clipping.
- `test_pdf_unicode_transliteration`: Accented/non-ASCII characters are converted to readable Latin equivalents.

---

## 19. End-to-End Scenarios

### Scenario A — Proven Static Evidence (Clean Path)
- **Target**: Python codebase with query parameterization verified by `POL-SQL-01`.
- **Pipeline**: Analysis produces proof obligation `REQUIRES_PARAMETERIZATION` with state `PROVEN_SAFE`.
- **Compliance**: PCI-DSS Requirement 6 (`PCI-6.2.4`) evaluates to `PROVEN`.
- **Attestation**: Sealed DSSE attestation emitted with valid Merkle root.
- **Verification**: `codesentinel compliance verify-attestation` passes.

### Scenario B — Inconclusive Coverage (Unknown Path)
- **Target**: Microservice without database calls or SQL sinks.
- **Pipeline**: Zero findings detected; zero proof obligations generated.
- **Compliance**: `PCI-6.2.4` evaluates to `UNKNOWN` with explanation: *"No relevant database sinks detected in scanned codebase; static proof cannot be established."*
- **Gate**: `--min-compliance-score` reports `0/1 Proven, 1 Unknown, 0 Violated`. Gate passes or warns based on `--require-proven`.

### Scenario C — Active Critical Violation
- **Target**: Flask application with raw string formatting in `cursor.execute()` (`SEC-PY-003`).
- **Pipeline**: Finding generated with severity `CRITICAL`.
- **Compliance**: `PCI-6.2.4` evaluates to `VIOLATED`. Overall PCI score drops to `0.0%`.
- **Gate**: CLI exits with code 2 (`[COMPLIANCE GATE FAILURE]`).

### Scenario D — Suppressed Finding Lifecycle & Expiration
- **Target**: Finding suppressed via `# codesentinel-suppress SEC-PY-003 reason="Legacy batch job" until="2026-09-01"`.
- **Run 1 (Evaluation at 2026-08-15)**: Suppression active $\to$ Control evaluates to `PARTIAL`. Snapshot stored immutably.
- **Run 2 (Evaluation at 2026-09-15)**: Suppression expired $\to$ Control evaluates to `VIOLATED`.
- **Audit Check**: Querying Run 1 snapshot still immutably returns `PARTIAL`.

### Scenario E — Rule Pack DAG Inheritance & Strictness
- **Packs**: `enterprise-core` (locks `SEC-PY-001` enabled, severity `CRITICAL`) $\to$ `pci-pack` $\to$ `.codesentinel.yaml`.
- **Action**: Local repo attempts to set `SEC-PY-001: enabled: false`.
- **Result**: Pipeline aborts during configuration load with `MonotonicPolicyViolationError`.

### Scenario F — Attestation Tampering Detection
- **Action**: Generate valid `scan.attestation.json`. Modify a single character in the finding Merkle root inside the payload.
- **Result**: `codesentinel compliance verify-attestation` fails with exit code 1: `[ATTESTATION VERIFICATION FAILED] Signature mismatch`.

### Scenario G — Audit Ledger Event Deletion Detection
- **Action**: Export ledger to JSONL. Delete line 3 (an event).
- **Result**: `AuditTrailLedger.verify_integrity()` returns `(False, "Tampered hash chain at event 3: previous_hash mismatch")`.

### Scenario H — Incremental Compliance Recalculation
- **Action**: Scan repo $\to$ results cached. Re-run scan with `--compliance hipaa` added.
- **Result**: AST, CFG, and taint graph caches reused (0ms re-parsing); only compliance evaluation layer executes.

---

## 20. Performance and Benchmark Requirements

All Phase 27 hardening must adhere to strict performance envelopes:
1. **Compliance Evaluation Overhead**: $< 10\text{ms}$ for up to 500 findings across all 4 framework catalogs.
2. **Merkle Root Computation**: $< 15\text{ms}$ for 2,000 findings.
3. **Canonical RFC 8785 Serialization**: $< 20\text{ms}$ for standard in-toto statements.
4. **Audit Trail Verification**: $< 5\text{ms}$ for a 1,000-event ledger.
5. **Report Generation**:
   - CycloneDX JSON: $< 50\text{ms}$.
   - OpenXML Excel: $< 150\text{ms}$.
   - PDF 1.4: $< 100\text{ms}$ for a 10-page document.
6. **Benchmark Protocol**: All performance tests must record CPU architecture, OS, Python version, memory consumption, and execution time across warm and cold cache runs.

---

## 21. Compatibility Matrix

| Prior Phase | Invariant / Model | Phase 27 Compatibility Contract |
| :--- | :--- | :--- |
| **Phase 25** | `FindingFingerprint` (`primary_hash`, `stable_id`) | 100% preserved. Merkle root leaves directly consume `primary_hash`. |
| **Phase 25** | `FindingLifecycleState` (11 states) | Preserved. Evaluator maps `SUPPRESSED` / `DEFERRED` to `PARTIAL`. |
| **Phase 25** | `FindingSuppression` (`expires_at`) | Evaluator strictly honors `is_expired()` against scan timestamp. |
| **Phase 24** | `PolicyProofObligation` (`PROVEN_SAFE`) | Directly consumed to distinguish `PROVEN` compliance from `UNKNOWN`. |
| **Phase 23** | `SecurityPolicy` / Trust Boundaries | Directly registered by hierarchical rule packs. |
| **Phase 21–22** | Incremental Caching (L1–L9) | L1–L6 caches preserved; compliance layer isolated in scoped L7 cache. |
| **Phase 10** | Analysis Snapshots | Backwards compatible; compliance data added to payload without schema breakage. |

---

## 22. Documentation Requirements (Future Implementation Scope)

When Phase 27 is implemented, the following comprehensive guides must be produced:
- `docs/compliance/COMPLIANCE_SEMANTICS.md`: Detailed explanation of `PROVEN` vs `UNKNOWN` vs `VIOLATED`, and why static analysis is not regulatory certification.
- `docs/compliance/FRAMEWORK_LIMITATIONS.md`: Control-by-control scope and limitations for PCI-DSS, HIPAA, SOC 2, and NIST SP 800-53.
- `docs/compliance/ATTESTATION_SPECIFICATION.md`: Cryptographic guide to in-toto statement, DSSE envelope, and verification procedures.
- `docs/compliance/RULE_PACK_GOVERNANCE.md`: Guide to composing enterprise rule packs and monotonic inheritance.

---

## 23. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation Strategy | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **Auditor Misinterpretation of Reports** | High | High | Prominent disclaimer on all reports: *"Static Technical Evidence Only — Not Regulatory Certification"*. | Users may still present reports as compliance proof to third parties. |
| **HMAC Secret Key Leakage** | Medium | High | Forbid default keys; enforce environment variable ingestion; zeroize keys in memory; omit from all logs. | Key compromise in CI environment allows forged attestations. |
| **Excel Formula Injection (CWE-1236)** | Low | High | Mandatory prefixing with `'` on all user-controlled text cells starting with formula symbols. | Minimal; standardized defense. |
| **Inaccurate Control Mappings** | Medium | Medium | Document exact mapping type (`DIRECT`, `PARTIAL`, etc.) and limitations on every control. | Catalog must be maintained as standards evolve. |
| **Nondeterministic Build Outputs** | Medium | Low | Canonicalize ZIP timestamps, UUID generation (UUID v5), and dictionary key sorting. | Minor variations if external environment locale differs. |
| **Breaking Existing CLI Workflows** | Low | Medium | Retain existing CLI flags with backward-compatible defaults; enforce strictness only on new compliance subcommands. | Minimal; all existing flags continue to function. |

---

## 24. Acceptance Gates

- [ ] **Gate 1 (Semantic Precision)**: Control evaluation distinguishes `PROVEN`, `VIOLATED`, `PARTIAL`, `UNKNOWN`, and `NOT_ASSESSED`. Empty codebases never evaluate to `PROVEN`.
- [ ] **Gate 2 (Suppression Integrity)**: Suppressed findings transition controls to `PARTIAL` with zero score inflation; expired suppressions transition to `VIOLATED`.
- [ ] **Gate 3 (Historical Immutability)**: Old snapshot evaluations remain 100% byte-identical after subsequent suppression changes or catalog updates.
- [ ] **Gate 4 (Standards Attestation)**: in-toto Statement outputs `_type`; DSSE correctly verifies PAE; RFC 8785 canonicalizer passes float and Unicode tests.
- [ ] **Gate 5 (Cryptographic Merkle Root)**: Binary Merkle tree uses domain separation (`0x00`/`0x01`) and raw 32-byte digests.
- [ ] **Gate 6 (Audit Ledger Security)**: Event deletions, reorderings, truncations, and cross-repo replays are detected deterministically.
- [ ] **Gate 7 (Rule Pack Monotonicity)**: Child configurations cannot relax locked rules, downgrade severities, decrease taint depth, or loosen gate policies.
- [ ] **Gate 8 (Report Robustness & Security)**: Excel escapes formula injection characters; CycloneDX outputs full component inventory; PDF wraps long text and handles Unicode.
- [ ] **Gate 9 (Incremental Cache Safety)**: Compliance-only changes invalidate L7 cache without evicting AST or taint caches.
- [ ] **Gate 10 (Full Regression Baseline)**: 100% of all existing 878 tests continue to pass cleanly.

---

## 25. Open Questions

1. **Asymmetric Key Support in DSSE**: Should Phase 27 introduce optional Ed25519 public-key signing for true non-repudiation, or remain purely symmetric HMAC with explicit documentation?
   *Recommendation*: Keep HMAC as default zero-dependency standard; add optional Ed25519 signing if Python 3.14 standard library / cryptography module is available.
2. **Weighting of Regulatory Controls**: Should framework scores remain unweighted percentages, or should critical controls have blocking veto power?
   *Recommendation*: Implement a dual metric: (1) Unweighted Compliance Percentage, and (2) Gate Verdict (`PASS`/`FAIL`) where any unsuppressed `CRITICAL` or `HIGH` control violation causes immediate gate failure regardless of score.

---

## 26. Implementation Order

1. **Step 1: Compliance Semantic Model & Catalogs**
   - Update `ComplianceStatus` to include `PROVEN`, `VIOLATED`, `PARTIAL`, `UNKNOWN`, `NOT_ASSESSED`.
   - Enrich `ComplianceControl` with provenance, limitations, and mapping types.
   - Refactor `evaluator.py` to require proof obligations for `PROVEN` and handle suppressions as `PARTIAL`.
2. **Step 2: Cryptographic Standards & Attestation**
   - Implement RFC 8785 JCS canonicalizer.
   - Fix in-toto `_type` serialization.
   - Implement domain-separated Merkle tree.
   - Harden DSSE envelope and eliminate default HMAC secret.
3. **Step 3: Audit Trail Hardening**
   - Bind Genesis block to `chain_id` and repository metadata.
   - Hash all event fields deterministically; eliminate `uuid4()`.
   - Add terminal sealing event.
4. **Step 4: Rule Pack Monotonicity**
   - Implement comprehensive parameter and gate policy monotonicity validation in `pack_resolver.py`.
   - Add canonical `resolved_pack_hash`.
5. **Step 5: Reporting Security & Validation**
   - Add CWE-1236 sanitization to `excel_reporter.py`.
   - Refactor `cyclonedx_reporter.py` to include full component inventory and schema validation.
   - Add line-wrapping and Unicode handling to `pdf_reporter.py`.
6. **Step 6: Incremental & Persistence Integration**
   - Incorporate resolved pack hash and catalog version into `config_fingerprint.py`.
   - Store compliance and attestation payloads in `backend/app/services/persistence.py`.
7. **Step 7: CLI, Gate Semantics & E2E Validation**
   - Update CLI `--min-compliance-score` output and gate evaluation.
   - Run complete Phase 27 test suite and verify 100% pass rate.

---

## 27. Rollback & Failure Strategy

- **Isolated Modules**: All Phase 27 changes are contained within `analyzer/compliance/`, `analyzer/rules/pack_resolver.py`, `analyzer/reporting/`, and `analyzer/incremental/`.
- **Feature Flag Fallback**: In the event of an unforeseen regression, `--compliance-mode=legacy` can revert evaluation semantics to Phase 26 behaviors without affecting core static analysis, taint tracking, or baseline comparisons.
- **Test Integrity**: Full regression test suite (`python -m pytest -q`) will be run after every atomic step to guarantee zero breakage of Phase 1–26 functionality.
