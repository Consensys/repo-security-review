# Phase 6: Report Builder Agent

## Goal
Aggregate all phase outputs into a single, well-structured security report
and write it to the user-specified output path.

## Input Files to Read

Read all that exist (some may be absent if a phase was skipped):
```
{repo_path}/.security-review/run-metadata.json
{repo_path}/.security-review/tech-stack.json
{repo_path}/.security-review/threat-model.json    ← present only if --context was used
{repo_path}/.security-review/phase1-secrets.json
{repo_path}/.security-review/phase2-architecture.json
{repo_path}/.security-review/phase3-cves.json
{repo_path}/.security-review/phase3b-reachability.json
{repo_path}/.security-review/phase4-owasp.json
{repo_path}/.security-review/phase5-validated.json
{repo_path}/.security-review/phase5-pocs.json
```

Check the `--verbose` flag (passed by the orchestrator). It controls which
report structure is produced — see Report Modes below.

## Output Path

```
{repo_path}/.security-review/final-report.md
```

The orchestrator owns the final copy step — Phase 6 must not write to
`--output` directly and must not call `present_files`.

---

## Calibration Step (only when threat-model.json exists)

When `threat-model.json` is present, compute `contextual_severity` for every
non-secret finding before building the report. Secrets are exempted — rotation
is always required regardless of context.

**Severity tier order**: CRITICAL → HIGH → MEDIUM → LOW.
Floor: LOW (nothing drops below). Ceiling: base severity (context never sharpens).

Apply softeners:

| Softener | Applies to |
|----------|-----------|
| `deployment_target: local` (−2 tiers) | all findings |
| `auth_required_to_reach: true` (−1 tier) | pre-auth findings only |

**How calibration surfaces in each mode:**
- **Default report**: `contextual_severity` is the displayed severity with no
  annotation. The dev team sees effective risk — no B/C columns, no explanation
  of why a finding is Medium vs High. Drift findings (`category: threat_model_drift`)
  are silently excluded from the default report.
- **Verbose report**: both `base_severity` and `contextual_severity` are shown,
  with the softeners listed in Section 5b. Drift findings appear as normal findings.

---

## Deduplication Step

Before building the report, identify Phase 2 (architecture) and Phase 4
(OWASP) findings that describe the same underlying issue. Phase 4 re-discovers
issues independently of Phase 2 to increase confidence, but this produces
duplicate entries.

**Match criterion — either suffices:**
1. **Same file + overlapping line range**: primary evidence file identical AND
   line ranges overlap or are within ±5 lines of each other.
2. **Same root cause on the same file**: same file AND titles/descriptions share
   a recognizable common pattern (e.g., "Secure flag", "X-Frame-Options",
   "fail-open", "CORS wildcard", same function name).

**When a match is found:**
1. Mark the Phase 2 finding as merged: `"merged_into": "O-XXX"`.
2. The Phase 4/5 finding (O-XXX) is canonical: fold one sentence of Phase 2's
   architectural framing into the description; take the higher severity.
3. The merged Phase 2 finding is omitted from the unified Findings list.
   In verbose mode it is suppressed from Section 2 with a cross-reference note.

---

## Report Modes

### Default report (no `--verbose`) — for dev teams

**Goal**: give developers exactly what they need to act — findings, evidence,
and what to do. No calibration context, no phase structure, no coverage tables.

Structure:
```
# Security Review Report
[4-line header]
---
## Summary
[risk posture + single-column count table + immediate actions]
---
## Exposed Secrets          ← omit entirely if no secrets found
---
## Findings                 ← ALL findings unified, sorted by Priority → severity
---
## False Positives          ← always include; builds trust
---
## Skipped Phases           ← omit if nothing was skipped
```

Rules:
- **Single severity** per finding: contextual if calibration ran, base otherwise.
  No B/C columns, no "base: X contextual: Y" annotations, no explanation of
  why a finding has the severity it has.
- **No phase labels**: do not split into Section 2 / Section 3 / Section 4.
  All findings (arch, CVE, code-level) appear in one unified list.
- **No calibration context**: omit Assumed Threat Model, Section 5b, drift notes.
- **Drift findings** (`category: threat_model_drift`): exclude entirely.
- Sort order: P0 → P1 → P2 → P3 → Backlog; within each tier, higher severity first.

### Verbose report (`--verbose`) — for security team / skill developer

Includes everything in the default report, structured by phase, plus:
- Assumed Threat Model section (before Executive Summary)
- B/C dual-severity columns in the summary table
- Phase-divided findings (Section 2: Architecture, Section 3: CVEs,
  Section 4: OWASP with Checks Run subsection)
- Section 5b: Context-Driven Adjustments (softeners per finding)
- Drift findings visible as regular findings in Section 2
- Standalone Remediation Priority section
- Appendix: Coverage & Tools

### Priority assignment (both modes)

Assign a `**Priority**` to every finding before rendering.
Secrets always P0; skip this table for them.

| Priority | Criteria |
|----------|---------|
| P0 | Runtime-confirmed exploit (`RUNTIME_CONFIRMED`). Critical severity with no auth prerequisite. |
| P1 | High severity, exploitable without complex preconditions (unauthenticated or low-priv user). |
| P2 | Medium severity, or fast fix available (e.g. a single `upgrade` command). |
| P3 | Low severity. Medium-severity finding requiring design or config changes. |
| Backlog | Architectural refactoring with no quick remediation path; low immediate exploitability. |

---

## Default Report Structure

```markdown
# Security Review Report
**Repository**: {repo_name}
**Review Date**: {date}
**Tech Stack**: {languages} / {frameworks} / {database_types}
**Reviewed By**: Claude Code · repo-security-review skill

---

## Summary

{2-3 sentences on overall posture. Name the highest-risk issues directly.
No mention of calibration or context.}

| Severity | Count |
|----------|-------|
| 🔴 Critical | N |
| 🟠 High | N |
| 🟡 Medium | N |
| 🟢 Low | N |

**Fix immediately**: {bullet list — P0 and P1 findings only, one line each}

---

## Exposed Secrets
{Omit this entire section if no secrets were found.}

> ⚠️ Rotate all secrets below immediately, regardless of other findings.

### {type} · {confidence} Confidence
- **File**: `{file}:{line}`
- **In Git History**: Yes/No {if yes: "— rewrite git history or consider the secret permanently compromised"}
- **Value (redacted)**: `AKIA****XYZ`
- **Remediation**: {remediation}

---

## Findings

{All confirmed findings from all phases (deduped), sorted by Priority then severity.
Use a flat numbered list — no sub-sections by phase.}

### 🟠 {ID} · {Title}
- **Priority**: P{N}
- **Category**: {e.g. Session Management / Missing Control / Dependency CVE / CI/CD / OWASP A07}
- **File**: `{primary_file}:{line}`
{If code snippet is available:}
**Vulnerable Code**:
```{language}
{snippet — keep to ≤10 lines}
```
- **Description**: {what the problem is and why it matters — include key architectural
  context if this was a merged arch+code finding, without labeling it as such}
- **Impact**: {what an attacker can do}
- **Remediation**: {specific, actionable fix}

{If PoC is available (from phase5-pocs.json):}
<details>
<summary>Proof of Concept</summary>

```{language}
{poc_code}
```
**Curl equivalent**:
```bash
{curl_equivalent}
```
**Success indicator**: {success_indicator}
**Setup required**: {setup_required}

</details>

{If runtime_status == RUNTIME_CONFIRMED:}
> ✅ **Runtime Validated** — confirmed against a live Docker instance.

---

## False Positives

Investigated and ruled out:

| ID | Type | File | Reason |
|----|------|------|--------|
| O-003 | XSS | templates/user.html | Output encoded by Jinja2 autoescape globally |

---

## Skipped Phases
{Omit this entire section if nothing was skipped.}

| Phase | Reason |
|-------|--------|
| Phase 3 — Dependencies | --skip dependencies |
```

---

## Verbose Report Structure

```markdown
# Security Review Report
**Repository**: {repo_name}
**Review Date**: {date}
**Tech Stack**: {languages} / {frameworks} / {database_types}
**Reviewed By**: Claude Code · repo-security-review skill
**Models Used**: {"`{phase2_model}` (extended thinking) — Architecture · `{other_model}` — all other phases"}

---

## Assumed Threat Model
{Include ONLY if threat-model.json exists.}

**Source**: {user-provided | default (strict)}

| Dimension | Declared | Effective |
|---|---|---|
| Deployment target | {deployment_target} | {effective} |
| Auth required to reach | {auth_required_to_reach} | {effective} |

{If drift_overrides were applied:}
> ⚠️ Drift detected: {dimension} declared `{declared}` but code shows `{observed}`.
> Reverted to strict default. See finding A-XXX.

The threat model was used to compute contextual severity (shown as Base / Contextual
in the tables below). Secrets are not calibrated.

---

## Executive Summary

{2-3 sentences. Mention how many findings were calibrated down.}

| Severity | Secrets | Architecture (B / C) | CVEs (B / C) | Code-Level (B / C) | Total (B / C) |
|----------|---------|---------------------|--------------|-------------------|---------------|
| 🔴 Critical | N | N / N | N / N | N / N | **N / N** |
| 🟠 High | N | N / N | N / N | N / N | **N / N** |
| 🟡 Medium | N | N / N | N / N | N / N | **N / N** |
| 🟢 Low | N | N / N | N / N | N / N | **N / N** |

**Immediate Actions Required**:
{P0 findings only}

---

## Section 1: Exposed Secrets
{Omit if Phase 1 skipped}

> ⚠️ Rotate all secrets below immediately.

### S-001 · {type} · {confidence} Confidence
- **File**: `{file}:{line}`
- **In Git History**: Yes/No
- **Value (redacted)**: `AKIA****XYZ`
- **Remediation**: {remediation}

---

## Section 2: Architectural Findings
{Omit if Phase 2 skipped}
{Group by severity. Use dual-severity header when calibration is active:
`🟡 A-001 · {title} · Base: 🔴 Critical · Contextual: 🟡 Medium`}

{If any Phase 2 findings were merged into Section 4:}
> *{N} finding(s) (A-001, …) also detected by code-level analysis — see Section 4.*

### 🔴 A-001 · {title}
- **Category**: {category}
- **Evidence**: `{file}:{line}`
- **Description**: {description}
- **Impact**: {impact}
- **Remediation**: {remediation}
- **Priority**: {P0 / P1 / P2 / P3 / Backlog}

---

## Section 3: Dependency Vulnerabilities
{Omit if Phase 3 skipped}

### Ecosystems Scanned
{ecosystems_scanned and ecosystems_skipped}

{CVE findings by priority, then severity. Dual-severity header when calibration active.
Include 🚨 KEV and ⚡ EPSS badges inline in heading.}

#### 🔴 C-001 · {cve_id} · {package}@{version} · CVSS {score} · 🚨 KEV · ⚡ EPSS 97.5%
- **Priority**: P0
- **Fixed In**: `{fixed_version}`
- **Reachability**: ✅ Confirmed reachable — import: `{site}`, call: `{site}`
- **Exploitation Signal**: In CISA KEV ({kev_date_added}). EPSS {percentile}th percentile.
- **Description**: {description}
- **Remediation**: `{package_manager} upgrade {package} to {fixed_version}`

{If enrichment fetch failed:}
> ⚠️ Enrichment note: {EPSS / KEV / both} unavailable. Findings reflect CVSS + reachability only.

---

## Section 4: Code-Level Vulnerabilities (OWASP)
{Omit if Phase 4 skipped}

### Checks Run
{checks_run and checks_skipped from phase4-owasp.json with reasons}

### Findings

{For each confirmed finding, grouped by severity. Dual-severity header when calibration active.
Merged findings include Arch confirmed field.}

#### 🔴 O-001 · {vulnerability_type} · {owasp_category}
- **File**: `{file}:{line_start}-{line_end}`
- **Validation**: Static ✅ {/ Runtime ✅}
- **Priority**: {P0 / P1 / P2 / P3 / Backlog}
{If merged:}
- **Arch confirmed**: {A-XXX} — {one sentence of Phase 2 framing}
**Vulnerable Code**:
```{language}
{snippet}
```
- **Description**: {description}
- **Attack Vector**: {attack_vector}
- **Remediation**: {remediation}

##### Proof of Concept
```{language}
{poc_code}
```
**Curl equivalent**: `{curl_equivalent}`
**Success indicator**: {success_indicator}

{If RUNTIME_CONFIRMED:}
> ✅ **Runtime Validated**

{If RUNTIME_SKIPPED:}
> ℹ️ **Runtime Validation Skipped**: {reason}

---

## Section 5: False Positives & Excluded Findings

| ID | Type | File | Reason Excluded |
|----|------|------|-----------------|
| O-003 | XSS | templates/user.html | Output encoded by Jinja2 autoescape globally |

---

## Section 5b: Context-Driven Adjustments
{Include ONLY if threat-model.json exists.}

| ID | Title | Base | Contextual | Softeners Applied |
|----|-------|------|-----------|-------------------|
| O-001 | SQL Injection | 🔴 Critical | 🟡 Medium | `deployment_target: local` (−2) |

**Rules:** contextual ≤ base; floor is LOW; CVSS-based trackers should use Base column.

{If drift_overrides active:}
**Drift overrides:** {dimensions} — declared values not used; Phase 2 detected contradiction.

---

## Section 6: Skipped Phases

| Phase | Reason Skipped |
|-------|---------------|
| Phase 3 | --skip dependencies |

---

## Remediation Priority

| Priority | Finding IDs | Effort | Rationale |
|----------|-------------|--------|-----------|
| P0 — Rotate Now | S-001 | Minutes | Live credentials |
| P1 — This Sprint | O-001 | Hours | High severity, exploitable |
| P2 — Next Sprint | C-001 | Low | Single upgrade command |
| P3 — Backlog | A-004 | High | Design refactoring required |

---

## Appendix: Coverage & Tools

| Phase | Tool / Method | Status |
|-------|--------------|--------|
| Secret Scanning | gitleaks {version} + grep patterns | ✅ Ran / ⏭️ Skipped |
| Architecture | Claude Fable (extended thinking) | ✅ Ran / ⏭️ Skipped |
| CVE Scanning | osv-scanner {version} | ✅ Ran / ⏭️ Skipped |
| EPSS Enrichment | FIRST.org EPSS API | ✅ Fetched / ⚠️ Unavailable |
| KEV Enrichment | CISA Known Exploited Vulnerabilities | ✅ Fetched / ⚠️ Unavailable |
| Reachability | Static call-graph analysis | ✅ Ran / ⏭️ Skipped |
| OWASP Analysis | semgrep + Claude Sonnet | ✅ Ran / ⏭️ Skipped |
| Validation | Static data flow tracing | ✅ Ran / ⏭️ Skipped |
| Runtime Validation | Docker + PoC probes | ✅ Ran / ⏭️ Skipped / ❌ Not available |
| PoC Generation | Claude Sonnet | ✅ Ran / ⏭️ Skipped |

*Report generated by repo-security-review skill v2*
```

---

## Formatting Guidelines

- Use severity emoji consistently: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
- Every finding must have a remediation — never "this is bad" without "do this"
- False Positives section is mandatory — it builds trust with the dev team
- In default mode: use `<details><summary>Proof of Concept</summary>` to keep
  long PoC blocks collapsed; they are still present but don't dominate the page
- Redact ALL secret values — show only first 4 and last 3 chars
- In verbose mode: finding headers use dual-severity format when calibration
  is active, e.g. `🟡 A-001 · {title} · Base: 🔴 Critical · Contextual: 🟡 Medium`
- In default mode: finding headers show a single severity (effective value only)

## Delivery

```bash
echo "✅ Phase 6 complete — report written to {repo_path}/.security-review/final-report.md"
```

Do not copy to `--output`, do not call `present_files`. The orchestrator performs those steps.
