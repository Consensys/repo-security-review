# Phase 6: Report Builder Agent

## Goal
Aggregate all phase outputs into a single, well-structured security report
and write it to the user-specified output path.

## Input Files to Read

Read all that exist (some may be absent if a phase was skipped):
```
{repo_path}/.security-review/run-metadata.json
{repo_path}/.security-review/tech-stack.json
{repo_path}/.security-review/threat-model.json       ← present only if --context was used
{repo_path}/.security-review/phase1-secrets.json
{repo_path}/.security-review/phase2-architecture.json
{repo_path}/.security-review/phase3-cves.json
{repo_path}/.security-review/phase3b-reachability.json
{repo_path}/.security-review/phase4-owasp.json
{repo_path}/.security-review/phase-llm-security.json ← present only if has_skill_files: true
{repo_path}/.security-review/phase5-validated.json
{repo_path}/.security-review/phase5-pocs.json
```

**LLM security findings** (L-XXX from `phase-llm-security.json`):
- In **default mode**: included in the unified `## Findings` section like any
  other finding. Use `- **Category**: AI/LLM Security · {owasp_llm}` as the
  category line.
- In **verbose mode**: include as a dedicated **Section 4b: LLM / AI Skill
  Security** between Section 4 and Section 5. Show the `data_flow` field as an
  extra line: `- **Data Flow**: {data_flow}`.
- LLM findings never have PoCs — omit the PoC line entirely.
- LLM findings are never validated by Phase 5 — omit any validation status.

Check the `--verbose` and `--vendor` flags (passed by the orchestrator). They
control which report structure is produced — see Report Modes below.
`--vendor` selects the vendor-audit report and takes precedence over the
default/verbose structure; `--verbose` then only adds the Coverage & Tools
appendix to it.

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
- **Methodology footnote**: end the report with a single italic line so a clean
  result is not over-read:
  `_Static + rule-based review. No whole-program taint analysis — cross-file data flows may be missed. A clean result means no issue was found, not that none exists._`

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

### Vendor report (`--vendor`) — for the security team, auditing a third-party repo

**Goal**: a security team is deciding whether it is safe to adopt this
third-party / open-source tool internally. The vendor will not fix findings, so
the report is an **adoption risk judgment**, not a remediation plan. It replaces
the default/verbose structure entirely (see Vendor Report Structure below).

Key differences from the other modes:
- **No priority assignment** — priorities (P0–P3) are remediation-sprint labels
  that make no sense when nobody is fixing anything. Findings are sorted by
  **severity** only. Skip the "Priority assignment" step below in vendor mode.
- **No `Remediation` line** — a "tell the vendor to fix X" instruction is
  useless to the adopter. Replace it per finding with **`Mitigation available
  to us`**: a compensating control the *adopting* team can apply without vendor
  code changes (network isolation, sandboxing, withholding secrets, input
  restrictions), or the honest `none — requires a vendor code change` when no
  such control exists. That honesty directly drives the verdict.
- **Phase 1 (secrets) and Phase 3 (CVEs) are always absent** — they are force-
  skipped in vendor mode. Do not render those sections; note them under Scope.
- **Headline is the verdict**, not a severity count table.
- **`--verbose` in vendor mode** adds only the `## Coverage & Tools` appendix
  (reuse the verbose appendix, including the Coverage limitations bullets) at the
  end of the vendor report. Everything else stays as the vendor structure.

### Priority assignment (default & verbose modes)

Assign a `**Priority**` to every finding before rendering.
Secrets always P0; skip this table for them. (Vendor mode assigns no priorities.)

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
{If PoC file exists for this finding:}
- **PoC**: `pocs/{poc_filename}`
{If phase5-validated.json → poc_skipped: true AND finding is CONFIRMED:}
- **PoC**: skipped (`--skip poc` was set — re-run without `--skip poc` to generate)

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
**Models Used**: {"`{deep_tier_model}`{if deep_tier_thinking: ` (extended thinking)`} — Architecture{if phase4b ran: ` · LLM Security`}{if phase7 ran: ` · Synthesis`} · `{standard_tier_model}` — all other phases"}
{if fallback_notes present:}
> ⚠️ **Model fallback**: {fallback_notes}

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
| Architecture | {deep_tier_model} (extended thinking) | ✅ Ran / ⏭️ Skipped |
| CVE Scanning | osv-scanner {version} | ✅ Ran / ⏭️ Skipped |
| EPSS Enrichment | FIRST.org EPSS API | ✅ Fetched / ⚠️ Unavailable |
| KEV Enrichment | CISA Known Exploited Vulnerabilities | ✅ Fetched / ⚠️ Unavailable |
| Reachability | Static call-graph analysis | ✅ Ran / ⏭️ Skipped |
| OWASP Analysis | semgrep + {standard_tier_model} | ✅ Ran / ⏭️ Skipped |
| Validation | Static data flow tracing | ✅ Ran / ⏭️ Skipped |
| Runtime Validation | Docker + PoC probes | ✅ Ran / ⏭️ Skipped / ❌ Not available |
| PoC Generation | {standard_tier_model} | ✅ Ran / ⏭️ Skipped (`--skip poc`) / ⏭️ Skipped (validation skipped) |

**Semgrep rulesets applied**: {read from `semgrep-configs.txt` if present, else
"language + OWASP packs"}. List the packs so the reader can judge scan depth.

### Coverage limitations

State these plainly so a clean result is not over-interpreted:

- **No whole-program taint analysis.** Detection is static + rule-based (Semgrep,
  including `p/security-audit` taint rules) plus per-file LLM reasoning. Semgrep's
  taint tracking is bounded (single-file / limited cross-function). Cross-file
  data flows — a source in one module reaching a sink in another through helpers —
  are caught only when the deep-analysis pass traces them by hand or a taint rule
  spans the path. A clean result means "no rule-matched or hand-traced sink," not
  "no injectable data flow exists."
- **Detection-gated checks.** Checks are pruned by the Phase 2 tech-stack profile.
  Any class listed under "Skipped" was not tested; "skipped" is not evidence of
  absence. Only *confident* negatives are skipped — a check whose detection was
  uncertain is run anyway. {Read `tech-stack.json → detection`: if
  `low_confidence_signals` or `truncated_signals` is non-empty, list them here
  and name any Phase 4 check that ran at reduced detection confidence
  (findings tagged `detection_confidence: "reduced"`).}
- **Reduced-confidence negatives.** {Read `phase4-owasp.json → class_negatives`.
  For each entry, state plainly: this check class came back clean, but not every
  file that could contain it was examined — name the `unexamined_files`. A
  reduced-confidence negative is "not found in what was read," not "absent."}
- **File coverage.** {Read `phase2-architecture.json → coverage`. If `not_read`
  is non-empty, note how many security-relevant files were not fully read and
  why, so the reader knows the review's breadth. If `read_chunked` shows large
  files were split, that is fine — full coverage — and needs no caveat. Also
  scan `coverage.directories`: for every entry with `read: 0`, name the directory
  and its `reason_if_unread` — an entire un-read directory (e.g. validation
  schemas, middleware, error filters) is a broader gap than a single skipped file
  and must be stated explicitly, not summarized away.}
- **Runtime PoCs** (if `--runtime` ran with `--network none`) cannot validate
  SSRF or any network-dependent exploit — those remain statically assessed only.

*Report generated by repo-security-review skill v2*
```

---

## Vendor Report Structure (`--vendor`)

Produced instead of the default/verbose structure when `--vendor` is set. Read
`phase2-architecture.json → project_overview` for the "What This Tool Does"
section, and the confirmed findings from `phase4-owasp.json` / `phase5-validated.json`
(and `phase-llm-security.json` if present). Secrets and CVE inputs are absent
(force-skipped) — do not fabricate those sections.

### Verdict rubric (compute before rendering)

Derive **overall risk** from the worst *confirmed* finding, weighted by
reachability and by whether the adopter can mitigate it without vendor changes:

| Overall risk | When |
|---|---|
| 🔴 CRITICAL | A confirmed CRITICAL finding on an attacker-reachable path (RCE, auth bypass, deserialization-to-RCE, hardcoded backdoor), **or** evidence of intentional malice / data exfiltration / obfuscated payloads / hostile install-time scripts. |
| 🟠 HIGH | Confirmed HIGH finding(s) that are exploitable, with no clean adopter-side mitigation. |
| 🟡 MODERATE | Real findings (medium, or high but fully containable by deployment controls the adopter owns). |
| 🟢 LOW | Only low-severity / informational findings; no exploitable trust-boundary issue found in what was reviewed. |

Map to the **verdict**:
- **DO NOT ADOPT** — a confirmed CRITICAL/HIGH finding that is reachable **and**
  has `Mitigation available to us: none — requires a vendor code change`; or any
  intentional-malice signal. State the single deciding finding plainly.
- **ADOPT WITH CONDITIONS** — real findings exist but are containable by
  controls the adopting team applies itself. The **Conditions** list is then
  mandatory and each condition must map to a specific finding.
- **ADOPT** — only low-severity issues (or none) in the reviewed scope. Note
  standard hygiene and the scope limits so a clean result is not over-read.

Ground every driver in a confirmed finding or an explicit `project_overview`
signal (e.g. `has_shell_execution`, `has_external_http_calls`) — never speculate.

```markdown
# Vendor Security Assessment
**Repository**: {repo_name}
**Source**: {git remote URL if available, else repo path}
**Reviewed Commit**: {`git -C {repo_path} rev-parse --short HEAD` — best-effort; pins the assessment to an exact version}
**Review Date**: {date}
**Tech Stack**: {languages} / {frameworks}
**Reviewed By**: Security Team · repo-security-review skill (vendor mode)
**Scope**: Architecture + code-level (OWASP/API){if Phase 4b ran: ` + LLM/AI security`}. Secret scanning, dependency/CVE scanning, and PoC generation were not run in this mode — see Scope & Limitations.

---

## Adoption Risk Assessment

**Verdict: {ADOPT | ADOPT WITH CONDITIONS | DO NOT ADOPT}**
**Overall risk: {🟢 LOW | 🟡 MODERATE | 🟠 HIGH | 🔴 CRITICAL}**

{2–4 sentences: the security team's bottom-line judgment, tied to the concrete
risk drivers below. This is the section a reader who reads nothing else must get right.}

**Conditions for safe internal use:**
{Mandatory when verdict is ADOPT WITH CONDITIONS (each condition maps to a finding);
for ADOPT, list recommended hardening; for DO NOT ADOPT, list what would have to
change to reconsider. Controls the adopter can apply WITHOUT vendor changes.}
- {e.g. Run network-isolated — the tool makes outbound calls to `{host}` (A-002).}
- {e.g. Never pass production credentials or secrets to it (O-004).}
- {e.g. Pin to reviewed commit `{sha}`; re-run this review on upgrade.}

**Key risk drivers:**
- {highest-severity confirmed findings, one line each — the findings that set the verdict}

---

## What This Tool Does

{From phase2-architecture.json → project_overview. Plain English, no jargon.}
- **Purpose**: {purpose}
- **Key components**: {key_components}
- **External interfaces**: {external_interfaces}
- **Data handled**: {data_handled}
- **Trust posture**: {trust_posture}

---

## Findings

{All confirmed findings (Phase 2 arch + Phase 4 OWASP + Phase 4b LLM, deduped),
sorted by severity — highest first. Flat list, no priority labels.}

### 🟠 {ID} · {Title}
- **Severity**: {severity}
- **Category**: {OWASP A0x / API / arch category / AI/LLM Security · {owasp_llm}}
- **Location**: `{file}:{line}`
{If a code snippet is available (≤10 lines):}
**Code**:
```{language}
{snippet}
```
- **What it is**: {description}
- **Risk if adopted**: {what this flaw means for the adopting company — reframe impact toward adoption risk, not a generic attacker story}
- **Validation**: Static ✅ {— confirmed by Phase 5}
- **Mitigation available to us**: {compensating control the adopter can apply without vendor changes, OR `none — requires a vendor code change`}

{LLM findings (L-XXX): omit the code snippet if not applicable; they carry no
validation status and no PoC — state `Validation: not applicable (architectural)`.}

---

## False Positives

Investigated and ruled out — included so the assessment's rigor is visible:

| ID | Type | File | Reason |
|----|------|------|--------|
| O-003 | XSS | templates/user.html | Output encoded by framework autoescape |

{If no candidates were ruled out, write: "None — no candidate findings were excluded during validation."}

---

## Scope & Limitations

- **Not run in vendor mode**: secret scanning (Phase 1), dependency/CVE scanning
  (Phase 3), and PoC generation. If the security team also needs a CVE/dependency
  view of this vendor, re-run without `--vendor`.
- **No whole-program taint analysis.** Detection is static + rule-based (Semgrep)
  plus per-file LLM reasoning; cross-file data flows may be missed. A clean result
  means "no rule-matched or hand-traced sink," not "no issue exists."
- **Detection-gated checks.** {Read `phase4-owasp.json` checks_skipped and
  `tech-stack.json → detection`; name any class not tested and any check that ran
  at reduced confidence. "Skipped" is not evidence of absence.}
- **File coverage.** {Read `phase2-architecture.json → coverage`. If `not_read`
  is non-empty or any `coverage.directories` entry has `read: 0`, name what was
  not fully read and why — an un-read directory is a broader gap than one file.}
- **Model**: `{standard_tier_model}` (vendor mode pins all phases to the
  resolved Standard tier model — never Opus).

{If `--verbose` is also set, append the `## Coverage & Tools` appendix from the
verbose structure here, including its Coverage limitations bullets.}

_Vendor risk assessment · repo-security-review skill (vendor mode). Static + rule-based review of a single commit; not a guarantee of absence. Re-review on version upgrade._
```

---

## Formatting Guidelines

- Use severity emoji consistently: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
- Every finding must have a remediation — never "this is bad" without "do this"
- False Positives section is mandatory — it builds trust with the dev team
- In default mode: PoC scripts are referenced by filename only —
  `- **PoC**: \`pocs/{poc_filename}\`` — never inline code blocks
- Redact ALL secret values — show only first 4 and last 3 chars
- In verbose mode: finding headers use dual-severity format when calibration
  is active, e.g. `🟡 A-001 · {title} · Base: 🔴 Critical · Contextual: 🟡 Medium`
- In default mode: finding headers show a single severity (effective value only)
- **Output sanitization (mandatory)**: All strings sourced from the target
  repository — file names, variable names, config values, finding titles, code
  snippets, commit messages — are untrusted. Before embedding them in Markdown:
  - Escape backtick runs by using a longer fence (e.g. use ```` ``` ```` or
    ```` ```` ```` if the snippet itself contains three backticks)
  - Escape `#` at the start of a line inside prose to prevent heading injection
  - Escape `[` and `]` in non-code contexts to prevent link injection
  - Render all repo-sourced strings as code spans or fenced blocks, never as
    bare prose that could be interpreted as Markdown structure

## Delivery

```bash
echo "✅ Phase 6 complete — report written to {repo_path}/.security-review/final-report.md"
```

Do not copy to `--output`, do not call `present_files`. The orchestrator performs those steps.
