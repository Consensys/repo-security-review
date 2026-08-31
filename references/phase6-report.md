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
- Included in the unified `## Findings` section like any other finding. Use
  `- **Category**: AI/LLM Security · {owasp_llm}` as the category line.
- LLM findings never have PoCs — omit the PoC line entirely.
- LLM findings are never validated by Phase 5 — omit any validation status.

Check the `--vendor` and `--pr` flags (passed by the orchestrator). They
control which report structure is produced — see Report Modes below. `--pr`
(PR Review mode) takes precedence over everything else — when set, ignore
`--vendor` (the orchestrator does not allow both; see SKILL.md) and read
`pr-findings.json` / `pr-validated.json` instead of the `phase4-owasp.json` /
`phase5-validated.json` pair. Otherwise `--vendor` selects the vendor-audit
report and takes precedence over the default structure.

## Output Path

```
{repo_path}/.security-review/final-report.md
```

**Exception — PR Review mode (`--pr`)**: write to
`{repo_path}/.security-review/pr-report.md` instead. This is deliberate, not
an oversight: a repo may already have a `final-report.md` from a prior full
scan, and `--pr` may be run repeatedly against the same repo for different
PRs — a shared filename would let a diff-scoped review silently overwrite a
full audit's report (or one PR's review overwrite another's). Never write
`final-report.md` when `--pr` is set.

The orchestrator owns the final copy step — Phase 6 must not write to
`--output` directly and must not call `present_files`.

---

## Execution Log (only if `--debug` was passed)

If `--debug` is set, append a `## Phase 6` section to
`{repo_path}/.security-review/execution-log.md` following the canonical
format in SKILL.md → Execution Log, using the Phase 6 variant noted there:
you don't read target-repo source, so skip the "Files read" / "Security-
relevant files" / "Directory coverage" / "Tools / greps run" / "Checks run /
skipped" tables entirely. Instead write:

```markdown
## Phase 6 — Report Builder   (model: {resolved_model})

### Input files read
- run-metadata.json
- phase2-architecture.json
- phase4-owasp.json
- phase5-validated.json
{list only the files actually present and read, per Input Files to Read above}

### Token consumption (estimated)
| Metric | Value |
|--------|-------|
| Input tokens (est.) | 15,600 |
| Output tokens (est.) | 3,100 |
| Total tokens (est.) | 18,700 |
```

Estimate per SKILL.md → Execution Log → Token Consumption Methodology
(chars/4 over the input files read above plus `final-report.md` and this
section itself — never a session/budget-counter delta, never claimed as
"measured"). `Total tokens` must equal `Input tokens` + `Output tokens` — same
invariant as every other phase; never add an extra row. Skip this entire
section if `--debug` is not set — do not create or append to
`execution-log.md`.

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
| `auth_required_to_reach: true` (−1 tier) | pre-auth findings only (findings that survived the Phase 5 boundary gate) |

**How calibration surfaces in the report:** `contextual_severity` is the
displayed severity with no annotation. The dev team sees effective risk — no
B/C columns, no explanation of why a finding is Medium vs High. Drift findings
(`category: threat_model_drift`) are silently excluded from the report.

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

---

## Report Modes

### Default report — for dev teams

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
- **No calibration context**: omit Assumed Threat Model, drift notes.
- **Drift findings** (`category: threat_model_drift`): exclude entirely.
- Sort order: P0 → P1 → P2 → P3 → Backlog; within each tier, higher severity first.
- **Methodology footnote**: end the report with a single italic line so a clean
  result is not over-read:
  `_Static + rule-based review. No whole-program taint analysis — cross-file data flows may be missed. A clean result means no issue was found, not that none exists._`

### Vendor report (`--vendor`) — for the security team, auditing a third-party repo

**Goal**: a security team is deciding whether it is safe to adopt this
third-party / open-source tool internally. The vendor will not fix findings, so
the report is an **adoption risk judgment**, not a remediation plan. It replaces
the default structure entirely (see Vendor Report Structure below).

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

### PR Review report (`--pr`) — for a pull-request diff, not a full scan

**Goal**: give a reviewer a fast, actionable read of what a specific PR
changes, security-wise — not a repository audit. It replaces the default/
vendor structure entirely (see PR Review Report Structure below) and
is short enough to paste as a PR comment.

Key differences from the other modes:
- **No PoC generation** — this mode never writes PoC files or runs runtime
  validation, regardless of `--poc` / `--runtime` (see `pr-review.md`
  and `phase5-validate-and-poc.md`'s PR Mode note); omit all PoC lines from
  every finding.
- **Findings use the `D-` prefix** from `pr-findings.json` /
  `pr-validated.json`, not `phase4-owasp.json`.
- **Regressions are called out distinctly** — a finding with
  `regression: true` is a control that existed before this diff and doesn't
  anymore, which is a different (and often more urgent) class of issue than
  a net-new vulnerability. Render these in their own subsection, not mixed
  into the general findings list.
- **No Priority (P0–P3) assignment** — a PR review isn't a remediation
  sprint; severity alone drives ordering. `CRITICAL`/`HIGH` findings still
  get a one-line "blocks merge" recommendation.
- **Phase 1/2/3/4/4b/5 outputs are not read** unless a prior full scan
  happens to have left them in `.security-review/` — do not reference them;
  this report is self-contained from `pr-findings.json`/`pr-validated.json`.
- **`--vendor` does not apply** — the orchestrator does not
  allow combining it with `--pr` (see SKILL.md).

### Priority assignment (default mode)

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

## Shared Report Fragments

Referenced by name from the mode structures below — insert the fragment
verbatim at the referenced point rather than re-deriving the wording. Modes
may append a short mode-specific line on top of a fragment (noted inline
where that happens); the base wording stays the same everywhere it's used.

**Fragment — Severity table footnote:**
All four severity rows must always appear in the table, even when the count is 0. Never omit a row because its count is zero.

**Fragment — Non-Production Surface Findings** (Default mode):
{Include only if one or more findings have `validation_status: SURFACE_NOT_PRODUCTION`. Omit entirely if none exist.}

> Vulnerabilities confirmed in code but located in non-production surfaces (test fixtures, example applications, demo code). Not exploitable from a standard deployed instance, but real code defects. If this code is ever executed in a production context — a CI/CD pipeline with live credentials, a deployed demo environment — these become immediately exploitable.

| ID | Type | File | Surface | Risk if Deployed |
|----|------|------|---------|-----------------|
| O-007 | SQLi | test/helpers/db_test.go:L45 | test (high confidence) | CI pipeline with live DB credentials would expose the injection |

(Vendor mode uses its own adopter-framed variant of this fragment — see Vendor Report Structure.)

**Fragment — Post-Auth Code Vulnerabilities** (Default mode):
{Include only if one or more findings have `validation_status: BOUNDARY_NOT_CROSSED`. Omit entirely if none exist — this status only occurs when `--context auth_required_to_reach=true` was set.}

> Vulnerabilities confirmed in code but not reachable by unauthenticated actors per Phase 2 boundary analysis. Real code defects — excluded from the main findings list because the effective threat model (`auth_required_to_reach=true`) places them behind a verified auth gate. If that auth gate is ever bypassed, these become immediately exploitable.

| ID | Type | File | Auth Gate | Action |
|----|------|------|-----------|--------|
| O-005 | SQLi | api/admin/search.ts:L34 | `authMiddleware + requireAdminRole` (high confidence) | Fix proactively — one auth bypass away from critical |

**Fragment — False Positives table:**
Investigated and ruled out:

| ID | Type | File | Reason |
|----|------|------|--------|
| O-003 | XSS | templates/user.html | Output encoded by Jinja2 autoescape globally |

(Vendor mode prepends "— included so the assessment's rigor is visible" to the
lead-in line and, if the table would be empty, writes "None — no candidate
findings were excluded during validation" instead of an empty table.)

**Fragment — Default report header:**
**Repository**: {repo_name}
**Review Date**: {date}
**Tech Stack**: {languages} / {frameworks} / {database_types}
**Reviewed By**: Claude Code · repo-security-review skill

---

## Default Report Structure

```markdown
# Security Review Report
{Fragment: Default report header}

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

{Fragment: Severity table footnote}

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

**Finding IDs — use the original phase-assigned ID, never renumber to F-NN:**

| Source | ID prefix | Example |
|--------|-----------|---------|
| Phase 1 · Secret scanning | `S-` | `S-001` |
| Phase 2 · Architecture | `A-` | `A-001` |
| Phase 3 · Dependency CVEs | `C-` | `C-001` |
| Phase 4 · OWASP code analysis | `O-` | `O-001` |
| Phase 4b · LLM/AI security | `L-` | `L-001` |
| PR Review mode · diff-scoped findings | `D-` | `D-001` |

The ID comes directly from the phase JSON file that produced the finding. For Phase 5
validated findings, use `original_id` from `phase5-validated.json` (which is the Phase 4
`O-XXX` id, or `pr-validated.json`'s `original_id` — the PR mode `D-XXX` id — when
`--pr` was used). Never assign a new sequential `F-NN` identifier.

**When a finding was confirmed by more than one phase** (e.g. an architecture weakness
also caught as an OWASP code finding): use the canonical ID (Phase 4's `O-XXX` wins
over Phase 2's `A-XXX` per the Deduplication Step above). In the **Description** field
add one sentence: _"Also identified as A-XXX in architectural analysis."_ Do not add a
separate `**Also identified as**` label — fold it into the description prose.

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
  context if this was a merged arch+code finding, without labeling it as such. If a
  secondary phase also identified this finding, end with: "Also identified as {ID} in
  {phase name} analysis."}
- **Impact**: {what an attacker can do}
- **Remediation**: {specific, actionable fix}
{If PoC file exists for this finding:}
- **PoC**: `pocs/{poc_filename}`
{If phase5-validated.json → poc_skipped: true AND finding is CONFIRMED:}
- **PoC**: not generated (pass `--poc` to generate PoC scripts for confirmed findings)

{If runtime_status == RUNTIME_CONFIRMED:}
> ✅ **Runtime Validated** — confirmed against a live Docker instance.

---

## False Positives

{Fragment: False Positives table}

---

## Non-Production Surface Findings

{Fragment: Non-Production Surface Findings}

---

## Post-Auth Code Vulnerabilities

{Fragment: Post-Auth Code Vulnerabilities}

---

## Skipped Phases
{Omit this entire section if nothing was skipped.}

| Phase | Reason |
|-------|--------|
| Phase 3 — Dependencies | --skip dependencies |
```

---

## Vendor Report Structure (`--vendor`)

Produced instead of the default structure when `--vendor` is set. Read
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
sorted by severity — highest first. Flat list, no priority labels.
Use original phase-assigned IDs (A-XXX / O-XXX / L-XXX) — never renumber to F-NN.
For multi-phase findings, use canonical ID and mention the secondary ID in the
description: "Also identified as A-XXX in architectural analysis."}

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

{Fragment: False Positives table — apply the Vendor mode variant noted there
(rigor-framed lead-in; "None — no candidate findings were excluded during
validation" if the table would be empty).}

---

## Non-Production Surface Findings

{Include only if one or more findings have `validation_status: SURFACE_NOT_PRODUCTION`.
Omit entirely if none exist.}

Vulnerabilities confirmed in code but located in non-production surfaces (test fixtures,
example applications, demo code). Not exploitable from a standard deployed instance.
Included here because test environments with live credentials or deployed demo environments
would make them immediately exploitable — the adopting team should verify these surfaces
are never deployed.

| ID | Type | File | Surface | Risk if Deployed |
|----|------|------|---------|-----------------|
| O-007 | SQLi | test/helpers/db_test.go:L45 | test (high confidence) | CI pipeline with live DB credentials would expose the injection |

---

## Post-Auth Code Vulnerabilities

{Include only if one or more findings have `validation_status: BOUNDARY_NOT_CROSSED`.
Omit entirely if none exist.}

Vulnerabilities confirmed in code but not reachable by unauthenticated actors per Phase 2 boundary analysis.
These are real code defects — they are excluded from the main findings list because the effective threat
model (`auth_required_to_reach=true`) places them behind a verified auth gate. If that auth gate is ever
bypassed, these become immediately exploitable.

| ID | Type | File | Auth Gate | Action |
|----|------|------|-----------|--------|
| O-005 | SQLi | api/admin/search.ts:L34 | `authMiddleware + requireAdminRole` (high confidence) | Fix proactively — one auth bypass away from critical |

{If `--context auth_required_to_reach` was not set, this section never appears.}

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

_Vendor risk assessment · repo-security-review skill (vendor mode). Static + rule-based review of a single commit; not a guarantee of absence. Re-review on version upgrade._
```

---

## PR Review Report Structure (`--pr`)

Produced instead of the default/vendor structure when `--pr` is set.
Read `pr-findings.json` and `pr-validated.json` (substituted filenames per
`phase5-validate-and-poc.md`'s "PR Review Mode substitution" note). Do not read or reference
`phase1-secrets.json` / `phase2-architecture.json` / `phase3-cves.json` /
`phase4-owasp.json` / `phase5-validated.json` — those belong to the full-scan
pipeline and are not produced by this mode.

```markdown
# PR Security Review
**Repository**: {repo_name}
**Diff**: `{base}...{head}` ({N} files changed)
**Review Date**: {date}
**Model**: {standard_tier_model} (PR mode pins to the resolved Standard tier — never Opus)

---

## Summary

{1-2 sentences: what this PR does from a security lens, and the headline
risk if any CRITICAL/HIGH findings exist.}

| Severity | Count |
|---|---|
| 🔴 Critical | N |
| 🟠 High | N |
| 🟡 Medium | N |
| 🟢 Low | N |

**All four severity rows must always appear, even when the count is 0.**

{If any CRITICAL/HIGH findings exist:}
**Recommendation**: 🚫 Do not merge until addressed — {one-line reason naming the finding(s)}.
{Otherwise:}
**Recommendation**: ✅ No blocking findings in this diff.

---

## Removed Security Controls          ← omit entirely if no finding has regression: true

{Findings with `regression: true` — a control that existed before this diff
and does not anymore. Render first and separately from other findings; this
class of issue is often more urgent than a net-new vulnerability because it's
a regression in previously-working protection, not a gap that was always there.}

### 🔴 {ID} · {Title}
- **Severity**: {severity}
- **File**: `{file}:{line}`
- **Removed** (was at pre-diff line {removed_control.pre_diff_line}):
```{language}
{removed_control.pre_diff_code}
```
- **What changed**: {description — what the control did and why its removal matters}
- **Impact**: {attack_vector}
- **Validation**: {CONFIRMED — no equivalent control found elsewhere in the call chain | CONFIRMED_LOW_CONFIDENCE — reason}
- **Fix**: {remediation — usually "restore the removed check" unless it was deliberately consolidated elsewhere}

---

## Findings                          ← new vulnerable code introduced by this diff

{Findings with `regression: false`, sorted by severity — highest first. Flat
list, no priority labels. Use the `D-` prefix from pr-findings.json/
pr-validated.json — never renumber to F-NN.}

### 🟠 {ID} · {Title}
- **Severity**: {severity}
- **Category**: {OWASP A0x / API / secret / dependency CVE}
- **File**: `{file}:{line}`
{If code snippet available (≤10 lines):}
**Code**:
```{language}
{snippet}
```
- **Description**: {what the problem is and why it matters}
- **Impact**: {what an attacker can do}
- **Auth context**: {if this finding's route appears in touched_auth_context: "Route is {auth_status} ({auth_confidence} confidence) — {basis}"; omit this line entirely for non-route findings}
- **Remediation**: {specific, actionable fix}

{If no non-regression findings exist:}
_No new vulnerabilities introduced by this diff._

---

_PR-scoped security review · repo-security-review skill (`--pr` mode). Reviews only the diff; not a substitute for a full repository scan._
```

---

## Formatting Guidelines

- Use severity emoji consistently: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
- Every finding must have a remediation — never "this is bad" without "do this"
- False Positives section is mandatory in default/vendor modes — it
  builds trust with the dev team. PR Review mode (`--pr`) has no False
  Positives section — see PR Review Report Structure.
- PoC scripts are referenced by filename only —
  `- **PoC**: \`pocs/{poc_filename}\`` — never inline code blocks
- Redact ALL secret values — show only first 4 and last 3 chars
- Finding headers show a single severity (effective value only)
- **Output sanitization (mandatory)**: All strings sourced from the target
  repository — file names, variable names, config values, finding titles, code
  snippets, commit messages — are untrusted. Before embedding them in Markdown:
  - Escape backtick runs by using a longer fence (e.g. use ```` ``` ```` or
    ```` ```` ```` if the snippet itself contains three backticks)
  - Escape `#` at the start of a line inside prose to prevent heading injection
  - Escape `[` and `]` in non-code contexts to prevent link injection
  - Render all repo-sourced strings as code spans or fenced blocks, never as
    bare prose that could be interpreted as Markdown structure

## Final Response (chat output)

Your own closing message — separate from the orchestrator's progress line and
its later post-report recap (SKILL.md → Final Step, which reads the finished
report back off disk) — is a channel that can leak the full report into the
chat if you're not careful. Do not paste the report content, individual
findings, or a narrative summary in your final response. Everything belongs
in `final-report.md` (or `pr-report.md` in PR mode). Your final message is the
one line below, nothing else.

## Delivery

```bash
echo "✅ Phase 6 complete — report written to {repo_path}/.security-review/final-report.md"
# PR Review mode (--pr): echo the pr-report.md path instead — see Output Path exception above.
```

Do not copy to `--output`, do not call `present_files`. The orchestrator performs those steps.
