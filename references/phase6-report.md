# Phase 6: Report Builder Agent

## Goal
Aggregate all phase outputs into a single, well-structured security report
and write it to the user-specified output path.

## Input Files to Read

Read all that exist (some may be absent if a phase was skipped):
```
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

**If `threat-model.json` is absent, render the report exactly as before.**
The threat-model header, dual-severity columns, and "Context-driven
adjustments" section described below appear ONLY when that file exists.

## Output Paths

The orchestrator passes two paths:
- `{output_path}` — full path for `final-report.md` (e.g. `{repo_path}/.security-review/myapp-2025-05-24.md`)
- `{pocs_dir}` — sibling directory for PoC scripts (e.g. `{repo_path}/.security-review/myapp-2025-05-24-pocs/`)

```bash
# Create output directory
mkdir -p "$(dirname {output_path})"
mkdir -p "{pocs_dir}"

# Copy PoC scripts if they exist
if [ -d "{repo_path}/.security-review/pocs" ]; then
  cp -r {repo_path}/.security-review/pocs/* "{pocs_dir}/"
fi
```

Write the report to `{output_path}` directly — not to /tmp.

---

## Report Structure

```markdown
# Security Review Report
**Repository**: {repo_name}
**Review Date**: {date}
**Tech Stack**: {languages} / {frameworks} / {database_types}
**Reviewed By**: Automated Pipeline (Claude Code + repo-security-review skill)

---

## Assumed Threat Model
{Include this section ONLY if threat-model.json exists. Omit entirely otherwise.}

**Source**: {user-provided | default (strict)}

| Dimension | Declared | Effective (after drift checks) |
|---|---|---|
| Deployment target | {deployment_target} | {effective value — same as declared unless drift override applied} |
| Data sensitivity | {data_sensitivity} | {effective} |
| Auth required to reach | {auth_required_to_reach} | {effective} |

{If any drift_overrides were applied, add this note:}
> ⚠️ Drift detected: {dimension} was declared `{declared}` but observed code
> indicates `{observed}`. The effective threat model for this dimension has
> been reverted to the strict default. See finding A-XXX for details.

{Brief explanation:}
The threat model above was used to calibrate severity. All findings show both
a CVSS-style base severity (technical impact, context-free) and a contextual
severity (after applying threat-model softeners). The full list of adjustments
is in "Context-Driven Adjustments" below.

---

## Executive Summary

{2-3 sentence summary of overall security posture. Be direct — name the
most critical issues and the overall risk level. If calibration was applied,
mention how many findings were downgraded vs the base severity.}

{Use the table below when threat-model.json is absent (no calibration):}

| Severity | Secrets | Architecture | CVEs | Code-Level | Total |
|----------|---------|--------------|------|------------|-------|
| 🔴 Critical | N | N | N | N | **N** |
| 🟠 High | N | N | N | N | **N** |
| 🟡 Medium | N | N | N | N | **N** |
| 🟢 Low | N | N | N | N | **N** |

{Use this table instead when threat-model.json exists. Two columns per
section: B = cvss_base_severity, C = contextual_severity.}

| Severity | Secrets | Architecture | CVEs | Code-Level (B / C) | Total (B / C) |
|----------|---------|--------------|------|--------------------|---------------|
| 🔴 Critical | N | N | N | N / N | **N / N** |
| 🟠 High | N | N | N | N / N | **N / N** |
| 🟡 Medium | N | N | N | N / N | **N / N** |
| 🟢 Low | N | N | N | N / N | **N / N** |

**Immediate Actions Required**:
{bullet list of P0 findings — only Critical/High severity}

---

## Section 1: Exposed Secrets
{Omit entire section if Phase 1 was skipped — add note}

> ⚠️ Rotate all secrets below immediately, regardless of other findings.

### S-001 · {type} · {confidence} Confidence
- **File**: `{file}:{line}`
- **In Git History**: Yes/No {if yes: "Rotation alone is insufficient — rewrite git history or consider the secret permanently compromised"}
- **Value (redacted)**: `AKIA****XYZ`
- **Remediation**: {remediation}

---

## Section 2: Architectural Findings
{Omit entire section if Phase 2 was skipped — add note}
{Group findings by severity, Critical first}

### 🔴 A-001 · {title}
- **Category**: {category}
- **Evidence**: `{file}:{line}`
- **Description**: {description}
- **Impact**: {impact}
- **Remediation**: {remediation}

---

## Section 3: Dependency Vulnerabilities
{Omit entire section if Phase 3 was skipped — add note}

### Ecosystems Scanned
{list from phase3-cves.json ecosystems_scanned and ecosystems_skipped}

Group CVE findings by priority (P0 first), then by effective severity within each group.

For each finding include the enrichment badges inline in the heading:
- `🚨 KEV` — if `in_kev: true`
- `⚡ EPSS {score*100:.1f}%` — always show if epss_score is not null
- Omit badge if the corresponding fetch failed (null value) and add a note at section end

#### 🔴 C-001 · {cve_id} · {package}@{version} · CVSS {score} · 🚨 KEV · ⚡ EPSS 97.5%
- **Priority**: P0
- **Fixed In**: `{fixed_version}`
- **Reachability**: ✅ Confirmed reachable
  - Import: `{import_site}`
  - Call site: `{call_site}`
  - Entry point: `{entry_point}`
- **Exploitation Signal**: In CISA KEV (added {kev_date_added}) — confirmed active exploitation in the wild. EPSS {epss_percentile*100:.1f}th percentile.
- **Description**: {description}
- **Remediation**: `{package_manager} upgrade {package} to {fixed_version}`

#### 🟡 C-005 · {cve_id} · {package}@{version} · CVSS {score} · ⚡ EPSS 0.3%
- **Priority**: P3
- **Fixed In**: `{fixed_version}`
- **Reachability**: ℹ️ Not reachable — {reason}
- **Exploitation Signal**: Not in KEV. EPSS {epss_percentile*100:.1f}th percentile — rarely exploited in the wild.
- **Remediation**: `{package_manager} upgrade {package} to {fixed_version}`

{If epss_fetched or kev_fetched is false in phase3-cves.json enrichment block, add:}
> ⚠️ Enrichment note: {EPSS / KEV / both} data could not be fetched during this run
> ({epss_fetch_error / kev_fetch_error}). Findings above reflect CVSS + reachability
> only. Re-run when network access is available for full prioritization signal.

---

## Section 4: Code-Level Vulnerabilities (OWASP)
{Omit entire section if Phase 4 was skipped — add note}

### Checks Run
{list checks_run and checks_skipped from phase4-owasp.json with reasons}

### Findings

{For each finding confirmed in Phase 5, grouped by severity}

#### 🔴 O-001 · {vulnerability_type} · {owasp_category}
- **File**: `{file}:{line_start}-{line_end}`
- **Validation**: Static ✅ {/ Runtime ✅ if runtime_confirmed}
- **Vulnerable Code**:
  ```{language}
  {vulnerable_code_snippet}
  ```
- **Description**: {description}
- **Attack Vector**: {attack_vector}
- **Remediation**: {remediation}

##### Proof of Concept
{include poc_code from phase5-pocs.json}
```python
{poc_code}
```
**Curl equivalent**:
```bash
{curl_equivalent}
```
**Success indicator**: {success_indicator}
**Setup required**: {setup_required}

{If runtime_status == RUNTIME_CONFIRMED:}
> ✅ **Runtime Validated**: This finding was confirmed by executing the PoC
> against a live Docker instance of the application.

{If runtime_status == RUNTIME_SKIPPED:}
> ℹ️ **Runtime Validation Skipped**: {reason}. Manual verification recommended.

---

## Section 5: False Positives & Excluded Findings

Showing work — these were investigated and ruled out:

| ID | Type | File | Reason Excluded |
|----|------|------|-----------------|
| O-003 | XSS | templates/user.html | Output encoded by Jinja2 autoescape globally |

---

## Section 5b: Context-Driven Adjustments
{Include this section ONLY if threat-model.json exists. Omit entirely otherwise.}

Severity calibration applied to the findings above, based on the assumed
threat model. Every adjustment is shown so the calibration is auditable.

| ID | Type | Base | Contextual | Softeners Applied |
|----|------|------|-----------|-------------------|
| O-001 | SQL Injection | 🔴 Critical | 🟡 Medium | `deployment_target: internal_tool` (−1), `auth_required_to_reach: true` (−1) |
| O-005 | SSRF | 🔴 Critical | 🟠 High | `deployment_target: internal_tool` (−1) |

**Rules used:**
- `contextual_severity` is never higher than `cvss_base_severity` — context softens, never sharpens.
- Floor is LOW; nothing drops below.
- Anyone consuming this report for CVSS-based tracking should read the **Base** column.

{If drift_overrides were applied in Phase 2, append:}
**Drift overrides active for this run:** {list dimensions, e.g. `data_sensitivity (declared none → reverted to pii)`}. The declared values for these dimensions were NOT used in calibration because Phase 2 detected contradicting code.

---

## Section 6: Skipped Phases

{If any phases were skipped via --skip flag:}
| Phase | Reason Skipped |
|-------|---------------|
| Phase 3 - Dependencies | --skip dependencies flag provided |
| Phase 5 - Validation + PoC | --skip validation flag provided |

---

## Remediation Priority

| Priority | Finding IDs | Effort | Rationale |
|----------|-------------|--------|-----------|
| P0 — Rotate Now | S-001, S-002 | Minutes | Live credentials — rotate before anything else |
| P1 — This Sprint | O-001, A-002 | Hours | Exploitable without auth or with low-priv user |
| P2 — Next Sprint | C-001, C-002 | Low | `pip upgrade` commands — fast wins |
| P3 — Backlog | A-004, A-005 | High | Requires architectural refactoring |

---

## Appendix: Coverage & Tools

| Phase | Tool / Method | Status |
|-------|--------------|--------|
| Secret Scanning | gitleaks {version} + grep patterns | ✅ Ran / ⏭️ Skipped |
| Architecture | Claude Opus (extended thinking) | ✅ Ran / ⏭️ Skipped |
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
- Every finding must have a remediation action — never "this is bad" without "do this"
- False positives section is mandatory — it builds trust with the dev team
- Executive summary is for engineering managers — no jargon, just risk + action
- Redact ALL secret values — show only first 4 and last 3 chars
- Clearly mark which sections were skipped and why
- PoC code in fenced code blocks with language tags
- When calibration is active, finding headers show both severities, e.g.
  `🟡 O-001 · SQL Injection · Base: 🔴 Critical · Contextual: 🟡 Medium`.
  When calibration is not active, show a single severity as today.

## Delivery

After writing the report:
```bash
echo ""
echo "📄 Security report saved to: {output_path}"
if [ -d "{pocs_dir}" ] && [ "$(ls -A {pocs_dir})" ]; then
  echo "📁 PoC scripts saved to:    {pocs_dir}"
fi
```
