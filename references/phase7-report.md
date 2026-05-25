# Phase 7: Report Builder Agent

## Goal
Aggregate all phase outputs into a single, well-structured security report
and write it to a permanent, user-specified path — not /tmp.

## Input Files to Read

Read all that exist (some may be absent if a phase was skipped):
```
/tmp/security-review-{name}/tech-stack.json
/tmp/security-review-{name}/phase1-secrets.json
/tmp/security-review-{name}/phase2-architecture.json
/tmp/security-review-{name}/phase3-cves.json
/tmp/security-review-{name}/phase3b-reachability.json
/tmp/security-review-{name}/phase4-owasp.json
/tmp/security-review-{name}/phase5-validated.json
/tmp/security-review-{name}/phase6-pocs.json
```

## Output Paths

The orchestrator passes two paths:
- `{output_path}` — full path for `final-report.md` (e.g. `~/security-reports/myapp-2025-05-24.md`)
- `{pocs_dir}` — sibling directory for PoC scripts (e.g. `~/security-reports/myapp-2025-05-24-pocs/`)

```bash
# Create output directory
mkdir -p "$(dirname {output_path})"
mkdir -p "{pocs_dir}"

# Copy PoC scripts if they exist
if [ -d "/tmp/security-review-{name}/pocs" ]; then
  cp -r /tmp/security-review-{name}/pocs/* "{pocs_dir}/"
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
**Reviewed By**: Automated Pipeline (Claude Code + security-review skill)

---

## Executive Summary

{2-3 sentence summary of overall security posture. Be direct — name the
most critical issues and the overall risk level.}

| Severity | Secrets | Architecture | CVEs | Code-Level | Total |
|----------|---------|--------------|------|------------|-------|
| 🔴 Critical | N | N | N | N | **N** |
| 🟠 High | N | N | N | N | **N** |
| 🟡 Medium | N | N | N | N | **N** |
| 🟢 Low | N | N | N | N | **N** |

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

### Reachable CVEs (Prioritize These)

#### 🔴 C-001 · {cve_id} · {package}@{version} · CVSS {score}
- **Fixed In**: `{fixed_version}`
- **Reachability**: ✅ Confirmed reachable
  - Import: `{import_site}`
  - Call site: `{call_site}`
  - Entry point: `{entry_point}`
- **Description**: {description}
- **Remediation**: `{package_manager} upgrade {package} to {fixed_version}`

### Unreachable CVEs (Lower Priority — Still Remediate)

#### 🟡 C-005 · {cve_id} · {package}@{version} · CVSS {score}
- **Fixed In**: `{fixed_version}`
- **Reachability**: ℹ️ Not reachable — {reason}
- **Remediation**: `{package_manager} upgrade {package} to {fixed_version}`

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
{include poc_code from phase6-pocs.json}
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

## Section 6: Skipped Phases

{If any phases were skipped via --skip flag:}
| Phase | Reason Skipped |
|-------|---------------|
| Phase 3 - Dependencies | --skip dependencies flag provided |
| Phase 6 - PoC | --skip poc flag provided |

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
| Reachability | Static call-graph analysis | ✅ Ran / ⏭️ Skipped |
| OWASP Analysis | semgrep + Claude Sonnet | ✅ Ran / ⏭️ Skipped |
| Validation | Static data flow tracing | ✅ Ran / ⏭️ Skipped |
| Runtime Validation | Docker + PoC probes | ✅ Ran / ⏭️ Skipped / ❌ Not available |
| PoC Generation | Claude Sonnet | ✅ Ran / ⏭️ Skipped |

*Report generated by security-review skill v2*
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

## Delivery

After writing the report:
```bash
echo ""
echo "📄 Security report saved to: {output_path}"
if [ -d "{pocs_dir}" ] && [ "$(ls -A {pocs_dir})" ]; then
  echo "📁 PoC scripts saved to:    {pocs_dir}"
fi
```
