# Phase 3 + 3b: Dependency CVE Scanning & Reachability Validation

## Phase 3: CVE Scanning

### Goal
Find known CVEs in the project's dependencies. Scope the scan to only the
package ecosystems actually present in the project — don't run npm audit on a
pure Python project.

### Step 0: Load Tech Stack Profile

Read `{repo_path}/.security-review/tech-stack.json`.

If that file doesn't exist (Phase 2 was skipped), run lightweight detection:
```bash
find {repo_path} -maxdepth 4 \( \
  -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \
  -o -name "requirements.txt" -o -name "Pipfile.lock" -o -name "poetry.lock" \
  -o -name "go.sum" -o -name "Cargo.lock" \
  -o -name "pom.xml" -o -name "build.gradle" \
  -o -name "Gemfile.lock" \
\) -not -path "*/node_modules/*" -not -path "*/.git/*"
```
Use the found files to infer ecosystems.

### Step 1: Run OSV-Scanner (always — handles all ecosystems)

OSV-Scanner auto-detects ecosystems from lockfiles. Run it across the entire repo:
```bash
osv-scanner --format json -r {repo_path} > {repo_path}/.security-review/osv-raw.json 2>&1
```

### Step 2: Ecosystem-Specific Tools (only if ecosystem is confirmed present)

Use `package_ecosystems` from tech-stack.json to decide which to run:

**npm / Node.js** — only if `"npm"` in `package_ecosystems`:
```bash
for lockfile in $(cat {repo_path}/.security-review/tech-stack.json | python3 -c \
  "import sys,json; d=json.load(sys.stdin); [print(f) for f in d.get('package_files',{}).get('npm',[])]"); do
  dir=$(dirname "{repo_path}/$lockfile")
  cd "$dir" && npm audit --json >> {repo_path}/.security-review/npm-audit-raw.json 2>&1
done
```

**Python / pip** — only if `"pypi"` in `package_ecosystems`:
```bash
# pip-audit handles requirements.txt, Pipfile.lock, poetry.lock
pip-audit --format json -r {requirements_file} \
  > {repo_path}/.security-review/pip-audit-raw.json 2>&1
```

**Java / Maven or Gradle** — only if `"maven"` in `package_ecosystems`:
```bash
# grype works on compiled JARs or source
grype dir:{repo_path} --output json > {repo_path}/.security-review/grype-raw.json 2>&1
```

**Skip entirely** for ecosystems not in `package_ecosystems`. Log the reason:
```
ℹ️  Skipping npm audit — no npm ecosystem detected in tech-stack.json
ℹ️  Skipping pip-audit — no pypi ecosystem detected
```

### Step 3: Parse, Deduplicate, and Write Initial Output

- Merge results from all tools
- Deduplicate by CVE ID
- Keep highest CVSS score if same CVE from multiple sources
- Write `phase3-cves.json` now with enrichment fields set to `null` as placeholders —
  Step 4 reads CVE IDs from this file and updates it in place

### Step 4: EPSS + KEV Enrichment

Read CVE IDs from the file written in Step 3, fetch both external signals, then
update each finding in `phase3-cves.json` with the results.

**EPSS scores** — batch fetch from FIRST.org (one HTTP call for all CVEs):
```bash
CVE_LIST=$(jq -r '[.findings[].cve_id] | join(",")' \
  {repo_path}/.security-review/phase3-cves.json)
curl -sf "https://api.first.org/data/v1/epss?cve=${CVE_LIST}" \
  -o {repo_path}/.security-review/epss-raw.json \
  || echo '{"data":[]}' > {repo_path}/.security-review/epss-raw.json
```

Response shape per CVE: `{ "cve": "CVE-...", "epss": "0.975", "percentile": "0.999" }`

If the API is unreachable, leave `epss_score: null` and `epss_percentile: null` on all
findings and set `enrichment.epss_fetched: false` — do not abort the phase.

**CISA KEV catalog** — download the full list (one HTTP call):
```bash
curl -sf "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  -o {repo_path}/.security-review/kev-catalog.json \
  || echo '{"vulnerabilities":[]}' > {repo_path}/.security-review/kev-catalog.json
```

Cross-reference each CVE against the `vulnerabilities[].cveID` field. If the catalog is
unreachable, leave `in_kev: null` on all findings and set `enrichment.kev_fetched: false`.

After both fetches, update `phase3-cves.json` in place: write the enriched values into
each finding and set the `enrichment` block fields to reflect fetch success/failure.

### Output: phase3-cves.json
```json
{
  "phase": "cve_scanning",
  "ecosystems_scanned": ["pypi"],
  "ecosystems_skipped": [
    {"ecosystem": "npm", "reason": "not present in tech-stack.json"}
  ],
  "enrichment": {
    "epss_fetched": true,
    "kev_fetched": true,
    "epss_fetch_error": null,
    "kev_fetch_error": null
  },
  "summary": {
    "total_dependencies_scanned": 0,
    "total_cves_found": 0,
    "in_kev": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "C-001",
      "cve_id": "CVE-2023-XXXXX",
      "package": "package-name",
      "installed_version": "1.2.3",
      "fixed_version": "1.2.4",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "description": "Remote code execution via malformed input in X",
      "affected_function": "packageName.vulnerableFunction()",
      "ecosystem": "pypi",
      "epss_score": 0.97548,
      "epss_percentile": 0.99977,
      "in_kev": true,
      "kev_date_added": "2021-12-10",
      "reachable": null
    }
  ]
}
```

Set `reachable: null` — Phase 3b fills this in.

---

## Phase 3b: Reachability Validation

### Goal
For each CVE, determine whether the vulnerable code path is actually exercised.
Unreachable CVEs are still reported but at lower effective severity.

### Reachability Criteria

**REACHABLE** — ALL true:
1. The vulnerable package is imported in application code (not just test/dev)
2. The specific vulnerable function/class is called
3. The call site can receive untrusted/external input

**UNREACHABLE** — ANY true:
- Package is only in `devDependencies` / test dependencies
- Package is imported but vulnerable API is never called
- Vulnerable function called only with hardcoded/trusted data
- Vulnerable version feature unused (e.g. CVE is in parser but app uses different parser)

**INDETERMINATE**:
- Call graph too complex to trace confidently
- Package used dynamically (`eval`, `require(variable)`)

### How to Assess Reachability

For each CVE:

1. **Find import sites** (adapt pattern to detected language):
```bash
# Python
grep -rn "import {package}\|from {package}" {repo_path} \
  --include="*.py" --exclude-dir=".git" --exclude-dir="test*" --exclude-dir="spec*"

# JavaScript / TypeScript
grep -rn "require.*{package}\|from.*{package}" {repo_path} \
  --include="*.js" --include="*.ts" \
  --exclude-dir="node_modules" --exclude-dir=".git" --exclude-dir="__tests__"

# Go
grep -rn '"{module_path}"' {repo_path} --include="*.go" --exclude-dir=".git"
```

2. **Check if vulnerable function is called** — search for the specific
   function name from `affected_function` in the CVE

3. **Trace to entry point** — does the call chain reach an HTTP handler,
   queue consumer, or external-input-receiving code?

### Output: phase3b-reachability.json
```json
{
  "phase": "reachability",
  "findings": [
    {
      "cve_id": "CVE-2023-XXXXX",
      "reachable": true,
      "confidence": "HIGH | MEDIUM | LOW",
      "evidence": {
        "import_sites": ["src/parser.py:L5"],
        "call_sites": ["src/parser.py:L42"],
        "entry_point": "routes/upload.py:L18 (POST /api/upload)"
      },
      "effective_severity": "CRITICAL",
      "priority": "P0",
      "priority_rationale": "In KEV + reachable",
      "notes": "Used in file upload handler with user-controlled input"
    }
  ]
}
```

### Severity Adjustment Rules

Apply in order — the first matching rule wins.

| Condition | Effective Severity | Priority |
|---|---|---|
| `in_kev: true` AND reachable | Keep CVSS severity (floor: HIGH) | **P0** |
| `in_kev: true` AND unreachable/indeterminate | Keep CVSS severity (floor: HIGH) | **P1** — KEV overrides reachability confidence |
| `epss_score >= 0.7` AND reachable | Keep CVSS severity | **P1** |
| `epss_score >= 0.7` AND unreachable | Keep CVSS severity (no downgrade) | **P1** — high exploitation likelihood overrides reachability |
| reachable AND `epss_score < 0.7` | Keep CVSS severity | **P1/P2** (CRITICAL/HIGH → P1, MEDIUM/LOW → P2) |
| unreachable AND `epss_score >= 0.1` | Downgrade one level | **P2** |
| unreachable AND `epss_score < 0.1` | Downgrade two levels | **P3** |
| indeterminate (any EPSS) | Keep CVSS severity with warning | **P2** |
| `epss_score: null` or `in_kev: null` (fetch failed) | Apply reachability rules only, note missing enrichment | per reachability |

**KEV floor rule**: a CVE in KEV is never reported below HIGH effective severity, regardless of CVSS base score or reachability. Active exploitation in the wild makes it a real threat independent of local code paths.

**EPSS interpretation**:
- `>= 0.7` (top ~3% of all CVEs) — actively targeted; treat as reachable even if static analysis says otherwise
- `0.1–0.7` — moderate exploitation interest; reachability drives the call
- `< 0.1` — rarely exploited; unreachable paths can be deprioritised aggressively
