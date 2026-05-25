# Phase 3 + 3b: Dependency CVE Scanning & Reachability Validation

## Phase 3: CVE Scanning

### Goal
Find known CVEs in the project's dependencies. Scope the scan to only the
package ecosystems actually present in the project — don't run npm audit on a
pure Python project.

### Step 0: Load Tech Stack Profile

Read `/tmp/security-review-{name}/tech-stack.json`.

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
osv-scanner --format json -r {repo_path} > /tmp/security-review-{name}/osv-raw.json 2>&1
```

### Step 2: Ecosystem-Specific Tools (only if ecosystem is confirmed present)

Use `package_ecosystems` from tech-stack.json to decide which to run:

**npm / Node.js** — only if `"npm"` in `package_ecosystems`:
```bash
for lockfile in $(cat /tmp/security-review-{name}/tech-stack.json | python3 -c \
  "import sys,json; d=json.load(sys.stdin); [print(f) for f in d.get('package_files',{}).get('npm',[])]"); do
  dir=$(dirname "{repo_path}/$lockfile")
  cd "$dir" && npm audit --json >> /tmp/security-review-{name}/npm-audit-raw.json 2>&1
done
```

**Python / pip** — only if `"pypi"` in `package_ecosystems`:
```bash
# pip-audit handles requirements.txt, Pipfile.lock, poetry.lock
pip-audit --format json -r {requirements_file} \
  > /tmp/security-review-{name}/pip-audit-raw.json 2>&1
```

**Java / Maven or Gradle** — only if `"maven"` in `package_ecosystems`:
```bash
# grype works on compiled JARs or source
grype dir:{repo_path} --output json > /tmp/security-review-{name}/grype-raw.json 2>&1
```

**Skip entirely** for ecosystems not in `package_ecosystems`. Log the reason:
```
ℹ️  Skipping npm audit — no npm ecosystem detected in tech-stack.json
ℹ️  Skipping pip-audit — no pypi ecosystem detected
```

### Step 3: Parse and Deduplicate
- Merge results from all tools
- Deduplicate by CVE ID
- Keep highest CVSS score if same CVE from multiple sources

### Output: phase3-cves.json
```json
{
  "phase": "cve_scanning",
  "ecosystems_scanned": ["pypi"],
  "ecosystems_skipped": [
    {"ecosystem": "npm", "reason": "not present in tech-stack.json"}
  ],
  "summary": {
    "total_dependencies_scanned": 0,
    "total_cves_found": 0,
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
      "notes": "Used in file upload handler with user-controlled input"
    }
  ]
}
```

### Severity Adjustment Rules
- Reachable → keep original CVSS severity
- Unreachable → downgrade one level (CRITICAL→HIGH, HIGH→MEDIUM, etc.)
- Indeterminate → keep original severity with a warning note
