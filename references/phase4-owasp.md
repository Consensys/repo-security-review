# Phase 4: Code-Level OWASP Analysis Agent

## Goal
Find code-level vulnerabilities mapped to OWASP Top 10 and OWASP API Security
Top 10. Scope the analysis to checks that are actually relevant to this
project's tech stack — don't test for SQLi in a project with no database.

## Step 0: Load Context

**tech-stack.json** (required — gates all checks):
- Read `{repo_path}/.security-review/tech-stack.json`
- If absent (Phase 2 was skipped), run the lightweight detection from
  `phase2-architecture.md` Step 0 to reconstruct it before continuing.

**phase2-architecture.json** (optional — improves prioritization):
- Read if present: used for auth model context and known weak areas.
- If absent (Phase 2 was skipped), continue without it. Note in output:
  `"architecture_context": "unavailable — Phase 2 was skipped"`.
  All OWASP checks still run; the analysis loses Phase 2's signal on
  auth model and trust boundaries but is otherwise unaffected.

**phase3b-reachability.json** (optional — narrows dep-related checks):
- Read if present: used to cross-reference vulnerable libs that are
  actively reachable.
- If absent (Phase 3 was skipped), continue without it.

**Codebase size** — used by the multi-pass decision below:
```bash
SOURCE_FILES=$(find {repo_path} \( \
  -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.tsx" \
  -o -name "*.go" -o -name "*.java" -o -name "*.rb" -o -name "*.php" \
  -o -name "*.cs" -o -name "*.rs" \
\) -not -path "*/.git/*" -not -path "*/node_modules/*" \
   -not -path "*/vendor/*"  -not -path "*/dist/*" -not -path "*/build/*" \
| wc -l | tr -d ' ')

PHASE2_HIGH_CRITICAL=$(jq '[.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' \
  {repo_path}/.security-review/phase2-architecture.json 2>/dev/null || echo 0)
```

## Step 1: Determine Which Checks to Run

Use tech-stack.json to build your check list BEFORE scanning. Log what you're
skipping and why — this appears in the report.

### OWASP Top 10 — Applicability Matrix

| Check | Run if | Skip if |
|-------|--------|---------|
| A01 Broken Access Control / IDOR | always | — |
| A02 Crypto Failures | always | — |
| A03 SQL Injection | `has_database: true` | `has_database: false` |
| A03 NoSQL Injection | `"mongodb"` or `"redis"` in `database_types` | not present |
| A03 Command Injection | `has_shell_execution: true` | `has_shell_execution: false` |
| A03 Template Injection | `has_html_rendering: true` | `has_html_rendering: false` |
| A03 LDAP/XPath Injection | grep for ldap/xpath usage first | not found |
| A04 Insecure Design | always | — |
| A05 Security Misconfiguration | always | — |
| A06 Vulnerable Components | covered by Phase 3 | — |
| A07 Auth & Session Failures | always | — |
| A08 Deserialization | `has_deserialization: true` | `has_deserialization: false` |
| A08 Unsafe YAML/pickle | language-specific (Python: pickle/yaml.load) | not applicable |
| A09 Logging Failures | always | — |
| A10 SSRF | `has_external_http_calls: true` | `has_external_http_calls: false` |
| Client-side XSS | `has_html_rendering: true` | `is_api_only: true` |
| Stored XSS | `has_html_rendering: true` AND `has_database: true` | either false |

### OWASP API Top 10 — Run Only if `is_api_only: true` OR API endpoints detected

If `is_api_only: false` AND no `/api/` routes found: skip all API Top 10 checks
and log: `ℹ️  OWASP API Top 10 skipped — project does not appear to be API-based`

| API Check | Run if | Skip if |
|-----------|--------|---------|
| API1 BOLA | always (if API) | not API |
| API2 Broken Auth | always (if API) | not API |
| API3 Object Property AuthZ | always (if API) | not API |
| API4 Resource Consumption | always (if API) | not API |
| API5 Function Level AuthZ | always (if API) | not API |
| API6 Business Flow Abuse | always (if API) | not API |
| API7 SSRF | `has_external_http_calls: true` | not applicable |
| API8 Misconfiguration | always (if API) | not API |
| API9 Inventory Management | always (if API) | not API |
| API10 Unsafe API Consumption | `has_external_http_calls: true` | not applicable |

**Print your check plan before scanning:**
```
📋 OWASP Check Plan:
  ✅ Running: A01, A02, A03-SQLi, A07, A09, API1-API9
  ⏭️  Skipped: A03-XSS (is_api_only=true, no HTML rendering)
  ⏭️  Skipped: A03-CmdInj (has_shell_execution=false)
  ⏭️  Skipped: A08-Deser (has_deserialization=false)
  ⏭️  Skipped: A10-SSRF (has_external_http_calls=false)
```

### Multi-Pass Decision

Count the items in your `checks_run` list → `APPLICABLE_CHECKS`.

Enable multi-pass if **any** of these is true:

| Criterion | Threshold | Rationale |
|-----------|-----------|-----------|
| `APPLICABLE_CHECKS` | `>= 10` | API Top 10 or multiple injection vectors — wide attack surface |
| `SOURCE_FILES` | `> 200` | Codebase too large for one reliable pass |
| `PHASE2_HIGH_CRITICAL` | `>= 2` | Structural security debt signals more code-level issues |

Log the outcome:
```
# Criteria met:
🔁 Multi-pass enabled — {reason(s)} (e.g. "847 source files, 12 applicable checks")
   Will run until dry, max 3 rounds.

# Criteria not met:
▶️  Single-pass — {source_files} files · {applicable_checks} checks · {phase2_high_critical} Phase 2 HIGH/CRITICAL findings
```

## Multi-Pass Execution

**If single-pass:** skip this section and proceed directly to Step 2. Run it once.

**If multi-pass:** Steps 2 and 3 run as a loop. Track the following state across rounds:

| Variable | Initial value | Description |
|----------|--------------|-------------|
| `ROUND` | 1 | Current round number |
| `DRY_ROUNDS` | 0 | Consecutive rounds with zero new findings |
| `COVERED_FILES` | empty set | All files examined across all rounds |
| `ALL_FINDING_KEYS` | empty set | Dedup keys: `(file, line_start, vulnerability_type)` |
| `NEW_THIS_ROUND` | 0 | New findings added in the current round |

**Each round:**

1. Run Steps 2 and 3.
   - **Round 1**: analyze the full codebase normally.
   - **Round 2+**: focus on files not yet in `COVERED_FILES` and on check
     categories that produced findings last round (examine adjacent files and
     unexplored patterns for those categories). Do not re-examine files already
     in `COVERED_FILES` unless a prior finding points directly into them.

2. Count findings whose `(file, line_start, vulnerability_type)` key is not
   already in `ALL_FINDING_KEYS` → set `NEW_THIS_ROUND`.

3. Update `COVERED_FILES` and `ALL_FINDING_KEYS` with this round's results.

4. Log the round outcome:
   ```
   🔁 Round {N} complete — {NEW_THIS_ROUND} new findings ({total_so_far} total across all rounds)
   ```

5. If `NEW_THIS_ROUND == 0`: increment `DRY_ROUNDS`. Otherwise reset `DRY_ROUNDS` to 0.

6. **Stop** if `DRY_ROUNDS >= 2` OR `ROUND >= 3`. Log:
   ```
   ✅ Multi-pass complete — {N} round(s), {total} findings
   ```
   Then proceed to Output Format.

7. Otherwise increment `ROUND` and repeat from step 1.

Merge all rounds into a single `findings` array. Deduplicate by
`(file, line_start, vulnerability_type)` — keep the entry with the higher severity
if the same location appears in multiple rounds.

## Step 2: Run Semgrep (scoped to relevant rules)

```bash
# Use language-specific configs, not --config=auto (too noisy)
LANG=$(python3 -c \
  "import json; d=json.load(open('{repo_path}/.security-review/tech-stack.json')); \
   langs=d.get('languages',[]); print(langs[0] if langs else '')" 2>/dev/null)

# Map tech-stack language names to Semgrep registry pack names.
# Go's registry pack is p/golang, not p/go — all others match their language name.
case "$LANG" in
  go) SEMGREP_LANG="golang" ;;
  *)  SEMGREP_LANG="$LANG" ;;
esac

if [ -n "$LANG" ]; then
  semgrep --config="p/${SEMGREP_LANG}" --config="p/owasp-top-ten" \
    --json --output {repo_path}/.security-review/semgrep-raw.json \
    {repo_path} 2>/dev/null
else
  # Language unknown — fall back to OWASP rules only
  semgrep --config="p/owasp-top-ten" \
    --json --output {repo_path}/.security-review/semgrep-raw.json \
    {repo_path} 2>/dev/null
fi
```

Parse semgrep output as seed findings, then validate each one manually.

## Step 3: Deep Analysis by Category

Only run checks from your check plan above.

---

### A01 - Broken Access Control / IDOR
- Authorization checks present on every sensitive endpoint?
- Can a user access/modify another user's resources by changing an ID?
- Privilege escalation paths? (role assignment, admin routes)
- Check: route files, controller methods, middleware application

### A02 - Cryptographic Failures
- Sensitive data in plaintext in DB? (passwords, SSNs, card numbers)
- Weak hashing? (MD5, SHA1, unsalted SHA256)
- Weak encryption? (ECB mode, hardcoded IVs, static keys)
- HTTP used where HTTPS should be? Insecure cookie flags?

### A03 - Injection (run only applicable sub-checks per check plan)

**SQL Injection** (only if `has_database: true`):
- String concatenation in queries
- ORM `raw()` / `execute()` calls
- Named `cursor.execute` with `%s` formatting

**Command Injection** (only if `has_shell_execution: true`):
- `exec`, `system`, `subprocess` with user input
- `shell=True` with user-controlled string

**Client-side XSS** (only if `has_html_rendering: true`):
- Unencoded user input in HTML output
- `innerHTML`, `document.write`, `dangerouslySetInnerHTML`
- Template rendering without escaping

**Template Injection** (only if `has_html_rendering: true`):
- User input passed directly to template engine
- `render(template=user_input)` patterns

**NoSQL Injection** (only if mongodb/redis in `database_types`):
- Unvalidated query operators ($where, $gt, etc.)

### A04 - Insecure Design
- Business logic: can a user skip required steps?
- Mass assignment: model attributes filtered on create/update?
- Missing input validation on critical fields

### A05 - Security Misconfiguration
- Debug mode in production config?
- Stack traces in error responses?
- Default credentials anywhere?
- Unnecessary features/endpoints?

### A07 - Auth & Session Failures
- Brute force protection on login?
- Session fixation? Session regenerated after login?
- Password complexity enforced?

### A08 - Deserialization (only if `has_deserialization: true`)
- `pickle.loads`, `yaml.load` (not `yaml.safe_load`), `unserialize`
- Unsigned/unverified data in security decisions

### A09 - Logging Failures
- Auth failures logged?
- Sensitive operations audited?
- Logs stored securely?

### A10 - SSRF (only if `has_external_http_calls: true`)
- User-controlled URLs fetched server-side?
- URL allowlists? IP restrictions?
- Internal metadata endpoints reachable?

---

### OWASP API Top 10 (only if API project)

**API1 - BOLA**
- Every endpoint returning/modifying a resource by ID: ownership verified?
- Look for: `GET /api/items/{id}`, `PUT /api/orders/{id}` without ownership check

**API2 - Broken Authentication**
- JWT signature actually verified?
- API key endpoints with no expiry?

**API3 - Object Property Level AuthZ**
- Over-fetching (user reads fields they shouldn't)?
- Mass assignment via API (user writes fields they shouldn't)?

**API4 - Resource Consumption**
- No pagination limits on list endpoints?
- No rate limits on expensive operations?
- File upload size limits?

**API5 - Function Level AuthZ**
- Admin-only functions accessible to regular users?
- HTTP method confusion?

**API6 - Business Flow Abuse**
- Checkout/signup/reset flows abusable at scale?

**API7 - SSRF** (only if `has_external_http_calls: true`)

**API8 - Misconfiguration**
- CORS: wildcard or reflecting Origin header?
- Verbose errors in API responses?

**API9 - Inventory Management**
- Old API versions still accessible?
- Undocumented endpoints?

**API10 - Unsafe API Consumption** (only if `has_external_http_calls: true`)
- Third-party API responses trusted without validation?

---

## Output Format

Write to `{repo_path}/.security-review/phase4-owasp.json`:
```json
{
  "phase": "owasp_analysis",
  "multi_pass": {
    "enabled": true,
    "rounds_completed": 2,
    "trigger_reasons": ["source_files=847", "applicable_checks=12"]
  },
  "checks_run": ["A01", "A02", "A03-SQLi", "A07", "A09", "API1", "API2"],
  "checks_skipped": [
    {"check": "A03-XSS", "reason": "is_api_only=true, no HTML rendering detected"},
    {"check": "A03-CmdInj", "reason": "has_shell_execution=false"},
    {"check": "A08-Deser", "reason": "has_deserialization=false"},
    {"check": "OWASP-API-Top-10", "reason": "project is not API-based"}
  ],
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "O-001",
      "owasp_category": "A01:2021 | API1:2023 | ...",
      "vulnerability_type": "IDOR | SQL_INJECTION | XSS | BOLA | ...",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "title": "Short descriptive title",
      "file": "relative/path/to/file.ext",
      "line_start": 42,
      "line_end": 55,
      "vulnerable_code_snippet": "// 3-5 lines of the actual vulnerable code",
      "description": "Why this is vulnerable",
      "attack_vector": "How an attacker would exploit this",
      "input_source": "HTTP parameter | Header | Body field | Path param | ...",
      "sink": "SQL query | HTML output | shell command | ...",
      "remediation": "Specific fix with code example if possible",
      "poc_needed": true,
      "validation_notes": "What the validator should check"
    }
  ]
}
```

## Quality Bar

Only include findings you're confident in. For BOLA/IDOR:
- Read the full auth middleware and verify it doesn't handle this globally
- Check for policy/permission layers you might have missed
- Mark `poc_needed: true` only if structurally confirmed
