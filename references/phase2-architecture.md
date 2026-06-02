# Phase 2: Architectural Analysis Agent

## Goal
Two outputs from this phase:
1. Security findings at the architectural/design level (no PoC needed)
2. **Tech stack profile** — a structured JSON read by Phase 3 and Phase 4 to
   scope their analysis correctly

## Model Guidance
Use extended thinking if available — architectural analysis requires reasoning
about intent, missing controls, and design decisions holistically.

## Step 0: Build the Tech Stack Profile FIRST

Before any security analysis, survey the repository structure to understand
what you're working with. This profile gates what Phase 3 and Phase 4 will run.

```bash
# Get top-level structure
ls -la {repo_path}

# Find all package/manifest files
find {repo_path} -maxdepth 4 \( \
  -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" \
  -o -name "requirements.txt" -o -name "Pipfile" -o -name "pyproject.toml" \
  -o -name "go.mod" -o -name "Cargo.toml" -o -name "pom.xml" \
  -o -name "build.gradle" -o -name "Gemfile" -o -name "composer.json" \
\) -not -path "*/node_modules/*" -not -path "*/.git/*"

# Check for Docker
find {repo_path} -maxdepth 3 -name "Dockerfile*" -o -name "docker-compose*.yml"

# Check for HTML templates / frontend rendering
find {repo_path} -maxdepth 5 \( \
  -name "*.html" -o -name "*.hbs" -o -name "*.ejs" -o -name "*.jinja*" \
  -o -name "*.blade.php" -o -name "*.erb" \
\) -not -path "*/node_modules/*" | head -20

# Check for DB usage
grep -rn "database\|db\.\|sql\|mongo\|redis\|postgres\|mysql\|sqlite\|orm\|sequelize\|typeorm\|prisma\|sqlalchemy\|django.db" \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.go" --include="*.java" -l \
  --exclude-dir="node_modules" --exclude-dir=".git" | head -20

# Check for shell execution
grep -rn "exec\|spawn\|system\|subprocess\|shell=True\|os\.popen\|child_process" \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.go" -l --exclude-dir="node_modules" | head -10

# Check for serialization/deserialization
grep -rn "pickle\|yaml\.load\|unserialize\|ObjectMapper\|JSON\.parse\|eval(" \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.go" --include="*.java" -l --exclude-dir="node_modules" | head -10

# Check if it's API-only or has HTML rendering
grep -rn "render_template\|res\.render\|return.*html\|template\." \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" \
  -l --exclude-dir="node_modules" | head -10

# Check for outbound HTTP
grep -rn "requests\.\|fetch(\|axios\.\|http\.get\|urllib\|httpx\." \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" \
  -l --exclude-dir="node_modules" | head -10

# Check for file uploads
grep -rn "multer\|multipart\|file_upload\|FileField\|upload\|FormData" \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" -l \
  --exclude-dir="node_modules" | head -10

# --- Runtime hints (used by Phase 5 when synthesizing a Dockerfile) ---

# Likely entry point
# Node: read package.json scripts.start or main field
[ -f "{repo_path}/package.json" ] && \
  grep -E '"(start|main)"' {repo_path}/package.json

# Python: files with a __main__ guard, in priority order
for f in app.py main.py server.py run.py manage.py wsgi.py asgi.py; do
  [ -f "{repo_path}/$f" ] && grep -l '__name__.*__main__\|app = \|application = ' "{repo_path}/$f"
done

# Go: file containing func main()
grep -rln "^func main()" {repo_path} --include="*.go" --exclude-dir="vendor" | head -3

# Procfile (Heroku-style)
[ -f "{repo_path}/Procfile" ] && cat {repo_path}/Procfile

# Likely listen port
grep -rnE "app\.listen\(|\.listen\([0-9]|PORT *= *[0-9]|port *= *[0-9]|listen *:[0-9]|bind.*0\.0\.0\.0:" \
  {repo_path} --include="*.py" --include="*.js" --include="*.ts" --include="*.go" \
  --exclude-dir="node_modules" --exclude-dir="vendor" | head -10
```

Based on findings, write `{repo_path}/.security-review/tech-stack.json`:
```json
{
  "languages": ["python"],
  "frameworks": ["fastapi"],
  "package_ecosystems": ["pypi"],
  "has_database": true,
  "database_types": ["postgresql"],
  "has_html_rendering": false,
  "is_api_only": true,
  "has_file_uploads": true,
  "has_external_http_calls": true,
  "has_shell_execution": false,
  "has_deserialization": false,
  "auth_mechanism": "jwt",
  "has_docker": true,
  "docker_compose_path": "docker-compose.yml",
  "package_files": {
    "pypi": ["requirements.txt"]
  },
  "runtime_hints": {
    "entry_point": "app.py",
    "listen_port": 5000
  }
}
```

`runtime_hints` is best-effort and used only by Phase 5 if it needs to synthesize
a Dockerfile (when `--runtime` is set and the repo has no Dockerfile or
docker-compose.yml). Set fields to `null` when detection is ambiguous — Phase 5
will fall back to framework defaults or decline synthesis.

Defaults Phase 5 will assume when `listen_port` is null:
Flask 5000, Django 8000, FastAPI/Uvicorn 8000, Express 3000, Rails 3000.

**Write this file before proceeding to security analysis.**
Phase 3 and Phase 4 will not run correctly without it.

---

## Security Analysis

### 1. Trust Boundaries
- Are there clear boundaries between public/private/internal services?
- Does the app trust input from external sources without validation?
- Are there services that trust each other without authentication?
- Do microservices have inter-service auth (mTLS, service tokens)?

### 2. Authentication & Authorization Model
- How is authentication implemented? (JWT, sessions, OAuth, API keys)
- Is auth enforced consistently — at the route level or controller level?
- Is there a centralized auth middleware or is it scattered?
- Are there routes/endpoints with missing auth decorators/middleware?
- Is authorization (not just authentication) checked? Who can do what?
- Is there a clear RBAC/ABAC model? Is it consistently applied?

### 3. Sensitive Data Flow
- Where is PII, financial data, or health data stored?
- Is sensitive data logged? (check logging setup, middleware)
- Is sensitive data included in error responses?
- Is data encrypted at rest? In transit? (check DB config, TLS settings)
- Are there overly broad data returns?

### 4. Third-Party Integrations
- What external services are integrated?
- How are integration credentials managed?
- Is data sent to third parties validated/minimized?
- Are webhooks verified (signature validation)?

### 5. Infrastructure & Config
- IaC files (Terraform, CDK, Helm): public S3 buckets, open security groups,
  overly broad IAM roles?
- Docker: running as root, exposed ports, secrets in Dockerfiles?
- CI/CD: secrets in workflow files, overly permissive pipeline access?
- Admin interfaces exposed (DB admin UIs, debug endpoints)?

### 6. Missing Security Controls
- No rate limiting on auth endpoints or APIs?
- No request size limits?
- No security headers (CSP, HSTS, X-Frame-Options)? ← only relevant if
  `has_html_rendering: true`
- No audit logging for sensitive operations?
- No input validation layer?
- CORS policy: wildcard or overly permissive?

### 7. Session & Token Management
- Session expiry? Refresh token rotation?
- Token storage: localStorage (bad) vs httpOnly cookies (better)?
- Are tokens invalidated on logout?

## Output Format

Write to `{repo_path}/.security-review/phase2-architecture.json`:
```json
{
  "phase": "architecture",
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "A-001",
      "category": "auth_model | trust_boundary | data_exposure | missing_control | infra_misconfiguration | session_management | third_party",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "title": "Short descriptive title",
      "description": "What the problem is and why it matters",
      "evidence": ["file1.py:L23", "routes/api.js:L45-L67"],
      "impact": "What an attacker could do",
      "remediation": "Specific fix recommendation",
      "poc_needed": false
    }
  ]
}
```

## Notes
- `poc_needed` is always `false` for architectural findings
- Reference specific files and line numbers as evidence
- Be concrete about impact — avoid vague "could lead to security issues"

---

## Threat-Model Drift Detection (only if `threat-model.json` exists)

Skip this section entirely if `{repo_path}/.security-review/threat-model.json`
does not exist. Existing behavior is preserved when no threat model was provided.

When the file is present, read it and check the declared values against what
the code actually shows. The goal is to prevent a user from silently softening
findings by declaring a falsely permissive context.

### Check 1: `data_sensitivity` drift

If `data_sensitivity` is `none` or `internal`, look for code patterns
indicating more sensitive data is handled:

```bash
# PII / regulated indicators
grep -rniE "ssn|social.security|tax.id|date.of.birth|passport|driver.license|\
patient|medical|diagnosis|credit.card|cvv|card.number|iban|routing.number|\
biometric|fingerprint" {repo_path} \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" \
  --include="*.java" --include="*.rb" --include="*.sql" \
  --exclude-dir="node_modules" --exclude-dir=".git" \
  --exclude-dir="vendor" --exclude-dir="tests" --exclude-dir="test" | head -20

# Schema indicators
grep -rniE "email.*varchar|email.*string|address.*varchar|phone.*varchar" \
  {repo_path} --include="*.sql" --include="*.py" --include="*.js" \
  --include="*.ts" | head -10
```

If concrete PII-handling code is found while `data_sensitivity` is declared
`none`, emit a drift finding (see "Drift finding shape" below).

### Check 2: `auth_required_to_reach` drift

If `auth_required_to_reach` is `true`, scan for publicly reachable routes
with no authentication middleware/decorator:

```bash
# Look for route definitions without nearby auth decorators
# (Phase 4 will do deeper analysis; this is a coarse drift check only)
grep -rniE "@app\.route|@router\.|app\.get\(|app\.post\(|@RequestMapping|\
def get\(self|def post\(self" {repo_path} \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --exclude-dir="node_modules" --exclude-dir=".git" | head -30
```

For each route, check whether the surrounding 10 lines contain auth markers
(`@login_required`, `@requires_auth`, `verifyToken`, middleware references,
etc.). If multiple unauthenticated public routes exist while
`auth_required_to_reach` is `true`, emit a drift finding.

### Check 3: `deployment_target` — no automatic drift check

There is no reliable code signal for whether something is a CLI, internal
service, or public service. Take this field at face value.

### Drift finding shape

Drift findings are normal Phase 2 findings with category `threat_model_drift`:

```json
{
  "id": "A-XXX",
  "category": "threat_model_drift",
  "severity": "MEDIUM",
  "title": "Declared threat model contradicts observed code",
  "description": "Threat model declares data_sensitivity=none, but code reads PII columns (users.email, users.ssn).",
  "evidence": ["models/user.py:L12-L18", "schema.sql:L45"],
  "impact": "Findings calibrated against the declared sensitivity will under-report exposure risk.",
  "remediation": "Update the threat-model file to reflect actual data handling, OR remove the PII-handling code.",
  "poc_needed": false,
  "drift_dimension": "data_sensitivity",
  "declared": "none",
  "observed": "pii"
}
```

### Side effect on the threat model

When drift is detected for a dimension, write a `drift_overrides` block into
`threat-model.json` so downstream phases revert that dimension to the strict
default for this run:

```json
{
  "source": "user",
  "deployment_target": "internal_tool",
  "data_sensitivity": "none",
  "auth_required_to_reach": true,
  "drift_overrides": {
    "data_sensitivity": "pii"
  }
}
```

Phase 5 reads `drift_overrides` and uses those values (not the declared ones)
for the affected dimensions when computing `contextual_severity`. This ensures
users cannot silence findings by passing a falsely permissive context.
