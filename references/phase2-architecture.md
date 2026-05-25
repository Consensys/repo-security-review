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
```

Based on findings, write `/tmp/repo-security-review-{name}/tech-stack.json`:
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
  }
}
```

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

Write to `/tmp/repo-security-review-{name}/phase2-architecture.json`:
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
