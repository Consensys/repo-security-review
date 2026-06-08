# Phase 1: Secret Scanning Agent

## Goal
Find exposed secrets, credentials, API keys, tokens, and passwords in the
repository — including in git history, not just the current working tree.

## Tools to Run

### 1. Gitleaks (primary — scans git history)
```bash
gitleaks detect --source {repo_path} --report-format json --report-path {repo_path}/.security-review/gitleaks-raw.json
```

### 2. Grep patterns (supplementary — catches what gitleaks misses)
Run these against the working tree:
```bash
# Generic high-entropy strings in assignment context
grep -rEn "(key|token|secret|password|credential|auth)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{32,}['\"]?" {repo_path} \
  --include="*.env*" --include="*.config*" --include="*.json" --include="*.yaml" --include="*.yml" --include="*.toml" \
  --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor"

# Common secret patterns
grep -rEn "(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key|client_secret)\s*[:=]\s*['\"][^'\"]{8,}" {repo_path} \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" \
  --include="*.java" --include="*.rb" --include="*.php" --include="*.env" \
  --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor"
```

### 3. Check for committed .env files
```bash
git -C {repo_path} log --all --full-history -- "**/.env" "*.env" ".env"
git -C {repo_path} ls-files --others --exclude-standard | grep -i "\.env"
```

### 4. Check for private keys
```bash
grep -rn "BEGIN.*PRIVATE KEY\|BEGIN RSA\|BEGIN EC\|BEGIN OPENSSH" {repo_path} --exclude-dir=".git"
```

## What to Look For

- AWS keys (`AKIA...`)
- GCP service account JSON blobs
- GitHub/GitLab tokens (`ghp_`, `glpat-`)
- Stripe, Twilio, SendGrid, etc. API keys
- JWT secrets / signing keys
- Database connection strings with credentials
- Private SSH/TLS keys
- Hardcoded passwords in config files
- `.env` files committed to the repo
- Secrets in CI/CD config files (`.github/workflows`, `.gitlab-ci.yml`)

## Confidence Assessment

For each finding, assess:
- **HIGH**: Clear secret format (AWS key pattern, PEM block, etc.)
- **MEDIUM**: Looks like a secret but could be a placeholder/example
- **LOW**: High-entropy string, possibly a secret

Flag LOW confidence findings but don't suppress them — let the report
reader decide.

## Output Format

Write to `{repo_path}/.security-review/phase1-secrets.json`:
```json
{
  "phase": "secrets",
  "summary": {
    "total": 0,
    "high_confidence": 0,
    "medium_confidence": 0,
    "low_confidence": 0
  },
  "findings": [
    {
      "id": "S-001",
      "type": "aws_access_key | github_token | private_key | password | generic_secret | ...",
      "confidence": "HIGH | MEDIUM | LOW",
      "file": "relative/path/to/file.ext",
      "line": 42,
      "in_git_history": false,
      "commit": "abc123 (if in history)",
      "description": "AWS Access Key ID found in config file",
      "redacted_value": "AKIA***************XYZ",
      "remediation": "Rotate the key immediately. Use environment variables or a secrets manager instead."
    }
  ]
}
```

## Important Notes

- **Never log full secret values** — always redact, showing only first 4 and
  last 3 characters
- Secrets in git history are just as dangerous as live ones — flag them clearly
- Do NOT attempt to validate/use secrets (no API calls to test if they work)
