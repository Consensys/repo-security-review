---
marp: true
theme: default
paginate: true
style: |
  section { font-size: 1.4rem; }
  h1 { color: #1a1a2e; }
  h2 { color: #16213e; border-bottom: 2px solid #e94560; padding-bottom: 0.3em; }
  code { background: #f4f4f4; border-radius: 4px; padding: 0.1em 0.4em; }
  pre { background: #1e1e2e; color: #cdd6f4; }
  .columns { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5em; }
---

# `repo-security-review`
## Automated Security Review Pipeline for Code Repositories

A Claude Code skill that runs a full, multi-phase security audit —  
**from secrets to PoCs** — in a single command.

```text
/repo-security-review /path/to/your/repo
```

---

## The Problem: Security Reviews at Scale

Manual security review is **slow, inconsistent, and easy to skip.**

- Junior engineers don't know what to look for
- Senior engineers don't have time to do it thoroughly
- Consultants are expensive and see a snapshot, not history
- CI tools (Snyk, Dependabot) only catch one layer — they miss architecture, logic flaws, and data flow

**What we actually need:**
- Full git history scanned (not just HEAD)
- Architecture-aware analysis (skip SQLi checks if there's no DB)
- Independent re-validation of findings (not just "semgrep said so")
- Runnable proof-of-concept scripts, not just CVE IDs

---

## Meet `repo-security-review`

A **Claude Code skill** — a slash command that orchestrates AI subagents  
to run a 6-phase security pipeline on any local repository.

```text
/repo-security-review /path/to/repo [options]

Options:
  --skip <phases>    Skip specific phases (secrets, architecture, dependencies, owasp, validation)
  --output <path>    Where to write the final report
  --runtime          Enable Docker-based live PoC validation
  --model <tier>     thorough | balanced | fast
  --context <pairs>  Inline threat model for severity calibration
```

**One command → full report with PoC scripts.**

No config files. No CI integration. No signup.

---

## The Pipeline: 6 Sequential Phases

```
Phase 1  →  Secret Scanning          gitleaks across full git history
Phase 2  →  Architectural Analysis   trust boundaries, auth model, tech-stack profile
Phase 3  →  Dependency CVEs          osv-scanner + EPSS + CISA KEV enrichment
Phase 3b →  Reachability Validation  is the vulnerable code path actually called?
Phase 4  →  OWASP Code Scan          semgrep + LLM, pruned by tech stack
Phase 5  →  Validate + PoC           independent re-validation, PoCs for confirmed findings
Phase 6  →  Report Builder           single markdown report, severity matrix, PoCs inline
```

Each phase is an **isolated subagent** — its output is a JSON file.  
The next phase reads the file path, not the content. Zero context bleed.

---

## Phase 1: Secret Scanning

**Tools**: `gitleaks` (git history) + targeted `grep` patterns

- Scans **entire git history** — not just the working tree
- Catches: AWS keys, GCP service account blobs, GitHub tokens, JWT secrets, private keys, committed `.env` files
- Confidence tiers: HIGH (known format) / MEDIUM (likely secret) / LOW (high entropy)

```json
{
  "id": "S-001",
  "type": "aws_access_key",
  "confidence": "HIGH",
  "file": "config/deploy.rb",
  "in_git_history": true,
  "redacted_value": "AKIA****XYZ",
  "remediation": "Rotate immediately. History rewrite required — treat as compromised."
}
```

> ⚠️ Secrets in git history are just as dangerous as live ones.  
> Rotation alone is not enough.

---

## Phase 2: Architectural Analysis

**Tool**: Claude Opus with extended thinking

Produces a **tech-stack profile** that gates every downstream phase:

```json
{
  "languages": ["python"],  "frameworks": ["django"],
  "has_database": true,     "database_types": ["postgresql"],
  "is_api_only": true,      "has_external_http_calls": true,
  "has_shell_execution": false,
  "auth_mechanism": "jwt",
  "docker_compose_path": "docker-compose.yml"
}
```

**Why this matters**: Phase 4 uses this to skip irrelevant checks automatically.

| If tech-stack says... | Phase 4 skips... |
|---|---|
| `has_database: false` | SQLi, NoSQL injection |
| `is_api_only: true` | XSS, Template injection |
| `has_external_http_calls: false` | SSRF |
| `has_deserialization: false` | Unsafe pickle/YAML |

---

## Phase 3: Dependency CVEs + Exploitation Signal

**Tools**: `osv-scanner` (all ecosystems) + `npm audit` + `pip-audit` + `grype`

Then two external signals that most CI tools ignore:

### EPSS (Exploit Prediction Scoring System)
Probability a CVE will be exploited in the wild in the next 30 days.  
`>= 0.7` = top 3% of all CVEs — treat as actively targeted.

### CISA KEV (Known Exploited Vulnerabilities)
The US government's list of CVEs with confirmed active exploitation.

```
🔴 C-001 · CVE-2021-44228 · log4j-core@2.14.1 · CVSS 10.0 · 🚨 KEV · ⚡ EPSS 97.5%
  Priority: P0
  Reachability: ✅ Confirmed — called from LoggingFilter.java:42 → POST /api/login
```

**Priority = CVSS + reachability + KEV + EPSS**. Not just CVSS.

---

## Phase 4: OWASP Code Analysis

**Tools**: `semgrep` (seed findings) + LLM deep analysis

Covers **OWASP Top 10** and **OWASP API Security Top 10**,  
pruned by the tech-stack profile from Phase 2.

```
📋 Check Plan:
  ✅ Running:  A01-IDOR, A02-Crypto, A03-SQLi, A07-Auth, A09-Logging, API1–API5
  ⏭️  Skipped: A03-XSS        (is_api_only=true, no HTML rendering)
  ⏭️  Skipped: A03-CmdInj     (has_shell_execution=false)
  ⏭️  Skipped: A08-Deser      (has_deserialization=false)
  ⏭️  Skipped: OWASP-API-Top-10 (no API routes detected)
```

For each finding it records:
- The exact source → sink data flow path
- The vulnerable code snippet
- `poc_needed: true/false` and what the validator should check

---

## The Trust Boundary: Finder vs Judgment Layer

This is the most important architectural decision in the pipeline.

```
┌─ FINDER LAYER ──────────────────────────────────────────────┐
│  Phase 2:  arch analysis      → writes phase2-architecture.json  │
│  Phase 4:  OWASP scan         → writes phase4-owasp.json → CLOSES│
└──────────────────────────────────────────────────────────────┘
                     ↓  file path only — content never passed
┌─ JUDGMENT LAYER (isolated context) ─────────────────────────┐
│  Phase 5:  reads phase4-owasp.json as UNTRUSTED input        │
│            re-validates each finding from scratch            │
│            writes PoC only for findings that pass            │
└──────────────────────────────────────────────────────────────┘
```

**Why**: LLM finders accumulate bias — by the time they've found 10 issues  
they're predisposed to confirm the 11th. A fresh agent challenges each finding.

**Result**: ~30-40% of Phase 4 candidates are filtered as false positives  
before reaching the report. The false positives log is shown explicitly.

---

## Phase 5: Validation + Proof of Concept

For each Phase 4 candidate, the judgment agent:

1. **Re-reads the source file from scratch** — traces source → sink independently
2. **Hunts for mitigations** Phase 4 may have missed (validators, middleware, output encoding)
3. **Verdict**: `CONFIRMED` or `FALSE_POSITIVE`
4. **Immediately writes a PoC** (only on `CONFIRMED`, in the same reasoning chain)

```python
# poc_O-001_sql_injection.py — generated by Phase 5
import requests

TARGET = "http://localhost:8000"
payload = "' OR '1'='1' --"

r = requests.post(f"{TARGET}/api/users/search",
                  json={"query": payload},
                  headers={"Authorization": f"Bearer {TOKEN}"})

# Success: response contains records from all users
assert r.status_code == 200 and len(r.json()["users"]) > 1
```

With `--runtime`: Phase 5 boots the app in Docker and **executes each PoC live.**

---

## Phase 6: The Report

Single markdown file. Everything in one place.

- **Executive Summary** — severity matrix, immediate actions
- **Section 1** — Secrets (redacted, rotation instructions)
- **Section 2** — Architectural findings
- **Section 3** — CVEs grouped by priority (P0 first), with KEV/EPSS badges
- **Section 4** — OWASP findings with PoC code inline
- **Section 5** — False positives log (shows what was investigated and ruled out)
- **Remediation Priority Table** — P0 (rotate now) → P3 (backlog)

```
📄 Report saved to: ~/reports/myapp-2026-06-08.md
📁 PoC scripts saved to: ~/reports/myapp-2026-06-08-pocs/
```

The false positives section is **not optional** — it builds trust with the dev team  
by showing the analysis was thorough, not just a list of noise.

---

## Threat Model Calibration (`--context`)

By default the skill assumes the **worst case** — a public, anonymous-facing service handling PII.

That's right for unknown codebases, but produces noise for internal tools.

```text
/repo-security-review /path/to/repo \
  --context deployment_target=internal_tool,auth_required_to_reach=true
```

| Axis | Effect |
|---|---|
| `deployment_target: local_cli` | −2 severity tiers, all findings |
| `deployment_target: internal_tool` | −1 tier, all findings |
| `auth_required_to_reach: true` | −1 tier, pre-auth findings only |
| `data_sensitivity: none` | −1 tier, data-exposure findings only |

**Every finding shows Base and Contextual severity** — Architecture, CVE, and code-level.  
Secrets are exempt: rotation is always required regardless of context.

**Drift detection**: if you declare `data_sensitivity: none` but Phase 2 finds  
PII columns, the skill reverts that axis and flags a "threat model drift" finding.

---

## Runtime PoC Validation (`--runtime`)

Phase 5 will attempt to boot the app in Docker and execute each confirmed PoC live.

Three paths, tried in order:

| Path | Condition | Notes |
|---|---|---|
| Project's `docker-compose.yml` | File found | Used as-is |
| Project's `Dockerfile` | No compose file | Run on detected port |
| **Synthesized environment** | Neither found | Phase 5 generates Dockerfile + DB sidecar from tech-stack profile |

Synthesized files persist in `.security-review/synthesized/` — you can re-run them later.

```bash
cd myrepo/.security-review/synthesized/
docker compose up
# then run any poc_*.py script manually
```

**Caveat**: synthesized DBs start empty. PoCs requiring existing user accounts  
report `RUNTIME_NOT_CONFIRMED` with an explicit seed-data note — not silent failure.

---

## When to Run It

This skill is built for **periodic, deep, whole-repo reviews** — not per-PR CI.

| Trigger | Why |
|---|---|
| Pre-launch / release candidate | Strongest ROI — you can still fix findings |
| Weekly/monthly scheduled run | Catches CVE drift even when code is frozen |
| Before a pentest | Baseline so the pentesters focus on hard problems |
| Post-incident | Root-cause companion |
| Before open-sourcing | Last-line check for secrets and obvious flaws |
| Major framework migration | Surface area shifts faster than per-PR scans track |

**Pair with Claude Code's built-in `/security-review`** for per-PR diff coverage.  
This skill catches systemic issues; the built-in command catches regressions per commit.

---

## Getting Started

**1. Install the skill**
```bash
mkdir -p ~/.claude/skills
git clone https://github.com/your-org/repo-security-review \
    ~/.claude/skills/repo-security-review
```

**2. Install CLI tools**
```bash
bash ~/.claude/skills/repo-security-review/scripts/setup.sh
# Installs: gitleaks, osv-scanner, semgrep, pip-audit
# Flags if Docker is missing (needed only for --runtime)
```

**3. Run**
```bash
# In any Claude Code session (CLI or Desktop):
/repo-security-review ~/repos/my-service

# With options:
/repo-security-review ~/repos/my-service \
  --context deployment_target=internal_tool \
  --output ~/reports/my-service-$(date +%F).md \
  --runtime
```

---

## Summary

| Feature | What it solves |
|---|---|
| Git history scanning | Secrets that were "deleted" but are still in history |
| Tech-stack gating | No false alarms for checks that can't apply |
| EPSS + KEV enrichment | Prioritize by real-world exploitation, not just CVSS |
| Finder / Judgment boundary | Eliminates LLM confirmation bias from findings |
| Structural PoC gate | Every PoC is backed by independent validation |
| Threat model calibration | Right severity for your actual deployment context |
| Runtime Docker validation | From "this looks exploitable" to "I ran it and it worked" |

**Repo**: `github.com/your-org/repo-security-review`  
**Invoke**: `/repo-security-review /path/to/repo`

---

*Built with Claude Code · repo-security-review skill*
