---
name: security-review
description: >
  Full automated security review pipeline for a code repository. Use this skill
  whenever the user asks to: review a repo for security issues, run a security
  audit, find vulnerabilities in a codebase, perform a security assessment, check
  for OWASP and OWASP API issues, scan for secrets or exposed credentials, audit dependencies
  for CVEs, or analyze architecture for security flaws. Trigger even for casual
  phrasings like "can you check this repo for security issues" or "run security
  on this". This skill orchestrates 7 sequential phases: secret scanning,
  architectural analysis, dependency CVE scanning with reachability validation,
  code-level OWASP analysis, finding validation, PoC generation (with optional
  runtime validation via Docker), and final report generation.
---

# Security Review Skill

Orchestrates a full, multi-phase security review of a code repository using
Claude Code subagents. Each phase has a narrow responsibility and passes its
output to the next.

## Prerequisites

Before running, ensure these CLI tools are available (install if missing):
- `gitleaks` — secret scanning with git history.
- `osv-scanner` — dependency CVE scanning (multi-language).
- `semgrep` — static analysis to assist OWASP scanning.
- `docker` — optional, required for runtime PoC validation only.

Check and install:
```bash
bash scripts/setup.sh
```

## Input

The user provides:
1. **Repo path** (required): path to the cloned repository
2. **Skip flags** (optional): comma-separated phases to skip
3. **Report output path** (optional): where to write the final report
4. **Runtime validation** (optional): whether to spin up Docker for PoC testing

Parse these from `$ARGUMENTS` using the format:
```
/security-review /path/to/repo [--skip phase1,phase3] [--output /path/to/report.md] [--runtime]
```

### Argument Parsing Rules

| Argument | Default | Description |
|----------|---------|-------------|
| (first positional) | required | Repo path |
| `--skip` | none | Comma-separated phase names to skip: `secrets`, `architecture`, `dependencies`, `owasp`, `validation`, `poc` |
| `--output` | `~/security-reports/{repo}-{date}.md` | Final report output path |
| `--runtime` | false | Enable Docker-based runtime PoC validation |

If no repo path is provided, ask the user before proceeding.

**Skip phase aliases**:
- `secrets` → Phase 1
- `architecture` → Phase 2
- `dependencies` → Phase 3 + 3b
- `owasp` → Phase 4
- `validation` → Phase 5 (validation + PoC together — skipping validation skips PoC automatically)

Skipping `owasp` also skips `validation` (Phase 5 has nothing to work from).

## Phase Execution Order

Run phases **sequentially** — each phase's output informs the next.
Each phase runs as an **isolated subagent** with strict context boundaries.
Skip any phase present in the `--skip` list.

```
Phase 1  → Secret Scanning              [skippable: --skip secrets]
Phase 2  → Architectural Analysis       [skippable: --skip architecture]
           └─ Produces: tech_stack profile used by Phase 3 and Phase 4
Phase 3  → Dependency CVE Scanning      [skippable: --skip dependencies]
           └─ Uses tech_stack from Phase 2 to select correct package ecosystems
Phase 3b → Reachability Validation      [runs as part of Phase 3, not separately skippable]
Phase 4  → Code-Level OWASP Analysis    [skippable: --skip owasp]
           └─ Uses tech_stack to skip irrelevant checks (no DB → no SQLi, etc.)
           └─ Uses API flag from Phase 2 to decide whether to run API Top 10
Phase 5  → Validation + PoC             [skippable: --skip validation]
           └─ Validates each Phase 4 finding independently, then immediately
              writes a PoC only for findings that pass the validation gate.
              PoC generation is gated inside this phase — unvalidated findings
              never get a PoC. Optional runtime validation via Docker if --runtime.
Phase 6  → Report Builder               [always runs, was previously Phase 7]
```

## Subagent Context Isolation (Critical)

The real trust boundary is between **finders** (Phase 2, Phase 4) and the
**judgment layer** (Phase 5). Validation and PoC generation share an agent
because the PoC writer benefits from having the validator's full reasoning
in context — and the gate is structural: a PoC is written immediately after
a finding passes, so unvalidated findings can never get one.

**Rules the orchestrator must follow:**

1. **Never read a phase's output JSON into orchestrator memory** before
   spawning the next phase. Pass only the *file path*. The receiving subagent
   reads the file itself.

2. **Each subagent receives exactly**:
   - Its reference file from `references/`
   - The file paths of its inputs (not the content)
   - The repo path and working directory path
   - Any flags relevant to it (`--runtime` for Phase 5)

3. **The orchestrator's only job** is sequencing, path management, and
   printing progress summaries. It must not accumulate findings across phases.

4. **The mandatory isolation boundary is between Phase 4 and Phase 5:**

   ```
   ┌─ FINDER LAYER (independent from judgment layer) ──────────────────┐
   │  Phase 2 agent:  arch analysis → writes phase2-architecture.json  │
   │  Phase 4 agent:  OWASP scan   → writes phase4-owasp.json → CLOSES │
   └────────────────────────────────────────────────────────────────────┘
                              ↓ file path only
   ┌─ JUDGMENT LAYER (isolated from finder context) ───────────────────┐
   │  Phase 5 agent:  reads phase4-owasp.json as untrusted input       │
   │                  validates each finding from scratch               │
   │                  writes PoC immediately on CONFIRMED               │
   │                  → writes phase5-validated.json + pocs/  → CLOSES │
   └────────────────────────────────────────────────────────────────────┘
   ```

Read the agent instructions for each phase from `references/` before spawning:

| Phase | Reference File |
|-------|---------------|
| 1 | `references/phase1-secrets.md` |
| 2 | `references/phase2-architecture.md` |
| 3 + 3b | `references/phase3-dependencies.md` |
| 4 | `references/phase4-owasp.md` |
| 5 (Validation + PoC) | `references/phase5-validate-and-poc.md` |
| 6 (Report) | `references/phase7-report.md` |

## Output Structure

Each phase writes its findings to a working directory:
```
/tmp/security-review-{repo-name}/
├── tech-stack.json           ← written by Phase 2, read by Phase 3 and 4
├── phase1-secrets.json
├── phase2-architecture.json
├── phase3-cves.json
├── phase3b-reachability.json
├── phase4-owasp.json
├── phase5-validated.json
├── phase6-pocs.json
├── pocs/                     ← individual PoC scripts
│   ├── poc_O-001.py
│   └── poc_O-002.sh
└── final-report.md           ← copied to --output path at end
```

Create this directory at the start before spawning any agents.

## Tech Stack Profile (Phase 2 → downstream phases)

Phase 2 must write `/tmp/security-review-{name}/tech-stack.json` in addition
to its normal output. This is the key handoff document:

```json
{
  "languages": ["python", "javascript"],
  "frameworks": ["django", "react"],
  "package_ecosystems": ["pypi", "npm"],
  "has_database": true,
  "database_types": ["postgresql", "redis"],
  "has_html_rendering": false,
  "is_api_only": true,
  "has_file_uploads": true,
  "has_external_http_calls": true,
  "has_shell_execution": false,
  "has_deserialization": true,
  "auth_mechanism": "jwt",
  "has_docker": true,
  "docker_compose_path": "docker-compose.yml",
  "package_files": {
    "pypi": ["requirements.txt"],
    "npm": ["frontend/package-lock.json"]
  }
}
```

If Phase 2 is skipped, Phase 3 and Phase 4 must run their own lightweight
tech-stack detection before proceeding (see each phase's reference file).

## Progress Updates

After each phase completes, print a one-line summary:
```
✅ Phase 1 complete — 3 secrets found (2 API keys, 1 private key)
✅ Phase 2 complete — 5 architectural findings | Stack: Python/Django, PostgreSQL, API-only
⏭️  Phase 3 skipped (--skip dependencies)
✅ Phase 4 complete — 8 candidates (SQLi ×2, BOLA ×3, SSRF ×1, CmdInj ×2) | Skipped: XSS (no HTML rendering), API Top 10 (not API project)
✅ Phase 5 complete — 5 confirmed, 3 false positives filtered
✅ Phase 6 complete — 5 PoCs generated (3 static, 2 runtime-validated)
✅ Phase 7 complete — Report written to {output_path}
```

## Model Selection

- Phase 2 (Architecture): `claude-opus-4-5` with extended thinking
- All other phases: `claude-sonnet-4-5`

## Error Handling

If a phase fails or a tool is not installed:
- Log the error to the working directory
- Continue to next phase with a warning
- Note the skipped phase and reason in the final report
- Never abort the full pipeline for a single phase failure

## Final Step

1. Copy `/tmp/security-review-{name}/final-report.md` to the `--output` path
2. If pocs/ directory has files, also copy that directory alongside the report
3. Print the output path clearly:
   ```
   📄 Report saved to: /path/to/report.md
   📁 PoC scripts saved to: /path/to/pocs/
   ```
4. Call `present_files` with the report path so the user can open it directly
