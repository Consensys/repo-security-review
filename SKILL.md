---
name: repo-security-review
description: >
  Full automated security review pipeline for a code repository. Use this skill
  whenever the user asks to: review a repo for security issues, run a security
  audit, find vulnerabilities in a codebase, perform a security assessment, check
  for OWASP Top 10 and OWASP API Top 10 issues, scan for secrets or exposed credentials, audit dependencies
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
/repo-security-review /path/to/repo [--skip phase1,phase3] [--output /path/to/report.md] [--runtime]
```

### Argument Parsing Rules

| Argument | Default | Description |
|----------|---------|-------------|
| (first positional) | required | Repo path |
| `--skip` | none | Comma-separated phase names to skip: `secrets`, `architecture`, `dependencies`, `owasp`, `validation`, `poc` |
| `--output` | `{repo_path}/.security-review/{repo}-{date}.md` | Final report output path |
| `--runtime` | false | Enable Docker-based runtime PoC validation |
| `--context` | none | Inline `key=value,key=value` threat model used to calibrate severity. Optional — when omitted, the skill runs exactly as before (no calibration, no new report sections). See "Threat-Model Context" below. |

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
| 6 (Report) | `references/phase6-report.md` |

## Output Structure

Each phase writes its findings to a working directory:
```
{repo_path}/.security-review/
├── tech-stack.json           ← written by Phase 2, read by Phase 3 and 4
├── threat-model.json         ← only if --context was provided
├── phase1-secrets.json
├── phase2-architecture.json
├── phase3-cves.json
├── phase3b-reachability.json
├── phase4-owasp.json
├── phase5-validated.json
├── phase5-pocs.json
├── pocs/                     ← individual PoC scripts
│   ├── poc_O-001.py
│   └── poc_O-002.sh
├── synthesized/              ← only if Phase 5 synthesized a Dockerfile (--runtime
│   │                           on a repo without its own Docker setup)
│   ├── Dockerfile
│   ├── docker-compose.yml    ← only if has_database: true
│   ├── synthesis-notes.md
│   └── startup.log
└── final-report.md           ← copied to --output path at end
```

Create this directory at the start before spawning any agents.

## Tech Stack Profile (Phase 2 → downstream phases)

Phase 2 must write `{repo_path}/.security-review/tech-stack.json` in addition
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
  },
  "runtime_hints": {
    "entry_point": "app.py",
    "listen_port": 5000
  }
}
```

`runtime_hints` is best-effort and consumed only by Phase 5 when `--runtime`
is set on a repo without its own Dockerfile / docker-compose. Fields may be
`null`; Phase 5 falls back to framework defaults or declines synthesis.

If Phase 2 is skipped, Phase 3 and Phase 4 must run their own lightweight
tech-stack detection before proceeding (see each phase's reference file).

## Threat-Model Context (optional, opt-in)

Calibration is **fully opt-in**. When `--context` is **not** passed, the skill
runs unchanged — no `threat-model.json` is written, no new logic runs in any
downstream phase, no new report sections appear. Existing users see zero
behavior change.

When `--context` **is** passed, the orchestrator parses the inline value,
validates it, and writes `{repo_path}/.security-review/threat-model.json`.
Downstream phases that find this file present apply the calibration; phases
that don't find it behave exactly as today.

### Inline syntax

Comma-separated `key=value` pairs. All three keys are optional and order does
not matter. Whitespace around `=` and `,` is trimmed.

```
--context deployment_target=internal_tool,data_sensitivity=internal,auth_required_to_reach=true
```

There is no file-path form. The schema is small and fixed (three keys, all
enum-valued or boolean), so inline is the only input format.

### Allowed keys and values

| Key | Allowed values |
|---|---|
| `deployment_target` | `local_cli` \| `internal_tool` \| `public_service` |
| `data_sensitivity` | `none` \| `internal` \| `pii` |
| `auth_required_to_reach` | `true` \| `false` |

### Strict defaults — applied to any missing key

| Field | Default | Rationale |
|---|---|---|
| `deployment_target` | `public_service` | Hardest reachable case |
| `data_sensitivity` | `pii` | Assume sensitive data |
| `auth_required_to_reach` | `false` | Pessimistic |

**Invariant: defaults are the most pessimistic value for each axis.** A
user-provided value can only soften severity, never tighten it further.
`contextual_severity` is never higher than `cvss_base_severity`.

### Orchestrator steps when `--context` is set

```text
RAW="<value passed after --context>"
TM_OUT={repo_path}/.security-review/threat-model.json

# 1. Split RAW on commas → list of pairs
# 2. For each pair:
#    - split on '=' (exactly once); trim whitespace
#    - reject if not exactly two non-empty parts → "❌ invalid pair: <pair>"
#    - reject if key not in {deployment_target, data_sensitivity, auth_required_to_reach}
#    - reject if value not in the allowed list for that key
#    - reject duplicate keys
# 3. Fill missing keys with strict defaults above.
# 4. Coerce auth_required_to_reach value to boolean.
# 5. Write JSON to $TM_OUT:
#    {
#      "source": "user",
#      "deployment_target": "...",
#      "data_sensitivity": "...",
#      "auth_required_to_reach": true|false
#    }
```

All validation errors must abort the run with a clear message that names the
offending key, value, and the allowed alternatives. Do not silently fall back
to defaults on validation errors.

If `--context` is absent: do nothing. `threat-model.json` is not created and
downstream phases skip all calibration logic.

### Output structure addition

`{repo_path}/.security-review/threat-model.json` — present only when
`--context` was supplied. See per-phase reference files for how each phase
consumes it.

## Progress Updates

After each phase completes, print a one-line summary:
```
✅ Phase 1 complete — 3 secrets found (2 API keys, 1 private key)
✅ Phase 2 complete — 5 architectural findings | Stack: Python/Django, PostgreSQL, API-only
⏭️  Phase 3 skipped (--skip dependencies)
✅ Phase 4 complete — 8 candidates (SQLi ×2, BOLA ×3, SSRF ×1, CmdInj ×2) | Skipped: XSS (no HTML rendering), API Top 10 (not API project)
✅ Phase 5 complete — 5 confirmed, 3 false positives filtered, 5 PoCs generated (3 static, 2 runtime-validated)
✅ Phase 6 complete — Report written to {output_path}
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

1. Copy `{repo_path}/.security-review/final-report.md` to the `--output` path
2. If pocs/ directory has files, also copy that directory alongside the report
3. Print the output path clearly:
   ```
   📄 Report saved to: /path/to/report.md
   📁 PoC scripts saved to: /path/to/pocs/
   ```
4. Call `present_files` with the report path so the user can open it directly
