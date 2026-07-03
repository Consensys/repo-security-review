# repo-security-review

A Claude Code **skill** that runs a full, multi-phase security review of a code repository. Each phase runs as an isolated subagent with a narrow responsibility, and findings flow through a strict finder → judgment trust boundary before a final report is produced.

See [SKILL.md](SKILL.md) for the full specification.

---

## What it does

Seven sequential phases (single-repo), plus Phase 0 and Phase 7 for multi-repo runs. Phase 4b runs automatically when skill/agent files are detected:

0. **Service topology mapping** *(multi-repo only)* — reads docker-compose, k8s manifests, OpenAPI specs, and .proto files across all repos; produces a shared `service-topology.json` passed to each service's Phase 2
1. **Secret scanning** — `gitleaks` across full git history
2. **Architectural analysis** — trust boundaries, auth model, infra config; produces a tech-stack profile that gates downstream phases; also detects AI skill files for Phase 4b
3. **Dependency CVE scanning** (+ 3b reachability) — `osv-scanner` against ecosystems detected in Phase 2; auto-skipped for pure skill repos
4. **Code-level OWASP analysis** — Top 10 + API Top 10, pruned by tech stack (no DB → skip SQLi, etc.); auto-skipped for pure skill repos
4b. **LLM / AI skill security** *(auto-activated when skill files detected)* — analyses agent instruction files against OWASP LLM Top 10: prompt injection, insecure output handling, excessive agency, insecure plugin design, sensitive data disclosure, and supply chain risks. Runs after Phase 2 for pure skill repos; after Phase 4 for mixed repos
5. **Finding validation + PoC generation** — independent re-validation of Phase 4 candidates; PoCs written only for findings that pass the gate (optional Docker runtime validation); auto-skipped for pure skill repos
6. **Report builder** — aggregates everything into a single markdown report with severity matrix, remediation table, false-positives log, and PoC scripts
7. **Cross-repo synthesis** *(multi-repo only)* — identifies vulnerabilities that are only visible at the system level: shared credentials, service-to-service blind trust, auth contract mismatches, cross-service data flows bypassing defenses

---

## Prerequisites

External CLI tools used by the phases:

| Tool | Used by | Required? |
|------|---------|-----------|
| `gitleaks` | Phase 1 — secret scanning | Recommended |
| `osv-scanner` | Phase 3 — dependency CVEs (all ecosystems) | Recommended |
| `semgrep` | Phase 4 — OWASP static analysis | Recommended |
| `jq` | Phase 3 — EPSS enrichment · Phase 5 — runtime paths | Recommended |
| `pip-audit` | Phase 3 — Python CVEs (supplementary) | Optional (Python repos only) |
| `grype` | Phase 3 — Java/Maven CVEs (supplementary) | Optional (Java repos only) |
| `poetry` | Phase 3 — exports `poetry.lock` for pip-audit | Optional (Poetry projects only) |
| `docker` | Phase 5 — runtime PoC validation | Optional (`--runtime` flag only) |

**Scanning strategy:** `osv-scanner` is the primary CVE scanner and covers all ecosystems (npm, Python, Go, Ruby, Cargo, Maven) from lockfiles. `pip-audit` and `grype` are supplementary — they run a second pass using different vulnerability databases (PyPA advisory and Anchore respectively) and occasionally surface CVEs that osv-scanner misses. `npm audit` is not listed separately because it is bundled with npm — any Node.js project already has it.

If a tool is missing, the corresponding phase runs in a degraded mode and the report notes the limitation — the pipeline never aborts because of a missing tool.

---

## Install

Skills live under `~/.claude/skills/` (user-level, available in both the Claude Code CLI and the Desktop app). Clone the repo straight into that directory so updates are a `git pull` away:

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/<your-org>/repo-security-review ~/.claude/skills/repo-security-review
```

Then install the external tools:

```bash
bash ~/.claude/skills/repo-security-review/scripts/setup.sh
```

The script detects `brew`, `go`, or `pip3` and installs whatever it can. It will also flag Docker as missing if you plan to use `--runtime`.

To update later:

```bash
cd ~/.claude/skills/repo-security-review && git pull
```

---

## Usage

In any Claude Code session (CLI or Desktop), invoke the skill on a local repository path:

```text
/repo-security-review /path/to/repo
```

### Common options

```text
/repo-security-review /path/to/repo --skip secrets,dependencies
/repo-security-review /path/to/repo --output ~/reports/myapp
/repo-security-review /path/to/repo --runtime
/repo-security-review /path/to/repo --skip architecture --output ~/reports/myapp --runtime

# Full detailed report (includes Appendix, OWASP coverage, Remediation Priority)
/repo-security-review /path/to/repo --verbose --output ~/reports/myapp

# Multi-repo — analyze three microservices and get a system-level report
/repo-security-review --repos ~/svcs/auth,~/svcs/gateway,~/svcs/users --output ~/reports/my-system
```

| Flag | Default | Effect |
|------|---------|--------|
| `--repos <paths>` | none | Comma-separated repo paths. Activates multi-repo mode (Phase 0 + Phase 7). |
| `--skip <phases>` | none | Comma-separated: `secrets`, `architecture`, `dependencies`, `owasp`, `skill-security`, `validation` |
| `--output <dir>` | none (single-repo) / `./system-security-review/` (multi-repo) | Directory to copy the report and PoC scripts into after the run. Created if it doesn't exist. |
| `--runtime` | off | Docker-based runtime PoC validation in Phase 5 |
| `--verbose` | off | Generate the full detailed report. Default report omits the OWASP Checks Run inventory, standalone Remediation Priority section, and Appendix. Findings, evidence, and per-finding priority labels are present in both modes. |
| `--context <pairs>` | none | Optional inline threat model (`key=value,key=value`) used to calibrate severity. See "Adding context" below |
| `--help` | — | Show usage |

**Cascade rules** (applied silently):
- `--skip owasp` → also skips `validation` (nothing to validate)
- `--skip validation` → PoC is skipped too (it lives inside Phase 5)

### Casual phrasings

The skill is also triggered by natural-language requests like:

- "Run a security review on `~/repos/my-service`"
- "Check this repo for OWASP issues"
- "Audit dependencies and secrets in this codebase"

---

## When to run

This skill is built for **periodic, deep, whole-repo reviews** — not per-PR CI. Its value comes from full git-history secret scanning, architecture-level reasoning, and cross-file data flow analysis, all of which are wasted when scoped to a single PR diff. Running it on every commit also burns tokens analyzing files the change never touched.

Good moments to trigger it:

- **Release candidates / pre-launch** — strongest signal-to-cost; you can still fix what it finds before shipping
- **Scheduled cadence** (weekly or monthly via cron or a GitHub Action) — catches dependency drift as new CVEs are published, even when code hasn't changed
- **Major dependency upgrades or framework migrations** — surface area shifts faster than per-PR scans can track
- **Before a pentest, or post-incident** — useful as a baseline or root-cause companion
- **Before open-sourcing or sharing a repo externally** — last-line check for secrets, sensitive data, and obvious flaws

**Complementary pattern:** pair this skill with Claude Code's built-in `/security-review` (diff-scoped) for per-PR coverage in CI. The built-in command catches regressions on the PR's actual diff cheaply and quickly; `repo-security-review` catches systemic and accumulated issues on a slower cadence. Together they cover the spectrum without duplicating cost.

---

## Phase flow

```mermaid
flowchart TD
    Start([/repo-security-review &lt;repo&gt;/]) --> P1

    subgraph FINDER["FINDER LAYER (sequential subagents)"]
        P1[Phase 1 · Secret Scanning<br/>gitleaks + grep]
        P2[Phase 2 · Architectural Analysis<br/>deep-tier model · extended thinking]
        TS[(tech-stack.json)]
        P3[Phase 3 · Dependency CVEs<br/>osv-scanner]
        P3b[Phase 3b · Reachability Validation]
        P4[Phase 4 · OWASP Code Scan<br/>semgrep + LLM]
        P4b[Phase 4b · LLM / AI Skill Security<br/>deep-tier model · extended thinking<br/>auto-activated when skill files detected]

        P1 --> P2
        P2 --> TS
        TS --> P3
        P3 --> P3b
        P3b --> P4
        TS -. also read by .-> P4
        TS -. skill_files .-> P4b
        P4 --> P4b
    end

    P4b -. file path only .-> P5

    subgraph JUDGMENT["JUDGMENT LAYER (isolated context)"]
        P5[Phase 5 · Validate + PoC<br/>re-validates Phase 4 findings only<br/>PoCs only for confirmed findings<br/>optional Docker runtime]
    end

    P1 --> R[Phase 6 · Report Builder]
    P2 --> R
    P3b --> R
    P4b --> R
    P5 --> R
    R --> Out([final-report.md + pocs/])

    classDef finder fill:#eef6ff,stroke:#5b8def,color:#1a1a1a
    classDef judgment fill:#fff4e6,stroke:#e0883a,color:#1a1a1a
    classDef report fill:#e8f5e9,stroke:#5a9a5a,color:#1a1a1a
    classDef store fill:#f5f5f5,stroke:#888,color:#1a1a1a,stroke-dasharray: 3 3
    class P1,P2,P3,P3b,P4,P4b finder
    class P5 judgment
    class R report
    class TS store
```

**Key invariants of the flow:**

- All phases run **strictly sequentially**: P1 → P2 → P3 → P3b → P4 → P5 → P6. No phase starts before the previous one finishes.
- Phase 2's `tech-stack.json` gates Phases 3 and 4 — irrelevant checks (e.g. SQLi when there is no DB, API Top 10 when the project is not an API) are skipped automatically. Phase 4 also consumes Phase 3b's reachability data and must run after Phase 3b completes.
- The arrow from Phase 4 to Phase 5 is **file-path only**. Phase 5 reads `phase4-owasp.json` as untrusted input and re-validates each finding from scratch — this is the trust boundary that filters false positives.
- PoC generation is gated *inside* Phase 5: a finding that fails validation never gets a PoC.
- Phase 6 always runs (even if upstream phases were skipped) and notes what was skipped and why.

---

## Output

### Single-repo

Working artifacts are written to `<repo>/.security-review/`:

```text
<repo>/.security-review/
├── tech-stack.json
├── phase1-secrets.json
├── phase2-architecture.json
├── phase3-cves.json
├── phase3b-reachability.json
├── phase4-owasp.json
├── phase5-validated.json
├── phase5-pocs.json
├── pocs/
│   ├── poc_O-001.py
│   └── poc_O-002.sh
└── final-report.md
```

When `--output <dir>` is provided, `final-report.md` and `pocs/` are copied into that directory (e.g. `--output ~/reports/myapp` → `~/reports/myapp/final-report.md` + `~/reports/myapp/pocs/`). When `--output` is omitted, no copy is made — everything stays under `.security-review/`.

### Multi-repo

Phase 0 and Phase 7 artifacts land in `--output` (defaults to `./system-security-review/`). Each service's report and PoCs are copied into a named subdirectory:

```text
~/reports/my-system/
├── service-topology.json   ← Phase 0: service graph
├── system-findings.json    ← Phase 7: cross-repo security findings
├── system-report.md        ← Phase 7: synthesis report (start here)
├── auth/
│   ├── final-report.md
│   └── pocs/
├── gateway/
│   ├── final-report.md
│   └── pocs/
└── users/
    ├── final-report.md
    └── pocs/
```

`system-report.md` is the entry point — it summarizes cross-service findings and links to each per-service report.

---

## Repository layout

```text
repo-security-review/
├── SKILL.md                  # Skill specification (read by Claude Code)
├── references/               # Per-phase agent instructions
│   ├── phase0-topology.md    # Multi-repo only: service topology mapping
│   ├── phase1-secrets.md
│   ├── phase2-architecture.md
│   ├── phase3-dependencies.md
│   ├── phase4-owasp.md
│   ├── phase5-validate-and-poc.md
│   ├── phase6-report.md
│   └── phase7-synthesis.md   # Multi-repo only: cross-repo synthesis
├── scripts/
│   ├── repo-security-review-command.md   # Slash-command definition
│   └── setup.sh                          # Installs gitleaks, osv-scanner, semgrep
└── assets/                   # (reserved for future templates/diagrams)
```

---

## Adding context (`--context`)

By default the skill assumes the worst case — a public, anonymous-facing service handling sensitive data — and grades severity accordingly. That's the right baseline for unknown codebases, but it produces noise for a CLI that only runs on a developer's laptop.

The `--context` flag lets you provide a small inline threat model. The skill uses it to compute a **contextual severity** alongside the base severity for Architecture, CVE, and code-level findings — each shows both: the technical impact (context-free) and the calibrated impact (after context). Secrets are not calibrated; rotation is always required regardless of deployment context.

**Opt-in only.** If you don't pass `--context`, **nothing changes** — the skill runs exactly as before. No new file is written, no calibration runs, no new report sections appear.

### Inline syntax

Comma-separated `key=value` pairs. All keys are optional; missing keys fall back to strict defaults. Order doesn't matter.

```text
--context deployment_target=local,auth_required_to_reach=true
```

You can pass any subset:

```text
--context deployment_target=local
--context auth_required_to_reach=true
--context include_readme=false
```

### Allowed keys and values

| Key | Allowed values |
|---|---|
| `deployment_target` | `local` \| `public` |
| `auth_required_to_reach` | `true` \| `false` |
| `include_readme` | `true` \| `false` |

`data_sensitivity` is not a user-facing key — it is hardcoded to `pii` (worst-case) for every run. All findings are scored as if sensitive data is always at risk.

Any unknown key, unknown value, malformed pair, or duplicate key aborts the run with a clear error — there is no silent fallback for invalid input.

### Strict defaults (when a key is omitted)

| Field | Default | Rationale |
|---|---|---|
| `deployment_target` | `public` | Hardest reachable case |
| `auth_required_to_reach` | `false` | Pessimistic |
| `include_readme` | `true` | README is read for project context by default |

**Invariant:** defaults are the most pessimistic value for each axis. A value you provide can only soften severity, never tighten it. `contextual_severity` is never higher than `cvss_base_severity`.

### How severity is calibrated

Each axis applies an independent softener to the base severity. Floor: nothing drops below LOW.

| Axis | Effect |
|---|---|
| `deployment_target: local` | −2 tiers, all findings |
| `deployment_target: public` | no change (default) |
| `auth_required_to_reach: true` | −1 tier, only for pre-auth findings (unauthenticated SSRF, anonymous SQLi) |
| `auth_required_to_reach: false` | no change (default) |

**Internal services:** use `auth_required_to_reach=true` to reflect that an attacker must first authenticate before reaching the service. This applies the same −1 tier softener that an explicit `internal` deployment tier would have provided.

### Drift detection — you can't downgrade findings by lying

Phase 2 checks the one axis that has a reliable code signal:

- If you declare `auth_required_to_reach: true` but Phase 2 finds public routes with no auth middleware, it emits a "threat model drift" finding **and** reverts that dimension to the strict default for this run.
- `deployment_target` has no reliable code signal — it's taken at face value.

This means the worst case from a wrong context is "a finding shows up as MEDIUM with a visible note explaining it was downgraded" — never "a finding disappears."

### Report changes when calibration is active

- New header section "Assumed Threat Model" showing what was used.
- Severity matrix shows both `Base` and `Contextual` columns.
- New "Section 5b: Context-Driven Adjustments" listing every finding whose severity changed and why.
- For CVSS-based downstream tooling, read the `Base` column and ignore the contextual one.

---

## Runtime PoC validation (`--runtime`)

When `--runtime` is set, Phase 5 stands the app up in Docker and executes each confirmed PoC against it. There are three paths, picked in order:

1. **Project's `docker-compose.yml`** — used as-is.
2. **Project's `Dockerfile`** — built and run on the port detected by Phase 2.
3. **Synthesized environment** — if neither file exists, Phase 5 generates a minimal `Dockerfile` (and a `docker-compose.yml` with a DB sidecar if the project uses one) from the tech-stack profile, and runs the PoC against that.

Synthesized files are written to `<repo>/.security-review/synthesized/` and **persist after the run** so you can re-run validation later (`cd .security-review/synthesized/ && docker compose up`).

**Limits of the synthesized path — be aware before trusting the result:**

- Covers stateless web apps on common stacks (Flask, FastAPI, Django, Express, Next.js, Go, Rails). Unsupported stacks fall back to `RUNTIME_SKIPPED`.
- A single supported DB (Postgres / MySQL / MongoDB / Redis) is synthesized as a sidecar with default credentials. Multi-DB or exotic dependencies (Elasticsearch, Kafka, custom services) are not synthesized — `RUNTIME_SKIPPED`.
- The synthesized DB comes up **empty** — no migrations beyond what the Dockerfile runs, no seed users. PoCs that require pre-existing accounts or records (BOLA, broken auth, IDOR) will fail at the login step and are reported as `RUNTIME_NOT_CONFIRMED` with a note explicitly flagging the seed-data limitation, so you don't mistake a setup failure for evidence of safety.
- Runtime-confirmed findings against a synthesized environment are labeled as such in the final report — they're a strong signal, but not a substitute for running the PoC against the project's real setup.

If you don't need runtime confirmation, omit `--runtime`. The PoCs are still real, runnable scripts you can execute manually against any live instance later.

---

## Troubleshooting

- **"Skill not found"** — verify the clone path is exactly `~/.claude/skills/repo-security-review/` and that `SKILL.md` sits at its root.
- **Phase 1 reports nothing** — check `gitleaks version`; if missing, rerun `scripts/setup.sh`.
- **Phase 3 misses ecosystems** — Phase 2 may have under-detected the tech stack. Re-run without `--skip architecture`.
- **`--runtime` does nothing** — confirm `docker --version` works and Docker Desktop is running.
- **`--runtime` produces `RUNTIME_SYNTHESIS_FAILED`** — the repo had no Docker setup and synthesis tried but failed. Check `<repo>/.security-review/synthesized/startup.log` for the build/startup log.
