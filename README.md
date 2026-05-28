# repo-security-review

A Claude Code **skill** that runs a full, multi-phase security review of a code repository. Each phase runs as an isolated subagent with a narrow responsibility, and findings flow through a strict finder → judgment trust boundary before a final report is produced.

See [SKILL.md](SKILL.md) for the full specification.

---

## What it does

Seven sequential phases:

1. **Secret scanning** — `gitleaks` across full git history
2. **Architectural analysis** — trust boundaries, auth model, infra config; produces a tech-stack profile that gates downstream phases
3. **Dependency CVE scanning** (+ 3b reachability) — `osv-scanner` against ecosystems detected in Phase 2
4. **Code-level OWASP analysis** — Top 10 + API Top 10, pruned by tech stack (no DB → skip SQLi, etc.)
5. **Finding validation + PoC generation** — independent re-validation of Phase 4 candidates; PoCs written only for findings that pass the gate (optional Docker runtime validation)
6. **Report builder** — aggregates everything into a single markdown report with severity matrix, remediation table, false-positives log, and PoC scripts

---

## Prerequisites

External CLI tools used by the phases:

| Tool | Used by | Required? |
|------|---------|-----------|
| `gitleaks` | Phase 1 | Recommended |
| `osv-scanner` | Phase 3 | Recommended |
| `semgrep` | Phase 4 | Recommended |
| `docker` | Phase 5 (`--runtime` only) | Optional |

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
/repo-security-review /path/to/repo --output ~/reports/myapp.md
/repo-security-review /path/to/repo --runtime
/repo-security-review /path/to/repo --skip architecture --output ~/reports/myapp.md --runtime
```

| Flag | Default | Effect |
|------|---------|--------|
| `--skip <phases>` | none | Comma-separated: `secrets`, `architecture`, `dependencies`, `owasp`, `validation` |
| `--output <path>` | `~/security-reports/<repo>-<date>.md` | Final report destination |
| `--runtime` | off | Docker-based runtime PoC validation in Phase 5 |
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

## Phase flow

```mermaid
flowchart TD
    Start([/repo-security-review &lt;repo&gt;/]) --> P1
    Start --> P2

    subgraph FINDER["FINDER LAYER (independent subagents)"]
        P1[Phase 1 · Secret Scanning<br/>gitleaks + grep]
        P2[Phase 2 · Architectural Analysis<br/>Opus + extended thinking]
        TS[(tech-stack.json)]
        P3[Phase 3 · Dependency CVEs<br/>osv-scanner]
        P3b[Phase 3b · Reachability Validation]
        P4[Phase 4 · OWASP Code Scan<br/>semgrep + LLM]

        P2 --> TS
        TS --> P3
        TS --> P4
        P3 --> P3b
    end

    P4 -. file path only .-> P5

    subgraph JUDGMENT["JUDGMENT LAYER (isolated context)"]
        P5[Phase 5 · Validate + PoC<br/>re-validates from scratch<br/>PoCs only for confirmed findings<br/>optional Docker runtime]
    end

    P1 --> R[Phase 6 · Report Builder]
    P2 --> R
    P3b --> R
    P5 --> R
    R --> Out([final-report.md + pocs/])

    classDef finder fill:#eef6ff,stroke:#5b8def,color:#1a1a1a
    classDef judgment fill:#fff4e6,stroke:#e0883a,color:#1a1a1a
    classDef report fill:#e8f5e9,stroke:#5a9a5a,color:#1a1a1a
    classDef store fill:#f5f5f5,stroke:#888,color:#1a1a1a,stroke-dasharray: 3 3
    class P1,P2,P3,P3b,P4 finder
    class P5 judgment
    class R report
    class TS store
```

**Key invariants of the flow:**

- Phase 2's `tech-stack.json` gates Phases 3 and 4 — irrelevant checks (e.g. SQLi when there is no DB, API Top 10 when the project is not an API) are skipped automatically.
- The arrow from Phase 4 to Phase 5 is **file-path only**. Phase 5 reads `phase4-owasp.json` as untrusted input and re-validates each finding from scratch — this is the trust boundary that filters false positives.
- PoC generation is gated *inside* Phase 5: a finding that fails validation never gets a PoC.
- Phase 6 always runs (even if upstream phases were skipped) and notes what was skipped and why.

---

## Output

Working artifacts are written to `/tmp/repo-security-review-<repo-name>/`:

```text
/tmp/repo-security-review-<name>/
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

At the end of the run, `final-report.md` is copied to the `--output` path (and the `pocs/` directory alongside it, if any PoCs were generated).

---

## Repository layout

```text
repo-security-review/
├── SKILL.md                  # Skill specification (read by Claude Code)
├── references/               # Per-phase agent instructions
│   ├── phase1-secrets.md
│   ├── phase2-architecture.md
│   ├── phase3-dependencies.md
│   ├── phase4-owasp.md
│   ├── phase5-validate-and-poc.md
│   └── phase6-report.md
├── scripts/
│   ├── repo-security-review-command.md   # Slash-command definition
│   └── setup.sh                          # Installs gitleaks, osv-scanner, semgrep
└── assets/                   # (reserved for future templates/diagrams)
```

---

## Troubleshooting

- **"Skill not found"** — verify the clone path is exactly `~/.claude/skills/repo-security-review/` and that `SKILL.md` sits at its root.
- **Phase 1 reports nothing** — check `gitleaks version`; if missing, rerun `scripts/setup.sh`.
- **Phase 3 misses ecosystems** — Phase 2 may have under-detected the tech stack. Re-run without `--skip architecture`.
- **`--runtime` does nothing** — confirm `docker --version` works and Docker Desktop is running.
