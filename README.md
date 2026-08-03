# repo-security-review

A Claude Code **skill** that runs a full, multi-phase security review of a code repository — secret scanning, architecture and threat analysis, dependency CVEs, OWASP code review, and independent validation — then writes a single markdown report. Each phase runs as an isolated subagent, and findings pass through a finder → judgment trust boundary before they reach the report.

Works on a single repo or across multiple microservices, and has a dedicated mode for auditing third-party/open-source tools before adopting them.

> Full specification: [SKILL.md](SKILL.md).

---

## Installation

Skills live under `~/.claude/skills/`. Clone the repo there so updates are a `git pull` away:

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/<your-org>/repo-security-review ~/.claude/skills/repo-security-review
```

Install the external scanners the phases use (`gitleaks`, `osv-scanner`, `semgrep`, `jq`, and optionally `docker` for `--runtime`):

```bash
bash ~/.claude/skills/repo-security-review/scripts/setup.sh
```

The script installs whatever it can via `brew`, `go`, or `pip3`. Any missing tool just degrades the matching phase — the pipeline never aborts. To update later: `cd ~/.claude/skills/repo-security-review && git pull`.

---

## Usage

In any Claude Code session (CLI or Desktop), point the skill at a local repo path:

```text
/repo-security-review /path/to/repo
```

### Sample commands

```text
# Skip phases you don't need, copy the report somewhere
/repo-security-review /path/to/repo --skip secrets,dependencies --output ~/reports/myapp

# Full detailed report (OWASP coverage, remediation priority, appendix)
/repo-security-review /path/to/repo --verbose

# Runtime PoC validation in Docker
/repo-security-review /path/to/repo --runtime

# CI / headless — validation only (no PoC files), no prompts
/repo-security-review . --output ./security-report --skip poc --yes

# Calibrate severity for a local-only tool behind auth
/repo-security-review /path/to/repo --context deployment_target=local,auth_required_to_reach=true

# Multi-repo — analyze several services, get a system-level report
/repo-security-review --repos ~/svcs/auth,~/svcs/gateway,~/svcs/users --output ~/reports/my-system

# Vendor audit — is this third-party/open-source tool safe to adopt internally?
/repo-security-review /path/to/vendor-tool --vendor --output ~/reports/vendor-tool
```

### Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--repos <paths>` | none | Comma-separated repo paths → multi-repo mode (adds cross-service topology + synthesis). |
| `--skip <phases>` | none | Comma-separated: `secrets`, `architecture`, `dependencies`, `owasp`, `skill-security`, `validation`, `poc`. |
| `--output <dir>` | none | Copy the report and PoC scripts into this directory after the run (created if needed). |
| `--verbose` | off | Full detailed report (OWASP checks inventory, remediation-priority section, appendix). |
| `--runtime` | off | Stand the app up in Docker and run each confirmed PoC against it. |
| `--vendor` | off | Third-party adoption audit. Skips secrets/dependencies/PoC, pins all phases to Sonnet, and produces an adoption-risk report (verdict + conditions + "what it does" + adopter-side controls). |
| `--context <pairs>` | none | Inline threat model to calibrate severity: `deployment_target=local\|public`, `auth_required_to_reach=true\|false`. Softens only — never sharpens. |
| `--claude5` | off | Opt into Claude 5 generation models (with 4.x fallback). By default uses pinned 4.x versions. |
| `--yes` | off | Non-interactive / CI mode — auto-confirms prompts (safety path checks still apply). |
| `--debug` | off | Write `.security-review/execution-log.md` showing how the file-reading phases actually ran. |
| `--help` | — | Show usage. |

**Skip cascades** (applied silently): `--skip owasp` also skips `validation` + `poc`; `--skip validation` also skips `poc`; `--skip poc` keeps validation but writes no PoC files; `--skip architecture` also skips `skill-security`. `--vendor` forces skip of `secrets`, `dependencies`, and `poc`.

### Output

Working artifacts go to `<repo>/.security-review/` (per-phase JSON, `pocs/`, and `final-report.md`); `--output` copies the report + PoCs out. In multi-repo mode, start from `system-report.md` in the output directory.

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
