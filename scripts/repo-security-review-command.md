# Repo Security Review Pipeline
# Save as: .claude/commands/repo-security-review.md in your Claude Code project
#
# Usage:
#   /repo-security-review --help
#   /repo-security-review /path/to/repo
#   /repo-security-review /path/to/repo --skip secrets
#   /repo-security-review /path/to/repo --skip architecture,dependencies
#   /repo-security-review /path/to/repo --output ~/reports/myapp.md
#   /repo-security-review /path/to/repo --runtime
#   /repo-security-review /path/to/repo --skip architecture --output ~/reports/myapp.md --runtime

Run a full automated security review of a code repository.

## Step 1: Check for --help

If `$ARGUMENTS` is `--help` or `-h` or empty, print the following and stop:

---

```
Security Review — Available Phases & Skip Options
══════════════════════════════════════════════════

Usage:
  /repo-security-review <repo-path> [options]

Options:
  --skip <phases>       Comma-separated phases to skip (see below)
  --output <path>       Where to save the final report
                        Default: <repo>/.security-review/<repo>-<date>.md
  --runtime             Enable Docker-based runtime PoC validation
  --model <tier>        Model quality/cost tier (default: thorough)
                        thorough  — most capable model + extended thinking
                                    (highest quality, highest cost)
                        balanced  — most capable model, no extended thinking
                                    (~40% cheaper, slightly less deep arch analysis)
                        fast      — lightweight models throughout
                                    (lowest cost, may miss subtle issues)
  --context <pairs>     Optional inline threat model used to calibrate
                        severity. Format: comma-separated key=value pairs.
                        Keys: deployment_target, data_sensitivity,
                        auth_required_to_reach, include_readme.
                        All keys optional; omitted keys fall back to strict
                        defaults. include_readme controls whether README.md
                        is read for project context (default: true). Omit
                        the flag entirely for default behavior (no
                        calibration).
                        Example:
                        --context deployment_target=internal_tool,data_sensitivity=internal,auth_required_to_reach=true,include_readme=true
  --help                Show this help

Phases you can skip (--skip <name>):

  Name              What it does
  ──────────────    ──────────────────────────────────────────────────────
  secrets           Phase 1 · Scans for hardcoded API keys, tokens,
                    passwords, and private keys — including git history.
                    Tools: gitleaks + grep patterns.

  architecture      Phase 2 · Analyzes the codebase at design level:
                    trust boundaries, auth model, data flow, infra config,
                    missing security controls. Also produces the tech-stack
                    profile used by all downstream phases.
                    Model: most capable available (tier-dependent).

  dependencies      Phase 3 · Finds known CVEs in project dependencies
                    using lockfiles. Only scans ecosystems present in the
                    project (npm only if Node detected, etc.). Also validates
                    whether each CVE is actually reachable at runtime.
                    Tools: osv-scanner + npm audit / pip-audit as needed.

  owasp             Phase 4 · Code-level vulnerability scan against OWASP
                    Top 10 and OWASP API Security Top 10. Skips checks that
                    don't apply (no DB → no SQLi scan, no HTML → no XSS, etc).
                    Also skips entire API Top 10 if project isn't API-based.
                    Skipping this also skips validation.

  validation        Phase 5 · Independent validation of Phase 4 findings
                    (data flow tracing, mitigation checks, false positive
                    filtering) + immediate PoC generation for confirmed
                    findings only. These two steps share one agent — PoC
                    generation is gated on passing validation.

Cascade rules:
  --skip owasp        → also skips validation (nothing to validate)
  --skip validation   → also skips PoC (PoC lives inside Phase 5)

Phase that always runs:
  Report Builder    Aggregates all completed phases into a structured
                    markdown report with severity matrix, remediation
                    priority table, false positives log, and PoC scripts.

Examples:
  # Full review
  /repo-security-review ~/repos/my-service

  # Skip secrets and deps (quick arch + code review only)
  /repo-security-review ~/repos/my-service --skip secrets,dependencies

  # Architecture review only — no code-level analysis
  /repo-security-review ~/repos/my-service --skip dependencies,owasp

  # Full review with runtime PoC validation via Docker
  /repo-security-review ~/repos/my-service --runtime --output ~/reports/my-service.md

  # Skip arch (you already reviewed it) — deps + OWASP only
  /repo-security-review ~/repos/my-service --skip architecture,secrets

  # Full review with severity calibrated to an internal tool
  /repo-security-review ~/repos/my-service --context deployment_target=internal_tool,data_sensitivity=internal,auth_required_to_reach=true
```

---

## Step 2: Parse Arguments (if not --help)

Parse `$ARGUMENTS` for:
- First positional arg → repo path (required)
- `--skip <phases>` → comma-separated list from: `secrets`, `architecture`,
  `dependencies`, `owasp`, `validation`
- `--output <path>` → destination for final report markdown file
  Default: `{repo_path}/.security-review/{repo-name}-{YYYY-MM-DD}.md`
- `--runtime` → enable Docker-based runtime PoC validation in Phase 5
- `--model <tier>` → `thorough` (default) | `balanced` | `fast`
  Abort with a clear error if any other value is given.
- `--context <pairs>` → optional inline threat model as comma-separated
  `key=value` pairs. Allowed keys: `deployment_target`, `data_sensitivity`,
  `auth_required_to_reach`, `include_readme`. Allowed values per key are
  listed in SKILL.md. `include_readme` controls whether README.md is read
  for project context by Phase 2 and Phase 4 agents; defaults to `false`.
  When set, the orchestrator validates the pairs and writes a normalized
  `threat-model.json` to the working directory. When unset, the skill
  behaves exactly as before — no calibration logic runs anywhere. Any
  unknown key, unknown enum value, malformed pair, or duplicate key aborts
  the run with a clear error message.

Apply cascade rules silently:
- `--skip owasp` → add `validation` to skip list
- `--skip validation` → PoC is already skipped (it's inside Phase 5)

## Step 3: Validate repo path

```bash
ls "$REPO_PATH" 2>/dev/null || { echo "❌ Repo path not found: $REPO_PATH"; exit 1; }
```

## Step 4: Print run plan

```
🔍 Security Review: {repo-name}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phases running:   {list}
Phases skipped:   {list or "none"}
Model tier:       {thorough / balanced / fast}
Output:           {output_path}
Runtime PoC:      {enabled / disabled}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Step 5: Check prerequisites

```bash
echo "Checking tools..."
which gitleaks    && gitleaks version  || echo "⚠️  gitleaks not found (Phase 1 limited)"
which osv-scanner                      || echo "⚠️  osv-scanner not found (Phase 3 limited)"
which semgrep     && semgrep --version || echo "⚠️  semgrep not found (Phase 4 limited)"
[ "$RUNTIME" = true ] && \
  { which docker && docker --version   || echo "⚠️  docker not found (runtime validation disabled)"; }
```

## Step 6: Create working directories

```bash
mkdir -p {repo_path}/.security-review
mkdir -p "$(dirname {output_path})"
```

## Step 7: Execute phases

Read SKILL.md and execute each non-skipped phase as an isolated subagent,
passing only file paths (never in-memory content) between phases.

After each phase, print a one-line progress summary.

## Step 8: Deliver

After the report phase completes:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Security review complete
📄 Report:  {output_path}
📁 PoCs:    {pocs_dir}  (if any were generated)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Call `present_files` with the report path.
