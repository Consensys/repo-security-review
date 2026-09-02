# Repo Security Review Pipeline
# Save as: .claude/commands/repo-security-review.md in your Claude Code project
# Requires the rest of this skill directory (references/*.md) to also be
# reachable from that project — this file is not fully standalone; see Step 7.
#
# Usage:
#   /repo-security-review --help
#   /repo-security-review /path/to/repo
#   /repo-security-review /path/to/repo --skip secrets
#   /repo-security-review /path/to/repo --skip architecture,dependencies
#   /repo-security-review /path/to/repo --output ~/reports/myapp
#   /repo-security-review /path/to/repo --poc
#   /repo-security-review /path/to/repo --runtime
#   /repo-security-review /path/to/repo --skip architecture --output ~/reports/myapp --runtime
#   /repo-security-review --repos /path/svc1,/path/svc2,/path/svc3 --output ~/reports/my-system

Run a full automated security review of a code repository.

## Step 1: Check for --help or missing arguments

If `$ARGUMENTS` is empty, ask the user for a repo path before proceeding:
> "Please provide the path to the repository you'd like to review."
Then wait for input and continue to Step 2 with the provided value.

If `$ARGUMENTS` is `--help` or `-h`, print the following and stop:

---

```
Security Review — Available Phases & Skip Options
══════════════════════════════════════════════════

Usage:
  /repo-security-review <repo-path> [options]

Options:
  --skip <phases>       Comma-separated phases to skip (see below)
  --repos <paths>       Comma-separated repo paths for multi-repo mode.
                        Activates Phase 0 (topology) and Phase 7 (synthesis).
                        Produces a system-level report alongside per-service
                        reports. Example:
                        --repos ~/svc/auth,~/svc/gateway,~/svc/users
  --output <dir>        Directory to save the report and PoC scripts into.
                        Default: (single-repo: none — everything stays in
                        <repo>/.security-review/) (multi-repo: ./system-security-review/)
  --poc                 Opt-in: generate a PoC for each finding Phase 5
                        confirms. Without this flag (the default), Phase 5
                        still validates every finding, but writes no PoC
                        files. Has no effect in --pr mode; forced off in
                        --vendor mode.
  --runtime             Enable Docker-based runtime PoC validation. Implies
                        --poc.
  --yes                 Non-interactive / CI mode. Auto-confirms all prompts:
                        the --output copy gate, the Docker runtime gate, and
                        the pure-skill-repo auto-skip cascade. Path-validation
                        safety checks (sensitive --output destinations) are
                        never bypassed. Requires a repo path or --repos —
                        aborts if neither is provided.
  --debug               Write an execution log to
                        <repo>/.security-review/execution-log.md showing how
                        Phases 2, 4, 5, and 6 actually ran: for the file-reading
                        phases (2, 4, 5), every file read with its line range
                        and a full/partial flag, which files were treated as
                        security-relevant, the greps run, and checks run vs
                        skipped; for Phase 6 (report builder), which phase
                        output files it read. Every phase also reports its own
                        token consumption. For inspecting skill behaviour.
                        Paste it back for analysis.
  --context <pairs>     Optional inline threat model used to calibrate
                        severity. Format: comma-separated key=value pairs.
                        Keys: deployment_target (local|public),
                        auth_required_to_reach (true|false).
                        data_sensitivity is not a key — always defaults to pii.
                        README is always read by Phase 2 for context — it is
                        not a --context key.
                        All keys optional; omitted keys use strict defaults.
                        Omit the flag entirely for default behavior (no
                        calibration).
                        Examples:
                        --context deployment_target=local
                        --context auth_required_to_reach=true
                        --context deployment_target=local,auth_required_to_reach=true
  --sonnet              Experimental: overrides Phase 2 (Deep tier) from Opus
                        to Sonnet family for this run, to A/B scan quality
                        and token consumption. Standard tier is unaffected
                        (already Sonnet). No effect in --vendor or --pr mode
                        (neither has a Deep tier).
  --skill-security      Opt-in: run Phase 4b (LLM/AI skill security) on a
                        mixed repo that also contains a SKILL.md or
                        .claude/commands/. Without this flag, a mixed repo
                        never runs Phase 4b by default — has_skill_files:
                        true alone is a structural signal, not an auto-run
                        trigger, for a repo whose primary content isn't skill
                        files (ordinary CLAUDE.md/AGENTS.md docs are common
                        in AI-assisted projects and would otherwise trigger
                        it every time). Redundant on a pure skill repo
                        (is_skill_repo: true — Phase 4b auto-runs there
                        regardless) and in --vendor mode (already auto-runs
                        it there).
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
                    filtering). PoC generation is opt-in (--poc) and, when
                    enabled, happens immediately for confirmed findings only.
                    Skipping this means --poc has no effect (nothing to
                    validate).

  skill-security    Phase 4b · LLM / AI skill security analysis. Analyses
                    instruction files against OWASP LLM Top 10. Auto-
                    activated only when the repo is entirely skill/agent
                    content (is_skill_repo: true). On a mixed repo that also
                    has a SKILL.md/.claude/commands/ (has_skill_files: true
                    but is_skill_repo: false), it does NOT auto-run — pass
                    --skill-security explicitly (or --vendor, which already
                    auto-runs it) to opt in.

Cascade rules:
  --skip owasp        → also skips validation (nothing to validate); --poc
                        then has no effect
  --skip validation   → --poc has no effect (PoC requires a validation verdict)
  --runtime           → implies --poc (runtime validation needs a PoC to run)
  --skip architecture → also skips skill-security (skill detection
                        requires tech-stack.json from Phase 2)
  --skip skill-security + --skill-security together → the skip wins

Phase that always runs:
  Report Builder    Aggregates all completed phases into a structured
                    markdown report with severity matrix, remediation
                    priority table, false positives log, and PoC scripts.

Examples:
  # Full review (single repo)
  /repo-security-review ~/repos/my-service

  # Skip secrets and deps (quick arch + code review only)
  /repo-security-review ~/repos/my-service --skip secrets,dependencies

  # Architecture review only — no code-level analysis
  /repo-security-review ~/repos/my-service --skip dependencies,owasp

  # Full review with runtime PoC validation via Docker (--runtime implies --poc)
  /repo-security-review ~/repos/my-service --runtime --output ~/reports/my-service

  # CI / headless — no interactive prompts, validation only (default: no PoC files)
  /repo-security-review . --output ./security-report --yes

  # CI — full review including PoC generation, auto-confirm all gates
  /repo-security-review . --output ./security-report --poc --yes

  # Inspect how the skill reads files — writes execution-log.md to paste back
  /repo-security-review ~/repos/my-service --debug

  # Skip arch (you already reviewed it) — deps + OWASP only
  /repo-security-review ~/repos/my-service --skip architecture,secrets

  # Full review with severity calibrated to a local CLI tool
  /repo-security-review ~/repos/my-service --context deployment_target=local

  # Full review calibrated to an internal (auth-required) service
  /repo-security-review ~/repos/my-service --context auth_required_to_reach=true

  # Multi-repo: review three microservices and get a system-level report
  /repo-security-review --repos ~/svcs/auth,~/svcs/gateway,~/svcs/users --output ~/reports/my-system

  # Multi-repo: skip secrets across all services, get system synthesis
  /repo-security-review --repos ~/svcs/auth,~/svcs/gateway --skip secrets --output ~/reports/my-system
```

---

## Step 2: Parse Arguments (if not --help)

Parse `$ARGUMENTS` for:
- `--repos <paths>` → comma-separated list of repo paths (multi-repo mode).
  When present, the first positional arg is not required.
  When absent, the first positional arg is the single repo path (required).
- First positional arg → single repo path (required unless `--repos` is set)
- `--skip <phases>` → comma-separated list from: `secrets`, `architecture`,
  `dependencies`, `owasp`, `validation`, `skill-security`
- `--output <dir>` → output directory; both `final-report.md` and `pocs/` are
  copied here at the end. Created if it doesn't exist.
  Default (single-repo): none — when omitted everything stays at `{repo_path}/.security-review/`
  Default (multi-repo): `./system-security-review/`
- `--poc` → opt-in: generate a PoC for each finding Phase 5 confirms.
  Without it (the default), Phase 5 validates every finding but writes no
  PoC files. Has no effect in `--pr` mode; forced off in `--vendor` mode.
- `--runtime` → enable Docker-based runtime PoC validation in Phase 5. Implies `--poc`.
- `--yes` → non-interactive mode: auto-confirm all user-facing prompts
  (the `--output` copy gate, the Docker runtime gate, the pure-skill-repo
  auto-skip cascade). Path-validation safety checks are never bypassed.
  If `--yes` is set and no repo path is provided, abort with:
  `❌ --yes requires a repo path or --repos — interactive input unavailable`
- `--debug` → write an execution log to `{repo_path}/.security-review/execution-log.md`.
  Passed to Phases 2, 4, 5, and 6, which append how they actually ran (files read
  with line ranges + full/partial flag, security-relevant files, greps, checks
  run/skipped — Phase 6 instead lists which phase-output files it read, since it
  doesn't read target-repo source). See SKILL.md → Execution Log for the format.
- `--context <pairs>` → optional inline threat model as comma-separated
  `key=value` pairs. Allowed keys: `deployment_target` (`local`|`public`),
  `auth_required_to_reach` (`true`|`false`).
  `data_sensitivity` is not an accepted key — reject it with a clear error.
  README.md is always read by Phase 2 for context, regardless of `--context`.
  When set, the orchestrator validates the pairs and writes a normalized
  `threat-model.json` to the working directory. When unset, the skill
  behaves exactly as before — no calibration logic runs anywhere. Any
  unknown key, unknown enum value, malformed pair, or duplicate key aborts
  the run with a clear error message.
- `--sonnet` → experimental: for this run, Phase 2 (Deep tier) resolves
  against the Sonnet family instead of Opus (falls back to Haiku only if
  Sonnet is entirely unavailable), so quality/token consumption can be
  A/B'd against a normal Opus run. Standard tier is unaffected. No effect in
  `--vendor` or `--pr` mode — neither has a Deep tier to override. Record
  `sonnet_flag` in `run-metadata.json`.
- `--skill-security` → opt-in: on a mixed repo (`is_skill_repo: false`) that
  also has `has_skill_files: true`, run Phase 4b anyway. Without it, Phase 4b
  does not run on a mixed repo — `has_skill_files: true` alone is a
  structural signal only there, not an auto-run trigger (see the
  `skill-security` phase description above for why). Redundant on a pure
  skill repo (`is_skill_repo: true` — auto-runs regardless) and in `--vendor`
  mode (already auto-runs it there).

Abort with a clear error if any skip value is not in the allowed list above:
`❌ Unknown --skip value: "{value}". Allowed: secrets, architecture, dependencies, owasp, validation, skill-security`

Apply cascade rules silently:
- `--skip owasp` → add `validation` to skip list; `--poc` then has no effect
- `--skip validation` → `--poc` has no effect (PoC requires a validation verdict)
- `--runtime` without `--poc` → treat `--poc` as set (runtime validation needs a PoC to run)
- `--poc` not set → pass no PoC flag to Phase 5; it validates every finding but writes no PoC files
- `--skip architecture` → add `skill-security` to skip list (skill detection requires Phase 2 output)

**Multi-repo validation:** if `--repos` is set with only one path, warn:
`⚠️  Only one repo path provided to --repos. Use the positional arg for single-repo mode.`
Then continue — it is not an error.

## Step 3: Validate repo path(s)

**Single-repo mode:**
```bash
ls "$REPO_PATH" 2>/dev/null || { echo "❌ Repo path not found: $REPO_PATH"; exit 1; }
```

**Multi-repo mode:** validate each path in the `--repos` list:
```bash
for each path in REPOS:
  ls "$path" 2>/dev/null || { echo "❌ Repo path not found: $path"; exit 1; }
done
```

## Step 4: Print run plan

**Single-repo mode:**
```
🔍 Security Review: {repo-name}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phases running:   {list}
Phases skipped:   {list or "none"}
Output:           {output_path if set, else "<repo>/.security-review/final-report.md"}
PoC generation:   {enabled (--poc) / disabled (default)}
Runtime PoC:      {enabled / disabled}
Deep tier model:  {Opus family (default) / Sonnet family (--sonnet)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Multi-repo mode:**
```
🔍 Multi-Repo Security Review ({N} services)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Services:         {svc1}, {svc2}, {svc3}
Phases running:   Phase 0 → [1–6 per service] → Phase 7
Phases skipped:   {list or "none" — applies to each service's per-repo phases}
Output:           {output_dir}
PoC generation:   {enabled (--poc) / disabled (default)}
Runtime PoC:      {enabled / disabled}
Deep tier model:  {Opus family (default) / Sonnet family (--sonnet)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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

**Single-repo mode:**
```bash
mkdir -p {repo_path}/.security-review
[ -n "{output_dir}" ] && mkdir -p "{output_dir}"
# When --debug is set, create an empty execution log for Phases 2/4/5 to append to
[ "$DEBUG" = true ] && : > {repo_path}/.security-review/execution-log.md
```

**Multi-repo mode:**
```bash
mkdir -p "{output_dir}"
for each repo in REPOS:
  mkdir -p "{repo_path}/.security-review"
  [ "$DEBUG" = true ] && : > "{repo_path}/.security-review/execution-log.md"
done
```

## Step 7: Execute phases

Read SKILL.md for full phase instructions. Execute each non-skipped phase as an
isolated subagent, passing only file paths (never in-memory content) between phases.

**Single-repo mode:**

```
Run Phase 1.
Run Phase 2.

After Phase 2: read tech-stack.json.
  if is_skill_repo: true →
    Print detection evidence and ask for confirmation (see SKILL.md auto-skip cascade).
    If confirmed: add phases 3, 4, 5 to the skip list. Run Phase 4b. Run Phase 6.
    If declined: run full pipeline; Phase 4b still auto-runs regardless
      (declining only affects whether phases 3/4/5 are skipped).
  else:
    Run Phase 3 (unless skipped).
    Run Phase 4 (unless skipped).
    if has_skill_files: true →
      if --vendor →
        Print "ℹ️  Skill files detected — Phase 4b (LLM security) will run (vendor mode)."
        Run Phase 4b (unless --skip skill-security).
      else if --skill-security →
        Print "ℹ️  Skill files detected and --skill-security passed — Phase 4b (LLM security) will run."
        Run Phase 4b (unless --skip skill-security).
      else →
        Print "ℹ️  Skill files detected but --skill-security was not passed — Phase 4b skipped by default."
        Do not run Phase 4b.
    Run Phase 5 (unless skipped).
    Run Phase 6.
```

**Multi-repo mode:**
1. Run Phase 0 (topology mapping) — passes all repo paths, writes `{output_dir}/service-topology.json`
2. For each repo in `--repos` (one at a time, never interleaved):
   - Run phases 1–6 for that repo using the single-repo logic above
   - Pass `{output_dir}/service-topology.json` to the Phase 2 agent as additional context
3. Run Phase 7 (cross-repo synthesis) — passes `{output_dir}` and all per-repo paths

After each phase (and each per-repo phase in multi-repo mode), print a one-line
progress summary **in the main session chat** as the phase's subagent returns —
see SKILL.md → Progress Updates for the multi-repo format (run header, per-service
banner with counter, per-phase lines, synthesis line). If any phase is dispatched
as a background task, the `/workflows` pointer supplements these main-chat updates;
it does not replace them. The main chat must never go silent for the whole run.

## Step 8: Deliver

### Single-repo mode

**If `--output` was explicitly provided:**

Before copying, validate the destination path and confirm with the user:
```bash
# Reject paths under sensitive system directories
case "{output_dir}" in
  "$HOME"/.ssh*|"$HOME"/.aws*|"$HOME"/.gnupg*|/etc*|/usr*|/bin*|/sbin*|/boot*)
    echo "❌ --output path rejected: '{output_dir}' is under a sensitive directory."
    exit 1 ;;
esac
```
If `--yes` is NOT set, prompt:
```
📋 Copy report and PoC scripts to: {output_dir}
   Confirm? [Y/n]:
```
If declined, skip the copy step and print the report location inside `.security-review/`.

If `--yes` IS set, skip the prompt and proceed directly to the copy step.
Print: `📋 Copying report to {output_dir} (--yes)`

Copy report and PoC scripts into the output directory:
```bash
cp {repo_path}/.security-review/final-report.md "{output_dir}/final-report.md"
if [ -d "{repo_path}/.security-review/pocs" ] && \
   [ -n "$(ls -A {repo_path}/.security-review/pocs)" ]; then
  mkdir -p "{output_dir}/pocs"
  cp {repo_path}/.security-review/pocs/* "{output_dir}/pocs/"
fi
```

Print completion banner:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Security review complete
📄 Report:  {output_dir}/final-report.md
📁 PoCs:    {output_dir}/pocs/  (if any were generated)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Call `present_files` with `{output_dir}/final-report.md`.

**If `--output` was NOT provided:**

No copy is made. Print completion banner:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Security review complete
📄 Report:  {repo_path}/.security-review/final-report.md
📁 PoCs:    {repo_path}/.security-review/pocs/  (if any were generated)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Call `present_files` with `{repo_path}/.security-review/final-report.md`.

### Multi-repo mode

Copy each service's report into a subdirectory of `{output_dir}`:
```bash
for each repo in REPOS:
  SVC_NAME=$(basename {repo_path})
  mkdir -p "{output_dir}/{SVC_NAME}/pocs"
  cp {repo_path}/.security-review/final-report.md "{output_dir}/{SVC_NAME}/final-report.md"
  if [ -d "{repo_path}/.security-review/pocs" ] && \
     [ -n "$(ls -A {repo_path}/.security-review/pocs)" ]; then
    cp {repo_path}/.security-review/pocs/* "{output_dir}/{SVC_NAME}/pocs/"
  fi
done
# system-report.md and system-findings.json are already in {output_dir} (written by Phase 7)
```

Print completion banner:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Multi-repo security review complete
📋 System report:  {output_dir}/system-report.md
📄 Per-service reports:
   {output_dir}/{svc1}/final-report.md
   {output_dir}/{svc2}/final-report.md
   ...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Call `present_files` with `{output_dir}/system-report.md`.
