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
  --poc                 Opt-in: persist the constructed exploit for each
                        finding Phase 5 confirms as a durable script under
                        pocs/. Independent of --runtime — does not execute
                        anything by itself. Without this flag (the default),
                        no files are written under pocs/ even if --runtime
                        constructs and runs an exploit internally. Has no
                        effect in --pr mode; forced off in --vendor mode.
  --runtime             Opt-in: dynamically verify eligible findings
                        (including ones static analysis alone couldn't
                        resolve) by constructing the exploit and executing
                        it against the repo stood up in Docker. Tool is
                        chosen automatically per finding type — curl for
                        most types, a headless Chromium browser for
                        XSS/CSRF/clickjacking — no separate flag for that
                        choice. A clean result can strengthen or soften the
                        finding's verdict (never straight to rejected). No
                        longer implies --poc — the constructed exploit is
                        discarded after use unless --poc is also set.
  --yes                 Non-interactive / CI mode. Auto-confirms all prompts:
                        the --output copy gate, the Docker runtime gate, the
                        deployment-verification gate (--verify-deployment),
                        and the pure-skill-repo auto-skip cascade.
                        Path-validation safety checks (sensitive --output
                        destinations) are never bypassed. Requires a repo
                        path or --repos — aborts if neither is provided.
  --cost                Write a cost report to
                        <repo>/.security-review/cost-report.md: duration and
                        estimated token consumption for every phase that ran,
                        including named subphases (3b; Phase 5's Exploit
                        Construction/Dynamic Verification parts when
                        --poc/--runtime were set). Scoped strictly
                        to time/tokens — no file-read tables, coverage,
                        greps, or checks-run detail (renamed from --debug,
                        which used to include that). Paste it back for cost
                        analysis.
  --local               Opt-in: assert this is a local-only tool, not a
                        publicly reachable service. Softens severity by -2
                        tiers. Omit for the pessimistic default
                        (deployment_target: public). Writes
                        <repo>/.security-review/threat-model.json with
                        deployment_target and the hardcoded data_sensitivity
                        (always "pii", not user-facing). Replaced the old
                        --context key=value mechanism (which had shrunk to
                        this one enum-valued key, one of whose two values
                        was already the no-op default) and
                        auth_required_to_reach, which is not settable here
                        or anywhere via a declared claim — it's derived from
                        an actual live check, see --verify-deployment.
                        README is always read by Phase 2a for context,
                        regardless of --local.
  --verify-deployment <url>
                        Opt-in: send one live, passive HTTP GET to a real
                        deployment URL so Phase 5 derives auth_required_to_reach
                        from an actual observation (login/SSO redirect, 401/403,
                        WAF challenge) instead of a declared claim. Runs inside
                        Phase 5 (Step 0.4), gated behind an explicit
                        confirmation prompt before anything is sent (--yes
                        auto-confirms, same as the --runtime Docker gate).
                        If the HTTP-only check is inconclusive, automatically
                        escalates to a headless Chromium (Playwright) recheck
                        (no separate flag) — its own confirmation prompt
                        first. Requires playwright + Chromium for that
                        escalation (not auto-installed by setup.sh; falls
                        back to the HTTP-only result if unavailable).
                        Also runs a few cheap TLS/security-header posture
                        checks (HSTS/CSP/cookie flags, negotiated TLS
                        version+cipher, weak-protocol acceptance) written to
                        the same file under security_posture — corroborates
                        matching Phase 4 cookie-flag/weak-crypto findings,
                        not a Qualys-style grading pass.
                        Writes <repo>/.security-review/deployment-verification.json.
                        No effect in --pr mode or when validation is skipped.
                        Example:
                        --verify-deployment https://app.example.com
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

  architecture      Phase 2a + Phase 2 (skipping this alias skips both).
                    Phase 2a builds the tech-stack profile used by all
                    downstream phases (manifest/grep detection, Standard
                    tier). Phase 2 analyzes the codebase at design level:
                    trust boundaries, auth model, data flow, infra config,
                    missing security controls (Deep tier — most capable
                    available).

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
                        and --runtime then both have no effect
  --skip validation   → --poc and --runtime both have no effect (nothing to
                        construct an exploit for)
  --runtime           → independent of --poc now; constructs and executes
                        an exploit either way, but only persists it to
                        pocs/ if --poc is also set
  --skip architecture → skips both Phase 2a and Phase 2, and also skips
                        skill-security (skill detection requires
                        tech-stack.json from Phase 2a)
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

  # Full review with dynamic verification via Docker (exploit discarded after use;
  # add --poc to also keep it in pocs/)
  /repo-security-review ~/repos/my-service --runtime --output ~/reports/my-service

  # CI / headless — no interactive prompts, validation only (default: no PoC files)
  /repo-security-review . --output ./security-report --yes

  # CI — full review including PoC generation, auto-confirm all gates
  /repo-security-review . --output ./security-report --poc --yes

  # Get per-phase duration + token cost — writes cost-report.md to paste back
  /repo-security-review ~/repos/my-service --cost

  # Skip arch (you already reviewed it) — deps + OWASP only
  /repo-security-review ~/repos/my-service --skip architecture,secrets

  # Full review with severity calibrated to a local CLI tool
  /repo-security-review ~/repos/my-service --local

  # Full review, verifying the live deployment is actually auth-gated
  /repo-security-review ~/repos/my-service --verify-deployment https://my-service.example.com

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
- `--poc` → opt-in: persist the constructed exploit for each finding Phase 5
  confirms to `pocs/` as a durable script. Independent of `--runtime` — does
  not execute anything by itself. Without it (the default), no files are
  written under `pocs/` even if `--runtime` constructs and runs an exploit
  internally. Has no effect in `--pr` mode; forced off in `--vendor` mode.
- `--runtime` → opt-in: dynamically verify eligible findings (including ones
  static analysis alone couldn't resolve) against the repo stood up in
  Docker in Phase 5. Tool chosen automatically per finding type — curl for
  most, a headless Chromium browser for XSS/CSRF/clickjacking, no separate
  flag for that choice. A clean result can strengthen or soften the
  finding's verdict. No longer implies `--poc`.
- `--yes` → non-interactive mode: auto-confirm all user-facing prompts
  (the `--output` copy gate, the Docker runtime gate, the pure-skill-repo
  auto-skip cascade). Path-validation safety checks are never bypassed.
  If `--yes` is set and no repo path is provided, abort with:
  `❌ --yes requires a repo path or --repos — interactive input unavailable`
- `--cost` → write a cost report to `{repo_path}/.security-review/cost-report.md`.
  Passed to every phase that runs, each of which appends its own duration
  and estimated token consumption (multi-row for Phase 3 and Phase 5, which
  have named subphases). No file-read tables, coverage, greps, or
  checks-run detail — renamed from `--debug`, which used to include that.
  See SKILL.md → Cost Report for the format.
- `--local` → opt-in boolean: asserts this is a local-only tool, not a
  publicly reachable service. Softens severity by -2 tiers
  (`deployment_target: "local"` in `threat-model.json`). Omit for the
  pessimistic default (`"public"`). `data_sensitivity` is always hardcoded to
  `"pii"`, not user-facing. Replaced `--context`'s `key=value` mechanism —
  with only one real axis left (and one of its two values already the no-op
  default), the comma/key=value parser and its per-key rejection branches
  were pure overhead. `auth_required_to_reach` was never a candidate to move
  here either way — it's not a declared claim at all, it's derived from an
  actual live check; see `--verify-deployment`.
  README.md is always read by Phase 2a for context, regardless of `--local`.
  When set, the orchestrator writes `threat-model.json` to the working
  directory. When unset, the skill behaves exactly as before — no
  calibration logic runs anywhere.
- `--verify-deployment <url>` → opt-in: Phase 5 (Step 0.4) sends one live,
  passive HTTP GET to `<url>`, gated behind an explicit confirmation prompt
  (auto-confirmed by `--yes`, same as the Docker runtime gate). Classifies
  the result as `gated` / `waf_present` / `not_gated` / `inconclusive` and
  writes `deployment-verification.json`. `auth_required_to_reach` for
  Phase 5's Boundary Gate and severity Axis 2 is `true` only when this file
  exists and `classification == "gated"`. If the classification comes back
  `not_gated`/`inconclusive`, automatically escalates to a headless Chromium
  (Playwright) recheck — no separate flag, a client-side-rendered SPA login
  wall with no server redirect is invisible to `curl` by construction. The
  escalation gets its own confirmation prompt (auto-confirmed by `--yes`)
  and falls back to the `curl` result if Playwright is unavailable or the
  prompt is declined. No effect in `--pr` mode or when `validation` is
  skipped.

  Alongside the gating check, also runs a few cheap TLS/security-header
  posture probes (HSTS/CSP/cookie flags off the same response headers;
  HTTPS enforcement, negotiated TLS version+cipher, weak-protocol
  acceptance as a few extra handshakes) written into
  `deployment-verification.json` under `security_posture`. This never
  affects `classification`/`auth_required_to_reach` — it's a separate,
  independent enrichment Phase 5 uses only to corroborate matching Phase 4
  cookie-flag/weak-crypto findings (Step 3), not a Qualys-style grading pass
  and not a source of new standalone findings.

  The same automatic browser choice applies to `--runtime`'s dynamic
  verification for XSS/CSRF/clickjacking findings (Part 3) — a `curl`-based
  check can prove reflection but not actual execution/rendering. Both
  escalation points use an ephemeral, headless, origin-scoped browser
  context every time; it never persists across findings or across a run.
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
- `--skip owasp` → add `validation` to skip list; `--poc`/`--runtime` then both have no effect
- `--skip validation` → `--poc`/`--runtime` both have no effect (nothing to construct an exploit for)
- `--runtime` without `--poc` → construct and execute the exploit normally, but discard it after use instead of persisting to `pocs/`
- `--poc` not set, `--runtime` not set → pass neither flag to Phase 5; it validates every finding, constructs nothing, writes no PoC files
- `--skip architecture` → also skip Phase 2a and add `skill-security` to skip list (skill detection requires Phase 2a's output)

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
[ -n "$VERIFY_DEPLOYMENT_URL" ] && \
  { which curl && curl --version | head -1 || echo "⚠️  curl not found (--verify-deployment disabled)"; }
[ -n "$VERIFY_DEPLOYMENT_URL" -o "$RUNTIME" = true ] && \
  { python3 -c "import playwright" 2>/dev/null && echo "✅ playwright installed (used automatically when a browser check is needed)" \
    || echo "ℹ️  playwright not found — browser-based checks will fall back to curl-only (pip3 install playwright && playwright install chromium to enable)"; }
```

## Step 6: Create working directories

**Single-repo mode:**
```bash
mkdir -p {repo_path}/.security-review
[ -n "{output_dir}" ] && mkdir -p "{output_dir}"
# When --cost is set, create an empty cost report for every phase to append to
[ "$COST" = true ] && : > {repo_path}/.security-review/cost-report.md
```

**Multi-repo mode:**
```bash
mkdir -p "{output_dir}"
# Phase 0 + Phase 7 are system-level — their cost-report.md lives at output_dir
[ "$COST" = true ] && : > "{output_dir}/cost-report.md"
for each repo in REPOS:
  mkdir -p "{repo_path}/.security-review"
  [ "$COST" = true ] && : > "{repo_path}/.security-review/cost-report.md"
done
```

## Step 7: Execute phases

Read SKILL.md for full phase instructions. Execute each non-skipped phase as an
isolated subagent, passing only file paths (never in-memory content) between phases.

**Single-repo mode:**

```
Run Phase 1.
Run Phase 2a (writes tech-stack.json).
Run Phase 2 (reads tech-stack.json from Phase 2a).

After Phase 2a: read tech-stack.json.
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
    Run Phase 5 (unless skipped) — passes --poc, --runtime,
      --verify-deployment's URL, and the --yes flag if set; Phase 5's own
      Step 0.4 handles the confirmation gate and the live check (with
      automatic browser escalation if the HTTP-only result is inconclusive)
      before its per-finding loop begins, and Part 3 handles dynamic
      verification for confirmed/NEEDS_RUNTIME findings when --runtime is
      set — automatically using a headless browser instead of curl for
      XSS/CSRF/clickjacking findings, with no separate flag to check.
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
