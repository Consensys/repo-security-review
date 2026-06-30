# Phase 4b: LLM / AI Skill Security Analysis

## Goal

Analyse the AI skill and agent instruction files in this repository against
the OWASP LLM Top 10. The attack surface here is **not traditional code** —
it is the set of instructions that shape agent behaviour, the data flows
between agents, and the tool grants each agent holds.

Operate with an adversarial mindset: assume the skill files were written by
an attacker and trace how malicious repo content, user-supplied arguments, or
tool output could hijack, redirect, or exfiltrate data from the agent pipeline.

## When this phase runs

Auto-activated by the orchestrator when Phase 2 writes `has_skill_files: true`
in `tech-stack.json`. The orchestrator reads that flag after Phase 2 completes
and spawns this phase only when it is set.

## Model Guidance

**Use `claude-fable-5` with `thinking: {type: "adaptive"}`.**

This phase requires deep multi-hop reasoning: following data flows through
instruction chains, identifying subtle injection vectors, and reasoning about
permission boundary violations. Do not use Sonnet for this phase.

## Inputs

Read all files listed under `skill_files` in `tech-stack.json`:
```
{repo_path}/.security-review/tech-stack.json       ← skill_files list
{repo_path}/.security-review/phase2-architecture.json  ← architecture context
```

Read each file path in `tech-stack.json → skill_files` in full.

## Output

Write to `{repo_path}/.security-review/phase-llm-security.json`.

Finding IDs use the prefix `L-` (e.g. `L-001`, `L-002`).

---

## Analysis Framework: OWASP LLM Top 10

Work through each check below in order. For every finding, trace the complete
data-flow path: **source** (where untrusted data enters) → **transformation**
(how it is processed or passed) → **sink** (where it influences agent behaviour
or system state). A finding without a traceable, concrete path is a false
positive.

---

### LLM01 — Prompt Injection

Does any phase instruction pass unsanitized external content directly into
an agent prompt?

Check for:
- Instructions that read files from the **target repo** and interpolate their
  content directly into a prompt without marking it as untrusted (e.g.
  `"read README.md and use it as context"` with no sanitization boundary)
- User-supplied arguments (`--context` values, `--output` path, repo path
  itself) that flow into agent prompts as interpolated strings
- Tool output (Bash stdout, file read results) passed directly as context to
  the next agent without a trust boundary — the agent has no way to distinguish
  instructions from data
- Phase instructions that give the agent a persona derived from the target repo
  (e.g. "act as this repo's lead developer") — a malicious `CLAUDE.md` or
  `README.md` in the target could then redefine the persona
- Instructions that chain phases by embedding one phase's full output text into
  the next phase's prompt (rather than passing a file path)

Severity guide:
| Outcome | Severity |
|---------|----------|
| Agent writes files, runs bash, or exfiltrates data to attacker-controlled location | CRITICAL |
| Agent suppresses real findings or fabricates false ones | HIGH |
| Agent alters report content, wording, or severity ratings | MEDIUM |
| Agent affects only benign output fields (formatting, labels) | LOW |

---

### LLM02 — Insecure Output Handling

Is agent output written to files or passed downstream without sanitization?

Check for:
- Phase output files (JSON, Markdown) that embed strings read from the target
  repo without escaping — a file named `"><script>alert(1)</script>.py` or
  a config value containing `## New Heading` could corrupt `final-report.md`
- Report builder instructions that render repo-sourced strings (file names,
  variable names, config values, commit messages) directly as markdown headings,
  links, or code blocks without noting that they are untrusted data
- PoC scripts that include live secret values rather than placeholder strings
  (the PoC file itself is an output that may be shared)

---

### LLM05 — Supply Chain Vulnerabilities

Does the skill depend on external resources that could be compromised?

Check for:
- Hard-coded model ID strings that are stale or reference deprecated model
  versions — a drift here silently downgrades analysis quality
- External URLs embedded in instructions (API endpoints, script download
  locations, enrichment sources) that are not under the skill owner's control
  and could be hijacked or go stale
- MCP server or tool references without pinned versions or integrity checks
- CLI tools invoked by bare name (`gitleaks`, `semgrep`) without path pinning —
  susceptible to PATH hijacking in a CI environment

---

### LLM06 — Sensitive Information Disclosure

Do phase instructions cause secrets, credentials, or PII to flow further than
necessary?

Check for:
- Phase 1 (secrets) passing **raw** secret values — not just redacted references
  — into downstream phase prompts or JSON outputs
- Progress output instructions that print full secret values during execution
  (the user's terminal is not a safe log destination for live credentials)
- Phase 6 instructions around secret redaction — is the "first 4 / last 3 chars"
  rule enforced in **all** output paths, including verbose mode and PoC files?
- Instructions that include the `--context` threat model values (deployment
  target, auth flags) in agent prompts in ways that could be read back by a
  malicious repo (information about the deployment environment is itself
  sensitive)

---

### LLM07 — Insecure Plugin / Tool Design

Are tool grants broader than each phase actually requires?

Check for:
- Phases that have Bash access but only need read-only file operations — does
  the instruction explicitly constrain the scope of Bash usage, or leave it open
  to any command?
- `WebFetch` / `WebSearch` calls driven by URLs that come from the target repo
  (e.g. fetching a URL found in `package.json` or a config file) without
  domain allow-listing
- Write/Edit access in phases whose sole output should be a JSON file — can
  the phase be coerced into modifying the target repo's files?
- Instructions that allow an agent to call `present_files`, run `git push`,
  send messages, or take other out-of-scope actions that are not revocable
- Missing confirmation gates before irreversible actions (the `--output` copy
  step, Docker container creation, external API calls)

---

### LLM08 — Excessive Agency

Can any agent take broader action than required for its narrow, stated task?

Check for:
- Phases that could, if prompted adversarially via injected repo content, modify
  the target repo's files rather than just reading them
- Instructions that allow a subagent to decide which phases to skip, add, or
  re-run — sequencing decisions must belong to the orchestrator, not subagents
- Absence of explicit scope constraints in phase prompts: e.g. no statement that
  the agent should only read from `{repo_path}` and only write to
  `{repo_path}/.security-review/`
- Unbounded tool-use loops: can a phase instruction lead to recursive or
  indefinitely repeating agent calls without a natural termination condition?
- Phase instructions that pass the user's full `$ARGUMENTS` string to a
  subagent — this gives the subagent visibility into flags (like `--output`) it
  should not act on

---

## Output Format

```json
{
  "phase": "llm_security",
  "skill_files_analyzed": [
    "SKILL.md",
    ".claude/commands/repo-security-review.md",
    "references/phase1-secrets.md"
  ],
  "summary": {
    "total": 3,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0
  },
  "findings": [
    {
      "id": "L-001",
      "owasp_llm": "LLM01",
      "category": "prompt_injection | insecure_output | sensitive_disclosure | insecure_plugin | excessive_agency | supply_chain",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "title": "Short descriptive title",
      "description": "What the vulnerability is and why it matters",
      "data_flow": "Source (file:line) → transformation → sink (file:line) — be concrete",
      "impact": "What an attacker can achieve if this is exploited",
      "remediation": "Specific, actionable fix",
      "evidence": [
        "SKILL.md:L45-L52",
        "references/phase2-architecture.md:L23"
      ],
      "poc_needed": false
    }
  ],
  "false_positives": [
    {
      "id": "L-FP-001",
      "title": "Short title",
      "reason": "Why this was investigated and ruled out"
    }
  ]
}
```

**`poc_needed` is always `false`** — these are instruction-level issues, not
runtime exploits. Phase 5 validation and PoC generation do not run for
LLM security findings.

When writing `evidence`, always cite the specific instruction sentence or
passage, not just the file name. The reader needs the exact location to fix.

---

```bash
echo "✅ Phase 4b complete — LLM security analysis written to {repo_path}/.security-review/phase-llm-security.json"
```
