# Phase 7: Cross-Repo Security Synthesis

## Goal

Identify security vulnerabilities that are **only visible at the system level** —
issues that per-service analysis cannot surface because each service looks correct
in isolation, but the combination creates a vulnerability.

**This phase runs only in multi-repo mode, after all per-repo phases (1–6) have
completed for every repo in `--repos`.**

## Model

Use the resolved Deep tier model (`{deep_tier_model}`, normally `claude-opus-4-8`)
with `thinking: {type: "adaptive"}`. This phase requires multi-document,
cross-hypothesis reasoning: connecting separate per-service findings to identify
emergent vulnerabilities. Adaptive thinking is essential.

> `claude-fable-5` is intentionally excluded from the Deep chain — see SKILL.md →
> Fallback Chains.

## Inputs

Read the following files:

```
{output_dir}/service-topology.json          ← topology map from Phase 0

For each repo (substituting its actual path):
  {repo_path}/.security-review/phase1-secrets.json
  {repo_path}/.security-review/phase2-architecture.json
  {repo_path}/.security-review/phase4-owasp.json
  {repo_path}/.security-review/phase5-validated.json
```

If a per-repo file is absent (phase was skipped), note it in `coverage_notes`
and continue — do not abort.

**Report mode:** The orchestrator passes the `--verbose` flag to this phase, the
same as it does to Phase 6. It controls the structure of `system-report.md`
(see Output below). `system-findings.json` is unaffected — it is always written
in full so downstream tooling has complete data regardless of report mode.

**Vendor mode:** When `--vendor` is passed (multi-repo vendor audit), keep the
cross-service analysis unchanged but frame `system-report.md` for a security
team deciding on adoption: open with a one-paragraph **system-level adoption
verdict** (does this set of vendor services, taken together, introduce risk that
the per-repo reports miss — e.g. shared credentials, blind service-to-service
trust?), and replace per-finding `Remediation:` with `Mitigation available to
us:` (adopter-side compensating control, or `none — requires a vendor code
change`), mirroring Phase 6's vendor report. Do not invent secret/CVE findings —
those phases were skipped.

## Vulnerability Classes to Investigate

These are the cross-repo issues that per-service analysis cannot see. Work
through each class in order.

---

### Class 1: Shared Credential Exposure

A secret that appears in multiple repos is a single point of failure: if it
leaks in any one repo, every service sharing it is compromised.

**Look for:**
- Env var names from `service-topology.json → shared_env_vars` that appear in
  `phase1-secrets.json` findings for any repo
- The same env var name set to an actual value (not a placeholder) in multiple
  `.env.example` or config files
- A single signing key (`JWT_SECRET`, `HMAC_KEY`) used by both the issuer and
  all validators — rotation requires updating every service simultaneously

**Severity guide:** CRITICAL if `JWT_SECRET` or DB credentials appear in
`phase1-secrets.json` for any repo; HIGH for other shared secrets.

---

### Class 2: Trust Boundary Gaps (Service-to-Service Blind Trust)

An internal service that accepts calls with no authentication trusts any caller
on its network. If an attacker gains a foothold in any service, they can make
authenticated-looking calls to unprotected internal services.

**Look for:**
- `trust_boundary_gaps` in `service-topology.json` — these are already flagged
  by Phase 0; your job is to assess the actual impact:
  - What does the unprotected service expose? (read its Phase 2 and Phase 4 output)
  - Is the Phase 4 BOLA/SQLi/SSRF finding actually exploitable by an internal
    attacker who can reach the service directly?
  - Can an authenticated user escalate by crafting a direct call to an internal service?
- Missing `NetworkPolicy` or overly permissive policies in k8s manifests
- `auth_inbound: "none"` on a service whose Phase 2 architecture shows it handles
  sensitive operations (auth decisions, payment, user data mutation)

**Severity guide:** CRITICAL if the unprotected service makes security decisions
(auth validation, privilege checks); HIGH for services handling PII.

---

### Class 3: Auth Contract Mismatches

Service A issues tokens; Service B validates them — but they use different
assumptions. The token passes without error, but one side allows what the
other intended to block.

**Look for:**
- JWT issuer and validators: does each Phase 2 report describe the same signing
  algorithm and key type? If `auth-service` signs with RS256 but `user-service`
  calls `jwt.verify(token, symmetricKey)`, tokens may be accepted unsigned.
- Scope/claims validation: issuer includes a `role` claim; consumer never checks
  it — any token grants any role.
- Algorithm confusion: service accepts both RS256 and HS256 — attacker can forge
  tokens using the public key as the HMAC secret.
- Token expiry: issuer sets `exp: 1h`; consumer validates signature but ignores
  `exp` — revoked/expired tokens still work.

**Evidence to cite:** quote the relevant auth code from Phase 2 architecture
analysis for each service involved.

---

### Class 4: Cross-Service Data Flows Bypassing Defenses

User input enters at one service and is processed at another — but the consuming
service trusts internal traffic without re-validating.

**Look for:**
- Entry-point service validates input (e.g. strips `<script>` tags, parameterizes
  SQL); downstream service receives the data from an internal queue or RPC call
  and uses it without re-validation (stored XSS, second-order SQLi).
- PII flows from one service to another over an unencrypted internal connection
  (HTTP, not HTTPS, between services).
- A Phase 4 finding in an internal service whose attack vector requires data
  originating from user input at the entry-point service — confirming the full
  exploit chain.

**Severity guide:** elevate a MEDIUM internal finding to HIGH if you can trace
a complete attack path from the public entry point.

---

### Class 5: Inconsistent Security Posture

The same library, policy, or security control is applied differently across
services — creating a path that bypasses the control in the stricter service.

**Look for:**
- Same library, different versions: a patched CVE in one repo but vulnerable
  version still in another. Cross-reference `phase3-cves.json` package versions
  across repos.
- Rate limiting at the API gateway but none on a direct service endpoint that is
  reachable via a trust gap (Class 2 above).
- HTTPS enforced at the gateway; plain HTTP used for service-to-service communication
  on the same network where traffic could be intercepted.
- Secrets rotation: one service uses short-lived tokens; another uses the same
  credentials in a static config file.

---

## Output

Write two files:

### 1. `{output_dir}/system-findings.json`

```json
{
  "phase": "cross_repo_synthesis",
  "services_analyzed": ["api-gateway", "auth-service", "user-service"],
  "findings": [
    {
      "id": "SYS-001",
      "category": "trust_boundary_gap | shared_credential | auth_contract_mismatch | cross_service_data_flow | inconsistent_posture",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "title": "Short descriptive title",
      "services_involved": ["api-gateway", "auth-service"],
      "description": "What the issue is and why it is only visible cross-repo",
      "evidence": [
        {
          "service": "api-gateway",
          "source_file": "phase2-architecture.json",
          "detail": "auth_mechanism: none on POST /internal/validate"
        }
      ],
      "attack_scenario": "Step-by-step: how an attacker exploits this across services",
      "remediation": "Which service needs to change, and specifically how"
    }
  ],
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "coverage_notes": [
    "phase4-owasp.json absent for user-service (--skip owasp was used) — Class 4 analysis is incomplete for that service"
  ]
}
```

### 2. `{output_dir}/system-report.md`

The structure mirrors Phase 6's two report modes. Check the `--verbose` flag
passed by the orchestrator.

#### Default system report (no `--verbose`) — for dev / platform teams

**Goal**: give the team the systemic issues and what to do, with no meta-context.
Drop the model-disclosure line and the detailed coverage narrative.

```markdown
# System Security Report — {system_name}

**Services analyzed:** api-gateway · auth-service · user-service

---

## Executive Summary

{2–3 paragraphs: overall cross-service security posture, most critical systemic
issue, and the single most impactful remediation step}

---

## Critical Cross-Service Findings

### SYS-001 · {title}

| | |
|---|---|
| **Severity** | CRITICAL |
| **Category** | Trust Boundary Gap |
| **Services** | api-gateway → auth-service |

{description}

**Attack scenario:** {step-by-step scenario}

**Remediation:** {concrete fix: which service, what change, example if possible}

---

## All Cross-Service Findings

| ID | Severity | Category | Services | Title |
|----|---------|----------|---------|-------|
| SYS-001 | CRITICAL | Trust Boundary Gap | api-gateway → auth-service | ... |

---

## Per-Service Findings Summary

| Service | Secrets | CVEs | OWASP | Validated |
|---------|---------|------|-------|-----------|
| api-gateway | 0 HIGH | 2 (1 reachable) | 3 findings | 2 confirmed |
| auth-service | 1 HIGH | 0 | 1 finding | 1 confirmed |

*(Full details in each service's own report)*

---

## Coverage Gaps          ← omit this section entirely if nothing was skipped

{One line per service whose analysis was incomplete: which phase was skipped and
what that leaves unanalyzed. Keep it short — no topology/inference narrative.}
```

Rules (parallel to Phase 6 default mode):
- **No model-disclosure line** in the header.
- **Single severity** per finding — no base/contextual columns.
- **Coverage Gaps** section is included only when a per-repo file was absent or a
  phase was skipped; omit it entirely otherwise.

#### Verbose system report (`--verbose`) — for security team

Everything in the default report, plus:
- **Model-disclosure line** in the header: `**Model:** {deep_tier_model} (adaptive thinking)`
  {if a Deep-tier fallback was recorded in `run-metadata.json → fallback_notes`,
  append a one-line notice}
- Full **Coverage Notes** section (replacing Coverage Gaps): what topology
  information was available vs. inferred, what was not analyzed (e.g., runtime
  service mesh encryption, sidecar proxies), and every phase skipped for any
  service — always included, even when nothing was skipped.

## Quality Bar

Only report findings you can trace to concrete evidence. For each finding:
- Name the exact file and field in the per-service output that supports it
- Explain why the issue is **not** visible in per-service analysis alone
- Provide a realistic attack scenario (not theoretical)

Avoid re-reporting per-service findings that are already covered in individual
reports unless they are amplified by the cross-repo context.
