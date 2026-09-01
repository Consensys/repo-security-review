# Phase 7: Cross-Repo Security Synthesis

## Goal

Identify security vulnerabilities that are **only visible at the system level** —
issues that per-service analysis cannot surface because each service looks correct
in isolation, but the combination creates a vulnerability.

**This phase runs only in multi-repo mode, after all per-repo phases (1–6) have
completed for every repo in `--repos`.**

This phase has a second, distinct duty: resolving per-repo Phase 2
(architecture) findings that Phase 5 could not validate alone and explicitly
deferred here — see [Deferred Architecture Finding Validation](#deferred-architecture-finding-validation)
below. That is *resolution* of existing per-repo findings, not new discovery;
keep the two duties separate in your own reasoning and in the output.

## Model

Use the resolved Standard tier model (`{standard_tier_model}`) — the Sonnet
family, whichever concrete snapshot the account resolves. This phase moved
off the Deep tier so only Phase 2 (architecture) uses it — an explicit,
deliberate choice, not a fallback.

> `claude-fable-5` is intentionally excluded from both tiers' chains — see
> SKILL.md → Fallback Chains.

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

## Deferred Architecture Finding Validation

Distinct from the five vulnerability classes above: this is not new
discovery, it's *resolving* per-repo Phase 2 findings that Phase 5 could not
validate alone and deliberately deferred here (see
`phase5-validate-and-poc.md` → Step 0.5). Do this pass separately from Classes
1–5 — don't let it influence, or be influenced by, the cross-service findings
you're independently discovering there.

For each repo, collect every finding in that repo's `phase5-validated.json`
with `"validation_status": "PENDING_CROSS_REPO_VALIDATION"`.

For each deferred finding:
```
1. Read the underlying finding's full record from that repo's own
   phase2-architecture.json (match by original_id) — the claim, evidence,
   and file:line, since phase5-validated.json only carries a placeholder.

2. Use service-topology.json and every other repo's phase2-architecture.json
   / phase4-owasp.json — including any dedicated infrastructure-as-code or
   workload-manifest repo passed in --repos (Terraform, Helm, Kubernetes
   manifests, network policy / IAM definitions) — to check the specific
   claim that blocked single-repo validation: network reachability,
   IAM/trust policy scope, NetworkPolicy/security-group scope, or a sibling
   service's actual behavior.

3. Resolve to exactly one of:
   - CONFIRMED   — cross-repo evidence proves the claim. Cite the specific
     file in the other repo (e.g. "infra-repo/k8s/netpol.yaml:L12 has no
     rule permitting this traffic").
   - REJECTED    — cross-repo evidence disproves the claim (e.g. a
     NetworkPolicy actually does restrict the traffic the Phase 2 finding
     assumed was open).
   - NEEDS_REVIEW — still unresolved even with every repo's context (e.g.
     the controlling policy lives in a cloud-provider console or IAM
     configuration not represented in any scanned repo). verdict_reason
     must name exactly what's still missing.

4. A resolution must cite the specific new cross-repo evidence (file:line in
   the other repo, or the specific topology field) that changed the answer.
   Restating the original Phase 2 claim without new cross-repo evidence is
   not a resolution — leave it NEEDS_REVIEW instead.
```

> **Genericity**: this operates purely on structural fields
> (`validation_status`, `original_id`, `file`, `line`, topology fields) and
> generic categories of cross-repo evidence (network policy, IAM, sibling-
> service behavior) — never on anything specific to one repository's subject
> matter.

Write the resolution to `system-findings.json → deferred_architecture_validations`
(schema below) — never mix these into the `findings` array above; they are a
different kind of record (resolutions of existing per-repo findings, not new
system-level findings with their own `SYS-XXX` id).

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
  "deferred_architecture_validations": [
    {
      "repo": "user-service",
      "original_id": "A-011",
      "resolved_status": "REJECTED",
      "verdict_reason": "infra-repo/k8s/netpol.yaml:L18 restricts ingress on this port to the api-gateway service account only — the internal service is not reachable from arbitrary pods as the Phase 2 finding assumed.",
      "evidence": [
        {"repo": "infra-repo", "source_file": "k8s/netpol.yaml", "detail": "L18: podSelector restricts to app=api-gateway"}
      ]
    },
    {
      "repo": "user-service",
      "original_id": "A-009",
      "resolved_status": "NEEDS_REVIEW",
      "verdict_reason": "The claimed exposure depends on the cloud load balancer's listener configuration, which is not represented in any scanned repo — cannot confirm or reject from repo content alone.",
      "evidence": []
    }
  ],
  "coverage_notes": [
    "phase4-owasp.json absent for user-service (--skip owasp was used) — Class 4 analysis is incomplete for that service"
  ]
}
```

`deferred_architecture_validations` is present (possibly empty) whenever any
repo's `phase5-validated.json` had a `PENDING_CROSS_REPO_VALIDATION` finding —
omit the key entirely only if no repo had one. `resolved_status` is always one
of `CONFIRMED` / `REJECTED` / `NEEDS_REVIEW`, mirroring the report-tier
vocabulary the rest of the pipeline uses (`CONFIRMED` maps to Phase 6's
Confirmed tier, `REJECTED` to Rejected, `NEEDS_REVIEW` stays Needs Review —
the per-repo `final-report.md`, written before this phase ran, will still
show the old "pending" placeholder; this file and `system-report.md` are the
authoritative resolved source).

### 2. `{output_dir}/system-report.md`

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

## Deferred Architecture Findings — Resolved     ← omit entirely if deferred_architecture_validations is empty

{One row per entry in `deferred_architecture_validations`. Each per-repo
`final-report.md` still shows these as "pending cross-repo validation" — this
table is the resolved answer.}

| Repo | ID | Resolved | Reason |
|------|----|----------|--------|
| user-service | A-011 | REJECTED | `infra-repo/k8s/netpol.yaml:L18` restricts ingress to `api-gateway` only |
| user-service | A-009 | NEEDS_REVIEW | Depends on cloud load-balancer listener config, not represented in any scanned repo |

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
- **Deferred Architecture Findings — Resolved** is included only when
  `deferred_architecture_validations` is non-empty; omit entirely otherwise.

## Quality Bar

Only report findings you can trace to concrete evidence. For each finding:
- Name the exact file and field in the per-service output that supports it
- Explain why the issue is **not** visible in per-service analysis alone
- Provide a realistic attack scenario (not theoretical)

Avoid re-reporting per-service findings that are already covered in individual
reports unless they are amplified by the cross-repo context.

This bar applies equally to the Deferred Architecture Finding Validation duty:
a resolution needs the same concrete evidence citation as a new finding does —
naming the exact cross-repo file:line or topology field that answered the
question. "Still can't tell" is a legitimate outcome (`NEEDS_REVIEW`); an
unsupported guess is not.

## Final Response (chat output)

Your own closing message — separate from the orchestrator's one-line progress
update — is a channel that can leak findings into the chat if you're not
careful. Do not restate cross-service findings, attack scenarios, or a
narrative summary in your final response. Everything belongs in
`system-findings.json` and `system-report.md`. Your final message is one
line: confirm completion and the output paths, nothing else — e.g. `Phase 7
complete — wrote system-findings.json, system-report.md`.
