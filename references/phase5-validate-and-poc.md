# Phase 5: Validation + PoC Agent

## Context Isolation — Read This First

You are the **judgment layer**. You receive candidate findings from Phase 4
(the finder) and your job has two sequential parts:

1. **Validate** each finding independently — challenge it, try to disprove it
2. **Write a PoC** immediately for any finding that passes — while your
   validation reasoning is still in context

You must be isolated from Phase 2 and Phase 4's agent context. You receive:
- This reference file
- The path to `phase4-owasp.json` (you read it yourself)
- The repo path to re-examine code independently
- The `--runtime` flag (if set)
- `tech-stack.json` path (includes `runtime_hints` used for Dockerfile synthesis)

Re-read the relevant source code from scratch for each finding. Do not
assume Phase 4 was correct. Your validation must be independent.

**The PoC gate is structural**: you only write a PoC immediately after a
finding passes validation within the same reasoning chain. A finding that
fails validation gets no PoC — ever. There is no separate step where PoCs
are generated for unvalidated findings.

---

## Workflow Per Finding

For each finding in `phase4-owasp.json`, execute this sequence in full
before moving to the next finding:

```
1. VALIDATE → 2. DECISION → 3. POC (only if confirmed) → 4. WRITE OUTPUTS
```

Never batch-validate all findings first and then batch-write PoCs. Process
one finding end-to-end at a time.

---

## Part 1: Validation

### Step 1: Reproduce the data flow independently

Re-read the source file(s) referenced in the Phase 4 finding. Trace from
scratch:
- Where does untrusted input enter the application?
- What transformations happen along the path?
- Does it reach the sink without sufficient sanitization?

If you cannot trace a complete, unbroken source → sink path: **FALSE_POSITIVE**.

### Step 2: Hunt for mitigations Phase 4 may have missed

Actively look for controls that would neutralize the vulnerability:
- Input validation / sanitization before the sink
- Parameterized queries (SQL injection)
- Output encoding (XSS)
- Ownership checks (BOLA/IDOR) — read the full controller AND any service
  methods it calls AND any global middleware
- Framework-level protections (ORM auto-escaping, template auto-escaping)
- Decorator/annotation-based auth applied at the route or class level

A mitigation on some paths but not all = valid finding for the unprotected
paths. Note which paths are unprotected.

### Step 3: Type-specific verification

- **SQL injection**: confirm the query uses string concatenation or unsafe
  ORM calls (`raw()`, `execute()`), not parameterized placeholders
- **XSS**: confirm output context (HTML body / attribute / JS) and that no
  encoding is applied at the output point
- **BOLA/IDOR**: confirm there is NO ownership check in the full controller
  method, its called service methods, and any applied middleware
- **Command injection**: confirm user input reaches `exec`/`spawn`/`system`
  without sanitization
- **SSRF**: confirm the URL is user-controlled and there is no allowlist

### Step 4: Assess exploitability

- Reachable without special privileges?
- Requires chaining with another vulnerability?
- WAF or infra controls present? (Flag but do not use as mitigation — code
  is the required control)

### Validation Decision

After the above steps, assign one of:

| Status | Meaning | Next step |
|--------|---------|-----------|
| `CONFIRMED` | True positive, high confidence | Write PoC now |
| `CONFIRMED_LOW_CONFIDENCE` | Real but exploitability uncertain | Write PoC, flag confidence |
| `FALSE_POSITIVE` | Not exploitable or mitigated | Record reason, no PoC |
| `NEEDS_RUNTIME` | Cannot confirm statically | Attempt runtime probe if `--runtime`, else no PoC |

---

## Part 2: PoC Generation (CONFIRMED and CONFIRMED_LOW_CONFIDENCE only)

Write the PoC immediately after the validation decision, while you still
have the full data flow context in mind. Use real values from the codebase —
actual endpoint paths, parameter names, HTTP methods, field names. No
unfilled placeholders.

### SQL Injection PoC

```python
#!/usr/bin/env python3
"""
PoC: SQL Injection
Finding ID: {id} | File: {file}:{line} | Severity: {severity}
"""
import requests

BASE_URL = "http://localhost:3000"  # adjust to target
TOKEN = "YOUR_AUTH_TOKEN"           # any valid low-privilege token

# Vulnerable code found at {file}:{line}:
#   {vulnerable_code_snippet}
payload = "' OR '1'='1"  # tune to match the specific query structure

resp = requests.get(
    f"{BASE_URL}{endpoint_path}",
    params={"{param_name}": payload},
    headers={"Authorization": f"Bearer {TOKEN}"}
)
print(f"Status: {resp.status_code}")
print(f"Response preview: {resp.text[:500]}")
# Success: unexpected rows / other users' data in response
```

### XSS PoC

```python
#!/usr/bin/env python3
"""PoC: XSS | Finding: {id} | Context: {html_body|attribute|js}"""
import requests

BASE_URL = "http://localhost:3000"
PAYLOADS = {
    "html_body":  "<script>alert(document.domain)</script>",
    "attribute":  "\" onmouseover=\"alert(document.domain)",
    "js_context": "';alert(document.domain)//"
}

payload = PAYLOADS["{context_type}"]
resp = requests.get(
    f"{BASE_URL}{endpoint_path}",
    params={"{param_name}": payload}
)
print("Payload reflected:", payload in resp.text)
```

### BOLA / IDOR PoC

```python
#!/usr/bin/env python3
"""
PoC: BOLA/IDOR | Finding: {id}
User A accesses User B's {resource_type} using their own token.
"""
import requests

BASE_URL = "http://localhost:3000"

# Authenticate as low-privilege User A
token_a = requests.post(f"{BASE_URL}/api/auth/login",
    json={"email": "usera@test.com", "password": "password123"}
).json()["token"]

# Baseline: User A accesses own resource (expect 200)
own = requests.get(
    f"{BASE_URL}{endpoint_path}".replace("{id_param}", "{user_a_id}"),
    headers={"Authorization": f"Bearer {token_a}"}
)
print(f"Own resource (expect 200): {own.status_code}")

# Attack: User A accesses User B's resource (expect 403, will get 200)
other = requests.get(
    f"{BASE_URL}{endpoint_path}".replace("{id_param}", "{user_b_id}"),
    headers={"Authorization": f"Bearer {token_a}"}
)
print(f"Other user's resource (expect 403, got): {other.status_code}")
if other.status_code == 200:
    print("✅ BOLA CONFIRMED")
    print(f"Leaked: {other.text[:300]}")
```

### Command Injection PoC

```python
#!/usr/bin/env python3
"""PoC: Command Injection | Finding: {id}"""
import requests, time

BASE_URL = "http://localhost:3000"
TOKEN = "YOUR_AUTH_TOKEN"

for payload in ["; id", "| id", "; sleep 5", "$(id)"]:
    start = time.time()
    resp = requests.post(
        f"{BASE_URL}{endpoint_path}",
        json={"{param_name}": f"normal_input{payload}"},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=10
    )
    elapsed = time.time() - start
    print(f"{payload!r} → {resp.status_code} ({elapsed:.1f}s)")
    if elapsed > 4.5:
        print("✅ BLIND COMMAND INJECTION CONFIRMED via time delay")
```

### SSRF PoC

```python
#!/usr/bin/env python3
"""PoC: SSRF | Finding: {id}"""
import requests

BASE_URL = "http://localhost:3000"
TOKEN = "YOUR_AUTH_TOKEN"

for url in [
    "http://169.254.169.254/latest/meta-data/",          # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/", # GCP metadata
    "http://localhost:8080",                               # Internal service
    "http://127.0.0.1:5432",                              # Internal DB
]:
    resp = requests.post(
        f"{BASE_URL}{endpoint_path}",
        json={"{url_param}": url},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=5
    )
    print(f"{url} → {resp.status_code} | {resp.text[:200]}")
```

---

## Part 3: Optional Runtime Validation (if `--runtime` flag set)

After writing the PoC script, execute it against a live Docker instance
to confirm exploitability at runtime.

### Check Docker availability
```bash
docker --version && docker compose version || echo "Docker not available"
```

If unavailable, mark `runtime_status: RUNTIME_SKIPPED` and continue.

### Decision tree — how to stand up the application

```
1. docker_compose_path in tech-stack.json points to an existing file  → use it
2. docker-compose.yml or docker-compose.yaml exists at repo root       → use it
3. Dockerfile exists at repo root                                      → docker build + run
4. None of the above                                                   → SYNTHESIZE (see Part 3a)
5. Synthesis declines or fails                                         → RUNTIME_SKIPPED
```

### Use the project's Docker setup (cases 1–3)

```bash
TS={repo_path}/.security-review/tech-stack.json

# Resolve compose file: prefer path recorded by Phase 2, fall back to root defaults
COMPOSE_PATH=$(jq -r '.docker_compose_path // empty' $TS)
if [ -n "$COMPOSE_PATH" ] && [ -f "{repo_path}/$COMPOSE_PATH" ]; then
  COMPOSE_FILE="{repo_path}/$COMPOSE_PATH"
elif [ -f "{repo_path}/docker-compose.yml" ]; then
  COMPOSE_FILE="{repo_path}/docker-compose.yml"
elif [ -f "{repo_path}/docker-compose.yaml" ]; then
  COMPOSE_FILE="{repo_path}/docker-compose.yaml"
else
  COMPOSE_FILE=""
fi

if [ -n "$COMPOSE_FILE" ]; then
  docker compose -f "$COMPOSE_FILE" up -d --build 2>&1 \
    | tee {repo_path}/.security-review/docker-startup.log
  RUNTIME_ENV="project"
elif [ -f "{repo_path}/Dockerfile" ]; then
  PORT=$(jq -r '.runtime_hints.listen_port // 8080' $TS)
  docker build -t sec-review-target {repo_path} && \
  docker run -d --name sec-review-target -p ${PORT}:${PORT} sec-review-target
  RUNTIME_ENV="project"
else
  # No Docker setup found — go to Part 3a
  :
fi
```

### Readiness probe (apply after any startup path)

The project may not expose `/health`. Probe in order — mark ready on the
first response (even a 404 confirms the server is listening).

```bash
PORT=$(jq -r '.runtime_hints.listen_port // 8080' {repo_path}/.security-review/tech-stack.json)
for i in $(seq 1 12); do
  sleep 5
  for ep in /health /healthz /; do
    curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PORT}${ep}" 2>/dev/null && \
      echo "Ready on ${ep}" && break 2
  done
  # Fallback: bare TCP connect
  (echo > /dev/tcp/localhost/${PORT}) 2>/dev/null && echo "TCP ready" && break
  echo "Waiting... $i/12"
done
```

### Run the PoC script
```bash
python3 {repo_path}/.security-review/pocs/poc_{id}_{type}.py 2>&1
```

Record outcome as `RUNTIME_CONFIRMED`, `RUNTIME_NOT_CONFIRMED`, or
`RUNTIME_ERROR`.

### Tear down
```bash
# Use the same $COMPOSE_FILE resolved during startup
if [ -n "$COMPOSE_FILE" ]; then
  docker compose -f "$COMPOSE_FILE" down 2>/dev/null
else
  (docker stop sec-review-target && docker rm sec-review-target) 2>/dev/null
fi
# If synthesis was used, also tear down the synthesized stack
if [ -d "{repo_path}/.security-review/synthesized" ]; then
  (cd {repo_path}/.security-review/synthesized && docker compose down) 2>/dev/null
fi
```

---

## Part 3a: Dockerfile Synthesis (fallback when no project Docker setup exists)

Only attempted when `--runtime` is set AND no `Dockerfile` / `docker-compose.yml`
is present in the repo. The synthesized files are written to
`{repo_path}/.security-review/synthesized/` and persist after the run so
the user can re-run the validation later.

### Step 1: Load runtime hints

```bash
TS={repo_path}/.security-review/tech-stack.json
LANG=$(jq -r '.languages[0] // "unknown"' $TS)
FRAMEWORK=$(jq -r '.frameworks[0] // "none"' $TS)
ENTRY=$(jq -r '.runtime_hints.entry_point // ""' $TS)
PORT=$(jq -r '.runtime_hints.listen_port // 0' $TS)
HAS_DB=$(jq -r '.has_database // false' $TS)
DBS=$(jq -r '.database_types[]?' $TS)
```

If `entry_point` or `listen_port` is missing, re-run the heuristics from
[phase2-architecture.md](phase2-architecture.md) "Runtime hints" block.
Use framework defaults if still unknown:
Flask 5000, Django 8000, FastAPI/Uvicorn 8000, Express 3000, Rails 3000.

### Step 2: Decide whether to synthesize

| Condition | Action |
|---|---|
| `(language, framework)` matches a template below | Proceed |
| Stack not in template table | `RUNTIME_SKIPPED` · reason `unsupported_stack_for_synthesis` |
| `has_database: true` with single supported DB (postgres/mysql/mongodb/redis) | Synthesize compose with DB sidecar |
| `has_database: true` with multiple DBs or exotic services (Elasticsearch, Kafka, custom) | `RUNTIME_SKIPPED` · reason `multi_service_dependency_not_synthesizable` |

### Step 3: Template lookup

Pick the matching template, fill in `{entry}`, `{port}`, lockfile path,
and the install command derived from `package_files`.

| Stack | Base image | Install | CMD |
|---|---|---|---|
| python + flask | `python:3.11-slim` | `pip install --no-cache-dir -r requirements.txt` | `python {entry}` |
| python + fastapi | `python:3.11-slim` | same | `uvicorn {module}:app --host 0.0.0.0 --port {port}` |
| python + django | `python:3.11-slim` | same + `python manage.py migrate --noinput` | `python manage.py runserver 0.0.0.0:{port}` |
| node + express / generic | `node:20-slim` | `npm ci --omit=dev` (fallback `npm install`) | `npm start` or `node {entry}` |
| node + next | `node:20-slim` | `npm ci && npm run build` | `npm start` |
| go + (any) | `golang:1.22` | `go build -o /app .` | `/app` |
| ruby + rails | `ruby:3.3-slim` | `bundle install` | `rails server -b 0.0.0.0 -p {port}` |

For Python/FastAPI, `{module}` is `entry_point` without the `.py` extension.

### Step 4: Write `synthesized/Dockerfile`

Example for `(python, flask)`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE {port}
CMD ["python", "{entry}"]
```

### Step 5: If `has_database: true`, write `synthesized/docker-compose.yml`

Pick the image and standard connection env vars based on the first matching DB:

| DB | Image | Env var name | Standard value |
|---|---|---|---|
| postgresql | `postgres:15-alpine` | `DATABASE_URL` | `postgresql://postgres:postgres@db:5432/app` |
| mysql | `mysql:8` | `DATABASE_URL` | `mysql://root:root@db:3306/app` |
| mongodb | `mongo:7` | `MONGO_URL` | `mongodb://db:27017/app` |
| redis | `redis:7-alpine` | `REDIS_URL` | `redis://db:6379` |

Compose skeleton:

```yaml
services:
  app:
    build:
      context: {repo_path}
      dockerfile: {repo_path}/.security-review/synthesized/Dockerfile
    ports: ["{port}:{port}"]
    environment:
      - {ENV_VAR_NAME}={standard_value}
    depends_on:
      db: { condition: service_healthy }
  db:
    image: {db_image}
    healthcheck:
      test: [{db_specific_check}]
      interval: 5s
      retries: 12
```

`context: {repo_path}` makes `COPY . /app` in the Dockerfile pick up the full repo
source. `dockerfile:` points to the synthesized file without touching the repo root.

### Step 6: Bring it up

```bash
SYN={repo_path}/.security-review/synthesized
cd $SYN
docker compose up -d --build 2>&1 | tee $SYN/startup.log
RUNTIME_ENV="synthesized"
```

Then apply the readiness probe from Part 3. If the probe fails within 60s,
capture `docker compose logs --tail=20` to `$SYN/startup.log` and mark
`RUNTIME_SYNTHESIS_FAILED`.

### Step 7: Write `synthesized/synthesis-notes.md`

Brief markdown noting:
- Template chosen and why (`stack`, `entry_point`, `listen_port`)
- DB sidecar added (if any) and the connection env vars used
- Any heuristics that fell back to defaults
- Re-run instructions: `cd synthesized/ && docker compose up`

### Step 8: Honest reporting of synthesis limits

The synthesized environment comes up empty — no migrations beyond what the
Dockerfile runs, no seed users, no fixtures. PoCs that need pre-existing
state (BOLA needs `usera@test.com`, broken-auth tests need a registered
account) will fail at their setup step.

If the PoC's setup step (e.g. login) returns a non-2xx, record
`RUNTIME_SKIPPED` with reason `missing_seed_data` and the note:
`"synthesized environment has no seeded data — PoC requires a test
user/record that does not exist in the empty DB"`.

Do **not** record `RUNTIME_NOT_CONFIRMED` for this case. That status means
the PoC ran and did not trigger the vulnerability — a meaningful safety
signal. A setup failure means the PoC never executed at all, which is not
evidence of safety and must not be presented as such.

---

## Part 3b: Failure mode reference

Every runtime path must terminate in one of these statuses. Never silently
swallow a failure.

| Status | Trigger | Required notes |
|---|---|---|
| `RUNTIME_CONFIRMED` | PoC ran, success indicator observed | — |
| `RUNTIME_NOT_CONFIRMED` | PoC ran fully, success indicator not observed | This is a safety signal — only use when the PoC actually executed |
| `RUNTIME_SKIPPED` | Docker unavailable / stack unsupported / multi-service deps / PoC setup step failed (`missing_seed_data`) | Reason code required; `missing_seed_data` must note that the vulnerability was not tested, not ruled out |
| `RUNTIME_SYNTHESIS_FAILED` | Synthesis attempted but build / startup failed | Last 20 lines of `docker compose logs` |
| `RUNTIME_ERROR` | Unexpected failure during PoC execution | Exception or exit code |

---

## Part 4: Contextual Severity Calibration (only if `threat-model.json` exists)

Skip this section entirely if `{repo_path}/.security-review/threat-model.json`
does not exist. When the file is absent, Phase 5 emits `severity` as it always
has and no calibration columns appear anywhere.

When the file is present, every confirmed finding gets **two** severity values:

- `cvss_base_severity` — the technical severity assuming worst-case exposure.
  This is what Phase 4 already produces. Copy it through unchanged.
- `contextual_severity` — the same finding's severity after applying the
  threat-model softeners below.

**Invariant: `contextual_severity` is never higher than `cvss_base_severity`.**
Context softens; it never sharpens.

### Step 1: Load the effective threat model

Check whether `{repo_path}/.security-review/threat-model.json` exists.
If it does **not** exist, skip Steps 2–4 of Part 4 entirely and proceed
directly to writing output. Do not exit Phase 5.

If it exists, read the effective values (drift overrides take precedence):

```bash
TM={repo_path}/.security-review/threat-model.json

# Apply drift overrides if Phase 2 wrote any — these revert specific
# dimensions to the strict default for this run.
DEPLOY=$(jq -r '.drift_overrides.deployment_target // .deployment_target' $TM)
DATA=$(jq -r '.drift_overrides.data_sensitivity // .data_sensitivity' $TM)
AUTH=$(jq -r '.drift_overrides.auth_required_to_reach // .auth_required_to_reach' $TM)
```

### Step 2: Apply axis softeners

Each axis subtracts severity tiers independently. Tiers, low to high:
`LOW` → `MEDIUM` → `HIGH` → `CRITICAL`.

Floor: nothing drops below `LOW`. Ceiling: never above `cvss_base_severity`.

#### Axis 1: `deployment_target`

| Value | Effect | Applies to |
|---|---|---|
| `public_service` | no change | all findings |
| `internal_tool` | −1 tier | all findings |
| `local_cli` | −2 tiers | all findings |

#### Axis 2: `data_sensitivity` (only for data-exposure findings)

Data-exposure findings include: SQL/NoSQL injection, IDOR/BOLA, information
disclosure, sensitive data in logs, mass assignment, broken object-property
authorization. Does NOT apply to: command injection, SSRF (unless leaking
metadata), authentication bypass for actions other than data read.

| Value | Effect on data-exposure findings |
|---|---|
| `pii` | no change |
| `internal` | no change |
| `none` | −1 tier |

#### Axis 3: `auth_required_to_reach` (only for pre-auth findings)

Pre-auth findings are those exploitable without first authenticating to the
service. Phase 4 should flag this; if unclear, check the data flow notes from
Step 1 of validation.

| Value | Effect on pre-auth findings |
|---|---|
| `false` | no change |
| `true` | −1 tier |

#### Composition

Softeners stack. Example: a CRITICAL pre-auth SQLi against PII columns, on a
`local_cli` (−2) with `auth_required_to_reach: true` (−1, pre-auth) and
`data_sensitivity: none` (would be −1, but this is a data-exposure finding,
so it applies) = CRITICAL − 4 tiers → LOW (clamped at floor).

### Step 3: Record the adjustment per finding

For each finding, capture WHY the severity changed so the report is auditable:

```json
{
  "original_id": "O-001",
  "cvss_base_severity": "CRITICAL",
  "contextual_severity": "MEDIUM",
  "severity_adjustment": {
    "applied": true,
    "softeners": [
      {"axis": "deployment_target", "value": "internal_tool", "delta_tiers": -1},
      {"axis": "auth_required_to_reach", "value": true, "delta_tiers": -1, "reason": "pre-auth finding gated by login"}
    ],
    "drift_overrides_applied": []
  }
}
```

When no threat model exists, omit `cvss_base_severity`, `contextual_severity`,
and `severity_adjustment` entirely — emit only the unchanged `severity` field
as today.

### Step 4: Update summary counters

When calibration is active, the summary gains:

```json
"summary": {
  "...existing counters...",
  "calibrated": true,
  "downgraded_count": 0,
  "drift_overrides_active": ["data_sensitivity"]
}
```

When calibration is not active (no threat model), `calibrated: false` and the
other two fields are absent.

---

## PoC Quality Requirements

1. Real values from the codebase — actual paths, parameter names, HTTP methods
2. No placeholder strings left unfilled in the final output
3. Setup instructions: what auth state or test data is needed
4. Success indicator: what output or behavior confirms the vulnerability
5. Curl equivalent for quick manual testing
6. Cleanup note if the PoC creates persistent data (e.g. stored XSS)

---

## Output

### phase5-validated.json
```json
{
  "phase": "validation_and_poc",
  "runtime_validation_attempted": false,
  "runtime_skipped_reason": "Docker not available",
  "runtime_environment": null,
  "synthesis_notes": null,
  "summary": {
    "total_input": 0,
    "confirmed": 0,
    "confirmed_low_confidence": 0,
    "false_positives": 0,
    "needs_runtime": 0,
    "pocs_generated": 0,
    "runtime_confirmed": 0,
    "runtime_synthesis_failed": 0
  },
  "findings": [
    {
      "original_id": "O-001",
      "validation_status": "CONFIRMED",
      "confidence": "HIGH",
      "data_flow": {
        "source": "req.params.userId (GET /api/users/:id)",
        "transformations": ["none"],
        "sink": "db.query(`SELECT * FROM users WHERE id = ${userId}`)"
      },
      "mitigations_checked": [
        "No parameterization found",
        "No input validation middleware on this route",
        "ORM not used for this query"
      ],
      "false_positive_reason": null,
      "exploitability_notes": "Exploitable by any authenticated user",
      "poc_generated": true,
      "poc_file": "poc_O-001_sqli.py",
      "runtime_status": "RUNTIME_SKIPPED",
      "runtime_notes": "Docker not available in this environment"
    },
    {
      "original_id": "O-003",
      "validation_status": "FALSE_POSITIVE",
      "confidence": "HIGH",
      "data_flow": null,
      "mitigations_checked": ["Jinja2 autoescape=True applies globally"],
      "false_positive_reason": "Template engine auto-escapes all output; no XSS possible via this path",
      "exploitability_notes": null,
      "poc_generated": false,
      "poc_file": null,
      "runtime_status": null,
      "runtime_notes": null
    }
  ]
}
```

### Individual PoC files
Write each PoC script to `{repo_path}/.security-review/pocs/poc_{id}_{type}.py`
where `{type}` is a short lowercase slug matching the vulnerability type:
`sqli`, `xss`, `bola`, `cmdinj`, `ssrf`, or a similar concise label.

### phase5-pocs.json (for report builder compatibility)
```json
{
  "phase": "poc_generation",
  "pocs": [
    {
      "finding_id": "O-001",
      "vulnerability_type": "SQL_INJECTION",
      "poc_file": "poc_O-001_sqli.py",
      "poc_code": "#!/usr/bin/env python3\n...",
      "curl_equivalent": "curl -X GET 'http://localhost:3000/api/users/1?id=...'",
      "setup_required": "Valid auth token for any user account",
      "success_indicator": "Response contains rows from other users",
      "cleanup": "N/A — read-only exploit"
    }
  ]
}
```
