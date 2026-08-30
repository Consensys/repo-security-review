# Phase 0: Service Topology Mapping

## Goal

Map the full multi-service architecture **before** individual repos are analyzed.
Produce `service-topology.json` — a shared context document passed to each
repo's Phase 2 and consumed by Phase 7 for cross-repo synthesis.

**This phase runs only in multi-repo mode (`--repos` flag).** In single-repo
mode it is skipped entirely.

## Inputs

The orchestrator passes:
- `repos` — the list of repo paths from `--repos`
- `output_dir` — the shared output directory where `service-topology.json` is written

For each repo in `repos`, search for the following files:

| File pattern | Location hints | What it tells you |
|---|---|---|
| `docker-compose*.yml` | repo root, `docker/`, `deploy/` | Service definitions, port mappings, env var names, network links |
| `*.yaml`, `*.yml` containing `kind: Service\|Ingress\|NetworkPolicy\|Deployment` | `k8s/`, `deploy/`, `manifests/`, `.kubernetes/` | Kubernetes service topology, ingress rules, network policies |
| `openapi.yaml`, `swagger.yaml`, `*.openapi.json`, `openapi.json` | repo root, `docs/api/`, `api/`, `spec/` | Endpoint contracts, declared auth schemes |
| `*.proto` | anywhere in repo | gRPC service definitions, RPC contracts |
| `istio/*.yaml`, `linkerd/*.yaml`, `VirtualService`, `AuthorizationPolicy` | anywhere | Service mesh auth and traffic policies |
| `.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml` | repo root | Service-to-service calls in CI, secret injection patterns |
| `README.md` | repo root | Service description, port/dep information |
| `.env.example`, `.env.sample` | repo root | Expected environment variable names |

## Step 1: Discover Services

For each repo in the `repos` list:
1. Use the repo's directory name as the default service name (can be overridden
   by `name:` in docker-compose or `app:` label in k8s).
2. Read all files from the table above that are present.
3. Identify:
   - **Exposed ports** (internal, external-facing, or both)
   - **Auth mechanism for inbound traffic** (jwt, api_key, mtls, basic, none, unknown)
   - **Outbound calls to other services** — which services it calls and with what auth
   - **Shared env var names** — vars present in multiple repos (e.g. `DATABASE_URL`,
     `JWT_SECRET`, `INTERNAL_API_KEY`, `REDIS_URL`)
   - **Entry points** — services that accept traffic from outside (Ingress, public ports)

## Step 2: Build the Connection Graph

For each outbound connection discovered:
```
FROM service → TO service (mechanism: http|grpc|tcp|unknown) auth: (presented|none|unknown)
```

Flag connections where `auth: "none"` between internal services — these are
**trust boundary gaps**: any service (or attacker) with network access can
impersonate the caller.

## Step 3: Assess Confidence

- **high** — docker-compose or k8s manifests found; service graph is explicit
- **medium** — some config found but connections are partially inferred
  (e.g. service names in env vars without explicit topology files)
- **low** — no topology config found; topology inferred from repo names,
  README files, and .env.example only

Note what you found and what you had to infer.

## Output

Write to `{output_dir}/service-topology.json`:

```json
{
  "phase": "service_topology",
  "services": [
    {
      "name": "api-gateway",
      "repo_path": "/absolute/path/to/api-gateway",
      "type": "entry_point",
      "exposed_ports": [8080],
      "auth_inbound": "jwt",
      "outbound_connections": [
        {
          "to": "auth-service",
          "mechanism": "http",
          "auth": "none",
          "path": "/validate",
          "note": "api-gateway calls auth-service with no mutual auth"
        },
        {
          "to": "user-service",
          "mechanism": "grpc",
          "auth": "jwt"
        }
      ]
    },
    {
      "name": "auth-service",
      "repo_path": "/absolute/path/to/auth-service",
      "type": "internal",
      "exposed_ports": [3000],
      "auth_inbound": "none",
      "outbound_connections": []
    },
    {
      "name": "user-service",
      "repo_path": "/absolute/path/to/user-service",
      "type": "internal",
      "exposed_ports": [50051],
      "auth_inbound": "jwt",
      "outbound_connections": [
        {
          "to": "auth-service",
          "mechanism": "http",
          "auth": "jwt"
        }
      ]
    }
  ],
  "shared_env_vars": ["DATABASE_URL", "JWT_SECRET", "INTERNAL_API_KEY"],
  "entry_points": ["api-gateway"],
  "trust_boundary_gaps": [
    {
      "from": "api-gateway",
      "to": "auth-service",
      "issue": "api-gateway calls auth-service with no auth — any service with network access can impersonate api-gateway",
      "severity": "HIGH"
    }
  ],
  "topology_confidence": "high",
  "topology_sources": ["docker-compose.yml (api-gateway)", "k8s/services.yaml (auth-service, user-service)"],
  "topology_notes": "No OpenAPI specs found. Connection from api-gateway to auth-service inferred from environment variable INTERNAL_AUTH_URL."
}
```

## How This File Is Used

- The orchestrator passes `{output_dir}/service-topology.json` to each repo's
  **Phase 2** subagent as additional context. Phase 2 reads it to understand
  the service's role in the wider system (entry point vs. internal, blind-trust
  callers, etc.) and incorporates this into its architecture analysis.
- **Phase 7** reads it as the authoritative service graph for cross-repo synthesis.

## Final Response (chat output)

Your own closing message — separate from the orchestrator's one-line progress
update — is a channel that can leak topology detail into the chat if you're
not careful. Do not restate the service graph, trust boundary gaps, or any
other analysis content in your final response. Everything belongs in
`service-topology.json`. Your final message is one line: confirm completion
and the output path, nothing else — e.g. `Phase 0 complete — wrote
service-topology.json`.
