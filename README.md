# Bulwark

HTTP reverse-proxy auth gateway — validates workload identity, enforces OPA policy, and injects signed upstream assertions.

Bulwark sits in front of your APIs. Every request is authenticated (mTLS, OIDC JWT, SPIFFE, or any combination), scored by assurance level, authorized by embedded OPA policy, and then forwarded to the upstream with a Bulwark-signed identity assertion. Services behind Bulwark need zero auth code.

> **Status:** Phase 1 complete — reverse proxy core, route matching, header stripping, audit log. Authentication (Phase 2) and authorization (Phase 4) coming next.

---

## Architecture

```
Client ──► Bulwark ──► Upstream API
             │
             ├─ Strip X-Bulwark-* inbound headers
             ├─ Route: host + longest path-prefix match
             ├─ Authn: mTLS / OIDC JWT / SPIFFE (Phase 2+)
             ├─ Authz: embedded OPA (Phase 4+)
             ├─ Inject: X-Bulwark-Subject / Bulwark-signed JWT (Phase 5+)
             └─ Audit: JSON event per request (stdout)
```

Bulwark is stateless — no sessions, no logins, no redirects. It only processes requests that already carry credentials.

---

## Quick Start (Docker)

```bash
docker compose up --build
# Bulwark on :8080, testapi echo server on :9090

curl -H "Host: api.local" http://localhost:8080/public
curl -H "Host: api.local" http://localhost:8080/orders
```

The `testapi` service echoes back the request and any identity headers Bulwark injects, annotated with the Rego policy that will eventually enforce each endpoint.

---

## Local Development

**Requirements:** Go 1.25+

```bash
make test          # run all tests
make build         # build ./bulwark binary
make run           # build + serve with testdata/bulwark.yaml
make validate      # validate config and exit
```

---

## Configuration

```yaml
listeners:
  - addr: ":8080"

routes:
  - id: trading-api
    match:
      host: api.example.com
      path_prefix: /
    upstream:
      url: http://trading-api:8000
    authn:
      required: false   # set true + add trust anchors in Phase 2
```

Run `bulwark validate --config bulwark.yaml` to check a config file without starting the server.

---

## Container Images

Images are published to GitHub Packages on every push:

| Image | Tag |
|---|---|
| `ghcr.io/stormbane-security/bulwark` | branch name, `sha-<short>`, `latest` (main only) |
| `ghcr.io/stormbane-security/bulwark-testapi` | same |

```bash
docker pull ghcr.io/stormbane-security/bulwark:dev
```

---

## Build Phases

| Phase | Status | Description |
|---|---|---|
| 0 | ✅ Done | Skeleton, config validation, audit logger, CLI |
| 1 | ✅ Done | Reverse proxy core — routing, header stripping, audit |
| 2 | Planned | OIDC + SPIFFE authn, multi-auth scoring |
| 3 | Planned | mTLS workload identity |
| 4 | Planned | OPA authorization |
| 5 | Planned | Upstream JWT minting + OIDC discovery |
| 6 | Planned | Header injection (X-Bulwark-Subject, Groups) |
| 7 | Planned | TLS, graceful shutdown, /healthz, Prometheus |

---

## Repository Layout

```
cmd/bulwark/        CLI entrypoint (serve, validate)
cmd/testapi/        Echo server for local dev and integration testing
internal/audit/     Audit event types + JSON logger
internal/config/    YAML config load + validation
internal/gateway/   HTTP handler pipeline
internal/proxy/     httputil.ReverseProxy wrapper
policy/             Default Rego policies (Phase 4+)
testdata/           Sample configs
```

---

## Related

**Anchor** (coming) — workload identity broker: enrollment, attestation verification, AI agent delegation chains, on-chain data, multisig authorization. Bulwark enforces; Anchor establishes identity.
