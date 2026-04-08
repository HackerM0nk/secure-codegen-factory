# CLAUDE.md — secure-codegen-factory

## What This Is

An AI-powered application builder with defense-in-depth security. Users prompt an LLM agent to generate full-stack applications inside isolated sandboxed workspaces. The core thesis: **treat the LLM as an untrusted, non-deterministic actor and engineer the surrounding system so that blast radius stays small, observable, and reversible**.

This is a **working local prototype** with full security control plane, observability stack, and detection pipeline running end-to-end. The goal is integration fidelity — every security claim should be backed by working code and observable signal.

## Design Philosophy

1. **Model-agnostic security**: The LLM is a black box. Security doesn't rely on the model being safety-trained — 16 independent layers inspect inputs, outputs, commands, packages, code, and runtime behavior.
2. **Control plane / data plane separation**: The backend orchestrates; workspaces execute. A compromised workspace cannot reach the control plane.
3. **Deterministic policy engine outside the model**: The agent proposes, the engine validates. Every tool call, file write, package install, and deploy goes through explicit policy checks.
4. **Observable by default**: Every security-relevant event flows through Redis Streams → SIEM → Audit Log → Prometheus → Grafana. If something happened, you can trace it.
5. **Layered defense with compound controls**: No single layer is trusted to catch everything. Prompt injection detection, intent classification, output filtering, code scanning, behavioral analysis, and runtime monitoring each catch different attack classes.

## Honest Status Assessment

### What's genuinely working end-to-end
- All 16 security layers are implemented and individually testable via `/api/security/*` endpoints
- SIEM rules engine processes Redis Stream events in real-time, fires detection + correlation rules
- Full observability stack runs locally: Prometheus, Grafana (6 dashboards), Loki, Jaeger, AlertManager
- 48-vector attack test suite with regression harness (100% pass rate on unit tests)
- E2E pipeline test verifies security API → SIEM → Prometheus → Loki chain (9/9 pass)
- Event-driven architecture: all security events flow through Redis Streams with consumer groups
- Behavioral detector uses local Ollama model for LLM-based session classification
- **Validation pipeline wired into agent loop** — post file_write AST checks and post-completion build verification run on every agent iteration
- **Prometheus metrics emitted from agent loop** — `agent_iterations_total`, `llm_tokens_total`, `tool_executions_total`, `llm_call_duration` all increment during runtime
- **Auth middleware on security routes** — `authMiddleware()` (required) on all security routes + `requireRole("admin")` on SIEM/scan endpoints + project ownership verification on project-scoped operations
- **SecurityLayer shared with security routes** — `setSecurityRouteLayer()` called from `index.ts` so `/api/security/stats` returns live firewall data from the same instance the agent loop uses
- **SecurityDashboard API contract aligned** — `/api/security/stats` returns shape matching frontend; `/api/agent/llm-health` endpoint added
- **Event bus correlation IDs propagated** from request context through event emissions
- **Build passes** — `npm run build` succeeds cleanly (tar-stream types + next.config.js fixed)
- **262 unit tests pass**, 48/48 regression vectors pass (100%), 9/9 E2E pipeline tests pass

### What's wired into the runtime path (previously listed as gaps — now fixed)
- **LLM provider_health events**: Health scorer emits `llm.provider_health` via eventBus when score <= 3 (SIEM rule 100010 fires)
- **OTel spans**: `withSpan("agent.loop")`, `withSpan("security.preprocess")`, `withSpan("agent.tool.${name}")` wrap business-critical paths
- **Editor file save**: Cmd+S persists via `POST /api/files/:projectId/write` with dirty indicator
- **Chat persistence**: Real assistant text accumulated from SSE events, saved to DB with split token accounting
- **Snapshot save/restore**: Docker tar wrapper extraction via `tar-stream` on save, proper wrapping on restore
- **Terminal auth**: CSPRNG credentials generated on container creation, fetched via API, sent in WebSocket handshake
- **Tenant safety**: Security routes use DB ownership check (`prisma.project.findFirst({ where: { id, orgId } })`) instead of naming convention
- **Auth**: All routes use `jwt.verify()` — no silent dev-user fallback, no `jwt.decode()`

### Known bugs to fix
- None currently blocking.

### Intentional simplifications for local demo
- **Auth**: `jwt.verify()` with a static secret (`JWT_SECRET` defaults to `"dev-secret-change-in-production"`). Signatures are verified, but the secret is not rotated. Production: Keycloak JWKS endpoint for RS256.
- **Docker sandbox**: `ReadonlyRootfs: false` in Docker mode. K8s pods use `readOnlyRootFilesystem: true` with writable volume mounts for `/workspace` and `/tmp`.
- **Localhost URLs**: Hardcoded across frontend/backend. Production: service discovery / env-based.

### Not yet built
- Unified org-level policy engine (OrgPolicy model + policy evaluation service)
- Session evidence chain API (complete timeline per conversation for audit)
- Admin UI for policy management

## How to Work on This Codebase

### Running Locally
```bash
docker compose up -d                              # core services (Redis, Postgres, Prometheus, etc.)
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d  # + monitoring stack
npm run dev                                       # backend (4100) + frontend (3100)
```

### Key URLs
| Service | URL | Notes |
|---------|-----|-------|
| Frontend | http://localhost:3100 | App builder UI |
| Backend API | http://localhost:4100/api/health | Express server |
| Grafana | http://localhost:3300 | admin/admin |
| Prometheus | http://localhost:9190 | Metrics |
| Jaeger | http://localhost:16786 | Traces |

### Testing Security
```bash
npm run test:security:pipeline          # 9-attack E2E pipeline test
npm run test:security:regression        # 48-vector regression suite
npm run test:security:model-regression  # LLM model comparison
npm test                                # unit tests
```

### Project Structure
```
src/
  app/                    # Next.js frontend
  server/
    security/             # 16 security layer implementations
    llm/                  # Multi-provider LLM router
    routes/               # Express API endpoints
    services/             # Workspace, docker, k8s, snapshot
    events/               # Redis Streams event bus + audit
    observability/        # Metrics, tracing, logging
    validation/           # Validation pipeline (wired into agent loop)
docs/                     # Granular docs by stream
k8s/                      # Kubernetes security manifests
tests/                    # Security test suites
```

### Conventions
- Security events use Redis Streams with consumer groups
- SIEM rule IDs: 100001-100022 (detection), 100011-100013 (correlation)
- MITRE ATT&CK and CWE mappings on all security controls
- Structured JSON logging via Pino with correlation IDs

### What NOT to Do
- Don't call things "production-grade" in UI until the joins are real
- Don't add Wazuh to Docker Compose — crashes on ARM64; use the TS SIEM engine
- Don't hardcode model names in security layers — use complexity classifier
- Don't bypass security layers for convenience — defense-in-depth is the point
- Don't add new security layers without wiring them into the runtime path — demonstrated breadth without integration hurts credibility
