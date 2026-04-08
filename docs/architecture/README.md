# System Architecture Overview

AI Dev Factory v2 is an AI-powered application builder with defense-in-depth security. Users prompt an LLM agent to generate full-stack applications inside isolated sandboxed workspaces. The core thesis: use uncensored or minimally-aligned LLMs as naive compliant coders, then wrap them in a defense-in-depth security stack that detects and blocks malicious outputs before they reach execution.

This is a local architecture prototype. The goal is to demonstrate that the security control plane works end-to-end: from user input through LLM inference, tool execution, code scanning, runtime monitoring, SIEM correlation, incident response, and observability.

## Architecture Diagram

```
                          +------------------+
                          |   Next.js UI     |
                          |   (port 3100)    |
                          |  Chat / Editor / |
                          |  Terminal / Admin |
                          +--------+---------+
                                   |
                                   | HTTP / SSE
                                   v
+------+  +--------+  +---------------------------+  +-----------+
|Keyclk|  |Traefik |  |   Express Backend         |  | Prometheus|
| OIDC |  | Proxy  |  |   (port 4100)             |  | (9190)    |
|(8280)|  | (8090) |  |                           |  +-----------+
+------+  +--------+  |  +-----+ +-------------+ |       |
                       |  | Auth| | Rate Limiter| |  +----+-----+
                       |  +-----+ +-------------+ |  | Grafana  |
                       |                           |  | (3300)   |
                       |  +----------+             |  +----------+
                       |  | Security |  16 layers  |
                       |  | Stack    |  in / out   |  +-----------+
                       |  +----------+             |  |  Jaeger   |
                       |                           |  |  (16786)  |
                       |  +----------+ +---------+ |  +-----------+
                       |  |LLM Router| |Event Bus| |
                       |  |          | | (Redis  | |  +-----------+
                       |  | Anthropic| | Streams)| |  |   Loki    |
                       |  | Bedrock  | +---------+ |  |  (3200)   |
                       |  | OpenAI   |      |      |  +-----------+
                       |  +----------+      |      |       ^
                       |       |            v      |       |
                       |       |   +-------------+ |  +-----------+
                       |       |   | SIEM Engine | |  | Fluent Bit|
                       |       |   | Audit Log   | |  | (24224)   |
                       |       |   | Incidents   | |  +-----------+
                       |       |   +-------------+ |       ^
                       +---------------------------+       |
                               |                           |
                               v                  .audit/actions.jsonl
                       +--------------+
                       |  Workspace   |
                       |  Containers  |
                       | (Docker/K8s) |
                       |  port 3000   |  preview
                       |  port 8080   |  terminal
                       +--------------+
                               |
                       +--------------+
                       |  S3 / Local  |
                       |  Stack (4666)|
                       |  Snapshots   |
                       +--------------+

              +----------+  +----------+
              | Postgres |  |  Redis   |
              |  (5534)  |  |  (6480)  |
              +----------+  +----------+
```

## Service Inventory

| Service | Image/Runtime | Port (host) | Purpose |
|---------|--------------|-------------|---------|
| Express Backend | `tsx watch src/server/index.ts` | 4100 | API server, security enforcement, LLM routing, event bus |
| Next.js Frontend | `next dev` | 3100 | Project management, chat, code editor, terminal, admin dashboard |
| PostgreSQL | `postgres:16-alpine` | 5534 | Persistent storage (projects, users, billing, conversations) |
| Redis | `redis:7-alpine` | 6480 | Event bus (Streams), rate limiting, LLM cache affinity, health scores |
| Traefik | `traefik:v3.0` | 8090 / 8190 | Reverse proxy for workspace containers |
| Keycloak | `keycloak:24.0` | 8280 | OIDC identity provider |
| Jaeger | `jaegertracing/all-in-one` | 16786 / 4418 | Distributed tracing (OpenTelemetry) |
| Prometheus | `prom/prometheus` | 9190 | Metrics collection, alerting rules |
| Grafana | `grafana:10.3.1` | 3300 | Dashboards (6 dashboards provisioned) |
| Loki | `grafana/loki:2.9.4` | 3200 | Log aggregation |
| AlertManager | `prom/alertmanager:v0.27.0` | 9293 | Alert routing and grouping |
| Fluent Bit | `fluent/fluent-bit:2.2` | 24224 | Log forwarding (audit log to Loki) |
| LocalStack | `localstack/localstack:3.8` | 4666 | S3 emulation for workspace snapshots |
| Stripe Mock | `stripe/stripe-mock` | 12211 | Payment API emulation |
| Wazuh Stack | `wazuh/*:4.7.2` | 9200 / 5701 / 55000 | SIEM indexer, manager, dashboard (monitoring overlay) |

## Control Plane vs Data Plane

- **Control plane**: Express backend (port 4100) handles auth, routing, security enforcement, the event bus, and observability. All decisions about what code to run pass through here.
- **Data plane**: Isolated Docker or Kubernetes containers (one per workspace) with restricted network, resource limits, and path validation. Code executes here, never on the host.
- **Frontend**: Next.js (port 3100) provides project management, the chat interface, code editor, terminal panel, and a security admin dashboard.

## Sub-Documentation

| Document | What It Covers |
|----------|---------------|
| [LLM Pipeline](llm-pipeline.md) | Provider architecture, routing logic, complexity classification, health scoring, cache affinity |
| [Workspace Lifecycle](workspace-lifecycle.md) | Container creation, isolation, file I/O, command execution, resource limits, snapshots |
| [Event System](event-system.md) | Redis Streams architecture, event types, consumer groups, audit logging, SIEM integration |
| [Data Model](data-model.md) | Prisma schema: all models, relationships, key fields |
| [Observability](../observability/README.md) | Prometheus metrics, Jaeger tracing, Pino logging, alert rules, Grafana dashboards |
| [Infrastructure](../infrastructure/README.md) | Docker Compose services, monitoring stack, log pipeline, network topology |
| [Testing](../testing/README.md) | 56-vector attack taxonomy, regression harness, pipeline tests, model regression |
