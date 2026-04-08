# Observability Stack

The observability stack provides metrics, distributed tracing, and structured logging across all components.

Source files:
- `src/server/observability/metrics.ts` -- Prometheus metrics definitions
- `src/server/observability/tracing.ts` -- OpenTelemetry/Jaeger tracing setup
- `src/server/observability/logger.ts` -- Pino structured logging
- `prometheus.yml` -- Prometheus scrape configuration
- `prometheus/alert-rules.yml` -- 32 alerting rules across 5 groups
- `grafana/provisioning/` -- datasource and dashboard provisioning
- `grafana/dashboards/` -- 6 dashboard JSON files

## Prometheus Metrics

All custom metrics are defined in `metrics.ts` and exposed at `GET /metrics` (no auth, for Prometheus scraping). Default Node.js metrics (event loop lag, heap, GC) are also collected.

The following metrics are actively incremented during runtime:
- **`agent_iterations_total`** -- incremented on each agent loop iteration
- **`llm_tokens_total`** -- incremented with input/output token counts on every LLM call completion
- **`tool_executions_total`** -- incremented on each tool invocation by the agent
- **`llm_call_duration_seconds`** -- observed on every LLM call (completed or failed)
- **`tool_execution_duration_seconds`** -- observed on each tool execution
- **`http_requests_total`** and **`http_request_duration_seconds`** -- recorded by the HTTP metrics middleware on every request
- **`credits_consumed_total`** -- incremented when billing credits are consumed

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `agent_iterations_total` | project_id, status | Total agent loop iterations |
| `llm_tokens_total` | model, direction (input/output) | Total LLM tokens processed |
| `security_blocks_total` | category, pattern | Total security blocks triggered |
| `behavioral_detections_total` | classification (NORMAL/SUSPICIOUS/MALICIOUS) | LLM-based behavioral detections |
| `siem_alerts_total` | rule, severity | SIEM rule alerts fired |
| `scan_findings_total` | tool (sast/sca/secrets/image), severity | Security scan findings |
| `credits_consumed_total` | model | Billing credits consumed |
| `tool_executions_total` | tool, status | Tool executions by the agent |
| `http_requests_total` | method, path, status_code | Total HTTP requests |

### Histograms

| Metric | Labels | Buckets | Description |
|--------|--------|---------|-------------|
| `llm_call_duration_seconds` | model, provider | 0.1, 0.5, 1, 2, 5, 10, 30, 60 | LLM call duration |
| `tool_execution_duration_seconds` | tool | 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30 | Tool execution duration |
| `workspace_creation_duration_seconds` | -- | 0.5, 1, 2, 5, 10, 20, 30 | Container creation time |
| `agent_session_duration_seconds` | -- | 1, 5, 10, 30, 60, 120, 300, 600 | Total session duration |
| `http_request_duration_seconds` | method, path, status_code | 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10 | HTTP request latency |

### Gauges

| Metric | Labels | Description |
|--------|--------|-------------|
| `active_workspaces` | -- | Number of running workspace containers |
| `active_agent_sessions` | -- | Number of active agent sessions |
| `provider_health_score` | provider | LLM provider health score (0-1) |
| `http_active_requests` | -- | In-flight HTTP requests |
| `app_uptime_seconds` | -- | Application uptime (updated every 15s) |
| `redis_connection_status` | -- | 1 = connected, 0 = disconnected |
| `db_connection_status` | -- | 1 = connected, 0 = disconnected |
| `security_trajectory_score` | -- | Max trajectory risk score across sessions |
| `event_bus_consumer_lag` | stream, group | Pending messages in consumer group |

### HTTP Metrics Middleware

`httpMetricsMiddleware()` is mounted before routes. It normalizes paths by replacing UUIDs with `:id` to avoid cardinality explosion. It tracks `http_requests_total`, `http_request_duration_seconds`, and `http_active_requests`.

## Prometheus Configuration

`prometheus.yml` defines:
- **Scrape interval**: 15 seconds
- **Evaluation interval**: 15 seconds
- **Scrape target**: `host.docker.internal:4100/metrics` (the Express backend)
- **Alert rules**: loaded from `/etc/prometheus/alert-rules.yml`
- **AlertManager**: configured at `alertmanager:9093`

## Alert Rules

`prometheus/alert-rules.yml` defines 32 alert rules across 5 groups:

### Group 1: Security Detections (14 rules)

| Alert | Expression | Severity | Description |
|-------|-----------|----------|-------------|
| HighInjectionRate | `rate(security_blocks_total{category="input_blocked"}[1h]) > 3` | warning | Sustained injection attempts (>3/hr) |
| InjectionBurst | `increase(security_blocks_total{category="input_blocked"}[5m]) > 10` | critical | 10+ attempts in 5 minutes |
| SandboxViolationSpike | `rate(security_blocks_total{category="command_blocked"}[1h]) > 10` | critical | >10 blocked commands/hr |
| ContainerEscapeAttempt | `security_blocks_total{pattern=~"nsenter\|unshare\|..."}` | critical | Namespace/mount tool detected |
| MetadataEndpointAccess | `security_blocks_total{pattern=~".*metadata.*"}` | critical | SSRF targeting 169.254.169.254 |
| ReverseShellAttempt | `security_blocks_total{pattern=~".*reverse_shell.*\|..."}` | critical | Reverse shell pattern matched |
| BehavioralMalicious | `behavioral_detections_total{classification="MALICIOUS"}` | critical | Session classified as malicious |
| BehavioralSuspiciousSpike | `increase(behavioral_detections_total{classification="SUSPICIOUS"}[1h]) > 5` | warning | 5+ suspicious sessions in 1 hour |
| TrajectoryPause | `security_blocks_total{category="trajectory_paused"}` | warning | Session auto-paused (score > 0.7) |
| SecretDetectionSpike | `increase(security_blocks_total{category="secret_detected"}[1h]) > 5` | warning | 5+ secrets detected in 1 hour |
| MaliciousPackageBlocked | `security_blocks_total{category="package_blocked"}` | critical | Typosquat/malware package blocked |
| RuntimeSecurityAlert | `security_blocks_total{category="runtime_alert"}` | critical | eBPF runtime alert (Tetragon) |
| CriticalScanFindings | `scan_findings_total{severity="critical"}` | warning | Critical SAST/SCA findings |

### Group 2: Application Health (5 rules)

| Alert | Expression | Severity |
|-------|-----------|----------|
| AppDown | `up{job="devfactory-api"} == 0` | critical |
| HighErrorRate | 5xx rate > 5% | critical |
| HighLatencyP95 | p95 > 5 seconds | warning |
| HighLatencyP99 | p99 > 10 seconds | critical |
| RedisDown | `redis_connection_status == 0` | critical |

### Group 3: Infrastructure (5 rules)

| Alert | Expression | Severity |
|-------|-----------|----------|
| HighMemoryUsage | Process memory > 1.5GB | warning |
| WorkspaceOOM | Process memory > 2GB | critical |
| PossibleCryptoMining | CPU > 90% sustained 5m | warning |
| EventLoopLag | Event loop lag > 500ms | warning |
| TooManyOpenFileDescriptors | FD usage > 80% | warning |

### Group 4: LLM Health (4 rules)

| Alert | Expression | Severity |
|-------|-----------|----------|
| LLMHighLatency | p95 > 2 minutes | warning |
| LLMProviderUnhealthy | Health score < 0.3 | warning |
| LLMHighErrorRate | Error rate > 10% | critical |
| LLMTokenBudgetBurn | >1M tokens/hour | warning |

### Group 5: Workspace Health (3 rules)

| Alert | Expression | Severity |
|-------|-----------|----------|
| WorkspaceCreationSlow | p95 > 30 seconds | warning |
| TooManyActiveWorkspaces | >50 active workspaces | warning |
| AgentSessionStuck | p95 session > 10 minutes | warning |

## Distributed Tracing

`tracing.ts` initializes OpenTelemetry with the Node.js SDK, exporting traces to Jaeger at `http://localhost:4418/v1/traces` (OTLP HTTP).

### Instrumented Libraries

- `@opentelemetry/instrumentation-http` -- HTTP client/server calls
- `@opentelemetry/instrumentation-express` -- Express route spans
- `@opentelemetry/instrumentation-ioredis` -- Redis commands
- `@opentelemetry/instrumentation-pg` -- PostgreSQL queries

### Custom Spans

`createSpan(name, attributes?)` and `withSpan(name, fn, attributes?)` create manual spans for application-level operations like LLM calls and security checks.

The service is identified as `ai-dev-factory` with the version from `APP_VERSION` env var.

## Structured Logging

`logger.ts` creates Pino loggers with:
- **Level**: `LOG_LEVEL` env var (default: `info`)
- **Timestamp**: ISO 8601 format
- **Base fields**: `service` name (e.g., `docker`, `k8s-workspace`, `agent-loop`, `server`)
- **Correlation**: `withCorrelation(logger, correlationId)` creates a child logger with the correlation ID attached

Log output is JSON, one object per line, suitable for machine parsing by Fluent Bit.

## Grafana Dashboards

Six dashboards are provisioned from `grafana/dashboards/`:

| Dashboard | File | Key Panels |
|-----------|------|------------|
| Security | `security.json` | Security blocks by category, injection rates, behavioral detections, SIEM alerts, trajectory scores, scan findings |
| Agent | `agent.json` | Agent iterations, tool execution rates, session durations, LLM token usage, error rates |
| LLM | `llm.json` | LLM call duration by provider, token throughput, provider health scores, cache hit rates |
| Workspace | `workspace.json` | Active workspaces, creation duration, container health, resource usage |
| Incidents | `incidents.json` | Incident response actions, severity distribution, response times |
| Network | `network.json` | HTTP request rates, latency percentiles, error rates, active connections |

### Datasources

Three datasources are provisioned in `grafana/provisioning/datasources/datasources.yaml`:
- **Prometheus** (default) -- `http://prometheus:9090`
- **Loki** -- `http://loki:3100`
- **Jaeger** -- `http://jaeger:16686`

## Related Documentation

- [Infrastructure](../infrastructure/README.md) -- how Prometheus, Grafana, Loki, and Fluent Bit are deployed
- [Event System](../architecture/event-system.md) -- audit log pipeline that feeds Fluent Bit
- [Testing](../testing/README.md) -- full pipeline test verifies Prometheus metrics and Loki ingestion
