# Infrastructure

The infrastructure runs as Docker Compose services across two files: a core stack and a monitoring overlay. All services share the `devfactory-v2` bridge network.

Source files:
- `docker-compose.yml` -- core services (8 containers)
- `docker-compose.monitoring.yml` -- monitoring overlay (6 containers)
- `fluent-bit/parsers.conf` -- log parser configuration
- `grafana/provisioning/` -- Grafana datasource and dashboard provisioning
- `prometheus.yml` -- Prometheus scrape configuration
- `prometheus/alert-rules.yml` -- alert rule definitions

## Starting the Stack

```bash
# Core services only
docker compose up -d

# Core + monitoring
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

## Core Services (docker-compose.yml)

| Service | Image | Host Port | Container Port | Purpose |
|---------|-------|-----------|---------------|---------|
| postgres | `postgres:16-alpine` | 5534 | 5432 | Primary database (projects, users, billing) |
| redis | `redis:7-alpine` | 6480 | 6379 | Event bus, rate limiting, LLM state |
| localstack | `localstack/localstack:3.8` | 4666 | 4566 | S3 emulation for workspace snapshots |
| traefik | `traefik:v3.0` | 8090 (HTTP), 8190 (dashboard) | 80, 8080 | Reverse proxy for workspace containers |
| keycloak | `keycloak:24.0` | 8280 | 8080 | OIDC identity provider |
| jaeger | `jaegertracing/all-in-one` | 16786 (UI), 4418 (OTLP) | 16686, 4318 | Distributed tracing |
| prometheus | `prom/prometheus` | 9190 | 9090 | Metrics collection and alerting |
| stripe-mock | `stripe/stripe-mock` | 12211 | 12111 | Payment API emulation |

### Service Details

**PostgreSQL**: Data persisted to `pgdata-v2` volume. Health check via `pg_isready`. Credentials: `devfactory/devfactory/devfactory` (user/password/db).

**Redis**: Configured with 256MB max memory and `allkeys-lru` eviction. Health check via `redis-cli ping`.

**LocalStack**: Provides S3, SQS, and IAM emulation. Init scripts run from `./localstack-init/` on startup. Test credentials: `test/test`.

**Traefik**: Reads Docker labels to auto-configure routing for workspace containers. Watches the `devfactory-net` network. Dashboard available at port 8190.

**Keycloak**: Runs in dev mode. Imports realm configuration from `./keycloak/`. Depends on PostgreSQL (uses a separate `keycloak` schema). Admin credentials: `admin/admin`.

**Jaeger**: OTLP collector enabled. The backend sends traces to port 4418 (mapped from 4318). UI at port 16786.

**Prometheus**: Loads `prometheus.yml` for scrape config and `prometheus/alert-rules.yml` for alerting. 7-day retention. Scrapes the backend at `host.docker.internal:4100/metrics` every 15 seconds.

**Stripe Mock**: Provides a local Stripe API for billing integration testing.

### Volumes

| Volume | Used By |
|--------|---------|
| `pgdata-v2` | PostgreSQL data |
| `lsdata-v2` | LocalStack state |
| `keycloak-data-v2` | Keycloak configuration |

## Monitoring Overlay (docker-compose.monitoring.yml)

| Service | Image | Host Port | Container Port | Purpose |
|---------|-------|-----------|---------------|---------|
| loki | `grafana/loki:2.9.4` | 3200 | 3100 | Log aggregation |
| grafana | `grafana/grafana:10.3.1` | 3300 | 3000 | Dashboards and visualization |
| alertmanager | `prom/alertmanager:v0.27.0` | 9293 | 9093 | Alert routing and grouping |
| fluent-bit | `fluent/fluent-bit:2.2` | 24224 | 24224 | Log forwarding to Loki |
| wazuh-indexer | `wazuh/wazuh-indexer:4.7.2` | 9200 | 9200 | OpenSearch-based SIEM storage |
| wazuh-manager | `wazuh/wazuh-manager:4.7.2` | 1514, 1515, 514/udp, 55000 | same | SIEM agent manager |
| wazuh-dashboard | `wazuh/wazuh-dashboard:4.7.2` | 5701 | 5601 | SIEM web dashboard |

### Service Details

**Loki**: Uses default local config. Health check at `/ready`. Data persisted to `loki-data` volume.

**Grafana**: Anonymous viewer access enabled. Admin credentials: `admin/admin`. Auto-provisions three datasources (Prometheus, Loki, Jaeger) and six dashboards from local files. Data persisted to `grafana-data` volume.

**AlertManager**: Loads config from `./prometheus/alertmanager.yml`. Connected to Prometheus via the alert rules configuration.

**Fluent Bit**: Dual input -- forward protocol on port 24224 and tail of `.audit/actions.jsonl`. Output to Loki with `job=fluent-bit` label. Refreshes the tail input every 2 seconds.

**Wazuh Stack**: Three-container SIEM deployment (indexer, manager, dashboard). Security plugins disabled for local development. The manager monitors `.audit/` for security events. Resource limits: indexer 1GB, manager 512MB, dashboard 512MB.

### Volumes (Monitoring)

| Volume | Used By |
|--------|---------|
| `loki-data` | Loki log storage |
| `grafana-data` | Grafana state and config |
| `alertmanager-data` | AlertManager state |
| `wazuh-indexer-data` | OpenSearch indices |
| `wazuh-manager-data` | Wazuh agent data |
| `wazuh-manager-logs` | Wazuh log files |
| `wazuh-dashboard-data` | Dashboard state |

## Log Pipeline

```
Application (Express Backend)
     |
     | Pino JSON logs (stdout)
     |
     +----> Docker log driver (default)
     |
     v
.audit/actions.jsonl
     |
     | tail input (refresh: 2s)
     v
Fluent Bit
     |
     | HTTP push (labels: job=fluent-bit)
     v
Loki (port 3100)
     |
     | LogQL queries
     v
Grafana (port 3000)
```

### Fluent Bit Parser

The JSON parser in `fluent-bit/parsers.conf` expects ISO 8601 timestamps in the `timestamp` field:

```
[PARSER]
    Name        json
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S.%LZ
```

## Network Topology

All services share the `devfactory-v2` bridge network. Inter-service communication uses container names as hostnames:

```
+-----------------devfactory-v2 network-----------------+
|                                                        |
|  postgres <-- keycloak                                 |
|  postgres <-- backend (host.docker.internal:4100)      |
|  redis    <-- backend                                  |
|  redis    <-- backend (event bus)                      |
|                                                        |
|  backend  --> jaeger (traces)                          |
|  backend  --> localstack (snapshots)                   |
|                                                        |
|  prometheus --> backend (scrape /metrics)               |
|  prometheus --> alertmanager (alerts)                   |
|                                                        |
|  fluent-bit --> loki (logs)                             |
|  grafana    --> prometheus, loki, jaeger (queries)      |
|                                                        |
|  traefik --> workspace containers (preview/terminal)   |
|                                                        |
|  wazuh-manager --> wazuh-indexer (events)               |
|  wazuh-dashboard --> wazuh-indexer (queries)            |
|  wazuh-dashboard --> wazuh-manager (API)                |
+--------------------------------------------------------+
```

Workspace containers are dynamically created on the same network. Traefik discovers them via Docker labels and routes HTTP traffic on port 8090.

## Key URLs

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3100 |
| Backend API | http://localhost:4100/api/health |
| Backend Metrics | http://localhost:4100/metrics |
| Grafana | http://localhost:3300 (admin/admin) |
| Prometheus | http://localhost:9190 |
| Jaeger | http://localhost:16786 |
| Keycloak | http://localhost:8280 (admin/admin) |
| Traefik Dashboard | http://localhost:8190 |
| Loki | http://localhost:3200 |
| AlertManager | http://localhost:9293 |
| Wazuh Dashboard | http://localhost:5701 |

## Related Documentation

- [Observability](../observability/README.md) -- metrics definitions, alert rules, Grafana dashboards
- [Event System](../architecture/event-system.md) -- how the audit log feeds Fluent Bit
- [Workspace Lifecycle](../architecture/workspace-lifecycle.md) -- workspace container configuration
