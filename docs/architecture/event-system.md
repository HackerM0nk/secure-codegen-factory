# Event System

The event system uses Redis Streams to decouple security enforcement, observability, and auditing from the main request path. Every significant action in the system emits an event that flows through SIEM rules, incident response, and audit logging.

Source files:
- `src/server/events/event-bus.ts` -- Redis Streams publisher and consumer
- `src/server/events/events.ts` -- event type catalog and typed payloads
- `src/server/events/audit-logger.ts` -- file-based audit trail

## Architecture

```
Producers                     Redis Streams              Consumers
---------                     -------------              ---------

Agent Loop    --+
Security Layer  |   emit()    +----------+
LLM Router      +----------->| security |------+------> SIEM Rules Engine
Workspace Svc   |             | agent    |      |------> Incident Responder
Billing         |             | workspace|      |------> Runtime Correlator
Deploy          +----------->| llm      |      |------> Behavioral Detector
                              | billing  |      +------> Audit Logger
                              | build    |
                              | deploy   |
                              +----------+
                                                              |
                                                              v
                                                    .audit/actions.jsonl
                                                              |
                                                              v
                                                         Fluent Bit
                                                              |
                                                              v
                                                      Loki --> Grafana
```

## Event Bus (`event-bus.ts`)

The `EventBus` class manages two Redis connections: one for publishing (`emit`) and one for subscribing (`xreadgroup`).

### Publishing

`emit(stream, type, payload, correlationId?)` adds an event to a Redis Stream via `XADD`. Each event contains:
- `type` -- event name (e.g., `security.input_blocked`)
- `timestamp` -- ISO 8601
- `correlationId` -- UUID linking related events across a request (propagated from HTTP request context when available)
- `payload` -- JSON-serialized event data

Correlation IDs are now propagated from the originating HTTP request context through event bus emissions, ensuring end-to-end traceability across the full event chain. If no correlation ID is provided by the caller, a new UUID is generated as a fallback.

### Subscribing

`subscribe(stream, group, consumer, handler)` starts a long-polling loop using `XREADGROUP` with:
- `COUNT 10` -- process up to 10 messages per poll
- `BLOCK 2000` -- block for 2 seconds waiting for new messages
- `>` -- only read new (undelivered) messages

On successful processing, the message is acknowledged with `XACK`. On handler failure, the message is **not** acknowledged and will be redelivered on the next read. A 1-second backoff prevents tight error loops.

### Consumer Groups

`createGroup(stream, group)` calls `XGROUP CREATE` with `MKSTREAM` (auto-creates the stream). If the group already exists (`BUSYGROUP` error), it is silently ignored.

### Reconnection

On Redis reconnect, all active subscriptions re-create their consumer groups to ensure the stream and group exist.

## Event Types (`events.ts`)

### Streams and Event Catalog

The system defines 7 streams. The stream for an event is derived from the event type prefix (e.g., `agent.started` goes to the `agent` stream).

#### Agent Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `agent.started` | projectId, userId, userMessage |
| `agent.iteration` | projectId, iteration, maxIterations |
| `agent.tool_called` | projectId, tool, input, toolUseId |
| `agent.tool_result` | projectId, tool, result, durationMs, isError |
| `agent.completed` | projectId, iterations, tokensUsed, model |
| `agent.error` | projectId, error, iteration |

#### Security Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `security.input_blocked` | userId, score, reason, inputPreview |
| `security.command_blocked` | userId, projectId, command, pattern |
| `security.command_alerted` | userId, projectId, command, pattern |
| `security.secret_detected` | userId, type, maskedValue |
| `security.trajectory_flagged` | sessionId, score, threshold |
| `security.runtime_alert` | source, rule, severity, pod, details |
| `security.runtime_alert_enriched` | source, rule, severity, pod, details, containerId, projectId |
| `security.scan_completed` | projectId, verdict, criticalFindings, totalFindings, tools |
| `security.behavioral_alert` | sessionId, classification, confidence, reason |
| `security.injection_detected` | userId, sessionId, attacks[], riskScore, blocked, inputPreview |
| `security.intent_flagged` | userId, sessionId, intent, riskScore, explanation, signalCount |
| `security.intent_blocked` | userId, sessionId, intent, riskScore, explanation, signalCount |

#### Workspace Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `workspace.created` | projectId, containerId, containerName |
| `workspace.destroyed` | projectId, containerId |
| `workspace.snapshot_saved` | projectId, snapshotKey, sizeBytes |
| `workspace.snapshot_restored` | projectId, snapshotKey, durationMs |

#### LLM Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `llm.call_started` | provider, model, inputTokens |
| `llm.call_completed` | provider, model, inputTokens, outputTokens, durationMs, cached |
| `llm.call_failed` | provider, model, error, durationMs |
| `llm.provider_health` | provider, score, weight, rpm |

#### Billing Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `billing.credits_reserved` | orgId, amount, reservationId |
| `billing.credits_consumed` | orgId, userId, projectId, amount, model |
| `billing.credits_released` | orgId, reservationId, amount |

#### Build Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `build.verification_started` | projectId |
| `build.verification_passed` | projectId, durationMs |
| `build.verification_failed` | projectId, error |
| `build.autofix_applied` | projectId, error, fixModel, durationMs |

#### Deploy Stream

| Event Type | Payload Fields |
|-----------|---------------|
| `deploy.started` | projectId, deploymentId, environment |
| `deploy.completed` | projectId, deploymentId, url |
| `deploy.failed` | projectId, deploymentId, error |

## Audit Logger (`audit-logger.ts`)

The `AuditLogger` subscribes to **all 7 streams** (`agent`, `security`, `workspace`, `llm`, `billing`, `build`, `deploy`) using a dedicated consumer group named `audit-logger`.

### Write Behavior

- Events are buffered in memory as JSONL strings
- Buffer flushes on a 1-second interval OR when batch size reaches 100
- Writes are synchronous (`fs.writeSync`) to the append-only file at `.audit/actions.jsonl`
- On write failure, data is re-buffered for the next flush attempt

### Audit Entry Format

Each line in `actions.jsonl` is a JSON object:

```json
{
  "timestamp": "2026-04-08T12:00:00.000Z",
  "correlationId": "uuid-v4",
  "eventType": "security.input_blocked",
  "userId": "user-123",
  "projectId": "project-456",
  "action": "security.input_blocked",
  "details": { ... full event payload ... }
}
```

### In-Memory Recent Entries

The audit logger maintains a circular buffer of the last 1000 entries accessible via `getRecentEntries(n)`, used by the SIEM rules engine and security dashboard.

## Consumer Topology

At server startup (`src/server/index.ts`), these consumers subscribe to the event bus:

| Consumer | Subscribed Streams | Purpose |
|----------|-------------------|---------|
| AuditLogger | all 7 streams | Writes `.audit/actions.jsonl` |
| SiemRulesEngine | security | Runs 13 detection + 3 correlation rules |
| IncidentResponder | security | Automated LOG/PAUSE/TERMINATE/ESCALATE |
| RuntimeCorrelator | security | Maps eBPF events to application context; emits `security.runtime_alert_enriched` (not `runtime_alert`) to avoid event loops |
| BehavioralDetector | agent (when enabled) | LLM-based session classification; only emits `security.behavioral_alert` for non-NORMAL classifications (SUSPICIOUS or MALICIOUS) |

## Related Documentation

- [Observability](../observability/README.md) -- how audit logs flow through Fluent Bit to Loki
- [Infrastructure](../infrastructure/README.md) -- Fluent Bit, Loki, and Wazuh service configuration
- [Testing](../testing/README.md) -- full pipeline test verifying end-to-end event flow
