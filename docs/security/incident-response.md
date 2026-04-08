# Incident Response

> Automated incident response engine that subscribes to security events
> and takes defensive actions. Implemented in
> `src/server/security/incident-response.ts` and
> `src/server/security/runtime-correlator.ts`.

## Architecture

Two components work together:

| Component | Role |
|---|---|
| `IncidentResponder` | Subscribes to security event bus; takes automated actions |
| `RuntimeCorrelator` | Enriches runtime events (Tetragon/Falco) with project/user context |

## Automated Response Actions

The incident responder handles four event types with severity-dependent
actions.

### Event: `security.runtime_alert`

Source: Tetragon eBPF, Falco, or AlertManager.

| Severity | Action | Details |
|---|---|---|
| CRITICAL (with pod name) | TERMINATE_WORKSPACE | Pod is destroyed via `destroyWorkspace()` callback |
| CRITICAL (no pod name) | ESCALATE | Alert logged for manual intervention |
| All other severities | LOG | Alert recorded in action log |

### Event: `security.behavioral_alert`

Source: Behavioral detector LLM classification.

| Classification | Actions | Details |
|---|---|---|
| MALICIOUS | PAUSE_SESSION + NOTIFY | Session is paused; security team notified |
| SUSPICIOUS | LOG | Alert recorded for review |

### Event: `security.scan_completed`

Source: Code scanning pipeline (SAST, SCA, secrets, image).

| Verdict | Action | Details |
|---|---|---|
| BLOCK | NOTIFY | Project owner notified of critical findings blocking deployment |

### Event: `security.trajectory_flagged`

Source: Trajectory monitor.

| Condition | Action | Details |
|---|---|---|
| Score > 0.7 | PAUSE_SESSION | Session paused for security review |

## Action Types

| Action | Description |
|---|---|
| `PAUSE_SESSION` | Blocks all further input on the session until manual resume |
| `TERMINATE_WORKSPACE` | Destroys the workspace pod (irreversible) |
| `NOTIFY` | Sends notification to security team or project owner |
| `ESCALATE` | Logs for manual intervention (when automated action is not possible) |
| `LOG` | Records the event in the action log |

All actions are logged with:
- Action type
- Target (session ID, pod name, or "security-team")
- Reason (human-readable)
- Timestamp
- `automated: true` flag

## Escalation Chain

```
Security Event
    |
    v
Severity < HIGH  ------>  LOG only
    |
    v
Severity = HIGH
    |
    +-- Behavioral SUSPICIOUS  -->  LOG
    +-- Trajectory > 0.4       -->  (handled by trajectory monitor)
    +-- Scan BLOCK             -->  NOTIFY project owner
    |
    v
Severity = CRITICAL
    |
    +-- Runtime alert + pod    -->  TERMINATE_WORKSPACE
    +-- Runtime alert (no pod) -->  ESCALATE
    +-- Behavioral MALICIOUS   -->  PAUSE_SESSION + NOTIFY security team
    +-- Trajectory > 0.7       -->  PAUSE_SESSION
```

## Runtime Correlator

The runtime correlator (`runtime-correlator.ts`) enriches raw runtime
security events with application context before they reach the incident
responder.

### Pod-to-Project Mapping

The correlator maintains an in-memory map of pod names to project metadata.

| Field | Source |
|---|---|
| `projectId` | From `workspace.created` event |
| `userId` | From workspace creation context |
| `sessionId` | From workspace creation context |
| `workspaceId` | Container name from workspace creation |

Mappings are registered on `workspace.created` events and removed on
`workspace.destroyed` events.

### Event Enrichment

When a `security.runtime_alert` arrives, the correlator:

1. Looks up the pod name in the mapping table (using a reverse map that
   resolves both container IDs and container names to the same entry)
2. Adds `projectId`, `userId`, `sessionId`, `workspaceId`
3. Generates a correlation ID (`rt-{timestamp}-{random}`)
4. Adds an ISO timestamp
5. Emits the enriched event as `security.runtime_alert_enriched`

The correlator emits `security.runtime_alert_enriched` rather than
re-emitting `security.runtime_alert`. This avoids an event loop where
the correlator would re-trigger on its own output. The incident responder
and SIEM engine subscribe to the enriched event type.

The pod-to-project mapping uses a reverse map keyed by both container ID
and container name, so workspace removal by either identifier correctly
cleans up the mapping entry. This fixes a prior mismatch where workspaces
were registered by container name but removed by container ID.

## Action Log

Recent actions are available via `getRecentActions(limit)` which returns
the last N actions (default 50) from the in-memory action log.

```typescript
interface IncidentAction {
  type: "PAUSE_SESSION" | "TERMINATE_WORKSPACE" | "NOTIFY" | "ESCALATE" | "LOG";
  target: string;
  reason: string;
  timestamp: string;
  automated: boolean;
}
```

## Related Docs

- [SIEM Engine](siem-engine.md) -- Detection and correlation rules that
  generate the events this responder acts on
- [Behavioral Detection](behavioral-detection.md) -- Source of behavioral
  alerts
- [Kubernetes Runtime](kubernetes-runtime.md) -- Source of runtime alerts
  from Tetragon and Falco
