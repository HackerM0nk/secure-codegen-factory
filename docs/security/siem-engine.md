# SIEM Rules Engine

> Lightweight SIEM that replaces Wazuh for ARM64 environments. Processes
> event bus events in real time, applies detection and correlation rules,
> emits alerts to Prometheus metrics. Implemented in
> `src/server/security/siem-rules-engine.ts` with mirrored rules in
> `wazuh/local_rules.xml`.

## Why This Exists

Wazuh does not run on ARM64 (Apple Silicon). This in-process SIEM rules
engine provides equivalent detection and correlation capabilities using
the same rule IDs and severity levels as the Wazuh configuration, so
alert dashboards and runbooks work identically regardless of platform.

## Detection Rules (13 Rules)

The engine subscribes to four event bus streams: `security`, `workspace`,
`deploy`, and `llm`. Each incoming event is matched against all detection
rules by event type and optional field matches.

### Security Detection Rules

| Rule ID | Level | Event Type | Description | MITRE | Groups |
|---|---|---|---|---|---|
| 100001 | 12 | `security.input_blocked` | Prompt injection attempt blocked by input firewall | T1059 | devfactory_security, prompt_injection |
| 100002 | 10 | `security.command_blocked` | Dangerous shell command blocked by output filter | T1059.004 | devfactory_security, command_blocked |
| 100003 | 8 | `security.secret_detected` | Secret/credential detected in user input | T1552 | devfactory_security, secret_detection |
| 100004 | 10 | `security.trajectory_flagged` | Session trajectory flagged -- risk score exceeded threshold | T1078 | devfactory_security, trajectory |
| 100005 | 14 | `security.behavioral_alert` | Behavioral detector flagged session as SUSPICIOUS or MALICIOUS | T1059 | devfactory_security, behavioral |
| 100006 | 13 | `security.runtime_alert_enriched` | Enriched runtime security alert from Tetragon eBPF monitor (correlated with project/user context) | T1611 | devfactory_security, runtime |
| 100020 | 12 | `security.injection_detected` | Prompt injection attack detected | T1059 | devfactory_security, prompt_injection, injection_detected |
| 100021 | 10 | `security.intent_flagged` | Malicious intent classified | T1203 | devfactory_security, intent_classification |
| 100022 | 13 | `security.intent_blocked` | High-risk intent BLOCKED | T1203 | devfactory_security, intent_classification, intent_blocked |

### Operations Detection Rules

| Rule ID | Level | Event Type | Description | MITRE | Groups |
|---|---|---|---|---|---|
| 100007 | 7 | `security.scan_completed` | Security scan completed with findings | -- | devfactory_operations, scanning |
| 100008 | 3 | `workspace.created` | New workspace created | -- | devfactory_operations, workspace |
| 100009 | 7 | `deploy.failed` | Deployment failed | -- | devfactory_operations, deploy |
| 100010 | 5 | `llm.provider_health` | LLM provider health degraded (score 0-3) | -- | devfactory_operations, llm |

### Upstream Signal Quality

Rule 100005 (`security.behavioral_alert`) now receives only SUSPICIOUS and
MALICIOUS classifications from the behavioral detector. NORMAL
classifications are filtered at the source and never reach the SIEM engine.
This eliminates false-positive critical alerts on routine development
sessions.

Rule 100006 subscribes to `security.runtime_alert_enriched` (emitted by the
runtime correlator) rather than the raw `security.runtime_alert` event. The
enriched event includes `projectId`, `userId`, `sessionId`, and
`workspaceId` fields, enabling the SIEM engine to correlate runtime alerts
with application-level context.

## Correlation Rules (3 Rules)

Correlation rules detect patterns across multiple events within a time
window. They use a correlation buffer that tracks event timestamps per
group.

| Rule ID | Level | Trigger Group | Frequency | Timeframe | Description | Groups |
|---|---|---|---|---|---|---|
| 100011 | 14 | `devfactory_security` | 3 events | 300s (5 min) | Multiple security events from same session -- coordinated attack | devfactory_security, correlation |
| 100012 | 15 | `prompt_injection` | 5 events | 600s (10 min) | Injection flood -- 5+ injection attempts in 10 minutes | devfactory_security, correlation, flood |
| 100013 | 14 | `command_blocked` | 3 events | 300s (5 min) | Sandbox escape sequence -- 3+ blocked commands in 5 minutes | devfactory_security, correlation, escape_attempt |

### Correlation Mechanics

1. When a detection rule fires, its group names are added to the
   correlation buffer with the current timestamp.
2. After each detection, all correlation rules are checked.
3. For each correlation rule, timestamps older than the timeframe are
   pruned.
4. If the remaining count >= frequency threshold, a correlation alert
   fires and the buffer for that group is reset (prevents re-firing on
   every subsequent event).

## Severity Levels

Levels mirror the Wazuh severity scale (1-15).

| Level Range | Severity Label | Prometheus Label |
|---|---|---|
| 12-15 | Critical | `critical` |
| 8-11 | High | `high` |
| 5-7 | Medium | `medium` |
| 1-4 | Low | `low` |

## Alert Storage and Metrics

- **In-memory history**: Last 1,000 alerts (auto-pruned to 500 when
  limit is hit).
- **Prometheus counter**: `siemAlertsTotal` with labels `{rule, severity}`.
- **Structured logging**: Every alert is logged at WARN level with
  ruleId, level, groups, and MITRE technique ID.

## Wazuh Parity

The `wazuh/local_rules.xml` file contains the same rule IDs, levels,
descriptions, and MITRE mappings. When running on x86_64 with Wazuh
deployed, the application emits events as JSON logs that Wazuh parses
using `decoded_as: json` and matches on the `action` field. The in-process
SIEM engine matches on `event.type` instead.

| Component | Wazuh Field | SIEM Engine Field |
|---|---|---|
| Event matching | `<field name="action">` | `match.eventType` |
| Correlation | `<if_matched_group>` + `frequency` + `timeframe` | `matchGroup` + `frequency` + `timeframeSeconds` |
| MITRE mapping | `<mitre><id>` | `mitre` property |
| Alert output | Wazuh Alerts index | In-memory array + Prometheus counter |

## Stats API

```typescript
engine.getStats() returns {
  totalAlerts: number;
  byLevel: { critical: N, high: N, medium: N, low: N };
  byGroup: { devfactory_security: N, prompt_injection: N, ... };
  recentAlerts: SiemAlert[];  // last 10
}
```

## Related Docs

- [Incident Response](incident-response.md) -- Automated actions triggered
  by SIEM alerts
- [Behavioral Detection](behavioral-detection.md) -- Source of
  `security.behavioral_alert` events
- [Kubernetes Runtime](kubernetes-runtime.md) -- Source of
  `security.runtime_alert` events from Tetragon
