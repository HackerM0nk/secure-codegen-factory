// src/server/security/siem-rules-engine.ts
// Lightweight SIEM rules engine — replaces Wazuh for ARM64 environments.
// Processes event bus events in real-time, applies detection + correlation rules,
// emits SIEM alerts to the event bus and Prometheus metrics.

import type { EventBus, DomainEvent } from "../events/event-bus";
import { createLogger } from "../observability/logger";
import { metrics } from "../observability/metrics";

const logger = createLogger("siem-rules-engine");

// ── Rule definition ──────────────────────────────────────────────────

export interface SiemRule {
  id: string;
  level: number; // 1-15, mirrors Wazuh severity
  description: string;
  match: {
    eventType: string;        // exact match on event.type
    fieldMatch?: Record<string, string | RegExp>; // match on payload fields
  };
  mitre?: string;             // MITRE ATT&CK technique ID
  groups: string[];
}

export interface CorrelationRule {
  id: string;
  level: number;
  description: string;
  matchGroup: string;         // group to correlate on
  frequency: number;          // N events...
  timeframeSeconds: number;   // ...within T seconds
  groups: string[];
}

export interface SiemAlert {
  ruleId: string;
  level: number;
  description: string;
  mitre?: string;
  groups: string[];
  timestamp: string;
  correlationId?: string;
  sourceEvent: {
    type: string;
    payload: Record<string, any>;
  };
}

// ── Detection rules (from local_rules.xml) ───────────────────────────

const DETECTION_RULES: SiemRule[] = [
  {
    id: "100001",
    level: 12,
    description: "Prompt injection attempt blocked by input firewall",
    match: { eventType: "security.input_blocked" },
    mitre: "T1059",
    groups: ["devfactory_security", "prompt_injection"],
  },
  {
    id: "100002",
    level: 10,
    description: "Dangerous shell command blocked by output filter",
    match: { eventType: "security.command_blocked" },
    mitre: "T1059.004",
    groups: ["devfactory_security", "command_blocked"],
  },
  {
    id: "100003",
    level: 8,
    description: "Secret/credential detected in user input",
    match: { eventType: "security.secret_detected" },
    mitre: "T1552",
    groups: ["devfactory_security", "secret_detection"],
  },
  {
    id: "100004",
    level: 10,
    description: "Session trajectory flagged — risk score exceeded threshold",
    match: { eventType: "security.trajectory_flagged" },
    mitre: "T1078",
    groups: ["devfactory_security", "trajectory"],
  },
  {
    id: "100005",
    level: 14,
    description: "Behavioral detector flagged session as MALICIOUS",
    match: { eventType: "security.behavioral_alert" },
    mitre: "T1059",
    groups: ["devfactory_security", "behavioral"],
  },
  {
    id: "100006",
    level: 13,
    description: "Runtime security alert from Tetragon eBPF monitor",
    match: { eventType: "security.runtime_alert" },
    mitre: "T1611",
    groups: ["devfactory_security", "runtime"],
  },
  {
    id: "100014",
    level: 13,
    description: "Enriched runtime security alert (correlated with workspace context)",
    match: { eventType: "security.runtime_alert_enriched" },
    mitre: "T1611",
    groups: ["devfactory_security", "runtime", "enriched"],
  },
  {
    id: "100020",
    level: 12,
    description: "Prompt injection attack detected",
    match: { eventType: "security.injection_detected" },
    mitre: "T1059",
    groups: ["devfactory_security", "prompt_injection", "injection_detected"],
  },
  {
    id: "100021",
    level: 10,
    description: "Malicious intent classified",
    match: { eventType: "security.intent_flagged" },
    mitre: "T1203",
    groups: ["devfactory_security", "intent_classification"],
  },
  {
    id: "100022",
    level: 13,
    description: "High-risk intent BLOCKED",
    match: { eventType: "security.intent_blocked" },
    mitre: "T1203",
    groups: ["devfactory_security", "intent_classification", "intent_blocked"],
  },
  {
    id: "100007",
    level: 7,
    description: "Security scan completed with findings",
    match: { eventType: "security.scan_completed" },
    groups: ["devfactory_operations", "scanning"],
  },
  {
    id: "100008",
    level: 3,
    description: "New workspace created",
    match: { eventType: "workspace.created" },
    groups: ["devfactory_operations", "workspace"],
  },
  {
    id: "100009",
    level: 7,
    description: "Deployment failed",
    match: { eventType: "deploy.failed" },
    groups: ["devfactory_operations", "deploy"],
  },
  {
    id: "100010",
    level: 5,
    description: "LLM provider health degraded",
    match: {
      eventType: "llm.provider_health",
      fieldMatch: { score: /^[0-3]/ }, // low scores
    },
    groups: ["devfactory_operations", "llm"],
  },
];

// ── Correlation rules ─────────────────────────────────────────────────

const CORRELATION_RULES: CorrelationRule[] = [
  {
    id: "100011",
    level: 14,
    description: "Multiple security events from same session in 5 minutes — coordinated attack",
    matchGroup: "devfactory_security",
    frequency: 3,
    timeframeSeconds: 300,
    groups: ["devfactory_security", "correlation"],
  },
  {
    id: "100012",
    level: 15,
    description: "Injection flood — 5+ injection attempts in 10 minutes",
    matchGroup: "prompt_injection",
    frequency: 5,
    timeframeSeconds: 600,
    groups: ["devfactory_security", "correlation", "flood"],
  },
  {
    id: "100013",
    level: 14,
    description: "Sandbox escape sequence — 3+ blocked commands in 5 minutes",
    matchGroup: "command_blocked",
    frequency: 3,
    timeframeSeconds: 300,
    groups: ["devfactory_security", "correlation", "escape_attempt"],
  },
];

// ── Engine ─────────────────────────────────────────────────────────────

export class SiemRulesEngine {
  private running = false;
  private alertHistory: SiemAlert[] = [];
  private correlationBuffer: Map<string, number[]> = new Map(); // group → timestamps

  constructor(private eventBus: EventBus) {}

  start(): void {
    if (this.running) return;
    this.running = true;
    logger.info(
      { rules: DETECTION_RULES.length, correlations: CORRELATION_RULES.length },
      "SIEM rules engine started"
    );
    this.subscribeToStreams();
  }

  stop(): void {
    this.running = false;
    logger.info("SIEM rules engine stopped");
  }

  getAlerts(limit = 100): SiemAlert[] {
    return this.alertHistory.slice(-limit);
  }

  getAlertsByLevel(minLevel: number): SiemAlert[] {
    return this.alertHistory.filter((a) => a.level >= minLevel);
  }

  getStats(): {
    totalAlerts: number;
    byLevel: Record<string, number>;
    byGroup: Record<string, number>;
    recentAlerts: SiemAlert[];
  } {
    const byLevel: Record<string, number> = {};
    const byGroup: Record<string, number> = {};

    for (const alert of this.alertHistory) {
      const levelKey = alert.level >= 12 ? "critical" : alert.level >= 8 ? "high" : alert.level >= 5 ? "medium" : "low";
      byLevel[levelKey] = (byLevel[levelKey] || 0) + 1;
      for (const g of alert.groups) {
        byGroup[g] = (byGroup[g] || 0) + 1;
      }
    }

    return {
      totalAlerts: this.alertHistory.length,
      byLevel,
      byGroup,
      recentAlerts: this.alertHistory.slice(-10),
    };
  }

  private async subscribeToStreams(): Promise<void> {
    const streams = ["security", "workspace", "deploy", "llm"];
    for (const stream of streams) {
      try {
        await this.eventBus.createGroup(stream, "siem-engine");
        this.eventBus.subscribe(stream, "siem-engine", `siem-${stream}`, async (event) => {
          if (this.running) {
            this.processEvent(event);
          }
        });
      } catch {
        // Stream may not exist yet — that's ok
      }
    }
  }

  private processEvent(event: DomainEvent): void {
    const payload = (event.payload || {}) as Record<string, any>;

    // Check each detection rule
    for (const rule of DETECTION_RULES) {
      if (event.type !== rule.match.eventType) continue;

      // Check field matches if present
      if (rule.match.fieldMatch) {
        let allMatch = true;
        for (const [field, pattern] of Object.entries(rule.match.fieldMatch)) {
          const value = String(payload[field] ?? "");
          if (pattern instanceof RegExp) {
            if (!pattern.test(value)) { allMatch = false; break; }
          } else if (value !== pattern) {
            allMatch = false; break;
          }
        }
        if (!allMatch) continue;
      }

      // Rule matched — generate alert.
      // For behavioral alerts (rule 100005), differentiate severity by classification:
      //   SUSPICIOUS → level 8 (high), MALICIOUS → level 14 (critical)
      const alert = this.createAlert(rule, event);
      if (rule.id === "100005" && payload.classification === "SUSPICIOUS") {
        alert.level = 8;
        alert.description = "Behavioral detector flagged session as SUSPICIOUS";
      }
      this.recordAlert(alert);

      // Feed into correlation buffer
      for (const group of rule.groups) {
        if (!this.correlationBuffer.has(group)) {
          this.correlationBuffer.set(group, []);
        }
        this.correlationBuffer.get(group)!.push(Date.now());
      }
    }

    // Check correlation rules
    this.checkCorrelations(event);
  }

  private checkCorrelations(triggerEvent: DomainEvent): void {
    const now = Date.now();

    for (const rule of CORRELATION_RULES) {
      const timestamps = this.correlationBuffer.get(rule.matchGroup);
      if (!timestamps) continue;

      // Prune old entries
      const cutoff = now - rule.timeframeSeconds * 1000;
      const recent = timestamps.filter((t) => t >= cutoff);
      this.correlationBuffer.set(rule.matchGroup, recent);

      if (recent.length >= rule.frequency) {
        const alert: SiemAlert = {
          ruleId: rule.id,
          level: rule.level,
          description: `${rule.description} (${recent.length} events in ${rule.timeframeSeconds}s)`,
          groups: rule.groups,
          timestamp: new Date().toISOString(),
          correlationId: triggerEvent.correlationId || undefined,
          sourceEvent: {
            type: `correlation:${rule.matchGroup}`,
            payload: {
              eventCount: recent.length,
              timeframeSeconds: rule.timeframeSeconds,
              triggerEvent: triggerEvent.type,
            },
          },
        };
        this.recordAlert(alert);

        // Reset the buffer to avoid re-firing every event
        this.correlationBuffer.set(rule.matchGroup, []);
      }
    }
  }

  private createAlert(rule: SiemRule, event: DomainEvent): SiemAlert {
    return {
      ruleId: rule.id,
      level: rule.level,
      description: rule.description,
      mitre: rule.mitre,
      groups: rule.groups,
      timestamp: new Date().toISOString(),
      correlationId: event.correlationId || undefined,
      sourceEvent: {
        type: event.type,
        payload: (event.payload || {}) as Record<string, any>,
      },
    };
  }

  private recordAlert(alert: SiemAlert): void {
    this.alertHistory.push(alert);

    // Cap history at 1000 entries
    if (this.alertHistory.length > 1000) {
      this.alertHistory = this.alertHistory.slice(-500);
    }

    // Increment Prometheus counter
    const severity = alert.level >= 12 ? "critical" : alert.level >= 8 ? "high" : "medium";
    try {
      metrics.siemAlertsTotal?.inc({ rule: alert.ruleId, severity });
    } catch {
      // Metric may not exist yet
    }

    logger.warn(
      {
        ruleId: alert.ruleId,
        level: alert.level,
        groups: alert.groups,
        mitre: alert.mitre,
        correlationId: alert.correlationId,
      },
      `SIEM Alert: ${alert.description}`
    );
  }
}
