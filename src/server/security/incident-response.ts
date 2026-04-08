// src/server/security/incident-response.ts
// Automated incident response hooks — subscribes to event bus and takes action

import type { EventBus } from "../events/event-bus";
import { createLogger } from "../observability/logger";

const logger = createLogger("incident-response");

export interface IncidentAction {
  type: "PAUSE_SESSION" | "TERMINATE_WORKSPACE" | "NOTIFY" | "ESCALATE" | "LOG";
  target: string;
  reason: string;
  timestamp: string;
  automated: boolean;
}

const actionLog: IncidentAction[] = [];

function logAction(action: IncidentAction): void {
  actionLog.push(action);
  logger.warn({ action }, `Incident response: ${action.type} on ${action.target}`);
}

/**
 * Get recent incident response actions.
 */
export function getRecentActions(limit: number = 50): IncidentAction[] {
  return actionLog.slice(-limit);
}

/**
 * Automated incident response engine.
 * Subscribes to security events and takes automated defensive actions.
 */
export class IncidentResponder {
  private running = false;
  private destroyWorkspace?: (name: string) => Promise<void>;

  constructor(
    private eventBus: EventBus,
    options?: {
      destroyWorkspace?: (name: string) => Promise<void>;
    }
  ) {
    this.destroyWorkspace = options?.destroyWorkspace;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    logger.info("Incident responder started");
    this.processSecurityEvents();
  }

  stop(): void {
    this.running = false;
  }

  private async processSecurityEvents(): Promise<void> {
    await this.eventBus.createGroup("security", "incident-responder");
    this.eventBus.subscribe("security", "incident-responder", "responder-1", async (event) => {
      if (this.running) {
        await this.handleEvent(event);
      }
    });
  }

  private async handleEvent(event: any): Promise<void> {
    const payload = event.payload || {};

    switch (event.type) {
      // ── Runtime alert from Tetragon/AlertManager ──────────────────────
      case "security.runtime_alert": {
        const severity = payload.severity?.toUpperCase?.() || "";

        if (severity === "CRITICAL" && payload.pod && this.destroyWorkspace) {
          // Auto-terminate pod on CRITICAL runtime alert
          logAction({
            type: "TERMINATE_WORKSPACE",
            target: payload.pod,
            reason: `CRITICAL runtime alert: ${payload.rule}`,
            timestamp: new Date().toISOString(),
            automated: true,
          });

          try {
            await this.destroyWorkspace(payload.pod);
            logger.warn({ pod: payload.pod, rule: payload.rule }, "Pod terminated due to CRITICAL runtime alert");
          } catch (err: any) {
            logger.error({ err: err.message, pod: payload.pod }, "Failed to terminate pod");
          }
        } else if (severity === "CRITICAL") {
          logAction({
            type: "ESCALATE",
            target: payload.pod || "unknown",
            reason: `CRITICAL alert requires attention: ${payload.rule}`,
            timestamp: new Date().toISOString(),
            automated: true,
          });
        } else {
          logAction({
            type: "LOG",
            target: payload.pod || "unknown",
            reason: `Runtime alert: ${payload.rule} (${severity})`,
            timestamp: new Date().toISOString(),
            automated: true,
          });
        }
        break;
      }

      // ── Behavioral alert ──────────────────────────────────────────────
      case "security.behavioral_alert": {
        const classification = payload.classification;

        if (classification === "MALICIOUS") {
          logAction({
            type: "PAUSE_SESSION",
            target: payload.sessionId,
            reason: `Behavioral detector: MALICIOUS — ${payload.reason}`,
            timestamp: new Date().toISOString(),
            automated: true,
          });

          logAction({
            type: "NOTIFY",
            target: "security-team",
            reason: `MALICIOUS session detected: ${payload.sessionId}`,
            timestamp: new Date().toISOString(),
            automated: true,
          });
        } else if (classification === "SUSPICIOUS") {
          logAction({
            type: "LOG",
            target: payload.sessionId,
            reason: `Behavioral detector: SUSPICIOUS — ${payload.reason}`,
            timestamp: new Date().toISOString(),
            automated: true,
          });
        }
        break;
      }

      // ── Scan completed with critical findings ─────────────────────────
      case "security.scan_completed": {
        if (payload.verdict === "BLOCK") {
          logAction({
            type: "NOTIFY",
            target: payload.projectId,
            reason: `Scan blocked deployment: ${payload.criticalFindings} critical findings`,
            timestamp: new Date().toISOString(),
            automated: true,
          });
        }
        break;
      }

      // ── Trajectory paused ─────────────────────────────────────────────
      case "security.trajectory_flagged": {
        if (payload.score > 0.7) {
          logAction({
            type: "PAUSE_SESSION",
            target: payload.sessionId,
            reason: `Trajectory score ${payload.score.toFixed(2)} exceeded pause threshold`,
            timestamp: new Date().toISOString(),
            automated: true,
          });
        }
        break;
      }

      default:
        break;
    }
  }
}
