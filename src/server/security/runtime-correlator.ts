// src/server/security/runtime-correlator.ts
// Correlates runtime security events (Tetragon) with application context
// Maps pod labels to project/user/session for enriched dashboards

import type { EventBus } from "../events/event-bus";
import { createLogger } from "../observability/logger";

const logger = createLogger("runtime-correlator");

interface RuntimeEvent {
  source: string;
  rule: string;
  severity: string;
  pod: string;
  details: Record<string, any>;
}

interface EnrichedEvent extends RuntimeEvent {
  projectId?: string;
  userId?: string;
  sessionId?: string;
  workspaceId?: string;
  timestamp: string;
  correlationId: string;
}

// In-memory pod-to-project mapping (populated from workspace creation events)
const podProjectMap = new Map<string, {
  projectId: string;
  userId?: string;
  sessionId?: string;
  workspaceId: string;
}>();

// Reverse map: containerId → containerName, so workspace.destroyed (which only
// carries containerId) can look up the containerName used as the podProjectMap key.
const containerIdToName = new Map<string, string>();

/**
 * Register a pod-to-project mapping when a workspace is created.
 */
export function registerPodMapping(
  podName: string,
  projectId: string,
  workspaceId: string,
  userId?: string,
  sessionId?: string,
  containerId?: string
): void {
  podProjectMap.set(podName, { projectId, userId, sessionId, workspaceId });
  if (containerId) {
    containerIdToName.set(containerId, podName);
  }
}

/**
 * Remove a pod mapping when a workspace is destroyed.
 * Accepts either a containerName (direct key) or a containerId (resolved via reverse map).
 */
export function removePodMapping(podName: string): void {
  podProjectMap.delete(podName);
}

/**
 * Remove a pod mapping by containerId, using the reverse map to find the containerName key.
 */
export function removePodMappingByContainerId(containerId: string): void {
  const containerName = containerIdToName.get(containerId);
  if (containerName) {
    podProjectMap.delete(containerName);
    containerIdToName.delete(containerId);
  }
}

/**
 * Enrich a runtime event with application context.
 */
export function enrichEvent(event: RuntimeEvent): EnrichedEvent {
  const mapping = podProjectMap.get(event.pod);

  return {
    ...event,
    projectId: mapping?.projectId,
    userId: mapping?.userId,
    sessionId: mapping?.sessionId,
    workspaceId: mapping?.workspaceId,
    timestamp: new Date().toISOString(),
    correlationId: `rt-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
  };
}

/**
 * Start the runtime correlator — subscribes to security events and enriches them.
 */
export class RuntimeCorrelator {
  private running = false;

  constructor(private eventBus: EventBus) {}

  start(): void {
    if (this.running) return;
    this.running = true;
    logger.info("Runtime correlator started");
    this.subscribeToWorkspaceEvents();
    this.subscribeToSecurityEvents();
  }

  stop(): void {
    this.running = false;
  }

  private async subscribeToWorkspaceEvents(): Promise<void> {
    await this.eventBus.createGroup("workspace", "runtime-correlator");
    this.eventBus.subscribe("workspace", "runtime-correlator", "correlator-ws", async (event) => {
      if (!this.running) return;
      if (event.type === "workspace.created") {
        const p = event.payload as any;
        registerPodMapping(p.containerName, p.projectId, p.containerName, undefined, undefined, p.containerId);
      } else if (event.type === "workspace.destroyed") {
        const p = event.payload as any;
        // workspace.destroyed only carries containerId, not containerName —
        // use the reverse map to find and remove the correct entry.
        removePodMappingByContainerId(p.containerId);
      }
    });
  }

  private async subscribeToSecurityEvents(): Promise<void> {
    await this.eventBus.createGroup("security", "runtime-correlator");
    this.eventBus.subscribe("security", "runtime-correlator", "correlator-sec", async (event) => {
      if (!this.running) return;
      if (event.type === "security.runtime_alert") {
        const runtimeEvent = event.payload as RuntimeEvent;
        const enriched = enrichEvent(runtimeEvent);

        logger.warn({
          ...enriched,
        }, `Runtime security event: ${enriched.rule} on ${enriched.pod}`);

        // Re-emit as a distinct event type to avoid feedback loop —
        // subscribing to security.runtime_alert and re-emitting the same type
        // would cause infinite recursion through the event bus.
        await this.eventBus.emit("security", "security.runtime_alert_enriched", enriched as any);
      }
    });
  }
}
