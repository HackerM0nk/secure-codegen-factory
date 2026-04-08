import { randomUUID } from "crypto";
import type { DomainEvent } from "./event-bus";

// ── Event type literals ──────────────────────────────────────────────

export const EVENT_TYPES = {
  // Agent
  AGENT_STARTED: "agent.started",
  AGENT_ITERATION: "agent.iteration",
  AGENT_TOOL_CALLED: "agent.tool_called",
  AGENT_TOOL_RESULT: "agent.tool_result",
  AGENT_COMPLETED: "agent.completed",
  AGENT_ERROR: "agent.error",
  // Security
  SECURITY_INPUT_BLOCKED: "security.input_blocked",
  SECURITY_COMMAND_BLOCKED: "security.command_blocked",
  SECURITY_COMMAND_ALERTED: "security.command_alerted",
  SECURITY_SECRET_DETECTED: "security.secret_detected",
  SECURITY_TRAJECTORY_FLAGGED: "security.trajectory_flagged",
  SECURITY_RUNTIME_ALERT: "security.runtime_alert",
  SECURITY_RUNTIME_ALERT_ENRICHED: "security.runtime_alert_enriched",
  SECURITY_SCAN_COMPLETED: "security.scan_completed",
  SECURITY_BEHAVIORAL_ALERT: "security.behavioral_alert",
  SECURITY_INJECTION_DETECTED: "security.injection_detected",
  SECURITY_INTENT_FLAGGED: "security.intent_flagged",
  SECURITY_INTENT_BLOCKED: "security.intent_blocked",
  // Workspace
  WORKSPACE_CREATED: "workspace.created",
  WORKSPACE_DESTROYED: "workspace.destroyed",
  WORKSPACE_SNAPSHOT_SAVED: "workspace.snapshot_saved",
  WORKSPACE_SNAPSHOT_RESTORED: "workspace.snapshot_restored",
  // LLM
  LLM_CALL_STARTED: "llm.call_started",
  LLM_CALL_COMPLETED: "llm.call_completed",
  LLM_CALL_FAILED: "llm.call_failed",
  LLM_PROVIDER_HEALTH: "llm.provider_health",
  // Billing
  BILLING_CREDITS_RESERVED: "billing.credits_reserved",
  BILLING_CREDITS_CONSUMED: "billing.credits_consumed",
  BILLING_CREDITS_RELEASED: "billing.credits_released",
  // Build
  BUILD_VERIFICATION_STARTED: "build.verification_started",
  BUILD_VERIFICATION_PASSED: "build.verification_passed",
  BUILD_VERIFICATION_FAILED: "build.verification_failed",
  BUILD_AUTOFIX_APPLIED: "build.autofix_applied",
  // Deploy
  DEPLOY_STARTED: "deploy.started",
  DEPLOY_COMPLETED: "deploy.completed",
  DEPLOY_FAILED: "deploy.failed",
} as const;

export type EventType = (typeof EVENT_TYPES)[keyof typeof EVENT_TYPES];

// ── Payload types per event ──────────────────────────────────────────

export interface EventPayloads {
  "agent.started": { projectId: string; userId: string; userMessage: string };
  "agent.iteration": { projectId: string; iteration: number; maxIterations: number };
  "agent.tool_called": { projectId: string; tool: string; input: Record<string, any>; toolUseId: string };
  "agent.tool_result": { projectId: string; tool: string; result: string; durationMs: number; isError: boolean };
  "agent.completed": { projectId: string; iterations: number; tokensUsed: number; model: string };
  "agent.error": { projectId: string; error: string; iteration: number };

  "security.input_blocked": { userId: string; score: number; reason: string; inputPreview: string };
  "security.command_blocked": { userId: string; projectId: string; command: string; pattern: string };
  "security.command_alerted": { userId: string; projectId: string; command: string; pattern: string };
  "security.secret_detected": { userId: string; type: string; maskedValue: string };
  "security.trajectory_flagged": { sessionId: string; score: number; threshold: number };
  "security.runtime_alert": { source: string; rule: string; severity: string; pod: string; details: Record<string, any> };
  "security.runtime_alert_enriched": { source: string; rule: string; severity: string; pod: string; details: Record<string, any>; projectId?: string; userId?: string; sessionId?: string; workspaceId?: string; timestamp: string; correlationId: string };
  "security.scan_completed": { projectId: string; verdict: string; criticalFindings: number; totalFindings: number; tools: string[] };
  "security.behavioral_alert": { sessionId: string; classification: string; confidence: number; reason: string };
  "security.injection_detected": { userId: string; sessionId: string; attacks: Array<{ vector: string; category: string; severity: string }>; riskScore: number; blocked: boolean; inputPreview: string };
  "security.intent_flagged": { userId: string; sessionId: string; intent: string; riskScore: number; explanation: string; signalCount: number };
  "security.intent_blocked": { userId: string; sessionId: string; intent: string; riskScore: number; explanation: string; signalCount: number };

  "workspace.created": { projectId: string; containerId: string; containerName: string };
  "workspace.destroyed": { projectId: string; containerId: string };
  "workspace.snapshot_saved": { projectId: string; snapshotKey: string; sizeBytes: number };
  "workspace.snapshot_restored": { projectId: string; snapshotKey: string; durationMs: number };

  "llm.call_started": { provider: string; model: string; inputTokens: number };
  "llm.call_completed": { provider: string; model: string; inputTokens: number; outputTokens: number; durationMs: number; cached: boolean };
  "llm.call_failed": { provider: string; model: string; error: string; durationMs: number };
  "llm.provider_health": { provider: string; score: number; weight: number; rpm: number };

  "billing.credits_reserved": { orgId: string; amount: number; reservationId: string };
  "billing.credits_consumed": { orgId: string; userId: string; projectId: string; amount: number; model: string };
  "billing.credits_released": { orgId: string; reservationId: string; amount: number };

  "build.verification_started": { projectId: string };
  "build.verification_passed": { projectId: string; durationMs: number };
  "build.verification_failed": { projectId: string; error: string };
  "build.autofix_applied": { projectId: string; error: string; fixModel: string; durationMs: number };

  "deploy.started": { projectId: string; deploymentId: string; environment: string };
  "deploy.completed": { projectId: string; deploymentId: string; url: string };
  "deploy.failed": { projectId: string; deploymentId: string; error: string };
}

// ── Stream mapping ───────────────────────────────────────────────────

export function streamForEvent(type: EventType): string {
  return type.split(".")[0]; // "agent.started" → "agent"
}

// ── Typed event factory ──────────────────────────────────────────────

export function createEvent<T extends EventType>(
  type: T,
  payload: EventPayloads[T],
  correlationId?: string
): DomainEvent {
  return {
    id: "", // assigned by Redis XADD
    stream: streamForEvent(type),
    type,
    timestamp: new Date().toISOString(),
    correlationId: correlationId || randomUUID(),
    payload,
  };
}
