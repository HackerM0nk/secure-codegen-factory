// src/server/security/index.ts
// Unified SecurityLayer class that chains all security components

import { evaluateInput, type FirewallResult } from "./input-firewall";
import {
  filterCommand,
  getSecurityStats,
  setSecurityEventCallback,
  type CommandContext,
  type FilterResult,
  type SecurityEventCallback,
} from "./output-filter";
import {
  filterPackageInstall,
  type PackageFilterResult,
} from "./package-filter";
import {
  detectSecrets,
  setRedisClient,
  type RedisLike,
  type SecretDetectorResult,
} from "./secret-detector";
import {
  TrajectoryMonitor,
  type TurnData,
  type RiskAssessment,
} from "./trajectory-monitor";
import {
  analyzeForInjection,
  type InjectionAnalysis,
} from "./prompt-injection-detector";
import {
  classifyIntent,
  type IntentClassification,
} from "./intent-classifier";

// ── Types ───────────────────────────────────────────────────────────────────

export interface SecurityContext {
  projectId: string;
  userId: string;
  sessionId: string;
  conversationTurn: number;
  containerName: string;
}

export interface SecurityResult {
  allowed: boolean;
  sanitizedInput: string;
  firewallResult: FirewallResult;
  secretsResult: SecretDetectorResult;
  injectionAnalysis?: InjectionAnalysis;
  intentClassification?: IntentClassification;
  trajectoryAssessment?: RiskAssessment;
  reason?: string;
}

export interface FilterToolResult {
  allowed: boolean;
  commandFilterResult?: FilterResult;
  packageFilterResult?: PackageFilterResult;
  message?: string;
}

export type SecurityEventHandler = (event: {
  type: "BLOCK" | "ALERT" | "INFO" | "SECRET_DETECTED" | "SESSION_FLAGGED" | "SESSION_PAUSED";
  details: Record<string, any>;
  timestamp: string;
  sessionId: string;
}) => void;

// ── SecurityLayer class ─────────────────────────────────────────────────────

export class SecurityLayer {
  private monitors = new Map<string, TrajectoryMonitor>();
  private eventHandler: SecurityEventHandler | null = null;
  private firewallCounts = { totalChecked: 0, blocked: 0, flagged: 0 };

  constructor(redisClient?: RedisLike) {
    if (redisClient) {
      setRedisClient(redisClient);
    }

    // Wire up output filter events to our unified handler
    setSecurityEventCallback((event) => {
      if (this.eventHandler) {
        this.eventHandler({
          type: event.level,
          details: {
            command: event.entry.command,
            pattern: event.entry.pattern,
            verdict: event.entry.verdict,
          },
          timestamp: new Date().toISOString(),
          sessionId: event.entry.projectId,
        });
      }
    });
  }

  onSecurityEvent(handler: SecurityEventHandler): void {
    this.eventHandler = handler;
  }

  // ── Pre-LLM: process user input ──────────────────────────────────────────

  async preprocessUserInput(
    input: string,
    sessionId: string
  ): Promise<SecurityResult> {
    // 1. Detect and redact secrets
    const secretsResult = detectSecrets(input);

    if (secretsResult.detections.length > 0 && this.eventHandler) {
      this.eventHandler({
        type: "SECRET_DETECTED",
        details: {
          count: secretsResult.detections.length,
          types: secretsResult.detections.map((d) => d.type),
        },
        timestamp: new Date().toISOString(),
        sessionId,
      });
    }

    // 2. Run input firewall on sanitized text
    const firewallResult = evaluateInput(secretsResult.sanitized);
    this.firewallCounts.totalChecked++;
    if (firewallResult.blocked) this.firewallCounts.blocked++;
    else if (firewallResult.score >= 0.4) this.firewallCounts.flagged++;

    if (firewallResult.blocked) {
      return {
        allowed: false,
        sanitizedInput: secretsResult.sanitized,
        firewallResult,
        secretsResult,
        reason: firewallResult.reason,
      };
    }

    // 2b. Deep prompt injection analysis
    const injectionAnalysis = analyzeForInjection(secretsResult.sanitized);
    if (injectionAnalysis.blocked) {
      if (this.eventHandler) {
        this.eventHandler({
          type: "BLOCK",
          details: {
            source: "prompt_injection_detector",
            attacks: injectionAnalysis.attacks.map((a) => ({
              vector: a.vector,
              category: a.category,
              severity: a.severity,
            })),
            riskScore: injectionAnalysis.riskScore,
          },
          timestamp: new Date().toISOString(),
          sessionId,
        });
      }
      return {
        allowed: false,
        sanitizedInput: secretsResult.sanitized,
        firewallResult,
        secretsResult,
        injectionAnalysis,
        reason: `Prompt injection detected: ${injectionAnalysis.attacks.map((a) => a.vector).join(", ")}`,
      };
    }

    // 2c. Intent classification — semantic-level intent detection
    const intentClassification = classifyIntent(secretsResult.sanitized);
    if (intentClassification.recommendation === "BLOCK") {
      if (this.eventHandler) {
        this.eventHandler({
          type: "BLOCK",
          details: {
            source: "intent_classifier",
            intent: intentClassification.primaryIntent,
            riskScore: intentClassification.riskScore,
            explanation: intentClassification.explanation,
            signals: intentClassification.signals.length,
          },
          timestamp: new Date().toISOString(),
          sessionId,
        });
      }
      return {
        allowed: false,
        sanitizedInput: secretsResult.sanitized,
        firewallResult,
        secretsResult,
        injectionAnalysis,
        intentClassification,
        reason: `Intent classified as ${intentClassification.primaryIntent}: ${intentClassification.explanation}`,
      };
    }

    // 3. Get trajectory assessment if monitor exists
    const monitor = this.monitors.get(sessionId);
    let trajectoryAssessment: RiskAssessment | undefined;
    if (monitor && monitor.isPausedState()) {
      return {
        allowed: false,
        sanitizedInput: secretsResult.sanitized,
        firewallResult,
        secretsResult,
        intentClassification,
        trajectoryAssessment: {
          score: monitor.getScore(),
          level: "PAUSED",
          reason: "Session paused for security review",
          turnNumber: -1,
          shouldPause: true,
        },
        reason: "Session paused for security review. Contact support to resume.",
      };
    }

    return {
      allowed: true,
      sanitizedInput: secretsResult.sanitized,
      firewallResult,
      secretsResult,
      intentClassification,
      trajectoryAssessment,
    };
  }

  // ── Post-LLM: filter tool execution ───────────────────────────────────────

  async filterToolExecution(
    toolName: string,
    toolInput: Record<string, any>,
    context: SecurityContext
  ): Promise<FilterToolResult> {
    const commandContext: CommandContext = {
      projectId: context.projectId,
      userId: context.userId,
      conversationTurn: context.conversationTurn,
      containerName: context.containerName,
    };

    if (toolName === "shell_exec" && typeof toolInput.command === "string") {
      const command = toolInput.command;

      // Check if it is a package install command
      const isInstallCmd =
        /(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\s/i.test(
          command
        );

      if (isInstallCmd) {
        const pkgResult = await filterPackageInstall(command);
        if (!pkgResult.allowed) {
          return {
            allowed: false,
            packageFilterResult: pkgResult,
            message: `Package installation blocked: ${pkgResult.reason}`,
          };
        }
      }

      // Run command filter
      const cmdResult = filterCommand(command, commandContext);
      if (!cmdResult.allowed) {
        return {
          allowed: false,
          commandFilterResult: cmdResult,
          message: cmdResult.message,
        };
      }

      return {
        allowed: true,
        commandFilterResult: cmdResult,
      };
    }

    // For file_write, check for secrets in content
    if (toolName === "file_write" && typeof toolInput.content === "string") {
      const secretCheck = detectSecrets(toolInput.content);
      if (secretCheck.detections.length > 0 && this.eventHandler) {
        this.eventHandler({
          type: "SECRET_DETECTED",
          details: {
            tool: "file_write",
            path: toolInput.path,
            secretTypes: secretCheck.detections.map((d) => d.type),
          },
          timestamp: new Date().toISOString(),
          sessionId: context.sessionId,
        });
      }
      // We allow the write but log it; the secrets are in generated code,
      // which may be intentional (e.g., .env.example patterns)
    }

    return { allowed: true };
  }

  // ── Trajectory monitoring ─────────────────────────────────────────────────

  getOrCreateMonitor(sessionId: string): TrajectoryMonitor {
    let monitor = this.monitors.get(sessionId);
    if (!monitor) {
      monitor = new TrajectoryMonitor(sessionId);
      this.monitors.set(sessionId, monitor);
    }
    return monitor;
  }

  recordTurn(sessionId: string, turn: TurnData): RiskAssessment {
    const monitor = this.getOrCreateMonitor(sessionId);
    const assessment = monitor.addTurn(turn);

    if (assessment.level === "FLAGGED" && this.eventHandler) {
      this.eventHandler({
        type: "SESSION_FLAGGED",
        details: { score: assessment.score, reason: assessment.reason },
        timestamp: new Date().toISOString(),
        sessionId,
      });
    }
    if (assessment.level === "PAUSED" && this.eventHandler) {
      this.eventHandler({
        type: "SESSION_PAUSED",
        details: { score: assessment.score, reason: assessment.reason },
        timestamp: new Date().toISOString(),
        sessionId,
      });
    }

    return assessment;
  }

  resumeSession(sessionId: string): boolean {
    const monitor = this.monitors.get(sessionId);
    if (!monitor) return false;
    monitor.resume();
    return true;
  }

  removeSession(sessionId: string): void {
    this.monitors.delete(sessionId);
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  getStats(): {
    commandStats: ReturnType<typeof getSecurityStats>;
    firewall: { totalChecked: number; blocked: number; flagged: number };
    activeSessions: Array<{
      sessionId: string;
      score: number;
      level: string;
    }>;
  } {
    const activeSessions: Array<{
      sessionId: string;
      score: number;
      level: string;
    }> = [];
    for (const [id, monitor] of this.monitors) {
      activeSessions.push({
        sessionId: id,
        score: monitor.getScore(),
        level: monitor.getLevel(),
      });
    }
    return {
      commandStats: getSecurityStats(),
      firewall: { ...this.firewallCounts },
      activeSessions,
    };
  }
}

// Re-export individual modules for direct access
export { evaluateInput } from "./input-firewall";
export { filterCommand, getSecurityStats, getSecurityLogs } from "./output-filter";
export { filterPackageInstall } from "./package-filter";
export { detectSecrets, shannonEntropy, setRedisClient as setSecretRedisClient } from "./secret-detector";
export { TrajectoryMonitor } from "./trajectory-monitor";
export type { FirewallResult } from "./input-firewall";
export type { FilterResult as CommandFilterResult, CommandLogEntry, CommandContext } from "./output-filter";
export type { BlockedPackage, PackageFilterResult } from "./package-filter";
export type { SecretDetection, SecretDetectorResult } from "./secret-detector";
export type { TurnData, RiskAssessment } from "./trajectory-monitor";
export { analyzeForInjection, hardenSystemPrompt, getCanaryTokens } from "./prompt-injection-detector";
export type { InjectionAnalysis, DetectedAttack, AttackCategory } from "./prompt-injection-detector";
export { classifyIntent } from "./intent-classifier";
export type { IntentClassification, IntentCategory, IntentSignal } from "./intent-classifier";
