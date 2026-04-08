// src/server/security/trajectory-monitor.ts
// Conversation trajectory risk scoring — per-session risk state

export interface TurnData {
  turnNumber: number;
  userMessage: string;
  toolCalls: Array<{
    tool: string;
    input: Record<string, any>;
    verdict?: "BLOCK" | "ALERT" | "PASS";
  }>;
  agentResponse: string;
}

export interface RiskAssessment {
  score: number;
  level: "NORMAL" | "FLAGGED" | "PAUSED";
  reason: string;
  turnNumber: number;
  shouldPause: boolean;
}

// ── Keywords and constants ──────────────────────────────────────────────────

const SECURITY_ADJACENT_KEYWORDS = [
  "root", "sudo", "privilege", "escalat", "bypass", "override",
  "injection", "exploit", "vulnerability", "hack", "crack",
  "reverse shell", "backdoor", "payload", "metasploit",
];

const DISABLE_SECURITY_PHRASES = [
  "undo security", "disable security", "turn off security",
  "remove security", "bypass security", "skip security",
  "ignore security", "disable filter", "disable firewall",
  "turn off filter", "remove filter", "bypass filter",
  "disable check", "skip check", "remove check",
];

const SYSTEM_INTERNAL_PATTERNS = [
  /\/proc\//,
  /\/sys\//,
  /\/etc\/(passwd|shadow|hosts|sudoers)/,
  /docker\.sock/,
  /kubernetes/i,
  /kube-system/,
  /\.kube\/config/,
  /\/var\/run\/docker/,
];

const NORMAL_DEV_PATTERNS = [
  /file_write.*\/workspace\/src\//,
  /npm\s+install\s+(react|express|lodash|axios|typescript|tailwindcss|next|vite)/i,
  /npm\s+run\s+(dev|build|start|test|lint)/i,
  /git\s+(init|add|commit|status|diff)/i,
  /mkdir\s+.*\/workspace\//,
  /cat\s+.*\/workspace\//,
];

const EVALUATION_INTERVAL = 5;

// ── TrajectoryMonitor class ─────────────────────────────────────────────────

export class TrajectoryMonitor {
  private sessionId: string;
  private score: number = 0;
  private turns: TurnData[] = [];
  private assessments: RiskAssessment[] = [];
  private isPaused: boolean = false;

  constructor(sessionId: string) {
    this.sessionId = sessionId;
  }

  addTurn(turn: TurnData): RiskAssessment {
    this.turns.push(turn);

    // Evaluate every EVALUATION_INTERVAL turns
    if (this.turns.length % EVALUATION_INTERVAL === 0) {
      this.evaluateWindow();
    } else {
      // Lightweight per-turn adjustments
      this.adjustPerTurn(turn);
    }

    // Clamp score
    this.score = Math.max(0, Math.min(1.0, this.score));

    const level = this.computeLevel();
    const assessment: RiskAssessment = {
      score: this.score,
      level,
      reason: this.buildReason(level),
      turnNumber: turn.turnNumber,
      shouldPause: level === "PAUSED",
    };

    this.assessments.push(assessment);

    if (level === "PAUSED") {
      this.isPaused = true;
    }

    return assessment;
  }

  getScore(): number {
    return this.score;
  }

  getLevel(): "NORMAL" | "FLAGGED" | "PAUSED" {
    return this.computeLevel();
  }

  getSessionId(): string {
    return this.sessionId;
  }

  isPausedState(): boolean {
    return this.isPaused;
  }

  reset(): void {
    this.score = 0;
    this.turns = [];
    this.assessments = [];
    this.isPaused = false;
  }

  resume(): void {
    this.isPaused = false;
    // Reduce score slightly on manual resume
    this.score = Math.max(0, this.score - 0.2);
  }

  // ── Private methods ─────────────────────────────────────────────────────

  private adjustPerTurn(turn: TurnData): void {
    const combined = `${turn.userMessage} ${turn.agentResponse}`;
    const lower = combined.toLowerCase();

    // Security-adjacent keywords
    for (const keyword of SECURITY_ADJACENT_KEYWORDS) {
      if (lower.includes(keyword)) {
        this.score += 0.02; // Light touch per-turn
        break;
      }
    }

    // Blocked command in this turn
    const hasBlock = turn.toolCalls.some((tc) => tc.verdict === "BLOCK");
    if (hasBlock) {
      this.score += 0.05;
    }

    // Normal dev activity reduces score
    const toolInputs = turn.toolCalls
      .map((tc) => `${tc.tool} ${JSON.stringify(tc.input)}`)
      .join(" ");
    for (const pattern of NORMAL_DEV_PATTERNS) {
      if (pattern.test(toolInputs) || pattern.test(turn.userMessage)) {
        this.score -= 0.01;
        break;
      }
    }

    this.score = Math.max(0, Math.min(1.0, this.score));
  }

  private evaluateWindow(): void {
    const windowSize = EVALUATION_INTERVAL;
    const recentTurns = this.turns.slice(-windowSize);

    let windowDelta = 0;

    for (const turn of recentTurns) {
      const combined = `${turn.userMessage} ${turn.agentResponse}`;
      const lower = combined.toLowerCase();

      // +0.1 per turn with security-adjacent keywords
      for (const keyword of SECURITY_ADJACENT_KEYWORDS) {
        if (lower.includes(keyword)) {
          windowDelta += 0.1;
          break; // count once per turn
        }
      }

      // +0.2 if a command was BLOCKED
      const hasBlock = turn.toolCalls.some((tc) => tc.verdict === "BLOCK");
      if (hasBlock) {
        windowDelta += 0.2;
      }

      // +0.3 if user asks to undo/disable security
      for (const phrase of DISABLE_SECURITY_PHRASES) {
        if (lower.includes(phrase)) {
          windowDelta += 0.3;
          break;
        }
      }

      // +0.15 if references system internals
      for (const pattern of SYSTEM_INTERNAL_PATTERNS) {
        if (pattern.test(combined)) {
          windowDelta += 0.15;
          break;
        }
      }

      // -0.05 for normal dev activity
      const toolInputs = turn.toolCalls
        .map((tc) => `${tc.tool} ${JSON.stringify(tc.input)}`)
        .join(" ");
      let isNormalDev = false;
      for (const pattern of NORMAL_DEV_PATTERNS) {
        if (pattern.test(toolInputs) || pattern.test(turn.userMessage)) {
          isNormalDev = true;
          break;
        }
      }
      if (isNormalDev) {
        windowDelta -= 0.05;
      }
    }

    this.score += windowDelta;
    this.score = Math.max(0, Math.min(1.0, this.score));
  }

  private computeLevel(): "NORMAL" | "FLAGGED" | "PAUSED" {
    if (this.isPaused || this.score > 0.7) return "PAUSED";
    if (this.score > 0.4) return "FLAGGED";
    return "NORMAL";
  }

  private buildReason(level: "NORMAL" | "FLAGGED" | "PAUSED"): string {
    switch (level) {
      case "PAUSED":
        return `Session paused for security review. Risk score: ${this.score.toFixed(2)}. Session: ${this.sessionId}`;
      case "FLAGGED":
        return `Session flagged for increased monitoring. Risk score: ${this.score.toFixed(2)}. Session: ${this.sessionId}`;
      case "NORMAL":
        return `Normal activity. Risk score: ${this.score.toFixed(2)}`;
    }
  }
}
