// src/server/routes/security.ts
// Security test endpoints + scanning API + runtime alert webhooks

import { Router, Request, Response } from "express";
import { SecurityLayer } from "../security/index";
import { evaluateInput } from "../security/input-firewall";
import { filterCommand, getSecurityStats } from "../security/output-filter";
import { filterPackageInstall } from "../security/package-filter";
import { detectSecrets } from "../security/secret-detector";
import { scanWorkspace, scanPlatform } from "../security/scanner";
import { analyzeForInjection } from "../security/prompt-injection-detector";
import { generateSbom } from "../security/sbom-generator";
import { classifyIntent } from "../security/intent-classifier";
import { readFileFromWorkspace } from "../services/workspace";
import { PrismaClient } from "@prisma/client";
import { requireRole } from "../middleware/auth";
import type { EventBus } from "../events/event-bus";
import type { SiemRulesEngine } from "../security/siem-rules-engine";

const prisma = new PrismaClient();

const router = Router();

// Singleton security layer instance — in production, inject via DI
let securityLayer: SecurityLayer | null = null;
let eventBus: EventBus | null = null;

export function setSecurityLayer(layer: SecurityLayer): void {
  securityLayer = layer;
}

export function setEventBus(bus: EventBus): void {
  eventBus = bus;
}

// Internal helper — bypasses ownership check. Only for test endpoints that don't take a real projectId.
function _internalContainerName(projectId: string): string {
  return `devfactory-v2-ws-${projectId}`;
}

// Ownership-verified container lookup — ensures the project belongs to the caller's org.
async function getVerifiedContainer(
  projectId: string,
  orgId: string
): Promise<{ containerName: string } | { error: string; status: number }> {
  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId },
  });
  if (!project) {
    return { error: "Project not found", status: 404 };
  }
  return { containerName: `devfactory-v2-ws-${projectId}` };
}

// ── POST /api/security/test-input ───────────────────────────────────────────
// Test input firewall with a sample prompt.
// Body: { "input": "string" }
router.post("/test-input", (req: Request, res: Response) => {
  const { input } = req.body;
  if (typeof input !== "string" || input.length === 0) {
    return res.status(400).json({ error: "input is required and must be a non-empty string" });
  }
  if (input.length > 50_000) {
    return res.status(400).json({ error: "input exceeds maximum length of 50000 characters" });
  }

  try {
    const firewallResult = evaluateInput(input);
    const secretsResult = detectSecrets(input);

    return res.json({
      firewall: {
        blocked: firewallResult.blocked,
        score: firewallResult.score,
        reason: firewallResult.reason,
        tier: firewallResult.tier,
        matchedPatterns: firewallResult.matchedPatterns,
      },
      secrets: {
        detected: secretsResult.detections.length > 0,
        count: secretsResult.detections.length,
        types: secretsResult.detections.map((d) => d.type),
        sanitizedPreview: secretsResult.sanitized.substring(0, 200),
      },
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Internal error: ${err.message}` });
  }
});

// ── POST /api/security/test-command ─────────────────────────────────────────
// Test output filter with a sample command.
// Body: { "command": "string", "projectId"?: "string", "userId"?: "string" }
router.post("/test-command", (req: Request, res: Response) => {
  const { command, projectId, userId } = req.body;
  if (typeof command !== "string" || command.length === 0) {
    return res.status(400).json({ error: "command is required and must be a non-empty string" });
  }
  if (command.length > 10_000) {
    return res.status(400).json({ error: "command exceeds maximum length of 10000 characters" });
  }

  try {
    const result = filterCommand(command, {
      projectId: projectId || "test-project",
      userId: userId || "test-user",
      conversationTurn: 0,
      containerName: "test-container",
    });

    return res.json({
      allowed: result.allowed,
      verdict: result.verdict,
      pattern: result.pattern || null,
      message: result.message || null,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Internal error: ${err.message}` });
  }
});

// ── POST /api/security/test-package ─────────────────────────────────────────
// Test package filter with a package install command.
// Body: { "command": "string" } — e.g., "npm install some-package"
router.post("/test-package", async (req: Request, res: Response) => {
  const { command } = req.body;
  if (typeof command !== "string" || command.length === 0) {
    return res.status(400).json({ error: "command is required and must be a non-empty string" });
  }

  try {
    const result = await filterPackageInstall(command);

    return res.json({
      allowed: result.allowed,
      blockedPackages: result.blockedPackages,
      reason: result.reason || null,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Internal error: ${err.message}` });
  }
});

// ── GET /api/security/stats ─────────────────────────────────────────────────
// Return security statistics.
router.get("/stats", (req: Request, res: Response) => {
  try {
    const commandStats = getSecurityStats();

    const activeSessions: Array<{
      sessionId: string;
      score: number;
      level: string;
    }> = [];

    let firewallStats = { totalChecked: 0, blocked: 0, flagged: 0 };
    if (securityLayer) {
      const layerStats = securityLayer.getStats();
      activeSessions.push(...layerStats.activeSessions);
      firewallStats = layerStats.firewall || firewallStats;
    }

    // Fetch recent block events from SIEM for block-reason visibility
    const siemEngine: SiemRulesEngine | undefined = req.app.get("siemEngine");
    let recentBlocks: Array<{ timestamp: string; item: string; reason: string; severity: string }> = [];
    if (siemEngine) {
      const alerts = siemEngine.getAlerts(50);
      recentBlocks = alerts
        .filter((a: any) => a.level >= 8)
        .slice(0, 20)
        .map((a: any) => ({
          timestamp: a.timestamp || new Date().toISOString(),
          item: a.data?.command?.substring(0, 80) || a.data?.inputPreview?.substring(0, 80) || a.ruleName || "unknown",
          reason: a.ruleName || a.ruleId || "Security policy",
          severity: a.level >= 12 ? "critical" : a.level >= 8 ? "high" : "medium",
        }));
    }

    return res.json({
      // Shape expected by SecurityDashboard.tsx
      inputFirewall: {
        totalChecked: firewallStats.totalChecked,
        blocked: firewallStats.blocked,
        flagged: firewallStats.flagged,
        topPatterns: commandStats.topBlockedPatterns.slice(0, 10),
      },
      outputFilter: {
        totalChecked: commandStats.totalBlocks + commandStats.totalAlerts + commandStats.totalPass,
        blocked: commandStats.totalBlocks,
        alerted: commandStats.totalAlerts,
        topBlocked: commandStats.topBlockedPatterns.slice(0, 10),
      },
      trajectoryMonitor: {
        activeSessions: activeSessions.length,
        flaggedSessions: activeSessions.filter((s) => s.level === "FLAGGED").length,
        pausedSessions: activeSessions.filter((s) => s.level === "PAUSED").length,
      },
      recentBlocks,
      // Raw data for backward compatibility
      commands: {
        totalBlocks: commandStats.totalBlocks,
        totalAlerts: commandStats.totalAlerts,
        totalPass: commandStats.totalPass,
        topBlockedPatterns: commandStats.topBlockedPatterns,
      },
      sessions: {
        activeCount: activeSessions.length,
        sessions: activeSessions,
        flaggedCount: activeSessions.filter((s) => s.level === "FLAGGED").length,
        pausedCount: activeSessions.filter((s) => s.level === "PAUSED").length,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Internal error: ${err.message}` });
  }
});

// ── POST /api/security/test-injection ─────────────────────────────────────────
// Deep prompt injection analysis.
// Body: { "input": "string", "history"?: [{ "role": "user"|"assistant", "content": "string" }] }
router.post("/test-injection", (req: Request, res: Response) => {
  const { input, history } = req.body;
  if (typeof input !== "string" || input.length === 0) {
    return res.status(400).json({ error: "input is required" });
  }

  try {
    const analysis = analyzeForInjection(input, {
      history: Array.isArray(history) ? history : undefined,
      turnNumber: Array.isArray(history) ? history.length : 0,
    });

    return res.json({
      blocked: analysis.blocked,
      riskScore: analysis.riskScore,
      recommendation: analysis.recommendation,
      canaryTriggered: analysis.canaryTriggered,
      attacks: analysis.attacks.map((a) => ({
        vector: a.vector,
        category: a.category,
        severity: a.severity,
        evidence: a.evidence,
        mitre: a.mitre,
        cwe: a.cwe,
      })),
      attackCount: analysis.attacks.length,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Analysis failed: ${err.message}` });
  }
});

// ── POST /api/security/classify-intent ────────────────────────────────────────
// Deep intent classification — goes beyond regex to detect semantic attack patterns.
// Body: { "input": "string", "history"?: [{ "role": "user"|"assistant", "content": "string" }] }
router.post("/classify-intent", (req: Request, res: Response) => {
  const { input, history } = req.body;
  if (typeof input !== "string" || input.length === 0) {
    return res.status(400).json({ error: "input is required" });
  }

  try {
    const classification = classifyIntent(input, {
      history: Array.isArray(history) ? history : undefined,
    });

    return res.json({
      primaryIntent: classification.primaryIntent,
      confidence: classification.confidence,
      riskScore: classification.riskScore,
      recommendation: classification.recommendation,
      explanation: classification.explanation,
      signals: classification.signals.map((s) => ({
        source: s.source,
        category: s.category,
        confidence: s.confidence,
        evidence: s.evidence,
      })),
      signalCount: classification.signals.length,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Classification failed: ${err.message}` });
  }
});

// ── POST /api/security/scan/:projectId ────────────────────────────────────────
// Run a full security scan on a workspace project.
router.post("/scan/:projectId", requireRole("admin", "member"), async (req: Request, res: Response) => {
  const { projectId } = req.params;
  const options = req.body || {};

  try {
    const containerResult = await getVerifiedContainer(projectId, req.user!.orgId);
    if ("error" in containerResult) {
      return res.status(containerResult.status).json({ error: containerResult.error });
    }
    const containerName = containerResult.containerName;
    const result = await scanWorkspace(projectId, containerName, {
      sast: options.sast !== false,
      sca: options.sca !== false,
      secrets: options.secrets !== false,
      sbom: options.sbom !== false,
      image: options.image === true,
    });

    // Emit scan completed event
    if (eventBus) {
      await eventBus.emit("security", "security.scan_completed", {
        projectId,
        verdict: result.verdict,
        criticalFindings: result.summary.criticalFindings,
        totalFindings: result.summary.totalFindings,
        tools: [
          result.sast ? "sast" : null,
          result.sca ? "sca" : null,
          result.secrets ? "secrets" : null,
          result.sbom ? "sbom" : null,
          result.image ? "image" : null,
        ].filter(Boolean),
      }, req.correlationId);
    }

    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ error: `Scan failed: ${err.message}` });
  }
});

// ── GET /api/security/sbom/:projectId ─────────────────────────────────────────
// Generate and return CycloneDX SBOM for a workspace project.
router.get("/sbom/:projectId", requireRole("admin", "member"), async (req: Request, res: Response) => {
  const { projectId } = req.params;

  try {
    const containerResult = await getVerifiedContainer(projectId, req.user!.orgId);
    if ("error" in containerResult) {
      return res.status(containerResult.status).json({ error: containerResult.error });
    }
    const containerName = containerResult.containerName;
    const pkgJson = await readFileFromWorkspace(containerName, "/workspace/package.json");
    let lockJson: string | undefined;
    try {
      lockJson = await readFileFromWorkspace(containerName, "/workspace/package-lock.json");
    } catch {}

    const result = generateSbom(pkgJson, lockJson);

    res.setHeader("Content-Type", "application/json");
    return res.json(result.bom);
  } catch (err: any) {
    return res.status(500).json({ error: `SBOM generation failed: ${err.message}` });
  }
});

// ── GET /api/security/scan/platform ───────────────────────────────────────────
// Self-scan the DevFactory platform source code.
router.get("/scan/platform", requireRole("admin"), async (_req: Request, res: Response) => {
  try {
    const result = await scanPlatform();
    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ error: `Platform scan failed: ${err.message}` });
  }
});

// ── POST /api/security/falco-webhook ──────────────────────────────────────────
// Receives Falco alerts via falcosidekick webhook.
router.post("/falco-webhook", async (req: Request, res: Response) => {
  const alert = req.body;

  if (eventBus) {
    await eventBus.emit("security", "security.runtime_alert", {
      source: "falco",
      rule: alert.rule || "unknown",
      severity: alert.priority || "WARNING",
      pod: alert.output_fields?.["k8s.pod.name"] || "unknown",
      details: {
        output: alert.output,
        tags: alert.tags,
        time: alert.time,
        fields: alert.output_fields,
      },
    }, req.correlationId);
  }

  return res.status(200).json({ received: true });
});

// ── POST /api/security/alert-webhook ──────────────────────────────────────────
// Receives Prometheus AlertManager alerts.
router.post("/alert-webhook", async (req: Request, res: Response) => {
  const { alerts } = req.body || {};

  if (Array.isArray(alerts) && eventBus) {
    for (const alert of alerts) {
      await eventBus.emit("security", "security.runtime_alert", {
        source: "alertmanager",
        rule: alert.labels?.alertname || "unknown",
        severity: alert.labels?.severity || "warning",
        pod: alert.labels?.pod || "unknown",
        details: {
          status: alert.status,
          annotations: alert.annotations,
          startsAt: alert.startsAt,
          endsAt: alert.endsAt,
        },
      }, req.correlationId);
    }
  }

  return res.status(200).json({ received: true, count: alerts?.length || 0 });
});

// ── GET /api/security/siem/alerts ─────────────────────────────────────────────
// Return SIEM alerts from the built-in rules engine.
router.get("/siem/alerts", requireRole("admin"), (req: Request, res: Response) => {
  const siemEngine: SiemRulesEngine | undefined = req.app.get("siemEngine");
  if (!siemEngine) {
    return res.status(503).json({ error: "SIEM engine not running" });
  }

  const minLevel = parseInt(req.query.minLevel as string) || 0;
  const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);

  const alerts = minLevel > 0
    ? siemEngine.getAlertsByLevel(minLevel)
    : siemEngine.getAlerts(limit);

  return res.json({ alerts, count: alerts.length });
});

// ── GET /api/security/siem/stats ──────────────────────────────────────────────
// Return SIEM alert statistics.
router.get("/siem/stats", requireRole("admin"), (req: Request, res: Response) => {
  const siemEngine: SiemRulesEngine | undefined = req.app.get("siemEngine");
  if (!siemEngine) {
    return res.status(503).json({ error: "SIEM engine not running" });
  }

  return res.json(siemEngine.getStats());
});

export default router;
