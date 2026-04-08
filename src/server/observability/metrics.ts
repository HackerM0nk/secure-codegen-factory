import client, {
  Counter,
  Histogram,
  Gauge,
  Registry,
  collectDefaultMetrics,
} from "prom-client";
import { Request, Response, NextFunction } from "express";

const register = client.register;

// Collect default Node.js metrics (event loop lag, heap, etc.)
collectDefaultMetrics({ register });

// ── Counters ─────────────────────────────────────────────────────────

const agentIterationsTotal = new Counter({
  name: "agent_iterations_total",
  help: "Total agent loop iterations",
  labelNames: ["project_id", "status"] as const,
});

const llmTokensTotal = new Counter({
  name: "llm_tokens_total",
  help: "Total LLM tokens processed",
  labelNames: ["model", "direction"] as const, // direction: input | output
});

const securityBlocksTotal = new Counter({
  name: "security_blocks_total",
  help: "Total security blocks triggered",
  labelNames: ["category", "pattern"] as const,
});

const behavioralDetectionsTotal = new Counter({
  name: "behavioral_detections_total",
  help: "Total behavioral LLM-based detections",
  labelNames: ["classification"] as const, // NORMAL | SUSPICIOUS | MALICIOUS
});

const siemAlertsTotal = new Counter({
  name: "siem_alerts_total",
  help: "Total SIEM rule alerts fired",
  labelNames: ["rule", "severity"] as const,
});

const scanFindingsTotal = new Counter({
  name: "scan_findings_total",
  help: "Total security scan findings",
  labelNames: ["tool", "severity"] as const, // tool: sast|sca|secrets|image, severity: critical|high|medium|low
});

const creditsConsumedTotal = new Counter({
  name: "credits_consumed_total",
  help: "Total billing credits consumed",
  labelNames: ["model"] as const,
});

const toolExecutionsTotal = new Counter({
  name: "tool_executions_total",
  help: "Total tool executions",
  labelNames: ["tool", "status"] as const,
});

// ── Histograms ───────────────────────────────────────────────────────

const llmCallDuration = new Histogram({
  name: "llm_call_duration_seconds",
  help: "LLM call duration in seconds",
  labelNames: ["model", "provider"] as const,
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60],
});

const toolExecutionDuration = new Histogram({
  name: "tool_execution_duration_seconds",
  help: "Tool execution duration in seconds",
  labelNames: ["tool"] as const,
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30],
});

const workspaceCreationDuration = new Histogram({
  name: "workspace_creation_duration_seconds",
  help: "Workspace container creation duration in seconds",
  buckets: [0.5, 1, 2, 5, 10, 20, 30],
});

const agentSessionDuration = new Histogram({
  name: "agent_session_duration_seconds",
  help: "Total agent session duration in seconds",
  buckets: [1, 5, 10, 30, 60, 120, 300, 600],
});

// ── Gauges ───────────────────────────────────────────────────────────

const activeWorkspaces = new Gauge({
  name: "active_workspaces",
  help: "Number of active workspace containers",
});

const activeAgentSessions = new Gauge({
  name: "active_agent_sessions",
  help: "Number of active agent sessions",
});

const providerHealthScore = new Gauge({
  name: "provider_health_score",
  help: "LLM provider health score",
  labelNames: ["provider"] as const,
});

// ── HTTP Request Metrics ─────────────────────────────────────────────

const httpRequestsTotal = new Counter({
  name: "http_requests_total",
  help: "Total HTTP requests",
  labelNames: ["method", "path", "status_code"] as const,
});

const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "path", "status_code"] as const,
  buckets: [0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10],
});

const httpActiveRequests = new Gauge({
  name: "http_active_requests",
  help: "Number of active HTTP requests",
});

// ── Application Health ──────────────────────────────────────────────

const appUptime = new Gauge({
  name: "app_uptime_seconds",
  help: "Application uptime in seconds",
});

const redisConnectionStatus = new Gauge({
  name: "redis_connection_status",
  help: "Redis connection status (1=connected, 0=disconnected)",
});

const dbConnectionStatus = new Gauge({
  name: "db_connection_status",
  help: "Database connection status (1=connected, 0=disconnected)",
});

const securityTrajectoryScore = new Gauge({
  name: "security_trajectory_score",
  help: "Maximum trajectory risk score across active sessions",
});

const eventBusLag = new Gauge({
  name: "event_bus_consumer_lag",
  help: "Event bus consumer lag (pending messages)",
  labelNames: ["stream", "group"] as const,
});

// ── Exports ──────────────────────────────────────────────────────────

export const metrics = {
  // Counters
  agentIterationsTotal,
  llmTokensTotal,
  securityBlocksTotal,
  behavioralDetectionsTotal,
  siemAlertsTotal,
  scanFindingsTotal,
  creditsConsumedTotal,
  toolExecutionsTotal,
  // Histograms
  llmCallDuration,
  toolExecutionDuration,
  workspaceCreationDuration,
  agentSessionDuration,
  // Gauges
  activeWorkspaces,
  activeAgentSessions,
  providerHealthScore,
  // HTTP
  httpRequestsTotal,
  httpRequestDuration,
  httpActiveRequests,
  securityTrajectoryScore,
  // App health
  appUptime,
  redisConnectionStatus,
  dbConnectionStatus,
  eventBusLag,
};

export function metricsMiddleware() {
  return async (_req: Request, res: Response, _next: NextFunction) => {
    try {
      const data = await register.metrics();
      res.set("Content-Type", register.contentType);
      res.end(data);
    } catch (err) {
      res.status(500).end("Error collecting metrics");
    }
  };
}

/**
 * Middleware that records HTTP request metrics (total, duration, active).
 * Mount early — before routes.
 */
export function httpMetricsMiddleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    // Normalize path to avoid cardinality explosion (strip IDs)
    const basePath = req.route?.path || req.path.replace(/\/[0-9a-f-]{20,}/g, "/:id");
    httpActiveRequests.inc();
    const end = httpRequestDuration.startTimer();

    res.on("finish", () => {
      const labels = {
        method: req.method,
        path: basePath,
        status_code: String(res.statusCode),
      };
      httpRequestsTotal.inc(labels);
      end(labels);
      httpActiveRequests.dec();
    });

    next();
  };
}
