import express from "express";
import cors from "cors";
import { createServer } from "http";
import Redis from "ioredis";

import { authMiddleware } from "./middleware/auth";
import { rateLimiter } from "./middleware/rate-limiter";
import { correlationMiddleware } from "./middleware/correlation";
import { metricsMiddleware, httpMetricsMiddleware, metrics } from "./observability/metrics";
import { initTracing } from "./observability/tracing";
import { createLogger } from "./observability/logger";
import { EventBus } from "./events/event-bus";
import { AuditLogger } from "./events/audit-logger";

import authRouter from "./routes/auth";
import projectRouter from "./routes/project";
import workspaceRouter from "./routes/workspace";
import agentRouter, { createLLMRouter } from "./routes/agent";
import filesRouter from "./routes/files";
import billingRouter from "./routes/billing";
import securityRouter, { setEventBus as setSecurityEventBus, setSecurityLayer as setSecurityRouteLayer } from "./routes/security";
import { SecurityLayer } from "./security/index";
import deployRouter from "./routes/deploy";
import { BehavioralDetector } from "./security/behavioral-detector";
import { IncidentResponder } from "./security/incident-response";
import { RuntimeCorrelator } from "./security/runtime-correlator";
import { SiemRulesEngine } from "./security/siem-rules-engine";

// Initialize tracing first
initTracing();

const app = express();
const server = createServer(app);
const logger = createLogger("server");
const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6480");

// Initialize event bus
const eventBus = new EventBus(process.env.REDIS_URL || "redis://localhost:6480");
const auditLogger = new AuditLogger(eventBus);

// Make event bus available to routes
app.set("eventBus", eventBus);
app.set("redis", redis);
setSecurityEventBus(eventBus);

// Share a SecurityLayer instance with security routes so /api/security/stats
// reflects the same firewall counts and session data as the agent loop.
const sharedSecurityLayer = new SecurityLayer(redis as any);
setSecurityRouteLayer(sharedSecurityLayer);

// Global middleware
app.use(cors({ origin: ["http://localhost:3100"], credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(correlationMiddleware);

// HTTP metrics (before routes, after CORS/JSON parsing)
app.use(httpMetricsMiddleware());

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    logger.info({
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - start,
      correlationId: req.correlationId,
      userId: req.user?.id,
    });
  });
  next();
});

// Routes
app.use("/api/auth", authRouter);
app.use("/api/projects", authMiddleware(), rateLimiter("project"), projectRouter);
app.use("/api/workspaces", authMiddleware(), rateLimiter("workspace"), workspaceRouter);
app.use("/api/agent", authMiddleware(), rateLimiter("agent"), agentRouter);
app.use("/api/files", authMiddleware(), filesRouter);
app.use("/api/billing", authMiddleware(), billingRouter);
app.use("/api/security", authMiddleware(), rateLimiter("security"), securityRouter);
app.use("/api/deploy", authMiddleware(), rateLimiter("deploy"), deployRouter);

// Metrics endpoint (no auth — for Prometheus scraping)
app.get("/metrics", metricsMiddleware());

// Health check
app.get("/api/health", (_, res) => {
  res.json({
    status: "ok",
    version: process.env.npm_package_version || "0.0.0",
    uptime: process.uptime(),
    services: {
      redis: redis.status === "ready" ? "ok" : "error",
    },
  });
});

// 404 handler — return JSON, not Express default HTML
app.use((req: express.Request, res: express.Response) => {
  res.status(404).json({ error: "Not found", path: req.path, correlationId: req.correlationId });
});

// Error handler
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  // JSON parse errors from express.json() middleware
  if (err.type === "entity.parse.failed" || (err instanceof SyntaxError && "body" in err)) {
    res.status(400).json({ error: "Invalid JSON in request body", correlationId: req.correlationId });
    return;
  }
  logger.error({ err, correlationId: req.correlationId }, "Unhandled error");
  res.status(500).json({ error: "Internal server error", correlationId: req.correlationId });
});

// Graceful shutdown
async function shutdown() {
  logger.info("Shutting down...");
  auditLogger.stop();
  await redis.quit();
  server.close();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// Eagerly create LLM router so behavioral detector can use it at startup
const llmRouter = createLLMRouter(redis, eventBus);

// Start behavioral detector if enabled
let behavioralDetector: BehavioralDetector | null = null;
if (process.env.BEHAVIORAL_DETECTION_ENABLED === "true") {
  behavioralDetector = new BehavioralDetector(eventBus, llmRouter);
  behavioralDetector.start();
  logger.info("Behavioral detector started at boot");
}

// Start incident responder and runtime correlator
const incidentResponder = new IncidentResponder(eventBus);
incidentResponder.start();

const runtimeCorrelator = new RuntimeCorrelator(eventBus);
runtimeCorrelator.start();

// Start SIEM rules engine (lightweight replacement for Wazuh on ARM64)
const siemEngine = new SiemRulesEngine(eventBus);
siemEngine.start();
app.set("siemEngine", siemEngine);

// Health metrics — report uptime and connection status every 15s
setInterval(() => {
  metrics.appUptime.set(process.uptime());
  metrics.redisConnectionStatus.set(redis.status === "ready" ? 1 : 0);
}, 15_000);

const PORT = process.env.API_PORT || 4100;
server.listen(PORT, () => {
  auditLogger.start();

  logger.info(`Backend API running on http://localhost:${PORT}`);
  logger.info(`Keycloak: ${process.env.KEYCLOAK_URL || "http://localhost:8280"}`);
  logger.info(`Jaeger: http://localhost:16786`);
  logger.info(`Prometheus: http://localhost:9190`);
});
