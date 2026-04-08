// src/server/routes/agent.ts
// POST message endpoint with SSE streaming and security integration

import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { runAgentLoop, type AgentEvent } from "../services/agent-loop";
import { SecurityLayer } from "../security/index";
import { LLMRouter } from "../llm/router";
import { CacheAffinity } from "../llm/cache-affinity";
import { HealthScorer } from "../llm/health-scorer";
import { BedrockProvider } from "../llm/providers/bedrock";
import { AnthropicProvider } from "../llm/providers/anthropic";
import { OpenAICompatProvider } from "../llm/providers/openai-compat";
import { EventBus } from "../events/event-bus";
import { EVENT_TYPES } from "../events/events";
import { reserveCredits, finalizeCredits, releaseReservation } from "../billing/ledger";
import { calculateLLMCost } from "../billing/credit-engine";
import { ValidationPipeline } from "../validation/pipeline";
import { createLogger } from "../observability/logger";
import { metrics } from "../observability/metrics";
import type Redis from "ioredis";

const router = Router();
const prisma = new PrismaClient();
const logger = createLogger("routes:agent");

// Lazy-initialized singletons
let securityLayerInstance: SecurityLayer | null = null;
let llmRouterInstance: LLMRouter | null = null;

/**
 * Create LLM router eagerly (called from index.ts at startup).
 * Also used lazily from getLLMRouter if not yet initialized.
 */
export function createLLMRouter(redis: Redis, eventBus: EventBus): LLMRouter {
  if (llmRouterInstance) return llmRouterInstance;

  const providers = (process.env.LLM_PROVIDERS || "bedrock").split(",").map((s) => s.trim());
  const llmProviders: any[] = [];

  if (providers.includes("bedrock")) llmProviders.push(new BedrockProvider());
  if (providers.includes("anthropic")) llmProviders.push(new AnthropicProvider());
  if (providers.includes("openai")) llmProviders.push(new OpenAICompatProvider("openai"));
  if (providers.includes("ollama")) {
    llmProviders.push(new OpenAICompatProvider("ollama", "http://localhost:11434/v1", "not-needed"));
  }

  const healthScorer = new HealthScorer(redis, providers, {
    bedrock: 50,
    anthropic: 40,
    openai: 60,
    ollama: 100,
  }, eventBus);
  const cacheAffinity = new CacheAffinity(redis);

  llmRouterInstance = new LLMRouter(llmProviders, healthScorer, cacheAffinity, eventBus);

  healthScorer.start().catch((err) => {
    logger.error({ error: err.message }, "Failed to start health scorer");
  });

  return llmRouterInstance;
}

function getSecurityLayer(req: Request): SecurityLayer {
  if (!securityLayerInstance) {
    const redis: Redis | undefined = req.app.get("redis");
    securityLayerInstance = new SecurityLayer(redis as any);
  }
  return securityLayerInstance;
}

function getLLMRouter(req: Request): LLMRouter {
  if (!llmRouterInstance) {
    const redis: Redis = req.app.get("redis");
    const eventBus: EventBus = req.app.get("eventBus");
    return createLLMRouter(redis, eventBus);
  }
  return llmRouterInstance;
}

// ── GET /api/agent/llm-health — LLM provider health scores ──────────────
// Defined BEFORE dynamic /:projectId routes to avoid shadowing

router.get("/llm-health", async (_req: Request, res: Response) => {
  if (!llmRouterInstance) {
    return res.json({ providers: [] });
  }
  try {
    const scores = await llmRouterInstance.getHealth();
    const providers = scores.map((s) => ({
      name: s.provider,
      score: s.score,
      weight: s.weight,
      rpm: s.rpm,
      rpmLimit: 0,
      errors: s.errors,
      successes: s.successes,
    }));
    return res.json({ providers });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── POST /api/agent/:projectId/message — Send message with SSE streaming ──

router.post("/:projectId/message", async (req: Request<{ projectId: string }>, res: Response) => {
  const projectId = req.params.projectId;
  const { message, conversationId } = req.body;
  const userId = req.user!.id;
  const orgId = req.user!.orgId;

  if (!message || typeof message !== "string" || message.trim().length === 0) {
    return res.status(400).json({ error: "message is required" });
  }

  // Get project and verify workspace is running
  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId },
  });
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }
  if (!project.containerName || project.status !== "running") {
    return res.status(400).json({ error: "Workspace not running. Start it first." });
  }

  // Get or create conversation
  let convId = conversationId;
  if (!convId) {
    const conversation = await prisma.conversation.create({
      data: { projectId },
    });
    convId = conversation.id;
  }

  // Load conversation history
  const previousMessages = await prisma.message.findMany({
    where: { conversationId: convId },
    orderBy: { createdAt: "asc" },
    take: 50,
  });

  // Convert DB messages to LLM format
  const conversationHistory = previousMessages.map((m) => {
    if (m.toolCalls) {
      return {
        role: m.role as "user" | "assistant",
        content: m.toolCalls as any,
      };
    }
    return {
      role: m.role as "user" | "assistant",
      content: m.content,
    };
  });

  // Save user message to DB
  await prisma.message.create({
    data: {
      conversationId: convId,
      userId,
      role: "user",
      content: message,
    },
  });

  // Reserve credits before LLM call
  let reservation;
  try {
    reservation = await reserveCredits(orgId, 5.0); // Reserve 5 credits max
  } catch (err: any) {
    return res.status(402).json({
      error: "Insufficient credits",
      message: err.message,
    });
  }

  // Set up SSE headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
    "X-Conversation-Id": convId,
  });

  let assistantText = "";
  const sendEvent = (event: AgentEvent) => {
    if (event.type === "text") {
      assistantText += event.data?.text || "";
    }
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  // Send conversation ID as first event
  sendEvent({
    type: "thinking",
    data: { conversationId: convId, projectId },
  });

  const eventBus: EventBus = req.app.get("eventBus");
  const securityLayer = getSecurityLayer(req);
  const llmRouter = getLLMRouter(req);
  const sessionId = `${projectId}:${convId}`;

  // Track active agent session
  metrics.activeAgentSessions.inc();
  const sessionStartTime = Date.now();

  try {
    const result = await runAgentLoop(
      project.containerName,
      message,
      conversationHistory,
      sendEvent,
      {
        projectId,
        userId,
        sessionId,
        securityLayer,
        llmRouter,
        eventBus,
        validationPipeline: new ValidationPipeline(eventBus),
      }
    );

    const { tokensUsed, inputTokens, outputTokens, model, provider } = result;

    // Calculate actual cost and finalize billing
    const cost = calculateLLMCost(model, inputTokens, outputTokens);
    await finalizeCredits(reservation, cost.totalCredits, {
      userId,
      projectId,
      eventType: "llm_call",
      model,
      tokensIn: inputTokens,
      tokensOut: outputTokens,
    });

    // Emit billing event
    await eventBus.emit("billing", EVENT_TYPES.BILLING_CREDITS_CONSUMED, {
      orgId,
      userId,
      projectId,
      amount: cost.totalCredits,
      model,
    });

    // Record billing metric
    metrics.creditsConsumedTotal.inc({ model }, cost.totalCredits);

    // Save assistant response with actual text content
    await prisma.message.create({
      data: {
        conversationId: convId,
        role: "assistant",
        content: assistantText || "[Agent completed task - no text output]",
        modelUsed: model,
        providerUsed: provider,
        tokenUsage: { input: inputTokens, output: outputTokens },
        creditsConsumed: cost.totalCredits,
      },
    });
  } catch (err: any) {
    // Release reservation on error
    if (reservation) {
      await releaseReservation(reservation).catch(() => {});
    }
    sendEvent({ type: "error", data: { message: err.message } });
    logger.error({ projectId, userId, error: err.message }, "Agent loop error");
  }

  // Record session duration and release active session gauge
  metrics.activeAgentSessions.dec();
  metrics.agentSessionDuration.observe((Date.now() - sessionStartTime) / 1000);

  res.write("data: [DONE]\n\n");
  res.end();
});

// ── GET /api/agent/:projectId/history — Get conversation history ──────────

router.get("/:projectId/history", async (req: Request<{ projectId: string }>, res: Response) => {
  const projectId = req.params.projectId;
  const orgId = req.user!.orgId;
  const convId = req.query.conversationId as string | undefined;

  // Verify project belongs to org
  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId },
  });
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }

  if (convId) {
    // Get messages for specific conversation
    const messages = await prisma.message.findMany({
      where: { conversationId: convId },
      orderBy: { createdAt: "asc" },
    });
    return res.json({ conversationId: convId, messages });
  }

  // List conversations for this project
  const conversations = await prisma.conversation.findMany({
    where: { projectId },
    orderBy: { createdAt: "desc" },
    take: 20,
    include: {
      messages: {
        orderBy: { createdAt: "asc" },
        take: 50,
        select: {
          id: true,
          role: true,
          content: true,
          modelUsed: true,
          tokenUsage: true,
          creditsConsumed: true,
          createdAt: true,
        },
      },
    },
  });

  res.json({ conversations });
});

// ── GET /api/agent/:projectId/conversations — List conversations ──────────

router.get("/:projectId/conversations", async (req: Request<{ projectId: string }>, res: Response) => {
  const projectId = req.params.projectId;
  const orgId = req.user!.orgId;

  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId },
  });
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }

  const conversations = await prisma.conversation.findMany({
    where: { projectId },
    orderBy: { createdAt: "desc" },
    include: {
      _count: { select: { messages: true } },
      messages: {
        orderBy: { createdAt: "desc" },
        take: 1,
        select: { content: true, role: true, createdAt: true },
      },
    },
  });

  res.json(
    conversations.map((c) => ({
      id: c.id,
      createdAt: c.createdAt,
      messageCount: c._count.messages,
      lastMessage: c.messages[0] || null,
    }))
  );
});

export default router;
