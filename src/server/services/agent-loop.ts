// src/server/services/agent-loop.ts
// Agent loop with security integration, LLM router, and event bus

import { SecurityLayer } from "../security/index";
import { HARDENED_SYSTEM_PROMPT } from "../security/system-prompt";
import { LLMRouter } from "../llm/router";
import { EventBus } from "../events/event-bus";
import { EVENT_TYPES } from "../events/events";
import type { Message, ContentBlock, Tool, CompletionResult } from "../llm/provider";
import type { SecurityContext } from "../security/index";
import type { TurnData } from "../security/trajectory-monitor";
import {
  execInWorkspace,
  writeFileToWorkspace,
  readFileFromWorkspace,
  listFilesInWorkspace,
} from "./workspace";
import { ValidationPipeline } from "../validation/pipeline";
import { createLogger } from "../observability/logger";
import { metrics } from "../observability/metrics";
import { withSpan } from "../observability/tracing";
import { getCorrelationId } from "../middleware/correlation";

const logger = createLogger("agent-loop");

// ── Tool definitions ──────────────────────────────────────────────────────

const TOOLS: Tool[] = [
  {
    name: "file_write",
    description: "Create or overwrite a file. Use absolute paths starting with /workspace/",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path (e.g., /workspace/src/App.tsx)",
        },
        content: { type: "string", description: "Complete file content" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "shell_exec",
    description:
      "Run a shell command. Use for: npm install, npm run dev, checking errors. Commands run in /workspace. For long-running processes (dev server), background them with & and nohup.",
    input_schema: {
      type: "object" as const,
      properties: {
        command: { type: "string" },
      },
      required: ["command"],
    },
  },
  {
    name: "file_read",
    description: "Read a file to check its contents or diagnose errors.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: { type: "string" },
      },
      required: ["path"],
    },
  },
  {
    name: "file_list",
    description: "List files in a directory (excludes node_modules, .git, dist).",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Directory path. Default: /workspace",
        },
      },
      required: [],
    },
  },
];

// ── Event types for SSE streaming ─────────────────────────────────────────

export interface AgentEvent {
  type: "thinking" | "tool_call" | "tool_result" | "text" | "error" | "done" | "security_block";
  data: any;
}

// ── Agent loop ────────────────────────────────────────────────────────────

const MAX_ITERATIONS = 50;

export async function runAgentLoop(
  containerName: string,
  userMessage: string,
  conversationHistory: Message[],
  onEvent: (event: AgentEvent) => void,
  context: {
    projectId: string;
    userId: string;
    sessionId: string;
    securityLayer: SecurityLayer;
    llmRouter: LLMRouter;
    eventBus: EventBus;
    validationPipeline?: ValidationPipeline;
  }
): Promise<{ messages: Message[]; tokensUsed: number; inputTokens: number; outputTokens: number; model: string; provider: string }> {
  const { projectId, userId, sessionId, securityLayer, llmRouter, eventBus } = context;

  return withSpan("agent.loop", async () => {
  const correlationId = getCorrelationId();

  // ── Pre-LLM: Security preprocessing ────────────────────────────────────
  const preprocessResult = await withSpan("security.preprocess", () =>
    securityLayer.preprocessUserInput(userMessage, sessionId)
  );

  if (!preprocessResult.allowed) {
    const reason = preprocessResult.reason || "Input blocked by security policy";
    metrics.securityBlocksTotal.inc({ category: "input_firewall", pattern: preprocessResult.firewallResult.tier || "unknown" });
    onEvent({
      type: "security_block",
      data: {
        reason,
        score: preprocessResult.firewallResult.score,
        tier: preprocessResult.firewallResult.tier,
      },
    });

    await eventBus.emit("security", EVENT_TYPES.SECURITY_INPUT_BLOCKED, {
      userId,
      score: preprocessResult.firewallResult.score,
      reason,
      inputPreview: userMessage.substring(0, 100),
    }, correlationId);

    // Also emit detailed injection/intent events for SIEM correlation
    if (preprocessResult.injectionAnalysis?.attacks?.length) {
      await eventBus.emit("security", EVENT_TYPES.SECURITY_INJECTION_DETECTED, {
        userId,
        sessionId,
        attacks: preprocessResult.injectionAnalysis.attacks.map((a) => ({
          vector: a.vector,
          category: a.category,
          severity: a.severity,
        })),
        riskScore: preprocessResult.injectionAnalysis.riskScore,
        blocked: true,
        inputPreview: userMessage.substring(0, 100),
      }, correlationId);
    }
    if (preprocessResult.intentClassification && preprocessResult.intentClassification.primaryIntent !== "BENIGN_DEV") {
      await eventBus.emit("security", EVENT_TYPES.SECURITY_INTENT_BLOCKED, {
        userId,
        sessionId,
        intent: preprocessResult.intentClassification.primaryIntent,
        riskScore: preprocessResult.intentClassification.riskScore,
        explanation: preprocessResult.intentClassification.explanation,
        signalCount: preprocessResult.intentClassification.signals.length,
      }, correlationId);
    }

    throw new Error(`Security: ${reason}`);
  }

  // Emit intent FLAG events for allowed-but-suspicious inputs (for SIEM visibility)
  if (preprocessResult.intentClassification &&
      preprocessResult.intentClassification.recommendation === "FLAG" &&
      preprocessResult.intentClassification.primaryIntent !== "BENIGN_DEV") {
    await eventBus.emit("security", EVENT_TYPES.SECURITY_INTENT_FLAGGED, {
      userId,
      sessionId,
      intent: preprocessResult.intentClassification.primaryIntent,
      riskScore: preprocessResult.intentClassification.riskScore,
      explanation: preprocessResult.intentClassification.explanation,
      signalCount: preprocessResult.intentClassification.signals.length,
    }, correlationId);
  }

  // Emit injection detection even if not blocked (FLAG-level for SIEM)
  if (preprocessResult.injectionAnalysis?.attacks?.length &&
      !preprocessResult.injectionAnalysis.blocked) {
    await eventBus.emit("security", EVENT_TYPES.SECURITY_INJECTION_DETECTED, {
      userId,
      sessionId,
      attacks: preprocessResult.injectionAnalysis.attacks.map((a) => ({
        vector: a.vector,
        category: a.category,
        severity: a.severity,
      })),
      riskScore: preprocessResult.injectionAnalysis.riskScore,
      blocked: false,
      inputPreview: userMessage.substring(0, 100),
    }, correlationId);
  }

  // Use sanitized input (secrets redacted)
  const sanitizedInput = preprocessResult.sanitizedInput;

  // Log secret detections
  if (preprocessResult.secretsResult.detections.length > 0) {
    await eventBus.emit("security", EVENT_TYPES.SECURITY_SECRET_DETECTED, {
      userId,
      type: preprocessResult.secretsResult.detections.map((d) => d.type).join(", "),
      maskedValue: preprocessResult.secretsResult.detections.map((d) => d.maskedValue).join(", "),
    }, correlationId);
  }

  // ── Build message array ─────────────────────────────────────────────────
  const messages: Message[] = [
    ...conversationHistory,
    { role: "user", content: sanitizedInput },
  ];

  let totalTokens = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let iterations = 0;
  let lastModel = "";
  let lastProvider = "";
  let turnNumber = conversationHistory.length;

  // Emit agent started event
  await eventBus.emit("agent", EVENT_TYPES.AGENT_STARTED, {
    projectId,
    userId,
    userMessage: sanitizedInput.substring(0, 500),
  }, correlationId);

  // ── Main loop ───────────────────────────────────────────────────────────
  while (iterations < MAX_ITERATIONS) {
    iterations++;
    turnNumber++;

    onEvent({
      type: "thinking",
      data: { iteration: iterations, maxIterations: MAX_ITERATIONS },
    });

    await eventBus.emit("agent", EVENT_TYPES.AGENT_ITERATION, {
      projectId,
      iteration: iterations,
      maxIterations: MAX_ITERATIONS,
    }, correlationId);

    // Increment iteration counter metric
    metrics.agentIterationsTotal.inc({ project_id: projectId, status: "started" });

    // ── LLM call via router ─────────────────────────────────────────────
    let response: CompletionResult;
    try {
      response = await llmRouter.complete(
        {
          model: "auto",
          messages,
          tools: TOOLS,
          maxTokens: 16384,
          system: HARDENED_SYSTEM_PROMPT,
        },
        {
          projectId,
          userMessage: sanitizedInput,
          history: messages,
        }
      );
    } catch (err: any) {
      metrics.agentIterationsTotal.inc({ project_id: projectId, status: "error" });
      onEvent({ type: "error", data: { message: `LLM error: ${err.message}` } });
      await eventBus.emit("agent", EVENT_TYPES.AGENT_ERROR, {
        projectId,
        error: err.message,
        iteration: iterations,
      }, correlationId);
      throw err;
    }

    totalInputTokens += response.usage.inputTokens;
    totalOutputTokens += response.usage.outputTokens;
    totalTokens += response.usage.inputTokens + response.usage.outputTokens;
    lastModel = response.model;
    lastProvider = response.provider;

    // Record token usage metrics
    metrics.llmTokensTotal.inc({ model: response.model, direction: "input" }, response.usage.inputTokens);
    metrics.llmTokensTotal.inc({ model: response.model, direction: "output" }, response.usage.outputTokens);

    messages.push({ role: "assistant", content: response.content });

    // ── Stream text blocks to frontend ──────────────────────────────────
    for (const block of response.content) {
      if (block.type === "text" && (block as { type: "text"; text: string }).text.trim()) {
        onEvent({ type: "text", data: { text: (block as { type: "text"; text: string }).text } });
      }
    }

    // ── If model is done (no tool use), finish ──────────────────────────
    if (response.stopReason === "end_turn") {
      onEvent({ type: "done", data: { iterations, tokensUsed: totalTokens, model: lastModel, provider: lastProvider } });

      await eventBus.emit("agent", EVENT_TYPES.AGENT_COMPLETED, {
        projectId,
        iterations,
        tokensUsed: totalTokens,
        model: lastModel,
      }, correlationId);

      // Post-completion: run full validation pipeline (build verify + autofix)
      if (context.validationPipeline) {
        try {
          const validationResult = await context.validationPipeline.runPostCompletion(
            containerName, llmRouter
          );
          if (validationResult.finalBuildPassed) {
            onEvent({ type: "text", data: { text: "\n✓ Build verification passed." } });
          } else {
            const errors = validationResult.buildVerification?.errors?.slice(0, 3).join("\n") || "Build failed";
            onEvent({ type: "text", data: { text: `\n⚠ Build verification failed:\n${errors}` } });
          }
        } catch (e: any) {
          logger.warn({ error: e.message }, "Post-completion validation error (non-fatal)");
        }
      }

      // Record final turn for trajectory monitoring
      const turnToolCalls: TurnData["toolCalls"] = [];
      const agentText = response.content
        .filter((b) => b.type === "text")
        .map((b) => (b as { type: "text"; text: string }).text)
        .join("\n");

      securityLayer.recordTurn(sessionId, {
        turnNumber,
        userMessage: sanitizedInput,
        toolCalls: turnToolCalls,
        agentResponse: agentText,
      });

      break;
    }

    // ── Process tool calls ──────────────────────────────────────────────
    if (response.stopReason === "tool_use") {
      const toolResults: ContentBlock[] = [];
      const turnToolCalls: TurnData["toolCalls"] = [];

      for (const block of response.content) {
        if (block.type !== "tool_use") continue;

        const toolBlock = block as { type: "tool_use"; id: string; name: string; input: Record<string, any> };
        const { name, input, id } = toolBlock;
        const inp = input as Record<string, string>;

        onEvent({
          type: "tool_call",
          data: { tool: name, input: inp, toolUseId: id },
        });

        await eventBus.emit("agent", EVENT_TYPES.AGENT_TOOL_CALLED, {
          projectId,
          tool: name,
          input: inp,
          toolUseId: id,
        }, correlationId);

        // ── Post-LLM: Security filter for shell_exec ──────────────────
        const securityContext: SecurityContext = {
          projectId,
          userId,
          sessionId,
          conversationTurn: turnNumber,
          containerName,
        };

        const filterResult = await securityLayer.filterToolExecution(name, input, securityContext);

        let result: string;
        let isError = false;
        let verdict: "BLOCK" | "ALERT" | "PASS" = "PASS";
        const start = Date.now();

        if (!filterResult.allowed) {
          // Command blocked by security
          result = filterResult.message || "Command blocked by security policy.";
          isError = true;
          verdict = "BLOCK";
          metrics.securityBlocksTotal.inc({ category: "output_filter", pattern: filterResult.commandFilterResult?.pattern || "package_filter" });

          await eventBus.emit("security", EVENT_TYPES.SECURITY_COMMAND_BLOCKED, {
            userId,
            projectId,
            command: (inp.command || "").substring(0, 200),
            pattern: filterResult.commandFilterResult?.pattern || "package_filter",
          }, correlationId);

          onEvent({
            type: "security_block",
            data: { tool: name, reason: result, toolUseId: id },
          });
        } else {
          // Check for ALERT verdict
          if (filterResult.commandFilterResult?.verdict === "ALERT") {
            verdict = "ALERT";
            await eventBus.emit("security", EVENT_TYPES.SECURITY_COMMAND_ALERTED, {
              userId,
              projectId,
              command: (inp.command || "").substring(0, 200),
              pattern: filterResult.commandFilterResult.pattern || "",
            }, correlationId);
          }

          // Execute tool (wrapped in OTel span for Jaeger visibility)
          try {
            result = await withSpan(`agent.tool.${name}`, async () => {
              let toolResult: string;
              switch (name) {
                case "file_write": {
                  if (!inp.path || typeof inp.path !== "string") {
                    throw new Error("file_write requires a 'path' argument (e.g. /workspace/src/App.tsx)");
                  }
                  const content = inp.content ?? "";
                  await writeFileToWorkspace(containerName, inp.path, content);
                  toolResult = `Written: ${inp.path} (${content.length} bytes)`;
                  // Post-write AST validation
                  if (context.validationPipeline) {
                    const astResult = await context.validationPipeline.runPostFileWrite(
                      containerName, inp.path, content
                    );
                    if (!astResult.valid) {
                      const errSummary = astResult.errors.slice(0, 3)
                        .map((e) => `L${e.line}:${e.column} ${e.message}`)
                        .join("; ");
                      toolResult += `\n⚠ Syntax errors: ${errSummary}`;
                    }
                  }
                  break;
                }
                case "file_read":
                  if (!inp.path || typeof inp.path !== "string") {
                    throw new Error("file_read requires a 'path' argument (e.g. /workspace/src/App.tsx)");
                  }
                  toolResult = await readFileFromWorkspace(containerName, inp.path);
                  break;
                case "file_list":
                  toolResult = await listFilesInWorkspace(containerName, inp.path || "/workspace");
                  break;
                case "shell_exec": {
                  if (!inp.command || typeof inp.command !== "string") {
                    throw new Error("shell_exec requires a 'command' argument (e.g. 'npm install')");
                  }
                  const execResult = await execInWorkspace(containerName, inp.command);
                  toolResult = execResult.stdout;
                  if (execResult.stderr) toolResult += `\nSTDERR: ${execResult.stderr}`;
                  if (execResult.exitCode !== 0) toolResult += `\nEXIT CODE: ${execResult.exitCode}`;
                  break;
                }
                default:
                  toolResult = `Unknown tool: ${name}`;
                  isError = true;
              }
              return toolResult;
            }, { "tool.name": name });
          } catch (e: any) {
            result = `Error: ${e.message}`;
            isError = true;
          }
        }

        const durationMs = Date.now() - start;

        // Record tool execution metrics
        metrics.toolExecutionsTotal.inc({ tool: name, status: isError ? "error" : "success" });
        metrics.toolExecutionDuration.observe({ tool: name }, durationMs / 1000);

        onEvent({
          type: "tool_result",
          data: {
            tool: name,
            toolUseId: id,
            result: result.substring(0, 2000),
            durationMs,
            isError,
          },
        });

        await eventBus.emit("agent", EVENT_TYPES.AGENT_TOOL_RESULT, {
          projectId,
          tool: name,
          result: result.substring(0, 500),
          durationMs,
          isError,
        }, correlationId);

        // Track tool call for trajectory
        turnToolCalls.push({ tool: name, input: inp, verdict });

        // Truncate result for context window management
        const truncated =
          result.length > 10000
            ? result.substring(0, 10000) + `\n... (truncated, ${result.length} total chars)`
            : result;

        toolResults.push({
          type: "tool_result",
          tool_use_id: id,
          content: truncated,
          is_error: isError,
        });
      }

      messages.push({ role: "user", content: toolResults });

      // Record turn for trajectory monitoring
      const agentText = response.content
        .filter((b) => b.type === "text")
        .map((b) => (b as { type: "text"; text: string }).text)
        .join("\n");

      const trajectoryResult = securityLayer.recordTurn(sessionId, {
        turnNumber,
        userMessage: sanitizedInput,
        toolCalls: turnToolCalls,
        agentResponse: agentText,
      });

      // If trajectory monitor pauses the session, stop the loop
      if (trajectoryResult.shouldPause) {
        onEvent({
          type: "security_block",
          data: {
            reason: "Session paused by trajectory monitor due to elevated risk score.",
            score: trajectoryResult.score,
            level: trajectoryResult.level,
          },
        });

        await eventBus.emit("security", EVENT_TYPES.SECURITY_TRAJECTORY_FLAGGED, {
          sessionId,
          score: trajectoryResult.score,
          threshold: 0.7,
        }, correlationId);

        onEvent({
          type: "done",
          data: { iterations, tokensUsed: totalTokens, model: lastModel, provider: lastProvider, paused: true },
        });

        break;
      }
    }
  }

  // ── Max iterations warning ──────────────────────────────────────────────
  if (iterations >= MAX_ITERATIONS) {
    onEvent({
      type: "error",
      data: { message: "Agent reached maximum iterations without completing." },
    });

    await eventBus.emit("agent", EVENT_TYPES.AGENT_ERROR, {
      projectId,
      error: "Max iterations reached",
      iteration: iterations,
    }, correlationId);
  }

  return { messages, tokensUsed: totalTokens, inputTokens: totalInputTokens, outputTokens: totalOutputTokens, model: lastModel, provider: lastProvider };
  }, { "project.id": context.projectId, "user.id": context.userId });
}
