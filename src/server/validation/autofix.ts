import { execSync } from "child_process";
import type { LLMRouter } from "../llm/router";
import type { RoutingContext } from "../llm/router";
import type { EventBus } from "../events/event-bus";
import { verify } from "./build-verifier";
import type { BuildVerification } from "./build-verifier";

export interface AutofixResult {
  success: boolean;
  fixApplied: boolean;
  buildVerification: BuildVerification | null;
  error?: string;
}

function dockerExec(containerName: string, cmd: string, timeoutMs = 10_000): string {
  try {
    return execSync(
      `docker exec ${containerName} sh -c "${cmd.replace(/"/g, '\\"')}"`,
      { timeout: timeoutMs, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }
    );
  } catch (err: any) {
    return err.stdout || err.stderr || err.message || "";
  }
}

function readFileFromContainer(containerName: string, filePath: string): string {
  return dockerExec(containerName, `cat ${filePath}`, 5_000);
}

function writeFileToContainer(
  containerName: string,
  filePath: string,
  content: string
): void {
  // Write via stdin to avoid shell escaping issues
  try {
    execSync(
      `docker exec -i ${containerName} sh -c "cat > ${filePath}"`,
      {
        input: content,
        timeout: 10_000,
        encoding: "utf-8",
      }
    );
  } catch (err: any) {
    throw new Error(`Failed to write file ${filePath}: ${err.message}`);
  }
}

export async function attemptAutofix(
  containerName: string,
  error: string,
  filePath: string,
  router: LLMRouter,
  eventBus: EventBus
): Promise<AutofixResult> {
  const startTime = Date.now();

  try {
    // Read the file that has the error
    const fileContent = readFileFromContainer(containerName, filePath);

    if (!fileContent || fileContent.includes("No such file")) {
      return {
        success: false,
        fixApplied: false,
        buildVerification: null,
        error: `Could not read file: ${filePath}`,
      };
    }

    // Build a focused fix prompt
    const fixPrompt = [
      "Fix the following TypeScript/build error. Return ONLY the complete corrected file content, no explanation.",
      "",
      `File: ${filePath}`,
      "",
      "Error:",
      error,
      "",
      "Current file content:",
      "```",
      fileContent,
      "```",
    ].join("\n");

    // Route to fast model with complexity override
    const routingContext: RoutingContext = {
      projectId: containerName,
      userMessage: fixPrompt,
      history: [],
      complexityOverride: "simple",
    };

    const result = await router.complete(
      {
        model: "", // let router choose based on complexity
        messages: [{ role: "user", content: fixPrompt }],
        maxTokens: 8192,
        system:
          "You are a code fixer. Return ONLY the corrected file content. No markdown fences, no explanation.",
      },
      routingContext
    );

    // Extract text content from result
    const fixedContent = result.content
      .filter((b) => b.type === "text")
      .map((b) => (b as { type: "text"; text: string }).text)
      .join("");

    if (!fixedContent.trim()) {
      return {
        success: false,
        fixApplied: false,
        buildVerification: null,
        error: "LLM returned empty fix",
      };
    }

    // Strip markdown fences if the model included them anyway
    const cleaned = fixedContent
      .replace(/^```[\w]*\n?/, "")
      .replace(/\n?```$/, "")
      .trim();

    // Write the fixed file
    writeFileToContainer(containerName, filePath, cleaned);

    // Re-verify
    const verification = await verify(containerName);
    const durationMs = Date.now() - startTime;

    if (verification.buildPassed) {
      await eventBus.emit("build", "build.autofix_applied", {
        projectId: containerName,
        error,
        fixModel: result.model,
        durationMs,
      });

      return {
        success: true,
        fixApplied: true,
        buildVerification: verification,
      };
    }

    return {
      success: false,
      fixApplied: true,
      buildVerification: verification,
      error: "Autofix applied but build still fails",
    };
  } catch (err: any) {
    return {
      success: false,
      fixApplied: false,
      buildVerification: null,
      error: err.message,
    };
  }
}
