import { validateSyntax } from "./ast-validator";
import { verify } from "./build-verifier";
import { attemptAutofix } from "./autofix";
import type { BuildVerification } from "./build-verifier";
import type { AutofixResult } from "./autofix";
import type { LLMRouter } from "../llm/router";
import type { EventBus } from "../events/event-bus";
import { createLogger } from "../observability/logger";

const logger = createLogger("validation-pipeline");

export interface PipelineValidationResult {
  astValid: boolean;
  astErrors: { message: string; line: number; column: number }[];
  buildVerification: BuildVerification | null;
  autofixResult: AutofixResult | null;
  finalBuildPassed: boolean;
}

export class ValidationPipeline {
  constructor(
    private eventBus: EventBus
  ) {}

  /**
   * Fast validation -- runs on every file_write.
   * AST-only, target <5ms per file.
   */
  async runPostFileWrite(
    _containerName: string,
    filePath: string,
    content: string
  ): Promise<{ valid: boolean; errors: { message: string; line: number; column: number }[] }> {
    const result = validateSyntax(content, filePath);
    if (!result.valid) {
      logger.warn(
        { filePath, errors: result.errors },
        "AST validation failed on file write"
      );
    }
    return result;
  }

  /**
   * Full validation pipeline -- runs after agent completion.
   * Build verify -> if fail -> autofix -> re-verify -> emit events.
   */
  async runPostCompletion(
    containerName: string,
    router: LLMRouter
  ): Promise<PipelineValidationResult> {
    const result: PipelineValidationResult = {
      astValid: true,
      astErrors: [],
      buildVerification: null,
      autofixResult: null,
      finalBuildPassed: false,
    };

    // Emit start event
    await this.eventBus.emit("build", "build.verification_started", {
      projectId: containerName,
    });

    const buildStart = Date.now();

    // Step 1: Run build verification
    const buildResult = await verify(containerName);
    result.buildVerification = buildResult;

    const buildDurationMs = Date.now() - buildStart;

    if (buildResult.buildPassed) {
      result.finalBuildPassed = true;
      await this.eventBus.emit("build", "build.verification_passed", {
        projectId: containerName,
        durationMs: buildDurationMs,
      });

      logger.info(
        { containerName, durationMs: buildDurationMs },
        "Build verification passed"
      );

      return result;
    }

    // Step 2: Build failed -- attempt autofix
    logger.warn(
      { containerName, errors: buildResult.errors },
      "Build verification failed, attempting autofix"
    );

    await this.eventBus.emit("build", "build.verification_failed", {
      projectId: containerName,
      error: buildResult.errors.join("\n"),
    });

    // Try to extract the failing file from the first error
    const failingFile = this.extractFileFromError(buildResult.errors[0] || "");
    const errorMessage = buildResult.errors.join("\n") || buildResult.buildOutput.slice(-2000);

    if (failingFile) {
      const autofixResult = await attemptAutofix(
        containerName,
        errorMessage,
        failingFile,
        router,
        this.eventBus
      );

      result.autofixResult = autofixResult;
      result.finalBuildPassed = autofixResult.success;

      if (autofixResult.success) {
        logger.info(
          { containerName, file: failingFile },
          "Autofix succeeded"
        );
      } else {
        logger.warn(
          { containerName, error: autofixResult.error },
          "Autofix failed"
        );
      }
    } else {
      logger.warn(
        { containerName },
        "Could not extract failing file from errors, skipping autofix"
      );
    }

    return result;
  }

  /**
   * Extract file path from common error patterns.
   */
  private extractFileFromError(error: string): string | null {
    if (!error) return null;

    // Pattern: ./src/components/Foo.tsx(12,5):
    const tsMatch = error.match(/\.?\/?(\S+\.(?:ts|tsx|js|jsx))\s*[\(:]/);
    if (tsMatch) {
      const filePath = tsMatch[1];
      return filePath.startsWith("/") ? filePath : `/workspace/${filePath}`;
    }

    // Pattern: Module not found: Can't resolve ... in '/workspace/src/...'
    const moduleMatch = error.match(/in '([^']+)'/);
    if (moduleMatch) {
      return moduleMatch[1];
    }

    return null;
  }
}
