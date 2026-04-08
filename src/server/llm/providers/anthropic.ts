import Anthropic from "@anthropic-ai/sdk";
import type {
  LLMProvider,
  CompletionParams,
  CompletionResult,
  ContentBlock,
} from "../provider";

export class AnthropicProvider implements LLMProvider {
  readonly name = "anthropic";
  private client: Anthropic;
  private maxRetries: number;

  constructor(apiKey?: string, maxRetries = 3) {
    this.client = new Anthropic({
      apiKey: apiKey || process.env.ANTHROPIC_API_KEY,
    });
    this.maxRetries = maxRetries;
  }

  async complete(params: CompletionParams): Promise<CompletionResult> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await this.client.messages.create({
          model: params.model,
          max_tokens: params.maxTokens,
          system: params.system,
          messages: params.messages.map((m) => ({
            role: m.role,
            content: m.content as any,
          })),
          ...(params.tools && params.tools.length > 0
            ? {
                tools: params.tools.map((t) => ({
                  name: t.name,
                  description: t.description,
                  input_schema: t.input_schema as any,
                })),
              }
            : {}),
        });

        const content: ContentBlock[] = response.content.map((block: any) => {
          if (block.type === "text") {
            return { type: "text" as const, text: block.text };
          }
          if (block.type === "tool_use") {
            return {
              type: "tool_use" as const,
              id: block.id,
              name: block.name,
              input: block.input as Record<string, any>,
            };
          }
          return { type: "text" as const, text: "" };
        });

        return {
          content,
          stopReason: response.stop_reason as CompletionResult["stopReason"],
          usage: {
            inputTokens: response.usage.input_tokens,
            outputTokens: response.usage.output_tokens,
            cacheReadTokens: (response.usage as any).cache_read_input_tokens,
          },
          model: response.model,
          provider: this.name,
        };
      } catch (err: any) {
        lastError = err;
        if (err.status === 429) {
          const retryAfter = parseInt(err.headers?.["retry-after"] || "1", 10);
          const backoffMs = Math.min(
            retryAfter * 1000 * Math.pow(2, attempt),
            30000
          );
          await new Promise((resolve) => setTimeout(resolve, backoffMs));
          continue;
        }
        // Non-retryable error
        throw err;
      }
    }

    throw lastError || new Error("Anthropic provider: max retries exceeded");
  }
}
