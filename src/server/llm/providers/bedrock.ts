import AnthropicBedrock from "@anthropic-ai/bedrock-sdk";
import type {
  LLMProvider,
  CompletionParams,
  CompletionResult,
  ContentBlock,
} from "../provider";

const MODEL_MAP: Record<string, string> = {
  "claude-sonnet-4-6": "us.anthropic.claude-sonnet-4-6-v1",
  "claude-sonnet-4-20250514": "us.anthropic.claude-sonnet-4-20250514-v1:0",
  "claude-sonnet-4": "us.anthropic.claude-sonnet-4-20250514-v1:0",
  "claude-haiku-3.5": "us.anthropic.claude-3-5-haiku-20241022-v1:0",
  "claude-opus-4": "us.anthropic.claude-opus-4-20250514-v1:0",
  "claude-opus-4-6": "us.anthropic.claude-opus-4-6-v1",
  "claude-opus-4-5": "us.anthropic.claude-opus-4-5-20251101-v1:0",
  "claude-opus-4-1": "us.anthropic.claude-opus-4-1-20250805-v1:0",
};

export class BedrockProvider implements LLMProvider {
  readonly name = "bedrock";
  private client: AnthropicBedrock;

  constructor() {
    // Use explicit credentials if available, otherwise rely on default AWS credential chain
    // (SSO profile, instance metadata, etc.)
    const opts: Record<string, any> = {
      awsRegion: process.env.AWS_REGION || "us-west-2",
    };
    if (process.env.AWS_ACCESS_KEY_ID) {
      opts.awsAccessKey = process.env.AWS_ACCESS_KEY_ID;
      opts.awsSecretKey = process.env.AWS_SECRET_ACCESS_KEY;
      opts.awsSessionToken = process.env.AWS_SESSION_TOKEN;
    }
    this.client = new AnthropicBedrock(opts as any);
  }

  private mapModel(model: string): string {
    return MODEL_MAP[model] || model;
  }

  async complete(params: CompletionParams): Promise<CompletionResult> {
    const bedrockModel = this.mapModel(params.model);

    try {
      const response = await this.client.messages.create({
        model: bedrockModel,
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
      throw new Error(
        `Bedrock provider error [${bedrockModel}]: ${err.message}`
      );
    }
  }
}
