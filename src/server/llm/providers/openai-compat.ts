import OpenAI from "openai";
import type {
  LLMProvider,
  CompletionParams,
  CompletionResult,
  ContentBlock,
  Tool,
} from "../provider";

export class OpenAICompatProvider implements LLMProvider {
  readonly name: string;
  private client: OpenAI;

  constructor(
    name: string = "openai",
    baseURL?: string,
    apiKey?: string
  ) {
    this.name = name;
    this.client = new OpenAI({
      apiKey: apiKey || process.env.OPENAI_API_KEY || "not-needed",
      baseURL: baseURL || process.env.OPENAI_BASE_URL || "https://api.openai.com/v1",
    });
  }

  async complete(params: CompletionParams): Promise<CompletionResult> {
    const messages: OpenAI.Chat.ChatCompletionMessageParam[] = [
      { role: "system", content: params.system },
    ];

    for (const msg of params.messages) {
      if (typeof msg.content === "string") {
        messages.push({
          role: msg.role as "user" | "assistant",
          content: msg.content,
        });
      } else {
        // Convert content blocks to OpenAI format
        const textParts = msg.content
          .filter((b) => b.type === "text")
          .map((b) => (b as { type: "text"; text: string }).text)
          .join("\n");

        if (msg.role === "assistant") {
          // Check for tool_use blocks
          const toolCalls = msg.content
            .filter((b) => b.type === "tool_use")
            .map((b) => {
              const tu = b as { type: "tool_use"; id: string; name: string; input: Record<string, any> };
              return {
                id: tu.id,
                type: "function" as const,
                function: {
                  name: tu.name,
                  arguments: JSON.stringify(tu.input),
                },
              };
            });

          if (toolCalls.length > 0) {
            messages.push({
              role: "assistant",
              content: textParts || null,
              tool_calls: toolCalls,
            });
          } else {
            messages.push({ role: "assistant", content: textParts });
          }
        } else {
          // User message -- check for tool_result blocks
          const toolResults = msg.content.filter((b) => b.type === "tool_result");
          if (toolResults.length > 0) {
            for (const tr of toolResults) {
              const result = tr as {
                type: "tool_result";
                tool_use_id: string;
                content: string;
                is_error?: boolean;
              };
              messages.push({
                role: "tool",
                tool_call_id: result.tool_use_id,
                content: result.content,
              });
            }
          } else {
            messages.push({ role: "user", content: textParts });
          }
        }
      }
    }

    const tools: OpenAI.Chat.ChatCompletionTool[] | undefined =
      params.tools && params.tools.length > 0
        ? params.tools.map((t: Tool) => ({
            type: "function" as const,
            function: {
              name: t.name,
              description: t.description,
              parameters: t.input_schema,
            },
          }))
        : undefined;

    const response = await this.client.chat.completions.create({
      model: params.model,
      messages,
      tools,
      max_tokens: params.maxTokens,
    });

    const choice = response.choices[0];
    const content: ContentBlock[] = [];

    if (choice.message.content) {
      content.push({ type: "text", text: choice.message.content });
    }

    if (choice.message.tool_calls) {
      for (const tc of choice.message.tool_calls) {
        content.push({
          type: "tool_use",
          id: tc.id,
          name: tc.function.name,
          input: JSON.parse(tc.function.arguments || "{}"),
        });
      }
    }

    let stopReason: CompletionResult["stopReason"] = "end_turn";
    // OpenAI uses "tool_calls", some Ollama models return "stop" even with tool calls present
    if (choice.finish_reason === "tool_calls") stopReason = "tool_use";
    if (choice.message.tool_calls && choice.message.tool_calls.length > 0) stopReason = "tool_use";
    if (choice.finish_reason === "length") stopReason = "max_tokens";

    return {
      content,
      stopReason,
      usage: {
        inputTokens: response.usage?.prompt_tokens || 0,
        outputTokens: response.usage?.completion_tokens || 0,
      },
      model: response.model,
      provider: this.name,
    };
  }
}
