// ── Message types ────────────────────────────────────────────────────

export interface TextBlock {
  type: "text";
  text: string;
}

export interface ToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, any>;
}

export interface ToolResultBlock {
  type: "tool_result";
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

export type ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock;

export interface Message {
  role: "user" | "assistant";
  content: string | ContentBlock[];
}

export interface Tool {
  name: string;
  description: string;
  input_schema: Record<string, any>;
}

// ── Provider interface ───────────────────────────────────────────────

export interface CompletionParams {
  model: string;
  messages: Message[];
  tools?: Tool[];
  maxTokens: number;
  system: string;
}

export interface CompletionResult {
  content: ContentBlock[];
  stopReason: "end_turn" | "tool_use" | "max_tokens";
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens?: number;
  };
  model: string;
  provider: string;
}

export interface LLMProvider {
  name: string;
  complete(params: CompletionParams): Promise<CompletionResult>;
}
