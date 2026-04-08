import type { Message } from "./provider";

export type Complexity = "simple" | "medium" | "complex";

interface ModelSelection {
  provider: string;
  model: string;
}

const SIMPLE_KEYWORDS = [
  "change",
  "update",
  "fix typo",
  "rename",
  "color",
  "text",
  "style",
  "padding",
  "margin",
  "font",
  "label",
  "placeholder",
  "icon",
  "spacing",
  "border",
  "css",
  "class name",
];

const MEDIUM_KEYWORDS = [
  "add feature",
  "implement",
  "create component",
  "integrate",
  "test",
  "add page",
  "form",
  "api endpoint",
  "fetch",
  "hook",
  "state management",
  "validation",
  "modal",
  "table",
  "list",
];

const COMPLEX_KEYWORDS = [
  "refactor",
  "architect",
  "migrate",
  "redesign",
  "performance",
  "security",
  "authentication",
  "authorization",
  "database schema",
  "microservice",
  "real-time",
  "websocket",
  "caching",
  "optimization",
  "scale",
  "ci/cd",
  "deployment",
];

// Default model map -- override via env vars or config
// Model routing: Haiku for trivial edits, Sonnet for features, Opus for architecture
const MODEL_MAP: Record<Complexity, ModelSelection> = {
  simple: {
    provider: process.env.SIMPLE_MODEL_PROVIDER || process.env.DEFAULT_LLM_PROVIDER || "bedrock",
    model: process.env.SIMPLE_MODEL || "claude-haiku-3.5",
  },
  medium: {
    provider: process.env.MEDIUM_MODEL_PROVIDER || process.env.DEFAULT_LLM_PROVIDER || "bedrock",
    model: process.env.MEDIUM_MODEL || "claude-sonnet-4-20250514",
  },
  complex: {
    provider: process.env.COMPLEX_MODEL_PROVIDER || process.env.DEFAULT_LLM_PROVIDER || "bedrock",
    model: process.env.COMPLEX_MODEL || "claude-opus-4",
  },
};

function estimateTokens(text: string): number {
  // Rough estimate: ~4 chars per token
  return Math.ceil(text.length / 4);
}

function matchesKeywords(text: string, keywords: string[]): boolean {
  const lower = text.toLowerCase();
  return keywords.some((kw) => lower.includes(kw));
}

function extractTextFromHistory(history: Message[]): string {
  return history
    .map((m) => {
      if (typeof m.content === "string") return m.content;
      return m.content
        .filter((b) => b.type === "text")
        .map((b) => (b as { type: "text"; text: string }).text)
        .join(" ");
    })
    .join(" ");
}

function hadBuildFailure(history: Message[]): boolean {
  const text = extractTextFromHistory(history);
  return (
    text.includes("build failed") ||
    text.includes("Build error") ||
    text.includes("TypeError") ||
    text.includes("Cannot find module") ||
    text.includes("compilation error")
  );
}

export function classifyComplexity(
  message: string,
  history: Message[]
): Complexity {
  const tokens = estimateTokens(message);
  const turns = history.length;

  // Check complex first (highest priority)
  if (matchesKeywords(message, COMPLEX_KEYWORDS)) return "complex";
  if (turns > 10) return "complex";
  if (hadBuildFailure(history)) return "complex";

  // If there's conversation history, never route to simple (Haiku lacks context reasoning)
  if (turns > 0) {
    if (matchesKeywords(message, MEDIUM_KEYWORDS)) return "medium";
    return "medium"; // default with history = medium
  }

  // Check simple (only for first message with no history)
  if (tokens < 100 && matchesKeywords(message, SIMPLE_KEYWORDS)) return "simple";
  if (tokens < 50) return "simple";

  // Check medium
  if (matchesKeywords(message, MEDIUM_KEYWORDS)) return "medium";

  // Default to medium
  return "medium";
}

export function getModelForComplexity(complexity: Complexity): ModelSelection {
  return MODEL_MAP[complexity];
}
