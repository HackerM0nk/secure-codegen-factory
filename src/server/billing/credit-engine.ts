// Credit cost calculation per model
// Rates are in credits per 1K tokens, with a margin multiplier

interface ModelRate {
  inputPer1K: number;
  outputPer1K: number;
  cachedInputPer1K: number;
}

// Zero-cost rate for local/FOSS models (Ollama, llama.cpp, etc.)
const LOCAL_MODEL_RATE: ModelRate = { inputPer1K: 0, outputPer1K: 0, cachedInputPer1K: 0 };

const MODEL_RATES: Record<string, ModelRate> = {
  // Anthropic models (4x markup over raw API cost)
  "claude-opus-4-6": { inputPer1K: 0.060, outputPer1K: 0.300, cachedInputPer1K: 0.006 },
  "claude-sonnet-4-6": { inputPer1K: 0.012, outputPer1K: 0.060, cachedInputPer1K: 0.0012 },
  "claude-haiku-4-5": { inputPer1K: 0.001, outputPer1K: 0.005, cachedInputPer1K: 0.0001 },
  // OpenAI models
  "gpt-4o": { inputPer1K: 0.010, outputPer1K: 0.060, cachedInputPer1K: 0.005 },
  "gpt-4o-mini": { inputPer1K: 0.0006, outputPer1K: 0.002, cachedInputPer1K: 0.0003 },
};

// Fixed costs
const BUILD_COST = 1.0;    // credits per build verification
const DEPLOY_COST = 5.0;   // credits per deployment
const STORAGE_PER_MB = 0.001; // credits per MB/month

export interface CostBreakdown {
  inputTokenCost: number;
  outputTokenCost: number;
  cachedTokenCost: number;
  totalCredits: number;
  model: string;
}

export function calculateLLMCost(
  model: string,
  inputTokens: number,
  outputTokens: number,
  cachedTokens = 0
): CostBreakdown {
  // Local/FOSS models (Ollama) contain a colon (e.g. "qwen2.5-coder:7b") or aren't in the rate table
  const isLocalModel = model.includes(":") || (!MODEL_RATES[model] && process.env.DEFAULT_LLM_PROVIDER === "ollama");
  const rate = isLocalModel ? LOCAL_MODEL_RATE : (MODEL_RATES[model] || MODEL_RATES["claude-sonnet-4-6"]);

  const inputTokenCost = (inputTokens / 1000) * rate.inputPer1K;
  const outputTokenCost = (outputTokens / 1000) * rate.outputPer1K;
  const cachedTokenCost = (cachedTokens / 1000) * rate.cachedInputPer1K;

  return {
    inputTokenCost,
    outputTokenCost,
    cachedTokenCost,
    totalCredits: inputTokenCost + outputTokenCost + cachedTokenCost,
    model,
  };
}

export function getBuildCost(): number {
  return BUILD_COST;
}

export function getDeployCost(): number {
  return DEPLOY_COST;
}

export { MODEL_RATES };
