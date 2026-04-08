import type {
  LLMProvider,
  CompletionParams,
  CompletionResult,
  Message,
} from "./provider";
import type { HealthScorer, ProviderHealth } from "./health-scorer";
import type { CacheAffinity } from "./cache-affinity";
import type { EventBus } from "../events/event-bus";
import { classifyComplexity, getModelForComplexity } from "./complexity-classifier";
import type { Complexity } from "./complexity-classifier";
import { metrics } from "../observability/metrics";

export interface RoutingContext {
  projectId: string;
  userMessage: string;
  history: Message[];
  complexityOverride?: Complexity;
}

const TIMEOUT_BY_COMPLEXITY: Record<string, number> = {
  simple: 30_000,
  medium: 90_000,
  complex: 180_000,
};
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_RETRIES = 2;

export class LLMRouter {
  private providerMap: Map<string, LLMProvider>;

  constructor(
    private providers: LLMProvider[],
    private healthScorer: HealthScorer,
    private cacheAffinity: CacheAffinity,
    private eventBus: EventBus
  ) {
    this.providerMap = new Map();
    for (const p of providers) {
      this.providerMap.set(p.name, p);
    }
  }

  async complete(
    params: CompletionParams,
    context: RoutingContext
  ): Promise<CompletionResult> {
    // 1. Classify complexity
    const complexity =
      context.complexityOverride ||
      classifyComplexity(context.userMessage, context.history);

    // 2. Get preferred model for complexity
    const preferred = getModelForComplexity(complexity);
    const targetModel = (!params.model || params.model === "auto") ? preferred.model : params.model;

    // 3. Check project affinity
    const affinityProvider = await this.cacheAffinity.getAffinity(
      context.projectId
    );

    // 4. Build ordered provider list
    const providerOrder = await this.buildProviderOrder(
      affinityProvider,
      preferred.provider
    );

    // 5. Try providers in order
    let lastError: Error | null = null;
    let attempts = 0;

    for (const providerName of providerOrder) {
      if (attempts >= MAX_RETRIES + 1) break;

      const provider = this.providerMap.get(providerName);
      if (!provider) continue;

      const isHealthy = await this.healthScorer.isHealthy(providerName);
      if (!isHealthy && attempts > 0) continue; // skip unhealthy on retries

      attempts++;

      const startTime = Date.now();

      await this.eventBus.emit("llm", "llm.call_started", {
        provider: providerName,
        model: targetModel,
        inputTokens: 0, // estimated later
      });

      try {
        const timeoutMs = TIMEOUT_BY_COMPLEXITY[complexity] || DEFAULT_TIMEOUT_MS;
        const result = await this.withTimeout(
          provider.complete({ ...params, model: targetModel }),
          timeoutMs
        );

        const durationMs = Date.now() - startTime;

        // Record LLM call duration metric
        metrics.llmCallDuration.observe(
          { model: result.model, provider: providerName },
          durationMs / 1000
        );

        // Record success
        await this.healthScorer.recordSuccess(providerName);
        await this.cacheAffinity.setAffinity(context.projectId, providerName);

        await this.eventBus.emit("llm", "llm.call_completed", {
          provider: providerName,
          model: result.model,
          inputTokens: result.usage.inputTokens,
          outputTokens: result.usage.outputTokens,
          durationMs,
          cached: (result.usage.cacheReadTokens || 0) > 0,
        });

        return result;
      } catch (err: any) {
        const durationMs = Date.now() - startTime;
        lastError = err;

        // Record failed LLM call duration metric
        metrics.llmCallDuration.observe(
          { model: targetModel, provider: providerName },
          durationMs / 1000
        );

        await this.healthScorer.recordError(providerName);
        await this.cacheAffinity.clearAffinity(context.projectId);

        await this.eventBus.emit("llm", "llm.call_failed", {
          provider: providerName,
          model: targetModel,
          error: err.message,
          durationMs,
        });

        continue;
      }
    }

    throw lastError || new Error("All LLM providers failed");
  }

  async getHealth(): Promise<ProviderHealth[]> {
    return this.healthScorer.getScores();
  }

  private async buildProviderOrder(
    affinityProvider: string | null,
    preferredProvider: string
  ): Promise<string[]> {
    const scores = await this.healthScorer.getScores();
    const scored = scores
      .map((s) => ({
        name: s.provider,
        sortKey:
          (s.provider === affinityProvider ? 1000 : 0) +
          (s.provider === preferredProvider ? 500 : 0) +
          s.weight * 100,
      }))
      .sort((a, b) => b.sortKey - a.sortKey);

    return scored.map((s) => s.name);
  }

  private withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`LLM call timed out after ${ms}ms`)),
        ms
      );
      promise
        .then((result) => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch((err) => {
          clearTimeout(timer);
          reject(err);
        });
    });
  }
}
