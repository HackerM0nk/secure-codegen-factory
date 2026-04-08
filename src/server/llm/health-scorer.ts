import Redis from "ioredis";
import { metrics } from "../observability/metrics";
import type { EventBus } from "../events/event-bus";

export interface ProviderHealth {
  provider: string;
  successes: number;
  errors: number;
  score: number;
  weight: number;
  rpm: number;
  lastUpdated: number;
}

const HEALTH_KEY_PREFIX = "llm:health:";
const RPM_KEY_PREFIX = "llm:rpm:";
const RECALC_INTERVAL_MS = 30_000;
const RPM_HEADROOM = 0.85; // 85% -- exclude at this threshold

export class HealthScorer {
  private redis: Redis;
  private providers: string[];
  private rpmLimits: Record<string, number>;
  private recalcTimer: NodeJS.Timeout | null = null;

  private eventBus?: EventBus;

  constructor(
    redis: Redis,
    providers: string[],
    rpmLimits: Record<string, number> = {},
    eventBus?: EventBus
  ) {
    this.redis = redis;
    this.providers = providers;
    this.rpmLimits = rpmLimits;
    this.eventBus = eventBus;
  }

  async start(): Promise<void> {
    // Initialize any providers that don't have health keys yet
    for (const provider of this.providers) {
      const existing = await this.redis.get(`${HEALTH_KEY_PREFIX}${provider}`);
      if (!existing) {
        const initial: ProviderHealth = {
          provider,
          successes: 0,
          errors: 0,
          score: 1,
          weight: 1 / this.providers.length,
          rpm: 0,
          lastUpdated: Date.now(),
        };
        await this.redis.set(
          `${HEALTH_KEY_PREFIX}${provider}`,
          JSON.stringify(initial)
        );
      }
    }

    this.recalcTimer = setInterval(() => this.recalculate(), RECALC_INTERVAL_MS);
  }

  async shutdown(): Promise<void> {
    if (this.recalcTimer) {
      clearInterval(this.recalcTimer);
      this.recalcTimer = null;
    }
  }

  async recordSuccess(provider: string): Promise<void> {
    const key = `${HEALTH_KEY_PREFIX}${provider}`;
    const raw = await this.redis.get(key);
    if (!raw) return;
    const health: ProviderHealth = JSON.parse(raw);
    health.successes += 1;
    health.lastUpdated = Date.now();
    await this.redis.set(key, JSON.stringify(health));

    // Increment RPM counter (expires after 60 seconds)
    const rpmKey = `${RPM_KEY_PREFIX}${provider}`;
    await this.redis.incr(rpmKey);
    await this.redis.expire(rpmKey, 60);
  }

  async recordError(provider: string): Promise<void> {
    const key = `${HEALTH_KEY_PREFIX}${provider}`;
    const raw = await this.redis.get(key);
    if (!raw) return;
    const health: ProviderHealth = JSON.parse(raw);
    health.errors += 1;
    health.lastUpdated = Date.now();
    await this.redis.set(key, JSON.stringify(health));
  }

  async recalculate(): Promise<void> {
    const healthList: ProviderHealth[] = [];

    for (const provider of this.providers) {
      const raw = await this.redis.get(`${HEALTH_KEY_PREFIX}${provider}`);
      if (!raw) continue;

      const health: ProviderHealth = JSON.parse(raw);
      const rpmStr = await this.redis.get(`${RPM_KEY_PREFIX}${provider}`);
      health.rpm = rpmStr ? parseInt(rpmStr, 10) : 0;

      // PID-inspired score: reward successes, heavily penalize errors
      health.score = health.successes - 200 * health.errors + 1;
      healthList.push(health);
    }

    // Normalize weights across providers
    const totalScore = healthList.reduce(
      (sum, h) => sum + Math.max(h.score, 0.01),
      0
    );

    for (const health of healthList) {
      health.weight = Math.max(health.score, 0.01) / totalScore;

      // Boost zero-usage providers slightly to allow re-entry
      if (health.successes === 0 && health.errors === 0) {
        health.weight += 0.1;
      }

      health.lastUpdated = Date.now();
      await this.redis.set(
        `${HEALTH_KEY_PREFIX}${health.provider}`,
        JSON.stringify(health)
      );

      // Update Prometheus gauge for provider health score
      metrics.providerHealthScore.set({ provider: health.provider }, health.score);

      // Emit provider_health event for degraded providers (consumed by SIEM rule 100010)
      if (this.eventBus && health.score <= 3) {
        await this.eventBus.emit("llm", "llm.provider_health", {
          provider: health.provider,
          score: health.score,
          weight: health.weight,
          rpm: health.rpm,
          errors: health.errors,
          status: health.score <= 1 ? "critical" : "degraded",
        });
      }
    }
  }

  async getScores(): Promise<ProviderHealth[]> {
    const results: ProviderHealth[] = [];
    for (const provider of this.providers) {
      const raw = await this.redis.get(`${HEALTH_KEY_PREFIX}${provider}`);
      if (!raw) continue;

      const health: ProviderHealth = JSON.parse(raw);
      const rpmStr = await this.redis.get(`${RPM_KEY_PREFIX}${provider}`);
      health.rpm = rpmStr ? parseInt(rpmStr, 10) : 0;
      results.push(health);
    }
    return results;
  }

  async isHealthy(provider: string): Promise<boolean> {
    const raw = await this.redis.get(`${HEALTH_KEY_PREFIX}${provider}`);
    if (!raw) return false;

    const health: ProviderHealth = JSON.parse(raw);

    // Check score viability
    if (health.score <= 0) return false;

    // 15% headroom enforcement
    const limit = this.rpmLimits[provider];
    if (limit) {
      const rpmStr = await this.redis.get(`${RPM_KEY_PREFIX}${provider}`);
      const rpm = rpmStr ? parseInt(rpmStr, 10) : 0;
      if (rpm >= limit * RPM_HEADROOM) return false;
    }

    return true;
  }
}
