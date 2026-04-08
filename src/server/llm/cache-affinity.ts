import Redis from "ioredis";

const AFFINITY_PREFIX = "llm:affinity:";
const TTL_SECONDS = 30 * 60; // 30 minutes

export class CacheAffinity {
  constructor(private redis: Redis) {}

  async getAffinity(projectId: string): Promise<string | null> {
    return this.redis.get(`${AFFINITY_PREFIX}${projectId}`);
  }

  async setAffinity(projectId: string, provider: string): Promise<void> {
    await this.redis.set(
      `${AFFINITY_PREFIX}${projectId}`,
      provider,
      "EX",
      TTL_SECONDS
    );
  }

  async clearAffinity(projectId: string): Promise<void> {
    await this.redis.del(`${AFFINITY_PREFIX}${projectId}`);
  }
}
