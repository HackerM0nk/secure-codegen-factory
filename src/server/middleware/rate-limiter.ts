import { Request, Response, NextFunction } from "express";
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6480");

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

const PLAN_LIMITS: Record<string, RateLimitConfig> = {
  free: { windowMs: 60_000, maxRequests: 5 },      // 5 req/min
  pro: { windowMs: 60_000, maxRequests: 30 },       // 30 req/min
  business: { windowMs: 60_000, maxRequests: 100 },  // 100 req/min
  enterprise: { windowMs: 60_000, maxRequests: 500 }, // 500 req/min
};

export function rateLimiter(keyPrefix = "rl") {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return next();

    const plan = req.user.plan || "free";
    const config = PLAN_LIMITS[plan] || PLAN_LIMITS.free;
    const key = `${keyPrefix}:${req.user.id}`;
    const windowStart = Math.floor(Date.now() / config.windowMs);
    const redisKey = `${key}:${windowStart}`;

    try {
      const current = await redis.incr(redisKey);
      if (current === 1) {
        await redis.pexpire(redisKey, config.windowMs);
      }

      res.setHeader("X-RateLimit-Limit", config.maxRequests);
      res.setHeader("X-RateLimit-Remaining", Math.max(0, config.maxRequests - current));
      res.setHeader("X-RateLimit-Reset", Math.ceil((windowStart + 1) * config.windowMs / 1000));

      if (current > config.maxRequests) {
        return res.status(429).json({
          error: "Rate limit exceeded",
          retryAfter: Math.ceil(config.windowMs / 1000),
          plan,
          limit: config.maxRequests,
        });
      }

      next();
    } catch {
      // If Redis is down, allow the request (fail open for availability)
      next();
    }
  };
}

// Concurrent workspace limiter
const CONCURRENT_LIMITS: Record<string, number> = {
  free: 1,
  pro: 3,
  business: 10,
  enterprise: 50,
};

export async function checkConcurrentLimit(userId: string, plan: string): Promise<{ allowed: boolean; current: number; max: number }> {
  const max = CONCURRENT_LIMITS[plan] || 1;
  const key = `concurrent:${userId}`;
  const current = await redis.scard(key);
  return { allowed: current < max, current, max };
}

export async function trackWorkspace(userId: string, projectId: string): Promise<void> {
  await redis.sadd(`concurrent:${userId}`, projectId);
}

export async function untrackWorkspace(userId: string, projectId: string): Promise<void> {
  await redis.srem(`concurrent:${userId}`, projectId);
}
