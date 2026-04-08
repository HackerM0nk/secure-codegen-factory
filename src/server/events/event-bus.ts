import Redis from "ioredis";
import { randomUUID } from "crypto";

export interface DomainEvent {
  id: string;
  stream: string;
  type: string;
  timestamp: string;
  correlationId: string;
  payload: Record<string, any>;
}

type EventHandler = (event: DomainEvent) => Promise<void>;

interface Subscription {
  stream: string;
  group: string;
  consumer: string;
  handler: EventHandler;
  active: boolean;
}

export class EventBus {
  private redis: Redis;
  private subscriber: Redis;
  private subscriptions: Subscription[] = [];
  private reconnecting = false;

  constructor(redisUrl: string = process.env.REDIS_URL || "redis://localhost:6379") {
    this.redis = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy(times: number) {
        return Math.min(times * 200, 5000);
      },
    });

    this.subscriber = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy(times: number) {
        return Math.min(times * 200, 5000);
      },
    });

    this.redis.on("error", (err) => this.handleConnectionError(err));
    this.subscriber.on("error", (err) => this.handleConnectionError(err));
    this.subscriber.on("connect", () => this.handleReconnect());
  }

  async emit(
    stream: string,
    type: string,
    payload: Record<string, any>,
    correlationId?: string
  ): Promise<string> {
    const event: Omit<DomainEvent, "id"> = {
      stream,
      type,
      timestamp: new Date().toISOString(),
      correlationId: correlationId || randomUUID(),
      payload,
    };

    const id = await this.redis.xadd(
      stream,
      "*",
      "type",
      event.type,
      "timestamp",
      event.timestamp,
      "correlationId",
      event.correlationId,
      "payload",
      JSON.stringify(event.payload)
    );

    return id as string;
  }

  async createGroup(stream: string, group: string): Promise<void> {
    try {
      await this.redis.xgroup("CREATE", stream, group, "0", "MKSTREAM");
    } catch (err: any) {
      if (!err.message?.includes("BUSYGROUP")) {
        throw err;
      }
      // Group already exists, safe to ignore
    }
  }

  subscribe(
    stream: string,
    group: string,
    consumer: string,
    handler: EventHandler
  ): void {
    const sub: Subscription = { stream, group, consumer, handler, active: true };
    this.subscriptions.push(sub);
    this.pollLoop(sub);
  }

  private async pollLoop(sub: Subscription): Promise<void> {
    while (sub.active) {
      try {
        const results = await this.subscriber.xreadgroup(
          "GROUP",
          sub.group,
          sub.consumer,
          "COUNT",
          10,
          "BLOCK",
          2000,
          "STREAMS",
          sub.stream,
          ">"
        );

        if (!results) continue;

        for (const [_stream, messages] of results as [string, [string, string[]][]]) {
          for (const [id, fields] of messages) {
            const fieldMap: Record<string, string> = {};
            for (let i = 0; i < fields.length; i += 2) {
              fieldMap[fields[i]] = fields[i + 1];
            }

            const event: DomainEvent = {
              id,
              stream: sub.stream,
              type: fieldMap.type || "",
              timestamp: fieldMap.timestamp || new Date().toISOString(),
              correlationId: fieldMap.correlationId || "",
              payload: fieldMap.payload ? JSON.parse(fieldMap.payload) : {},
            };

            try {
              await sub.handler(event);
              await this.subscriber.xack(sub.stream, sub.group, id);
            } catch (handlerErr) {
              // Do not ack -- message will be redelivered on next read
              console.error(
                `[EventBus] Handler error for ${event.type} on ${sub.stream}:`,
                handlerErr
              );
              // Wait before retrying to avoid tight error loops
              await this.sleep(1000);
            }
          }
        }
      } catch (err) {
        if (sub.active) {
          console.error(`[EventBus] Poll error on ${sub.stream}:`, err);
          await this.sleep(2000);
        }
      }
    }
  }

  private handleConnectionError(err: Error): void {
    console.error("[EventBus] Redis connection error:", err.message);
  }

  private async handleReconnect(): Promise<void> {
    if (this.reconnecting) return;
    this.reconnecting = true;
    try {
      for (const sub of this.subscriptions) {
        if (sub.active) {
          await this.createGroup(sub.stream, sub.group);
        }
      }
    } finally {
      this.reconnecting = false;
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async shutdown(): Promise<void> {
    for (const sub of this.subscriptions) {
      sub.active = false;
    }
    this.subscriptions = [];
    await this.redis.quit();
    await this.subscriber.quit();
  }
}
