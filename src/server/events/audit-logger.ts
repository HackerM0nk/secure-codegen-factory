import * as fs from "fs";
import * as path from "path";
import type { DomainEvent } from "./event-bus";
import type { EventBus } from "./event-bus";

export interface AuditEntry {
  timestamp: string;
  correlationId: string;
  eventType: string;
  userId: string | null;
  projectId: string | null;
  action: string;
  details: Record<string, any>;
}

const LOG_DIR = process.env.AUDIT_LOG_DIR || path.join(process.cwd(), ".audit");
const LOG_FILE = path.join(LOG_DIR, "actions.jsonl");
const FLUSH_INTERVAL_MS = 1000;
const FLUSH_BATCH_SIZE = 100;

const STREAMS = ["agent", "security", "workspace", "llm", "billing", "build", "deploy"];

export class AuditLogger {
  private buffer: string[] = [];
  private fd: number | null = null;
  private flushTimer: NodeJS.Timeout | null = null;
  private started = false;
  private recentEntries: AuditEntry[] = [];
  private maxRecent = 1000;

  constructor(private eventBus: EventBus) {}

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;

    // Ensure log directory exists
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }

    // Open file in append mode
    this.fd = fs.openSync(LOG_FILE, "a");

    // Subscribe to all streams
    for (const stream of STREAMS) {
      const group = "audit-logger";
      const consumer = `audit-${stream}-${process.pid}`;
      await this.eventBus.createGroup(stream, group);
      this.eventBus.subscribe(stream, group, consumer, (event) =>
        this.handleEvent(event)
      );
    }

    // Periodic flush
    this.flushTimer = setInterval(() => this.flush(), FLUSH_INTERVAL_MS);
  }

  async stop(): Promise<void> {
    this.started = false;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    this.flush();
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
  }

  getRecentEntries(n: number): AuditEntry[] {
    return this.recentEntries.slice(-n);
  }

  private async handleEvent(event: DomainEvent): Promise<void> {
    const entry: AuditEntry = {
      timestamp: event.timestamp,
      correlationId: event.correlationId,
      eventType: event.type,
      userId: event.payload.userId ?? null,
      projectId: event.payload.projectId ?? null,
      action: event.type,
      details: event.payload,
    };

    this.recentEntries.push(entry);
    if (this.recentEntries.length > this.maxRecent) {
      this.recentEntries = this.recentEntries.slice(-this.maxRecent);
    }

    this.buffer.push(JSON.stringify(entry));

    if (this.buffer.length >= FLUSH_BATCH_SIZE) {
      this.flush();
    }
  }

  private flush(): void {
    if (this.buffer.length === 0 || this.fd === null) return;

    const data = this.buffer.join("\n") + "\n";
    this.buffer = [];

    try {
      fs.writeSync(this.fd, data);
    } catch (err) {
      console.error("[AuditLogger] Failed to write audit log:", err);
      // Re-buffer the data on failure
      const lines = data.trim().split("\n");
      this.buffer.unshift(...lines);
    }
  }
}
