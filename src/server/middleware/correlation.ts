import { Request, Response, NextFunction } from "express";
import { AsyncLocalStorage } from "async_hooks";
import { randomUUID } from "crypto";

// Extend Express Request to carry correlation ID
declare global {
  namespace Express {
    interface Request {
      correlationId: string;
    }
  }
}

export interface CorrelationContext {
  correlationId: string;
}

export const correlationStorage = new AsyncLocalStorage<CorrelationContext>();

export function getCorrelationId(): string | undefined {
  return correlationStorage.getStore()?.correlationId;
}

export function correlationMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const correlationId =
    (req.headers["x-correlation-id"] as string) || randomUUID();

  req.correlationId = correlationId;
  res.setHeader("x-correlation-id", correlationId);

  correlationStorage.run({ correlationId }, () => {
    next();
  });
}
