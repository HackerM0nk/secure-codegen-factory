import pino from "pino";

const BASE_CONFIG: pino.LoggerOptions = {
  level: process.env.LOG_LEVEL || "info",
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level(label: string) {
      return { level: label };
    },
  },
  base: undefined, // remove default pid/hostname; we add our own fields
};

export function createLogger(name: string): pino.Logger {
  return pino({
    ...BASE_CONFIG,
    base: { service: name },
  });
}

export function withCorrelation(
  logger: pino.Logger,
  correlationId: string
): pino.Logger {
  return logger.child({ correlationId });
}
