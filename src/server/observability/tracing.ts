import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { HttpInstrumentation } from "@opentelemetry/instrumentation-http";
import { ExpressInstrumentation } from "@opentelemetry/instrumentation-express";
import { IORedisInstrumentation } from "@opentelemetry/instrumentation-ioredis";
import { PgInstrumentation } from "@opentelemetry/instrumentation-pg";
import {
  trace,
  Span,
  SpanStatusCode,
  context as otelContext,
} from "@opentelemetry/api";
import { Resource } from "@opentelemetry/resources";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";

let sdk: NodeSDK | null = null;

const JAEGER_ENDPOINT =
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT || "http://localhost:4418";

export function initTracing(serviceName = "ai-dev-factory"): void {
  const exporter = new OTLPTraceExporter({
    url: `${JAEGER_ENDPOINT}/v1/traces`,
  });

  sdk = new NodeSDK({
    resource: new Resource({
      [ATTR_SERVICE_NAME]: serviceName,
      [ATTR_SERVICE_VERSION]: process.env.APP_VERSION || "0.1.0",
    }),
    traceExporter: exporter,
    instrumentations: [
      new HttpInstrumentation(),
      new ExpressInstrumentation(),
      new IORedisInstrumentation(),
      new PgInstrumentation(),
    ],
  });

  sdk.start();

  process.on("SIGTERM", async () => {
    if (sdk) await sdk.shutdown();
  });
}

const tracer = trace.getTracer("ai-dev-factory");

export function createSpan(
  name: string,
  attributes?: Record<string, string>
): Span {
  const span = tracer.startSpan(name);
  if (attributes) {
    for (const [key, value] of Object.entries(attributes)) {
      span.setAttribute(key, value);
    }
  }
  return span;
}

export async function withSpan<T>(
  name: string,
  fn: () => Promise<T>,
  attributes?: Record<string, string>
): Promise<T> {
  const span = createSpan(name, attributes);
  const ctx = trace.setSpan(otelContext.active(), span);

  try {
    const result = await otelContext.with(ctx, fn);
    span.setStatus({ code: SpanStatusCode.OK });
    return result;
  } catch (err: any) {
    span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
    span.recordException(err);
    throw err;
  } finally {
    span.end();
  }
}

export async function shutdownTracing(): Promise<void> {
  if (sdk) await sdk.shutdown();
}
