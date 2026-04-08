# LLM Pipeline Architecture

The LLM pipeline routes user prompts to the most appropriate model and provider based on task complexity, provider health, and project affinity. It supports three provider backends and implements automatic failover with retry logic.

Source files:
- `src/server/llm/router.ts` -- orchestrator
- `src/server/llm/provider.ts` -- shared interface and types
- `src/server/llm/complexity-classifier.ts` -- model selection logic
- `src/server/llm/cache-affinity.ts` -- project-to-provider stickiness
- `src/server/llm/health-scorer.ts` -- weighted provider scoring
- `src/server/llm/providers/anthropic.ts` -- direct Anthropic API
- `src/server/llm/providers/bedrock.ts` -- AWS Bedrock (Anthropic models)
- `src/server/llm/providers/openai-compat.ts` -- OpenAI-compatible (Ollama, OpenAI, etc.)

## Request Flow

```
User message
     |
     v
+--------------------+
| classifyComplexity |  keywords + token count + history analysis
|  simple / medium / |
|  complex           |
+--------+-----------+
         |
         v
+--------+-----------+
| getModelForComplex |  maps complexity -> (provider, model)
|  simple  -> Haiku  |
|  medium  -> Sonnet |
|  complex -> Opus   |
+--------+-----------+
         |
         v
+--------+-----------+
| cacheAffinity      |  check Redis for project -> provider binding
| .getAffinity()     |
+--------+-----------+
         |
         v
+--------+-----------+
| buildProviderOrder |  score = affinity(1000) + preferred(500) + health(weight*100)
|                    |  sort descending
+--------+-----------+
         |
         v
+--------+-----------+
| Try providers      |  up to MAX_RETRIES+1 = 3 attempts
| in scored order    |  skip unhealthy on retries
|                    |  timeout per complexity tier
+--------+-----------+
         |
    success / failure
         |
         v
+--------+-----------+
| Record health      |  success -> recordSuccess, setAffinity
| Emit events        |  failure -> recordError, clearAffinity
+--------------------+
```

## Provider Interface

Every provider implements the `LLMProvider` interface defined in `provider.ts`:

```typescript
interface LLMProvider {
  name: string;
  complete(params: CompletionParams): Promise<CompletionResult>;
}
```

`CompletionParams` includes `model`, `messages` (with `TextBlock`, `ToolUseBlock`, `ToolResultBlock` content types), `tools`, `maxTokens`, and `system` prompt. `CompletionResult` returns `content` blocks, `stopReason` (`end_turn` | `tool_use` | `max_tokens`), `usage` (input/output/cacheRead tokens), `model`, and `provider` name.

## Providers

### Anthropic Direct (`anthropic.ts`)

Uses the `@anthropic-ai/sdk` package. Configured via `ANTHROPIC_API_KEY`. Implements internal retry with exponential backoff on 429 (rate limit) responses, up to 3 retries with a 30-second max backoff. Non-429 errors are thrown immediately.

### AWS Bedrock (`bedrock.ts`)

Uses the `@anthropic-ai/bedrock-sdk` package. Configured via standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) or the default credential chain (SSO, instance metadata). Defaults to `us-west-2` region.

Maintains a model name mapping table translating short names to Bedrock model IDs:

| Short Name | Bedrock Model ID |
|-----------|------------------|
| `claude-haiku-3.5` | `us.anthropic.claude-3-5-haiku-20241022-v1:0` |
| `claude-sonnet-4-20250514` | `us.anthropic.claude-sonnet-4-20250514-v1:0` |
| `claude-sonnet-4` | `us.anthropic.claude-sonnet-4-20250514-v1:0` |
| `claude-opus-4` | `us.anthropic.claude-opus-4-20250514-v1:0` |
| `claude-opus-4-5` | `us.anthropic.claude-opus-4-5-20251101-v1:0` |
| `claude-opus-4-1` | `us.anthropic.claude-opus-4-1-20250805-v1:0` |
| `claude-opus-4-6` | `us.anthropic.claude-opus-4-6-v1` |
| `claude-sonnet-4-6` | `us.anthropic.claude-sonnet-4-6-v1` |

### OpenAI-Compatible (`openai-compat.ts`)

Uses the `openai` npm package. The `name`, `baseURL`, and `apiKey` are constructor parameters. This provider supports any OpenAI-compatible API, including local Ollama instances (`http://localhost:11434/v1`).

Handles message format translation: Anthropic `tool_use`/`tool_result` content blocks are mapped to OpenAI `function` tool calls and `tool` role messages. The `system` prompt is injected as a system message.

## Complexity Classifier

The classifier in `complexity-classifier.ts` determines whether a user message is `simple`, `medium`, or `complex` using a keyword + heuristic approach.

### Classification Logic

1. **Complex** (checked first, highest priority):
   - Message matches complex keywords (`refactor`, `architect`, `migrate`, `security`, `authentication`, `database schema`, `websocket`, `deployment`, etc.)
   - Conversation has more than 10 turns
   - Conversation history contains build failure indicators (`Build error`, `TypeError`, `Cannot find module`)

2. **Medium** (default when history exists):
   - Any message with conversation history defaults to medium (Haiku lacks context reasoning)
   - Message matches medium keywords (`add feature`, `implement`, `create component`, `form`, `api endpoint`, `state management`, etc.)

3. **Simple** (only for first message with no history):
   - Token estimate under 100 AND matches simple keywords (`change`, `fix typo`, `rename`, `color`, `padding`, `css`, etc.)
   - Token estimate under 50 (regardless of keywords)

4. **Default**: medium

### Model Mapping

| Complexity | Default Provider | Default Model | Override Env Vars |
|-----------|-----------------|---------------|-------------------|
| simple | bedrock | claude-haiku-3.5 | `SIMPLE_MODEL_PROVIDER`, `SIMPLE_MODEL` |
| medium | bedrock | claude-sonnet-4-20250514 | `MEDIUM_MODEL_PROVIDER`, `MEDIUM_MODEL` |
| complex | bedrock | claude-opus-4 | `COMPLEX_MODEL_PROVIDER`, `COMPLEX_MODEL` |

All providers fall back to `DEFAULT_LLM_PROVIDER` (env var), then to `bedrock`.

## Timeout Configuration

Timeouts scale with complexity to give larger models sufficient time:

| Complexity | Timeout |
|-----------|---------|
| simple | 30 seconds |
| medium | 90 seconds |
| complex | 180 seconds |
| default | 120 seconds |

## Health Scorer

`health-scorer.ts` maintains per-provider health state in Redis under `llm:health:<provider>` keys. Each provider tracks: `successes`, `errors`, `score`, `weight`, `rpm`, `lastUpdated`.

### Scoring Algorithm

Scores are recalculated every 30 seconds:
- `score = successes - (200 * errors) + 1` (PID-inspired: heavily penalize errors)
- Weights are normalized across all providers: `weight = max(score, 0.01) / totalScore`
- Zero-usage providers get a +0.1 weight bonus to allow re-entry after recovery

### Health Check

A provider is considered **unhealthy** when:
- Its score is <= 0
- Its RPM reaches 85% of the configured limit (`RPM_HEADROOM = 0.85`)

RPM is tracked via Redis keys with 60-second TTL (`llm:rpm:<provider>`), incremented on each success.

## Cache Affinity

`cache-affinity.ts` provides project-to-provider stickiness stored in Redis under `llm:affinity:<projectId>` with a 30-minute TTL. When a project successfully completes a request through a provider, that provider gets a 1000-point bonus in the next routing decision for the same project. This improves cache hit rates when providers support prompt caching.

Affinity is cleared on provider failure to allow failover.

## Provider Ordering

The `buildProviderOrder` method in the router scores each provider:
- **Affinity match**: +1000 points
- **Preferred provider** (from complexity classifier): +500 points
- **Health weight**: weight * 100 points

Providers are sorted by descending score. On the first attempt, even unhealthy providers are tried (the affinity or preferred provider might be temporarily degraded). On retries, unhealthy providers are skipped.

## Validation Pipeline Integration

The LLM pipeline is integrated with a post-generation validation pipeline:
- **Post file_write AST validation**: after the agent writes a file, the validation pipeline parses the output using AST analysis to catch syntax errors and structural issues before they persist.
- **Post-completion build verification with autofix**: after the agent completes a task, a build verification step runs. If the build fails, the pipeline invokes a secondary LLM call to attempt an automatic fix and re-verify.

Build events (`build.verification_started`, `build.verification_passed`, `build.verification_failed`, `build.autofix_applied`) are emitted to the `build` stream throughout this process.

## LLM Call Metrics

The router instruments every LLM call with Prometheus metrics:
- `llm_call_duration_seconds` histogram -- observed on every completed or failed call, labeled by model and provider
- `llm_tokens_total` counter -- incremented with input and output token counts on each successful completion

These metrics are actively recorded during runtime, enabling latency percentile alerting and token budget monitoring.

## Health Endpoint

`GET /api/agent/llm-health` exposes current provider health scores, weights, RPM counters, and error/success counts for all configured providers. This endpoint is used by monitoring dashboards and operational tooling to inspect real-time provider status.

## Event Emission

The router emits three event types to the `llm` stream:
- `llm.call_started` -- provider, model, estimated input tokens
- `llm.call_completed` -- provider, model, input/output tokens, duration, cache status
- `llm.call_failed` -- provider, model, error message, duration
