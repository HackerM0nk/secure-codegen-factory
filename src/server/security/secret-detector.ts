// src/server/security/secret-detector.ts
// Detect secrets in user chat messages and agent-generated code

export interface SecretDetection {
  type: string;
  placeholder: string;
  startIndex: number;
  endIndex: number;
  maskedValue: string;
}

export interface SecretDetectorResult {
  sanitized: string;
  detections: SecretDetection[];
}

// ── Redis interface (optional dependency) ───────────────────────────────────

export interface RedisLike {
  set(key: string, value: string, ...args: any[]): Promise<any>;
  get(key: string): Promise<string | null>;
}

let redisClient: RedisLike | null = null;

export function setRedisClient(client: RedisLike): void {
  redisClient = client;
}

// ── Shannon entropy ─────────────────────────────────────────────────────────

export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

// ── Secret patterns ─────────────────────────────────────────────────────────

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  // AWS
  { name: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g },
  { name: "aws_secret_key", regex: /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}/g },

  // Anthropic
  { name: "anthropic_api_key", regex: /sk-ant-api\d{2}-[A-Za-z0-9\-_]{86}/g },

  // OpenAI (but not Anthropic sk-ant-)
  { name: "openai_api_key", regex: /sk-(?!ant-)[A-Za-z0-9]{48,}/g },

  // GitHub
  { name: "github_pat", regex: /ghp_[A-Za-z0-9]{36}/g },
  { name: "github_pat_fine", regex: /github_pat_[A-Za-z0-9_]{82}/g },

  // Stripe
  { name: "stripe_secret_live", regex: /sk_live_[A-Za-z0-9]{24,}/g },
  { name: "stripe_secret_test", regex: /sk_test_[A-Za-z0-9]{24,}/g },
  { name: "stripe_pub_live", regex: /pk_live_[A-Za-z0-9]{24,}/g },
  { name: "stripe_pub_test", regex: /pk_test_[A-Za-z0-9]{24,}/g },

  // Private keys
  {
    name: "private_key_pem",
    regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
  },

  // Generic tokens (Slack, SendGrid)
  {
    name: "slack_token",
    regex: /xox[bpras]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/g,
  },
  {
    name: "sendgrid_key",
    regex: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
  },
];

// ── High-entropy token detection ────────────────────────────────────────────

function findHighEntropyTokens(
  text: string
): Array<{ start: number; end: number; token: string }> {
  const tokenRegex = /[A-Za-z0-9+/=\-_]{20,}/g;
  const results: Array<{ start: number; end: number; token: string }> = [];
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(text)) !== null) {
    const token = match[0];
    const entropy = shannonEntropy(token);
    if (entropy > 4.5) {
      const isLikelyPath = /^[a-z0-9]+(-[a-z0-9]+)*$/.test(token);
      const isUUID =
        /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(
          token
        );
      if (!isLikelyPath && !isUUID) {
        results.push({
          start: match.index,
          end: match.index + token.length,
          token,
        });
      }
    }
  }
  return results;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const chr = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

function maskValue(value: string): string {
  if (value.length <= 8) return "****";
  return value.substring(0, 4) + "****" + value.substring(value.length - 4);
}

// ── Public API ──────────────────────────────────────────────────────────────

export function detectSecrets(text: string): SecretDetectorResult {
  const allMatches: Array<{
    type: string;
    start: number;
    end: number;
    value: string;
  }> = [];

  // Pattern-based detection
  for (const { name, regex } of SECRET_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      allMatches.push({
        type: name,
        start: match.index,
        end: match.index + match[0].length,
        value: match[0],
      });
    }
  }

  // High-entropy detection
  const entropyMatches = findHighEntropyTokens(text);
  for (const { start, end, token } of entropyMatches) {
    const alreadyCovered = allMatches.some(
      (m) =>
        (start >= m.start && start < m.end) ||
        (m.start >= start && m.start < end)
    );
    if (!alreadyCovered) {
      allMatches.push({
        type: "high_entropy_token",
        start,
        end,
        value: token,
      });
    }
  }

  if (allMatches.length === 0) {
    return { sanitized: text, detections: [] };
  }

  // Sort descending by start for safe replacement
  allMatches.sort((a, b) => b.start - a.start);

  // Deduplicate overlapping matches
  const deduped: typeof allMatches = [];
  for (const match of allMatches) {
    const overlaps = deduped.some(
      (m) =>
        (match.start >= m.start && match.start < m.end) ||
        (m.start >= match.start && m.start < match.end)
    );
    if (!overlaps) {
      deduped.push(match);
    }
  }

  deduped.sort((a, b) => b.start - a.start);

  let sanitized = text;
  const detections: SecretDetection[] = [];

  deduped.forEach((match, idx) => {
    const placeholder = `[REDACTED_SECRET_${deduped.length - idx}]`;
    sanitized =
      sanitized.substring(0, match.start) +
      placeholder +
      sanitized.substring(match.end);

    const detection: SecretDetection = {
      type: match.type,
      placeholder,
      startIndex: match.start,
      endIndex: match.end,
      maskedValue: maskValue(match.value),
    };
    detections.push(detection);

    // Store in Redis if available (fire-and-forget)
    if (redisClient) {
      const hash = simpleHash(match.value);
      const redisValue = JSON.stringify({
        type: match.type,
        maskedValue: detection.maskedValue,
        detectedAt: new Date().toISOString(),
      });
      redisClient
        .set(`secret:${hash}`, redisValue, "EX", 86400)
        .catch(() => {});
    }
  });

  detections.reverse();
  return { sanitized, detections };
}
