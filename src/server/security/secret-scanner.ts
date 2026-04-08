// src/server/security/secret-scanner.ts
// Bulk file scanner for secrets using TruffleHog-style patterns + entropy analysis
// Distinct from secret-detector.ts which handles single user input strings

import { createHash } from "crypto";

export interface SecretFinding {
  rule: string;
  severity: "critical" | "high" | "medium";
  file: string;
  line: number;
  snippet: string;
  type: string;
  entropy?: number;
}

export interface SecretScanResult {
  tool: "secrets";
  findings: SecretFinding[];
  filesScanned: number;
  durationMs: number;
  passed: boolean;
}

interface SecretPattern {
  id: string;
  type: string;
  severity: SecretFinding["severity"];
  pattern: RegExp;
}

const PATTERNS: SecretPattern[] = [
  // ── AWS ──────────────────────────────────────────────────────────────
  {
    id: "aws-access-key",
    type: "AWS Access Key",
    severity: "critical",
    pattern: /(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:$|[^A-Z0-9])/,
  },
  {
    id: "aws-secret-key",
    type: "AWS Secret Key",
    severity: "critical",
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)\s*[:=]\s*['"`]?([A-Za-z0-9/+=]{40})['"`]?/,
  },

  // ── GitHub ───────────────────────────────────────────────────────────
  {
    id: "github-pat",
    type: "GitHub PAT",
    severity: "critical",
    pattern: /\b(ghp_[A-Za-z0-9]{36,})\b/,
  },
  {
    id: "github-pat-fine",
    type: "GitHub Fine-Grained PAT",
    severity: "critical",
    pattern: /\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b/,
  },
  {
    id: "github-oauth",
    type: "GitHub OAuth",
    severity: "critical",
    pattern: /\b(gho_[A-Za-z0-9]{36,})\b/,
  },

  // ── Anthropic / OpenAI ───────────────────────────────────────────────
  {
    id: "anthropic-key",
    type: "Anthropic API Key",
    severity: "critical",
    pattern: /\b(sk-ant-api[A-Za-z0-9-]{20,})\b/,
  },
  {
    id: "openai-key",
    type: "OpenAI API Key",
    severity: "critical",
    pattern: /\b(sk-[A-Za-z0-9]{48,})\b/,
  },

  // ── Stripe ───────────────────────────────────────────────────────────
  {
    id: "stripe-live-secret",
    type: "Stripe Live Secret Key",
    severity: "critical",
    pattern: /\b(sk_live_[A-Za-z0-9]{24,})\b/,
  },
  {
    id: "stripe-live-publish",
    type: "Stripe Live Publishable Key",
    severity: "high",
    pattern: /\b(pk_live_[A-Za-z0-9]{24,})\b/,
  },

  // ── Slack ────────────────────────────────────────────────────────────
  {
    id: "slack-webhook",
    type: "Slack Webhook",
    severity: "high",
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+)/,
  },
  {
    id: "slack-token",
    type: "Slack Token",
    severity: "critical",
    pattern: /\b(xox[bpors]-[A-Za-z0-9-]{10,})\b/,
  },

  // ── SendGrid ─────────────────────────────────────────────────────────
  {
    id: "sendgrid-key",
    type: "SendGrid API Key",
    severity: "critical",
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/,
  },

  // ── Private Keys ─────────────────────────────────────────────────────
  {
    id: "private-key-rsa",
    type: "RSA Private Key",
    severity: "critical",
    pattern: /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/,
  },
  {
    id: "private-key-ec",
    type: "EC Private Key",
    severity: "critical",
    pattern: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/,
  },
  {
    id: "private-key-openssh",
    type: "OpenSSH Private Key",
    severity: "critical",
    pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/,
  },
  {
    id: "private-key-generic",
    type: "Private Key",
    severity: "critical",
    pattern: /-----BEGIN\s+PRIVATE\s+KEY-----/,
  },

  // ── Database URLs ────────────────────────────────────────────────────
  {
    id: "database-url",
    type: "Database Connection String",
    severity: "high",
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^\s'"]+/,
  },

  // ── JWT / Generic ────────────────────────────────────────────────────
  {
    id: "jwt-token",
    type: "JWT Token",
    severity: "medium",
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  },

  // ── Google ───────────────────────────────────────────────────────────
  {
    id: "google-api-key",
    type: "Google API Key",
    severity: "high",
    pattern: /\b(AIza[A-Za-z0-9_-]{35})\b/,
  },
];

// Files/dirs to skip
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next",
  "coverage", "__pycache__", ".devfactory",
]);
const SKIP_FILES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
]);
// Skip binary extensions
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot",
  ".zip", ".gz", ".tar", ".br",
  ".mp3", ".mp4", ".webm", ".ogg",
  ".wasm", ".map",
]);

/**
 * Shannon entropy of a string segment.
 */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Find high-entropy strings that look like secrets.
 */
function findHighEntropyStrings(
  line: string,
  lineNum: number,
  filePath: string
): SecretFinding[] {
  const findings: SecretFinding[] = [];

  // Match quoted strings and assignments
  const patterns = [
    /['"`]([A-Za-z0-9+/=_-]{20,})['"`]/g,
    /[:=]\s*['"`]([A-Za-z0-9+/=_-]{20,})['"`]/g,
  ];

  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(line)) !== null) {
      const candidate = match[1];
      if (!candidate) continue;

      // Skip common non-secret patterns
      if (/^[a-f0-9]{24}$/.test(candidate)) continue; // MongoDB ObjectId
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(candidate)) continue; // UUID
      if (/^(https?:|\/|\.\/|\.\.\/|node_modules)/.test(candidate)) continue; // URLs/paths
      if (/^[A-Z_]+$/.test(candidate)) continue; // Constants

      const entropy = shannonEntropy(candidate);
      if (entropy > 4.5 && candidate.length >= 24) {
        findings.push({
          rule: "high-entropy-string",
          severity: "medium",
          file: filePath,
          line: lineNum,
          snippet: line.trim().substring(0, 120),
          type: "High-Entropy String",
          entropy: Math.round(entropy * 100) / 100,
        });
        break; // One per line is enough
      }
    }
  }

  return findings;
}

/**
 * Scan file contents for secrets.
 * Accepts a map of { relativePath: fileContent }.
 */
export function scanForSecrets(
  files: Map<string, string>
): SecretScanResult {
  const start = Date.now();
  const findings: SecretFinding[] = [];
  const seen = new Set<string>(); // Deduplicate by file+line+rule
  let filesScanned = 0;

  for (const [filePath, content] of files) {
    // Skip excluded paths
    const pathParts = filePath.split("/");
    if (pathParts.some((p) => SKIP_DIRS.has(p))) continue;
    const fileName = pathParts[pathParts.length - 1];
    if (SKIP_FILES.has(fileName)) continue;
    const ext = fileName.includes(".") ? "." + fileName.split(".").pop() : "";
    if (BINARY_EXT.has(ext.toLowerCase())) continue;

    filesScanned++;
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      // Skip comment lines
      if (/^\s*(\/\/|#|\/\*|\*)/.test(line) && !line.includes("sk-") && !line.includes("AKIA")) continue;

      // Pattern-based detection
      for (const pat of PATTERNS) {
        if (pat.pattern.test(line)) {
          const key = `${filePath}:${i + 1}:${pat.id}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              rule: pat.id,
              severity: pat.severity,
              file: filePath,
              line: i + 1,
              snippet: line.trim().substring(0, 120),
              type: pat.type,
            });
          }
        }
      }

      // Entropy-based detection (only on lines with assignments or strings)
      if (line.includes("=") || line.includes(":") || line.includes("'") || line.includes('"')) {
        const entropyFindings = findHighEntropyStrings(line, i + 1, filePath);
        for (const f of entropyFindings) {
          const key = `${f.file}:${f.line}:${f.rule}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push(f);
          }
        }
      }
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3));

  return {
    tool: "secrets",
    findings,
    filesScanned,
    durationMs: Date.now() - start,
    passed: !findings.some((f) => f.severity === "critical"),
  };
}
