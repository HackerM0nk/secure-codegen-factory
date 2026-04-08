// src/server/security/sast-scanner.ts
// In-process semgrep-like static analysis with pattern matching and AST-lite rules

export interface SastFinding {
  rule: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  message: string;
}

interface SastRule {
  id: string;
  severity: SastFinding["severity"];
  cwe: string;
  message: string;
  pattern: RegExp;
  filePattern?: RegExp;
  // If true, only flag when pattern matches inside a function context (not top-level const)
  requireContext?: boolean;
}

const RULES: SastRule[] = [
  // ── Injection ────────────────────────────────────────────────────────
  {
    id: "eval-with-variable",
    severity: "critical",
    cwe: "CWE-95",
    message: "eval() called with dynamic input — code injection risk",
    pattern: /\beval\s*\(\s*(?!['"`])[a-zA-Z_$]/,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },
  {
    id: "function-constructor",
    severity: "critical",
    cwe: "CWE-95",
    message: "Function constructor used — equivalent to eval()",
    pattern: /new\s+Function\s*\(/,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },
  {
    id: "innerhtml-assignment",
    severity: "high",
    cwe: "CWE-79",
    message: "innerHTML assignment — XSS risk",
    pattern: /\.innerHTML\s*=\s*(?!['"`]<)/,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },
  {
    id: "dangerously-set-innerhtml",
    severity: "high",
    cwe: "CWE-79",
    message: "dangerouslySetInnerHTML — XSS risk, ensure input is sanitized",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/,
    filePattern: /\.(tsx|jsx)$/,
  },
  {
    id: "document-write",
    severity: "high",
    cwe: "CWE-79",
    message: "document.write() — XSS risk and performance issue",
    pattern: /document\.write\s*\(/,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },

  // ── Command Injection ────────────────────────────────────────────────
  {
    id: "child-process-exec-variable",
    severity: "critical",
    cwe: "CWE-78",
    message: "child_process.exec with dynamic input — command injection risk",
    pattern: /(?:exec|execSync)\s*\(\s*(?!['"`])[a-zA-Z_$`]/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },
  {
    id: "shell-spawn-variable",
    severity: "high",
    cwe: "CWE-78",
    message: "spawn/execFile with shell:true — potential command injection",
    pattern: /(?:spawn|execFile)\s*\([^)]*shell\s*:\s*true/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },

  // ── SQL Injection ────────────────────────────────────────────────────
  {
    id: "sql-string-concat",
    severity: "critical",
    cwe: "CWE-89",
    message: "SQL query built with string concatenation — SQL injection risk",
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\$\{/i,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },
  {
    id: "sql-string-plus",
    severity: "high",
    cwe: "CWE-89",
    message: "SQL query built with + operator — SQL injection risk",
    pattern: /(?:query|execute)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE)\s.*['"]\s*\+/i,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },

  // ── Path Traversal ───────────────────────────────────────────────────
  {
    id: "path-traversal-join",
    severity: "high",
    cwe: "CWE-22",
    message: "path.join with user input without validation — path traversal risk",
    pattern: /path\.(?:join|resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },
  {
    id: "fs-read-variable",
    severity: "medium",
    cwe: "CWE-22",
    message: "fs.readFile with dynamic path — ensure path validation",
    pattern: /fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?!['"`\/])[a-zA-Z_$]/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },

  // ── Hardcoded Credentials ────────────────────────────────────────────
  {
    id: "hardcoded-password",
    severity: "high",
    cwe: "CWE-798",
    message: "Hardcoded password detected",
    pattern: /(?:password|passwd|secret|token|apiKey|api_key)\s*[:=]\s*['"`][A-Za-z0-9+/=]{8,}/i,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs|json)$/,
  },
  {
    id: "hardcoded-aws-key",
    severity: "critical",
    cwe: "CWE-798",
    message: "Hardcoded AWS access key detected",
    pattern: /AKIA[0-9A-Z]{16}/,
  },
  {
    id: "hardcoded-private-key",
    severity: "critical",
    cwe: "CWE-321",
    message: "Private key embedded in source code",
    pattern: /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----/,
  },

  // ── Insecure Crypto ──────────────────────────────────────────────────
  {
    id: "weak-hash-md5",
    severity: "medium",
    cwe: "CWE-328",
    message: "MD5 hash used — cryptographically broken, use SHA-256+",
    pattern: /createHash\s*\(\s*['"`]md5['"`]\s*\)/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },
  {
    id: "weak-hash-sha1",
    severity: "medium",
    cwe: "CWE-328",
    message: "SHA-1 hash used — deprecated, use SHA-256+",
    pattern: /createHash\s*\(\s*['"`]sha1['"`]\s*\)/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },
  {
    id: "math-random-security",
    severity: "medium",
    cwe: "CWE-338",
    message: "Math.random() used for potential security purpose — use crypto.randomBytes()",
    pattern: /Math\.random\s*\(\s*\)/,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },

  // ── Deserialization ──────────────────────────────────────────────────
  {
    id: "json-parse-unvalidated",
    severity: "medium",
    cwe: "CWE-502",
    message: "JSON.parse on external input — validate schema after parsing",
    pattern: /JSON\.parse\s*\(\s*(?:req\.|body|data|response|input|payload)/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },

  // ── Prototype Pollution ──────────────────────────────────────────────
  {
    id: "prototype-pollution",
    severity: "high",
    cwe: "CWE-1321",
    message: "Dynamic property assignment — prototype pollution risk",
    pattern: /\[(?:key|prop|name|field|attr)\]\s*=/,
    filePattern: /\.(ts|js|mjs|cjs)$/,
  },

  // ── SSRF ─────────────────────────────────────────────────────────────
  {
    id: "ssrf-fetch-variable",
    severity: "high",
    cwe: "CWE-918",
    message: "fetch() with dynamic URL — SSRF risk, validate URL allowlist",
    pattern: /fetch\s*\(\s*(?!['"`]https?:\/\/)[a-zA-Z_$`]/,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },

  // ── Logging Sensitive Data ───────────────────────────────────────────
  {
    id: "log-sensitive-data",
    severity: "medium",
    cwe: "CWE-532",
    message: "Potentially logging sensitive data — ensure PII/secrets are masked",
    pattern: /(?:console\.log|logger\.info|logger\.debug)\s*\([^)]*(?:password|token|secret|apiKey|authorization)/i,
    filePattern: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
  },
];

// Files/dirs to always skip
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".devfactory",
  "coverage",
  "__pycache__",
]);

const SKIP_FILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
]);

export interface SastScanResult {
  tool: "sast";
  findings: SastFinding[];
  filesScanned: number;
  rulesApplied: number;
  durationMs: number;
  passed: boolean;
}

/**
 * Scan file contents for SAST findings.
 * Accepts a map of { relativePath: fileContent } so it works with both
 * local files and workspace container files.
 */
export function scanFiles(
  files: Map<string, string>,
  options?: { severityThreshold?: SastFinding["severity"] }
): SastScanResult {
  const start = Date.now();
  const findings: SastFinding[] = [];
  let filesScanned = 0;

  for (const [filePath, content] of files) {
    // Skip excluded files
    const pathParts = filePath.split("/");
    if (pathParts.some((part) => SKIP_DIRS.has(part))) continue;
    if (SKIP_FILES.has(pathParts[pathParts.length - 1])) continue;

    filesScanned++;
    const lines = content.split("\n");

    for (const rule of RULES) {
      // Check file pattern
      if (rule.filePattern && !rule.filePattern.test(filePath)) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = rule.pattern.exec(line);
        if (match) {
          findings.push({
            rule: rule.id,
            severity: rule.severity,
            cwe: rule.cwe,
            file: filePath,
            line: i + 1,
            column: match.index + 1,
            snippet: line.trim().substring(0, 120),
            message: rule.message,
          });
        }
      }
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const threshold = options?.severityThreshold || "critical";
  const thresholdLevel = severityOrder[threshold];
  const passed = !findings.some((f) => severityOrder[f.severity] <= thresholdLevel);

  return {
    tool: "sast",
    findings,
    filesScanned,
    rulesApplied: RULES.length,
    durationMs: Date.now() - start,
    passed,
  };
}
